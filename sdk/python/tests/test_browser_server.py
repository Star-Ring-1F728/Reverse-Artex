from contextlib import closing
import io
import json
import os
import secrets
import signal
import socket
import sqlite3
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

from reverse_artex_guard.browser_server import BrowserSSOServer, run_browser_server
from reverse_artex_guard.browser_sso import BrowserSSO, BrowserSSOHandler, NoRedirect, Unavailable
from reverse_artex_guard.browser_state_migration import transition_browser_state
from reverse_artex_guard.sqlite_browser_state import SQLiteBrowserState
import test_sqlite_browser_state as shared
from sqlite_browser_sessions import SQLiteBrowserSessions


class BrowserRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        shared.SharedBrowserStateTests.setUpClass()

    def setUp(self):
        self.fx = shared.SharedBrowserStateTests(); self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.servers, self.releases = [], []
        self.addCleanup(self.finish)
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def finish(self):
        for event in self.releases: event.set()
        for server, thread in self.servers:
            server.stop(2)
            if thread is not None: thread.join(2)

    def make_server(self, *, sso=None, readiness=None, handler=BrowserSSOHandler, start=True, **options):
        sso = self.fx.a if sso is None else sso
        readiness = sso._state_store.ready if readiness is None else readiness
        server = BrowserSSOServer(('127.0.0.1', 0), handler, sso=sso, edge_origin='http://127.0.0.1:18273',
            allow_read=lambda path: path == '/api/objects/1', readiness_check=readiness, **options)
        thread = None
        if start:
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            self.assertTrue(server.started.wait(1))
        self.servers.append((server, thread))
        return server

    def request(self, server, path, *, method='GET', headers=None, data=None):
        request = urllib.request.Request('http://127.0.0.1:' + str(server.server_port) + path, method=method,
            headers={'Host': self.fx.origin.split('://')[1], **(headers or {})}, data=data)
        try: response = self.http.open(request, timeout=3)
        except urllib.error.HTTPError as error: response = error
        with response: return response.status, response.read(), response.headers

    def wait(self, predicate):
        deadline = time.monotonic() + 3
        while not predicate():
            if time.monotonic() > deadline: self.fail('owned runtime condition deadline')
            time.sleep(.01)

    def snapshot(self):
        with closing(sqlite3.connect(self.fx.path)) as db:
            return tuple(db.execute('SELECT * FROM ' + table + ' ORDER BY 1,2').fetchall()
                         for table in ('ra_browser_state_meta', 'ra_browser_records', 'sessions'))

    def held_callback(self, server, *, sid='held-session'):
        f = self.fx
        query, binding = f.begin(server.sso)
        entered, release = threading.Event(), threading.Event()
        self.releases.append(release)
        def exchange(*_):
            entered.set()
            if not release.wait(4): raise RuntimeError('owned exchange deadline')
            return f.flow.tokens(query['nonce'], sid=sid)
        server.sso.exchange = exchange
        result = []
        path = '/auth/callback?' + urllib.parse.urlencode({'state': query['state'], 'code': 'c'})
        def call():
            try: result.append(self.request(server, path, headers={'Cookie': server.sso.tx_cookie + '=' + binding}))
            except Exception as error: result.append(type(error).__name__)
        thread = threading.Thread(target=call, daemon=True); thread.start()
        self.assertTrue(entered.wait(2))
        return result, thread, release

    def test_probes_are_boolean_only_and_do_not_prune_or_extend_state(self):
        f = self.fx
        f.complete(); f.begin(); f.flow.now += 121
        before = self.snapshot()
        server = self.make_server()
        for path, expected in (('/healthz', {'live': True}), ('/readyz', {'ready': True})):
            status, body, headers = self.request(server, path)
            self.assertEqual((status, json.loads(body)), (200, expected))
            self.assertEqual(headers['Cache-Control'], 'no-store')
            self.assertEqual(headers['Connection'], 'close')
            self.assertNotIn('Set-Cookie', headers)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(server.active_requests, 0)

    def test_probe_methods_host_query_and_identity_headers_stay_strict(self):
        server = self.make_server()
        self.assertEqual(self.request(server, '/readyz', method='HEAD')[:2], (200, b''))
        for path, method, headers, want in [('/readyz?x=1', 'GET', {}, 400), ('/readyz', 'POST', {}, 405),
            ('/healthz', 'GET', {'Host': 'wrong.example'}, 400), ('/readyz', 'GET', {'Authorization': 'Bearer unrelated'}, 400),
            ('/readyz', 'GET', {'X-RA-Forged': 'yes'}, 400), ('/readyz', 'GET', {'Content-Length': '1'}, 400)]:
            with self.subTest(path=path, method=method, headers=list(headers)):
                self.assertEqual(self.request(server, path, method=method, headers=headers)[0], want)
        self.assertEqual(self.request(server, '/auth/drain')[0], 404)

    def test_schema_failure_changes_readiness_but_liveness_survives(self):
        server = self.make_server()
        self.fx.raw('ALTER TABLE sessions RENAME TO unavailable_sessions')
        try:
            self.assertEqual(self.request(server, '/readyz')[:2], (503, b'{"ready":false}'))
            self.assertEqual(self.request(server, '/healthz')[0], 200)
        finally:
            self.fx.raw('ALTER TABLE unavailable_sessions RENAME TO sessions')
        self.assertEqual(self.request(server, '/readyz')[0], 200)

    def test_DB_busy_fails_readiness_closed_and_recovers_without_state_changes(self):
        server = self.make_server()
        before = self.snapshot()
        with self.fx.app._write():
            self.assertEqual(self.request(server, '/readyz')[0], 503)
            self.assertEqual(self.request(server, '/healthz')[0], 200)
        self.assertEqual(self.request(server, '/readyz')[0], 200)
        self.assertEqual(self.snapshot(), before)

    def test_key_rotation_readiness_fences_old_worker_and_adopts_preloaded_key(self):
        f = self.fx
        next_key = secrets.token_bytes(32)
        state = SQLiteBrowserState(f.app, f.master, additional_keys=(next_key,), identity_digest=f.digest, public_origin=f.origin, capacity=f.capacity)
        prepared = f.controller(state)
        old, new = self.make_server(), self.make_server(sso=prepared)
        self.assertEqual(self.request(old, '/readyz')[0], 200)
        result = transition_browser_state(f.app, (f.master,), identity_config=f.flow.config, public_origin=f.origin,
            capacity=f.capacity, target_key=next_key, expected_epoch=state.epoch, operation_id='readiness-rotation')
        self.assertEqual(self.request(old, '/readyz')[0], 503)
        self.assertEqual(self.request(old, '/healthz')[0], 200)
        self.assertEqual(self.request(new, '/readyz')[0], 200)
        self.assertEqual(state.epoch, result['to_epoch'])

    def test_drain_blocks_all_new_application_mutations_without_consuming_state(self):
        f = self.fx
        cookie, _ = f.complete()
        query, binding = f.begin()
        token = f.flow.logout_token()
        before = self.snapshot()
        server = self.make_server()
        server.begin_drain()
        self.assertEqual(self.request(server, '/readyz')[0], 503)
        self.assertEqual(self.request(server, '/healthz')[0], 200)
        routes = [('/auth/login', 'GET', {}, None),
            ('/auth/callback?' + urllib.parse.urlencode({'state': query['state'], 'code': 'c'}), 'GET', {'Cookie': f.a.tx_cookie + '=' + binding}, None),
            ('/auth/backchannel-logout', 'POST', {'Content-Type': 'application/x-www-form-urlencoded'}, urllib.parse.urlencode({'logout_token': token}).encode()),
            ('/auth/logout', 'POST', {'Cookie': f.a.cookie_name + '=' + cookie, 'Content-Type': 'application/x-www-form-urlencoded', 'Origin': f.origin}, b'csrf=unused'),
            ('/api/objects/1', 'GET', {'Cookie': f.a.cookie_name + '=' + cookie}, None)]
        for path, method, headers, data in routes:
            status, _, response_headers = self.request(server, path, method=method, headers=headers, data=data)
            self.assertEqual(status, 503)
            self.assertEqual(response_headers['Retry-After'], '1')
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(server.active_requests, 0)

    def test_admitted_code_exchange_finishes_before_graceful_close_and_cookie_survives(self):
        server = self.make_server()
        result, thread, release = self.held_callback(server)
        stopped, reports = threading.Event(), []
        closer = threading.Thread(target=lambda: (reports.append(server.stop(2)), stopped.set()), daemon=True)
        closer.start()
        self.wait(lambda: self.request(server, '/readyz')[0] == 503)
        self.assertFalse(stopped.is_set())
        release.set(); thread.join(3); closer.join(3)
        self.assertTrue(stopped.is_set()); self.assertTrue(reports[0].drained)
        self.assertEqual(result[0][0], 303)
        cookie = next(v for v in result[0][2].get_all('Set-Cookie') if v.startswith(self.fx.a.cookie_name + '='))
        key = cookie.split(';')[0].split('=', 1)[1]
        self.assertIsNotNone(self.fx.b.session(key))
        self.assertEqual(self.fx.flow.count(), 1)

    def test_drain_waits_through_response_write_not_just_handler_work(self):
        entered, release = threading.Event(), threading.Event(); self.releases.append(release)
        class HeldReply(BrowserSSOHandler):
            def _reply(self, response):
                if self.path == '/':
                    entered.set()
                    if not release.wait(3): raise RuntimeError('owned reply deadline')
                return super()._reply(response)
        server = self.make_server(handler=HeldReply)
        results, reports = [], []
        thread = threading.Thread(target=lambda: results.append(self.request(server, '/')), daemon=True); thread.start()
        self.assertTrue(entered.wait(1)); self.assertEqual(server.active_requests, 1)
        closer = threading.Thread(target=lambda: reports.append(server.stop(2)), daemon=True); closer.start()
        self.wait(lambda: self.request(server, '/readyz')[0] == 503)
        self.assertFalse(reports)
        release.set(); thread.join(3); closer.join(3)
        self.assertEqual(results[0][0], 200); self.assertTrue(reports[0].drained)

    def test_timeout_is_incomplete_and_late_exchange_cannot_install_a_session(self):
        f = self.fx
        cookie, _ = f.complete(sid='existing')
        server = self.make_server()
        results, thread, release = self.held_callback(server, sid='late')
        start = time.monotonic()
        report = server.stop(.1)
        self.assertLess(time.monotonic() - start, 1)
        self.assertFalse(report.drained); self.assertTrue(report.timed_out)
        self.assertEqual(report.active_requests, 1); self.assertFalse(report.cleanup_complete)
        release.set(); thread.join(3)
        self.wait(lambda: server.active_requests == 0)
        self.assertEqual(f.flow.count(), 1)
        self.assertIsNotNone(f.b.session(cookie))
        self.assertTrue(f.a.closed)

    def test_idle_header_connection_is_closed_without_blocking_application_drain(self):
        server = self.make_server(request_timeout=5)
        with socket.create_connection(server.server_address, timeout=1) as client:
            client.sendall(b'GET /auth/login HTTP/1.1\r\nHost:')
            self.wait(lambda: len(server._connections) == 1)
            self.assertEqual(server.active_requests, 0)
            report = server.stop(1)
            self.assertTrue(report.drained)
            self.assertEqual(client.recv(1), b'')

    def test_connection_capacity_rejects_excess_without_creating_browser_state(self):
        server = self.make_server(max_connections=1)
        before = self.snapshot()
        with socket.create_connection(server.server_address, timeout=1) as client:
            client.sendall(b'GET /auth/login HTTP/1.1\r\nHost:')
            self.wait(lambda: len(server._connections) == 1)
            for attempt in range(8):
                with self.subTest(rejection=attempt):
                    self.assertEqual(self.request(server, '/auth/login')[0], 503)
            self.assertEqual(self.snapshot(), before)

    def test_probe_rechecks_drain_after_a_concurrent_backend_check(self):
        entered, release = threading.Event(), threading.Event(); self.releases.append(release)
        def ready():
            entered.set()
            if not release.wait(2): raise RuntimeError('owned probe deadline')
            return True
        server = self.make_server(readiness=ready)
        results = []
        thread = threading.Thread(target=lambda: results.append(self.request(server, '/readyz')), daemon=True); thread.start()
        self.assertTrue(entered.wait(1))
        server.begin_drain(); release.set(); thread.join(3)
        self.assertEqual(results[0][0], 503)

    def test_probe_failure_does_not_expose_exception_or_configuration(self):
        def failure(): raise RuntimeError('confidential fixture marker')
        server = self.make_server(readiness=failure)
        self.assertEqual(self.request(server, '/readyz')[:2], (503, b'{"ready":false}'))
        self.assertEqual(self.request(server, '/healthz')[0], 200)

    def test_memory_mode_graceful_close_revokes_owned_app_digests(self):
        f = self.fx
        memory = BrowserSSO(f.flow.config, public_origin=f.origin, lifecycle=f.app, clock=lambda: f.flow.now)
        f.flow.sso = memory
        f.flow.complete()
        self.assertEqual(f.flow.count(), 1)
        server = self.make_server(sso=memory, readiness=f.app.ready)
        self.assertEqual(self.request(server, '/readyz')[0], 200)
        report = server.stop(1)
        self.assertTrue(report.drained); self.assertEqual(f.flow.count(), 0)

    def test_stdin_eof_stops_runner_and_restores_signal_handlers(self):
        f = self.fx
        cookie, _ = f.complete()
        server = self.make_server(start=False)
        previous = {n: signal.getsignal(n) for n in (signal.SIGINT, signal.SIGTERM)}
        report = run_browser_server(server, shutdown_stdin=io.BytesIO(b''), drain_timeout=1)
        self.assertTrue(report.drained)
        self.assertIsNotNone(f.b.session(cookie))
        self.assertEqual({n: signal.getsignal(n) for n in previous}, previous)

    def test_main_thread_signal_handler_requests_drain_without_taking_server_locks(self):
        server = self.make_server(start=False)
        previous = signal.getsignal(signal.SIGTERM)
        report = run_browser_server(server, drain_timeout=1, on_started=lambda: signal.raise_signal(signal.SIGTERM))
        self.assertTrue(report.drained)
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)

    def test_external_stop_cancels_open_stdin_reader_and_preserves_caller_stream(self):
        for via_signal in (True, False):
            with self.subTest(via_signal=via_signal):
                server = self.make_server(start=False)
                stop = threading.Event()
                read_fd, write_fd = os.pipe()
                with os.fdopen(read_fd, 'rb') as source, os.fdopen(write_fd, 'wb') as writer:
                    def request_stop():
                        if via_signal:
                            signal.raise_signal(signal.SIGTERM)
                        else:
                            stop.set()
                    report = run_browser_server(server, drain_timeout=1, shutdown_stdin=source,
                        stop_event=stop, on_started=request_stop)
                    self.assertTrue(report.drained)
                    self.assertFalse(any(t.name == 'browser-supervisor-input' for t in threading.enumerate()))
                    self.assertFalse(source.closed)
                    writer.write(b'caller-owned'); writer.flush()
                    self.assertEqual(source.read(12), b'caller-owned')

    def test_open_stdin_data_is_not_a_stop_but_eof_is(self):
        server = self.make_server(start=False)
        read_fd, write_fd = os.pipe()
        with os.fdopen(read_fd, 'rb') as source, os.fdopen(write_fd, 'wb') as writer:
            started, reports = threading.Event(), []
            runner = threading.Thread(target=lambda: reports.append(run_browser_server(server,
                drain_timeout=1, shutdown_stdin=source, install_signals=False, on_started=started.set)))
            runner.start()
            try:
                self.assertTrue(started.wait(2))
                writer.write(b'keep-running'); writer.flush()
                self.assertEqual(self.request(server, '/readyz')[0], 200)
                self.assertTrue(runner.is_alive())
            finally:
                writer.close()
                runner.join(3)
            self.assertFalse(runner.is_alive())
            self.assertTrue(reports[0].drained)
            self.assertFalse(source.closed)

    def test_listener_failure_restores_handlers_closes_transport_and_fails(self):
        server = self.make_server(start=False)
        def fail(**_):
            server.started.set()
            raise OSError('owned listener failure')
        server.serve_forever = fail
        previous = signal.getsignal(signal.SIGINT)
        with self.assertRaises(RuntimeError): run_browser_server(server, drain_timeout=1)
        self.assertEqual(signal.getsignal(signal.SIGINT), previous)
        self.assertTrue(server.sso.closed)
        self.assertEqual(server.socket.fileno(), -1)

    def test_local_lifecycle_probes_are_read_only_and_missing_DB_is_not_created(self):
        f = self.fx
        before = self.snapshot()
        self.assertTrue(f.app.ready())
        self.assertTrue(SQLiteBrowserSessions(f.path).ready())
        missing = f.path.parent / 'missing.db'
        with self.assertRaises(sqlite3.OperationalError): SQLiteBrowserSessions(missing).ready()
        self.assertFalse(missing.exists())
        self.assertEqual(self.snapshot(), before)

    def test_begin_close_fences_direct_late_consumption_and_backchannel_work(self):
        f = self.fx
        query, binding = f.begin()
        token = f.flow.logout_token()
        before = self.snapshot()
        f.a.begin_close()
        with self.assertRaises(Unavailable): f.a.callback({'state': query['state'], 'code': 'c'}, binding)
        with self.assertRaises(Unavailable): f.a.backchannel(token)
        self.assertIsNone(f.a.session('unused'))
        self.assertEqual(self.snapshot(), before)

    def test_shutdown_is_idempotent_and_configuration_is_bounded(self):
        server = self.make_server()
        report = server.stop(1)
        self.assertIs(server.stop(1), report)
        for changes in ({'max_connections': 0}, {'max_connections': 1025}, {'request_timeout': float('nan')}):
            with self.subTest(changes=list(changes)), self.assertRaises(ValueError): self.make_server(**changes)
        with self.assertRaises(ValueError):
            BrowserSSOServer(('0.0.0.0', 0), BrowserSSOHandler, sso=self.fx.b,
                edge_origin='http://127.0.0.1:18273', allow_read=lambda _: False, readiness_check=lambda: True)


if __name__ == '__main__':
    unittest.main()

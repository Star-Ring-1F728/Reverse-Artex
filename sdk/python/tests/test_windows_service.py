from dataclasses import asdict
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from reverse_artex_guard.browser_server import ShutdownReport
from reverse_artex_guard.windows_service import (
    BrowserServiceHost, Win32ServiceAPI, run_windows_service, service_name,
    ServiceStatus, START_PENDING, RUNNING, STOP_PENDING, STOPPED,
    CONTROL_STOP, CONTROL_SHUTDOWN, CONTROL_INTERROGATE,
    ACCEPT_STOP, ACCEPT_SHUTDOWN, ERROR_SERVICE_SPECIFIC_ERROR,
    ERROR_SERVICE_CANNOT_ACCEPT_CTRL, ERROR_CALL_NOT_IMPLEMENTED)
import test_browser_server as runtime
import browser_sso_service as entry


class ServiceLifecycleTests(unittest.TestCase):
    def lifecycle(self, report, *, code=None, control=CONTROL_STOP, publisher=None):
        statuses = []
        host = BrowserServiceHost(publisher or statuses.append)
        def runner(server, **options):
            self.assertFalse(options['install_signals'])
            self.assertIs(options['stop_event'], host.stop_event)
            options['on_started']()
            self.assertEqual(host.control(control), 0)
            self.assertTrue(host.stop_event.is_set())
            return report
        with patch('reverse_artex_guard.browser_server.run_browser_server', side_effect=runner):
            returned = host.execute(lambda h: (
                h.run_server(object(), drain_timeout=.5),
                (0 if report.drained else 2) if code is None else code)[1])
        return host, statuses, returned

    def test_STOP_and_SHUTDOWN_map_to_event_and_publish_stopped_last_once(self):
        for control in (CONTROL_STOP, CONTROL_SHUTDOWN):
            with self.subTest(control=control):
                host, statuses, code = self.lifecycle(ShutdownReport(True, False, 0, True), control=control)
                self.assertEqual(code, 0)
                self.assertEqual([s.state for s in statuses], [START_PENDING, RUNNING, STOP_PENDING, STOPPED])
                self.assertEqual(statuses[0].controls_accepted, 0)
                self.assertEqual(statuses[1].controls_accepted, ACCEPT_STOP | ACCEPT_SHUTDOWN)
                self.assertEqual(statuses[-1], ServiceStatus(STOPPED))
                count = len(statuses)
                self.assertEqual(host.control(CONTROL_INTERROGATE), 0)
                self.assertEqual(host.control(CONTROL_STOP), ERROR_SERVICE_CANNOT_ACCEPT_CTRL)
                self.assertEqual(len(statuses), count)

    def test_incomplete_drain_is_specific_error_two_not_success(self):
        for report in (ShutdownReport(False, True, 1, False), ShutdownReport(False, False, 0, False)):
            with self.subTest(report=report):
                host, statuses, code = self.lifecycle(report)
                self.assertEqual(code, 2)
                self.assertEqual(statuses[-1].win32_exit_code, ERROR_SERVICE_SPECIFIC_ERROR)
                self.assertEqual(statuses[-1].service_exit_code, 2)

    def test_application_return_does_not_override_report_or_missing_control(self):
        host, statuses, code = self.lifecycle(ShutdownReport(True, False, 0, True), code=2)
        self.assertEqual(code, 1)
        host = BrowserServiceHost(lambda status: None)
        self.assertEqual(host.execute(lambda h: 0), 1)
        self.assertEqual(host.status.service_exit_code, 1)

    def test_startup_failure_is_stopped_without_accepting_controls(self):
        statuses = []
        host = BrowserServiceHost(statuses.append)
        def fail(h):
            self.assertEqual(h.control(CONTROL_STOP), ERROR_SERVICE_CANNOT_ACCEPT_CTRL)
            self.assertFalse(h.stop_event.is_set())
            raise ValueError('confidential fixture marker')
        self.assertEqual(host.execute(fail), 1)
        self.assertEqual([s.state for s in statuses], [START_PENDING, STOPPED])
        self.assertNotIn('confidential', repr([asdict(s) for s in statuses]))

    def test_duplicate_stop_and_interrogate_do_not_claim_new_progress(self):
        statuses = []
        host = BrowserServiceHost(statuses.append)
        def runner(server, **options):
            options['on_started']()
            self.assertEqual(host.control(2), ERROR_CALL_NOT_IMPLEMENTED)
            self.assertEqual(host.control(CONTROL_STOP), 0)
            count = len(statuses)
            for code in (CONTROL_STOP, CONTROL_SHUTDOWN, CONTROL_INTERROGATE):
                self.assertEqual(host.control(code), 0)
            self.assertEqual(len(statuses), count)
            self.assertEqual(statuses[-1].checkpoint, 1)
            return ShutdownReport(True, False, 0, True)
        with patch('reverse_artex_guard.browser_server.run_browser_server', side_effect=runner):
            self.assertEqual(host.execute(lambda h: (h.run_server(object()), 0)[1]), 0)

    def test_publisher_failure_requests_stop_and_cannot_report_success(self):
        statuses = []
        def publish(status):
            statuses.append(status)
            if status.state == STOP_PENDING:
                raise OSError('owned status channel failure')
        host = BrowserServiceHost(publish)
        def runner(server, **options):
            options['on_started']()
            self.assertNotEqual(host.control(CONTROL_STOP), 0)
            self.assertTrue(host.stop_event.is_set())
            return ShutdownReport(True, False, 0, True)
        with patch('reverse_artex_guard.browser_server.run_browser_server', side_effect=runner):
            self.assertEqual(host.execute(lambda h: (h.run_server(object()), 0)[1]), 1)
        self.assertEqual(statuses[-1].service_exit_code, 1)

    def test_all_application_work_precedes_single_stopped_report(self):
        done = []
        statuses = []
        def publish(status):
            if status.state == STOPPED:
                self.assertEqual(done, ['returned-and-cleaned'])
            statuses.append(status)
        host = BrowserServiceHost(publish)
        def runner(server, **options):
            options['on_started']()
            host.control(CONTROL_STOP)
            return ShutdownReport(True, False, 0, True)
        def app(h):
            h.run_server(object())
            done.append('returned-and-cleaned')
            return 0
        with patch('reverse_artex_guard.browser_server.run_browser_server', side_effect=runner):
            self.assertEqual(host.execute(app), 0)
        self.assertEqual(sum(s.state == STOPPED for s in statuses), 1)
        with self.assertRaises(RuntimeError): host.execute(app)

    def test_stdin_and_bad_timeout_are_rejected_without_serving(self):
        host = BrowserServiceHost(lambda s: None)
        for options in ({'shutdown_stdin': io.BytesIO()}, {'drain_timeout': float('nan')}, {'drain_timeout': 0}, {'drain_timeout': 61}):
            with self.subTest(options=list(options)), self.assertRaises(ValueError):
                host.run_server(object(), **options)

    def test_service_name_and_native_console_misuse_fail_closed(self):
        for name in ('', '../service', 'name with space', 'x'*65, 'x\0y'):
            with self.subTest(name=repr(name)), self.assertRaises(ValueError): service_name(name)
        if os.name == 'nt':
            with self.assertRaises(OSError) as result:
                run_windows_service('RAConsoleOnlyProbe', lambda host: self.fail('SCM callback ran in console'))
            self.assertEqual(result.exception.winerror, 1063)
            api = Win32ServiceAPI()
            self.assertEqual(api.ctypes.sizeof(api.NativeStatus), 28)
            self.assertEqual(api.ctypes.sizeof(api.Entry), api.ctypes.sizeof(api.ctypes.c_void_p) * 2)
        else:
            with self.assertRaises(OSError): Win32ServiceAPI()


class ServiceHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runtime.BrowserRuntimeTests.setUpClass()

    def setUp(self):
        self.http = runtime.BrowserRuntimeTests()
        self.http.setUp()
        self.addCleanup(self.http.doCleanups)
        self.hosts = []
        self.addCleanup(self.finish_hosts)

    def finish_hosts(self):
        for event in self.http.releases: event.set()
        for host, thread in self.hosts:
            host.control(CONTROL_STOP)
            thread.join(4)

    def start_host(self, timeout=2):
        server = self.http.make_server(start=False)
        statuses, ready = [], threading.Event()
        host = BrowserServiceHost(statuses.append)
        def app(h):
            report = h.run_server(server, drain_timeout=timeout, on_started=ready.set)
            return 0 if report.drained else 2
        thread = threading.Thread(target=lambda: host.execute(app), daemon=True)
        self.hosts.append((host, thread))
        thread.start()
        self.assertTrue(ready.wait(2))
        return server, host, thread, statuses

    def test_stop_callback_drains_admitted_work_rejects_new_state_and_preserves_cookie(self):
        server, host, worker, statuses = self.start_host()
        query, binding = self.http.fx.begin()
        result, caller, release = self.http.held_callback(server)
        before = self.http.snapshot()
        started = time.monotonic()
        self.assertEqual(host.control(CONTROL_STOP), 0)
        self.assertLess(time.monotonic() - started, .2)
        self.http.wait(lambda: self.http.request(server, '/readyz')[0] == 503)
        self.assertTrue(worker.is_alive())
        self.assertEqual(host.status.state, STOP_PENDING)
        self.assertEqual(self.http.request(server, '/auth/login')[0], 503)
        self.assertEqual(self.http.snapshot(), before)
        release.set(); caller.join(3); worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result[0][0], 303)
        cookie = next(v for v in result[0][2].get_all('Set-Cookie') if v.startswith(server.sso.cookie_name+'='))
        value = cookie.split(';')[0].split('=',1)[1]
        self.assertIsNotNone(self.http.fx.b.session(value))
        self.assertEqual(host.exit_code, 0)
        self.assertEqual(statuses[-1], ServiceStatus(STOPPED))

    def test_service_timeout_is_specific_failure_and_late_exchange_cannot_install(self):
        server, host, worker, statuses = self.start_host(.1)
        cookie, _ = self.http.fx.complete(sid='existing')
        count = self.http.fx.flow.count()
        result, caller, release = self.http.held_callback(server, sid='late-service-session')
        self.assertEqual(host.control(CONTROL_STOP), 0)
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(host.exit_code, 2)
        self.assertEqual(statuses[-1].win32_exit_code, ERROR_SERVICE_SPECIFIC_ERROR)
        self.assertEqual(statuses[-1].service_exit_code, 2)
        self.assertFalse(host.report.cleanup_complete)
        release.set(); caller.join(3)
        self.http.wait(lambda: server.active_requests == 0)
        self.assertEqual(self.http.fx.flow.count(), count)
        self.assertIsNotNone(self.http.fx.b.session(cookie))

    def test_shutdown_uses_host_event_without_changing_python_signal_handlers(self):
        previous = {n:signal.getsignal(n) for n in (signal.SIGINT,signal.SIGTERM)}
        server, host, worker, statuses = self.start_host()
        self.assertEqual(self.http.request(server, '/readyz')[0], 200)
        self.assertEqual(host.control(CONTROL_SHUTDOWN), 0)
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(host.exit_code, 0)
        self.assertEqual({n:signal.getsignal(n) for n in previous}, previous)


class ServiceConfigTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.identity = self.directory/'identity.json'; self.identity.write_text('{}')
        self.database = self.directory/'app.db'; self.database.touch()
        self.args = ['--identity-config',str(self.identity),'--database',str(self.database),
            '--public-origin','https://app.fixture.invalid','--edge-origin','http://127.0.0.1:9082','--listen','127.0.0.1:9083']
        self.config = self.directory/'service.json'

    def write(self, args=None, extra=None):
        value = dict(schema='browser-sso-windows-service/1',gateway_argv=self.args if args is None else args)
        value.update(extra or {})
        self.config.write_text(json.dumps(value))
        return self.config

    def test_bounded_listener_config_and_cli_check_do_not_enter_SCM(self):
        path = self.write()
        self.assertEqual(entry.load_gateway_args(path), tuple(self.args))
        with patch.object(entry,'run_windows_service',side_effect=AssertionError('check entered SCM')), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(entry.main(['--service-name','RAConfigCheck','--config',str(path),'--check']),0)
        self.assertTrue(json.loads(output.getvalue())['valid'])

    def test_admin_eof_unknown_args_and_relative_paths_are_rejected(self):
        variants=[self.args+['--initialize-browser-state'],self.args+['--describe-browser-state'],
            self.args+['--rotate-browser-state'],self.args+['--migrate-browser-state'],
            self.args+['--shutdown-on-stdin-eof'],self.args+['--not-an-option','confidential'],
            self.args+['--help'],['relative' if v==str(self.database) else v for v in self.args]]
        for args in variants:
            with self.subTest(args=args),self.assertRaises((ValueError,TypeError)):
                entry.load_gateway_args(self.write(args))

    def test_service_bootstrap_help_needs_no_SDK_or_venv_site_packages(self):
        base = getattr(sys, '_base_executable', sys.executable)
        environment = {k:v for k,v in os.environ.items() if k not in ('PYTHONPATH','VIRTUAL_ENV')}
        result = subprocess.run([base,'-B','-S',str(Path(entry.__file__).resolve()),'--help'],
            env=environment,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
        self.assertIn(b'--service-name',result.stdout)

    def test_config_rejects_duplicates_raw_environment_overrides_and_oversize(self):
        for raw in ('{"schema":"browser-sso-windows-service/1","schema":"duplicate","gateway_argv":[]}',
                    json.dumps(dict(schema='browser-sso-windows-service/1',gateway_argv=self.args,environment={'secret':'forbidden'})),
                    ' '*65537):
            self.config.write_text(raw)
            with self.subTest(size=len(raw)),self.assertRaises(ValueError): entry.load_gateway_args(self.config)

    def test_service_gateway_is_run_through_host_with_console_output_suppressed(self):
        path=self.write()
        import browser_sso_gateway as gateway
        host=BrowserServiceHost(lambda s:None)
        seen=[]
        def run(args,**options):
            self.assertEqual(tuple(args),tuple(self.args))
            self.assertEqual(options['runtime_runner'],host.run_server)
            options['announce']('not-for-console',flush=True)
            seen.append(True)
            return 0
        with patch.object(gateway,'main',side_effect=run),redirect_stdout(io.StringIO()) as output:
            self.assertEqual(entry.gateway_application(path)(host),0)
        self.assertEqual(output.getvalue(),'')
        self.assertEqual(seen,[True])


if __name__=='__main__':
    unittest.main()

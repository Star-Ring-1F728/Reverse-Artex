"""Owned test BFF worker; synthetic code exchange only, never a real IdP.

All keys arrive over stdin. Public identity config and encrypted shared state
are production SDK code; fixture-only exchange/race barriers stay in this file.
"""
import base64
import hashlib
from http.server import ThreadingHTTPServer
import json
import re
from pathlib import Path
import secrets
import signal
import sys
import threading
import time

import jwt
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'examples'))
from browser_sso_gateway import PortalHandler, allow_read
from reverse_artex_guard.browser_sso import BrowserSSO
from reverse_artex_guard.browser_server import BrowserSSOServer, run_browser_server
from reverse_artex_guard._supervisor_input import SupervisorInput
from reverse_artex_guard.browser_tokens import half_hash
from reverse_artex_guard.oidc import OIDCVerifier
from reverse_artex_guard.sqlite_application import SQLiteApplicationStore
from reverse_artex_guard.sqlite_browser_state import SQLiteBrowserState


def main():
    raw = sys.stdin.buffer.readline(65537)
    if len(raw) > 65536 or not raw.endswith(b'\n'):
        raise ValueError('bounded owned fixture configuration required')
    c = json.loads(raw)
    application = SQLiteApplicationStore(c['database'])
    rsa_key = serialization.load_pem_private_key(c['fixture_private_pem'].encode('ascii'), password=None)
    key = base64.b64decode(c['state_key'], validate=True)
    identity = OIDCVerifier(c['oidc'])
    state = SQLiteBrowserState(application, key, identity_digest=identity.digest, public_origin=c['public_origin'],
        additional_keys=tuple(base64.b64decode(k, validate=True) for k in c.get('additional_state_keys', [])),
        capacity=c.get('capacity', 1024), minimum_generation=c.get('minimum_generation', 0))
    class FixtureSSO(BrowserSSO):
        def exchange(self, code, verifier):
            claims = jwt.decode(code, rsa_key.public_key(), algorithms=['RS256'], issuer=c['oidc']['issuer'], audience=c['oidc']['client_id'],
                                options={'require': ['iat', 'exp', 'sub', 'nonce', 'sid', 'pkce', 'typ']})
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
            if claims['typ'] != 'FixtureCode' or claims['pkce'] != challenge:
                raise ValueError('owned fixture code rejected')
            with open(c['exchange_trace'], 'a', encoding='utf-8') as trace:
                trace.write(json.dumps({'code_sha256': hashlib.sha256(code.encode()).hexdigest(), 'worker': c['worker']}) + '\n')
            if claims.get('hold') is True:
                tag = claims.get('barrier_id', '')
                if not isinstance(tag, str) or not re.fullmatch(r'[0-9a-f]{16}', tag): raise ValueError('owned fixture barrier rejected')
                directory = Path(c['barrier_directory'])
                Path(directory / ('entered-' + tag)).write_text('entered', encoding='ascii')
                until = time.monotonic() + (10 if c.get('managed_runtime') else 4)
                while not Path(directory / ('release-' + tag)).exists():
                    if time.monotonic() > until: raise ValueError('owned fixture barrier deadline')
                    time.sleep(.02)
            now = int(time.time())
            subject = c['oidc']['subjects'][claims['sub']]
            access = jwt.encode({'iss': c['oidc']['issuer'], 'aud': c['oidc']['audience'], 'azp': c['oidc']['client_id'],
                'sub': claims['sub'], 'sid': claims['sid'], 'jti': 'onrtac:' + secrets.token_hex(16), 'typ': 'Bearer',
                'iat': now, 'exp': now + 300, 'ra_tenant': subject['tenant']}, rsa_key, algorithm='RS256', headers={'kid': 'fixture-key'})
            identity_token = jwt.encode({'iss': c['oidc']['issuer'], 'aud': c['oidc']['client_id'], 'azp': c['oidc']['client_id'],
                'sub': claims['sub'], 'sid': claims['sid'], 'typ': 'ID', 'iat': now, 'exp': now + 300, 'nonce': claims['nonce'],
                'at_hash': half_hash(access)}, rsa_key, algorithm='RS256', headers={'kid': 'fixture-key'})
            return access, identity_token
    sso = FixtureSSO(c['oidc'], public_origin=c['public_origin'], lifecycle=application, state_store=state, capacity=c.get('capacity', 1024))
    class TracedPortal(PortalHandler):
        def _handle(self):
            start = time.monotonic()
            observation = dict(path=self.path.partition('?')[0], method=self.command)
            try:
                response = super()._handle()
                observation['status'] = response.status
                return response
            except Exception as error:
                observation['exception'] = type(error).__name__
                observation['sqlite_error'] = getattr(error, 'sqlite_errorname', None)
                raise
            finally:
                observation['elapsed_ms'] = round((time.monotonic() - start) * 1000, 3)
                if c.get('request_trace'):
                    with open(c['request_trace'], 'a', encoding='ascii') as trace:
                        trace.write(json.dumps(observation, sort_keys=True) + '\n')
    if c.get('managed_runtime'):
        server = BrowserSSOServer(('127.0.0.1', 0), TracedPortal, sso=sso, edge_origin=c['edge_origin'],
            allow_read=allow_read, readiness_check=state.ready, max_connections=c.get('max_connections', 64))
        stop_event, control_cancelled, control_errors = threading.Event(), threading.Event(), []
        # Startup consumed the one config line before readiness; subsequent input
        # is exclusively read here without a blocking BufferedReader lock.
        control_input = SupervisorInput(sys.stdin.buffer)
        def control():
            pending = b''
            try:
                while True:
                    chunk = control_input.read(control_cancelled, 1025)
                    if chunk is None:
                        return
                    if not chunk:
                        stop_event.set(); return
                    pending += chunk
                    while b'\n' in pending:
                        raw, pending = pending.split(b'\n', 1)
                        if len(raw) >= 1024:
                            raise ValueError('owned control limit')
                        command = json.loads(raw)
                        if command == {'begin_drain': True}:
                            server.begin_drain()
                        elif command == {'stop': True}:
                            stop_event.set(); return
                        elif command == {'signal': 'SIGTERM'}:
                            signal.raise_signal(signal.SIGTERM); return
                        else:
                            raise ValueError('owned control rejected')
                    if len(pending) >= 1024:
                        raise ValueError('owned control limit')
            except Exception:
                control_errors.append(True); stop_event.set()
        controller = threading.Thread(target=control, name='owned-worker-control', daemon=True)
        controller.start()
        try:
            report = run_browser_server(server, drain_timeout=c.get('drain_timeout', 10), stop_event=stop_event,
                on_started=lambda: print('http://127.0.0.1:' + str(server.server_port), flush=True))
        finally:
            control_cancelled.set()
            controller.join(1)
        if controller.is_alive():
            control_errors.append(True)
        if c.get('shutdown_trace'):
            Path(c['shutdown_trace']).write_text(json.dumps(dict(drained=report.drained, timed_out=report.timed_out,
                active_requests=report.active_requests, cleanup_complete=report.cleanup_complete,
                control_error=bool(control_errors)), sort_keys=True) + '\n', encoding='ascii')
        print('closed', flush=True)
        return 0 if report.drained and not control_errors else 2
    server = ThreadingHTTPServer(('127.0.0.1', 0), TracedPortal)
    server.daemon_threads = True
    server.sso, server.edge_origin, server.allow_read = sso, c['edge_origin'], allow_read
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
    thread.start()
    print('http://127.0.0.1:' + str(server.server_port), flush=True)
    try:
        # A test-owned stdin command exercises graceful close without HTTP controls.
        command = sys.stdin.buffer.readline(1024)
        if json.loads(command) != {'stop': True}: raise ValueError('owned fixture stop command required')
    finally:
        server.shutdown(); server.server_close(); thread.join(2)
        sso.close()
    print('closed', flush=True)


if __name__ == '__main__':
    raise SystemExit(main())

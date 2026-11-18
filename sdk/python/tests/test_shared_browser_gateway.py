import base64
from contextlib import closing, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import unittest
from unittest.mock import patch

import test_browser_sso as fixture
from reverse_artex_guard.sqlite_application import SQLiteApplicationStore
from reverse_artex_guard.sqlite_browser_state import SQLiteBrowserState
from reverse_artex_guard.browser_server import ShutdownReport
from reverse_artex_guard.oidc import OIDCVerifier
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'examples'))
import browser_sso_gateway as gateway


class SharedBrowserGatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.BrowserSSOTests.setUpClass()

    def setUp(self):
        flow = fixture.BrowserSSOTests(); flow.setUp()
        self.addCleanup(flow.doCleanups)
        self.flow = flow
        self.path = flow.db.parent / 'native-gateway.db'
        self.app = SQLiteApplicationStore.initialize(self.path)
        config = flow.db.parent / 'oidc.json'
        config.write_text(json.dumps(flow.config), encoding='utf-8')
        self.key = os.urandom(32)
        self.environment = {'RA_TEST_STATE_KEY': base64.b64encode(self.key).decode()}
        self.args = ['--identity-config', str(config), '--public-origin', 'http://127.0.0.1:18272', '--edge-origin', 'http://127.0.0.1:18273',
                     '--database', str(self.path), '--database-profile', 'sqlite-native-acl/1', '--listen', '127.0.0.1:18272',
                     '--browser-state-key-env', 'RA_TEST_STATE_KEY']

    def initialize(self):
        out = io.StringIO()
        with patch.dict(os.environ, self.environment), redirect_stdout(out):
            result = gateway.main(self.args + ['--initialize-browser-state'])
        self.assertEqual(result, 0)
        self.assertNotIn(self.environment['RA_TEST_STATE_KEY'], out.getvalue())

    def test_explicit_initialization_exits_without_listener_and_preserves_native_data(self):
        revisions = self.app.create_object('1', tenant='alpha', owner='alice', payload={'value': 'unchanged'})
        with patch.object(gateway, 'BrowserSSOServer', side_effect=AssertionError('initialization opened a server')):
            self.initialize()
        self.assertEqual(self.app.current_revisions('1'), revisions)
        state = SQLiteBrowserState(self.app, self.key, identity_digest=OIDCVerifier(self.flow.config).digest, public_origin='http://127.0.0.1:18272')
        self.assertFalse(state.bound)

    def test_reopen_uses_shared_state_and_worker_close_leaves_it_in_DB(self):
        self.initialize()
        calls = []
        class Server:
            daemon_threads = False
            def __init__(self, address, handler, **options):
                self.sso = options['sso']; calls.append(('bind', address))
            def stop(self, timeout=10):
                self.sso.close(); self.server_close()
                return ShutdownReport(True, False, 0, True)
            def serve_forever(self):
                calls.append(('shared', self.sso._state_store is not None))
                self.sso.login()
            def server_close(self): calls.append(('closed', True))
        with patch.dict(os.environ, self.environment), patch.object(gateway, 'BrowserSSOServer', Server), patch.object(gateway, 'run_browser_server', side_effect=lambda server, **kw: (server.serve_forever(), server.stop())[1]), redirect_stdout(io.StringIO()):
            self.assertEqual(gateway.main(self.args), 0)
        self.assertIn(('shared', True), calls)
        self.assertIn(('closed', True), calls)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM ra_browser_records WHERE kind='transaction'").fetchone(), (1,))

    def test_missing_bad_or_wrong_key_and_legacy_profile_fail_without_listener(self):
        self.initialize()
        variants = [({}, self.args), ({'RA_TEST_STATE_KEY': 'not-base64'}, self.args),
                    ({'RA_TEST_STATE_KEY': base64.b64encode(b'x' * 32).decode()}, self.args),
                    (self.environment, [v if v != 'sqlite-native-acl/1' else 'legacy-session-v1' for v in self.args])]
        for env, args in variants:
            output = io.StringIO()
            with self.subTest(env=list(env), profile=args[args.index('--database-profile') + 1]), patch.dict(os.environ, env, clear=True), \
                 patch.object(gateway, 'BrowserSSOServer', side_effect=AssertionError('invalid state opened server')), redirect_stderr(output):
                with self.assertRaises(SystemExit) as result: gateway.main(args)
            self.assertEqual(result.exception.code, 2)
            self.assertNotIn(self.environment['RA_TEST_STATE_KEY'], output.getvalue())

    def test_initialization_needs_key_and_existing_state_is_never_overwritten(self):
        args = self.args[:-2] + ['--initialize-browser-state']
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit): gateway.main(args)
        self.initialize()
        with closing(sqlite3.connect(self.path)) as db:
            before = db.execute('SELECT * FROM ra_browser_state_meta').fetchall()
        with patch.dict(os.environ, self.environment), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            gateway.main(self.args + ['--initialize-browser-state'])
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('SELECT * FROM ra_browser_state_meta').fetchall(), before)

    def admin(self, flags, *, env=None, args=None):
        out = io.StringIO()
        with patch.dict(os.environ, env or self.environment), redirect_stdout(out), \
             patch.object(gateway, 'BrowserSSOServer', side_effect=AssertionError('admin opened a listener')):
            self.assertEqual(gateway.main((args or self.args) + flags), 0)
        for value in (env or self.environment).values(): self.assertNotIn(value, out.getvalue())
        return json.loads(out.getvalue())

    def test_describe_rotation_and_exact_retry_are_listener_free_and_secret_free(self):
        self.initialize()
        old = self.admin(['--describe-browser-state'])
        self.assertEqual(old['generation'], 0)
        self.assertEqual(old['counts'], dict(session=0, transaction=0, revocation=0, seen=0))
        new_key = os.urandom(32)
        env = dict(self.environment, RA_TEST_NEXT_KEY=base64.b64encode(new_key).decode())
        flags = ['--rotate-browser-state', '--browser-state-target-key-env', 'RA_TEST_NEXT_KEY',
                 '--expected-state-epoch', old['epoch'], '--state-operation-id', 'cli-rotate-1']
        result = self.admin(flags, env=env)
        self.assertEqual(result['generation'], 1)
        self.assertFalse(result['replayed'])
        self.assertTrue(self.admin(flags, env=env)['replayed'])
        new_args = [v if v != 'RA_TEST_STATE_KEY' else 'RA_TEST_NEXT_KEY' for v in self.args]
        status = self.admin(['--describe-browser-state', '--browser-state-minimum-generation', '1'], args=new_args, env=env)
        self.assertEqual(status['epoch'], result['to_epoch'])
        self.assertNotEqual(status['key_id'], old['key_id'])

    def test_capacity_migration_uses_explicit_target_and_can_retain_current_master(self):
        self.initialize()
        epoch = self.admin(['--describe-browser-state'])['epoch']
        result = self.admin(['--migrate-browser-state', '--browser-state-target-key-env', 'RA_TEST_STATE_KEY',
            '--expected-state-epoch', epoch, '--state-operation-id', 'cli-capacity-1', '--target-state-capacity', '32'])
        self.assertEqual(result['result']['capacity'], 32)
        status = self.admin(['--describe-browser-state', '--browser-state-capacity', '32'])
        self.assertEqual(status['generation'], 1)

    def test_invalid_transition_combinations_and_missing_CAS_never_open_listener(self):
        self.initialize()
        epoch = self.admin(['--describe-browser-state'])['epoch']
        variants = [['--rotate-browser-state'], ['--state-operation-id', 'ignored'],
            ['--browser-state-target-key-env', 'RA_TEST_STATE_KEY'],
            ['--rotate-browser-state', '--browser-state-target-key-env', 'RA_TEST_STATE_KEY'],
            ['--migrate-browser-state', '--browser-state-target-key-env', 'RA_TEST_STATE_KEY', '--expected-state-epoch', epoch,
             '--state-operation-id', 'unsafe-origin', '--target-public-origin', 'https://new.example'],
            ['--browser-state-additional-key-env', 'RA_TEST_STATE_KEY'],
            ['--browser-state-minimum-generation', '1', '--describe-browser-state']]
        with closing(sqlite3.connect(self.path)) as db:
            before = db.execute('SELECT * FROM ra_browser_state_meta').fetchall()
        for flags in variants:
            with self.subTest(flags=flags), patch.dict(os.environ, self.environment), redirect_stderr(io.StringIO()), \
                 patch.object(gateway, 'BrowserSSOServer', side_effect=AssertionError('invalid transition opened listener')):
                with self.assertRaises(SystemExit) as result: gateway.main(self.args + flags)
                self.assertEqual(result.exception.code, 2)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('SELECT * FROM ra_browser_state_meta').fetchall(), before)

    def test_preloaded_keyring_can_serve_before_and_after_atomic_rotation(self):
        self.initialize()
        new = os.urandom(32)
        env = dict(self.environment, RA_TEST_NEXT_KEY=base64.b64encode(new).decode())
        calls = []
        class Server:
            def __init__(self, *_, **options): self.sso = options['sso']
            def stop(self, timeout=10):
                self.sso.close(); self.server_close()
                return ShutdownReport(True, False, 0, True)
            def serve_forever(self):
                calls.append(self.sso._state_store.describe()['generation'])
                self.sso.login()
            def server_close(self): pass
        args = self.args + ['--browser-state-additional-key-env', 'RA_TEST_NEXT_KEY']
        with patch.dict(os.environ, env), patch.object(gateway, 'BrowserSSOServer', Server), patch.object(gateway, 'run_browser_server', side_effect=lambda server, **kw: (server.serve_forever(), server.stop())[1]), redirect_stdout(io.StringIO()):
            self.assertEqual(gateway.main(args), 0)
        epoch = self.admin(['--describe-browser-state'], env=env)['epoch']
        self.admin(['--rotate-browser-state', '--browser-state-target-key-env', 'RA_TEST_NEXT_KEY',
                    '--expected-state-epoch', epoch, '--state-operation-id', 'prepared-rotation'], env=env)
        with patch.dict(os.environ, env), patch.object(gateway, 'BrowserSSOServer', Server), patch.object(gateway, 'run_browser_server', side_effect=lambda server, **kw: (server.serve_forever(), server.stop())[1]), redirect_stdout(io.StringIO()):
            self.assertEqual(gateway.main(args), 0)
        self.assertEqual(calls, [0, 1])

    def test_runtime_options_are_bounded_and_admin_commands_reject_listener_options(self):
        variants = [['--shutdown-timeout', 'nan'], ['--shutdown-timeout', '0'], ['--shutdown-timeout', '61'],
                    ['--max-connections', '0'], ['--max-connections', '1025'],
                    ['--initialize-browser-state', '--shutdown-on-stdin-eof'],
                    ['--describe-browser-state', '--shutdown-timeout', '1']]
        for flags in variants:
            with self.subTest(flags=flags), patch.dict(os.environ, self.environment), redirect_stderr(io.StringIO()), \
                 patch.object(gateway, 'BrowserSSOServer', side_effect=AssertionError('invalid options opened a listener')):
                with self.assertRaises(SystemExit) as result: gateway.main(self.args + flags)
                self.assertEqual(result.exception.code, 2)


if __name__ == '__main__':
    unittest.main()

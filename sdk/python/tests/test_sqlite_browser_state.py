from contextlib import closing
import hashlib
import secrets
import sqlite3
import threading
import unittest
from unittest.mock import patch
import urllib.parse

from reverse_artex_guard.browser_sso import BrowserSSO, Unavailable
from reverse_artex_guard.oidc import OIDCVerifier
from reverse_artex_guard.sqlite_application import SQLiteApplicationStore
from reverse_artex_guard.sqlite_browser_state import SQLiteBrowserState
import test_browser_sso as fixture


class SharedBrowserStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.BrowserSSOTests.setUpClass()

    def setUp(self):
        self.flow = fixture.BrowserSSOTests()
        self.flow.setUp()
        self.addCleanup(self.flow.doCleanups)
        self.path = self.flow.db.parent / 'shared.db'
        self.master = secrets.token_bytes(32)
        self.capacity = 4
        self.origin = self.flow.sso.public_origin
        self.digest = OIDCVerifier(self.flow.config).digest
        self.app = SQLiteApplicationStore.initialize(self.path, clock=lambda: self.flow.now)
        state = SQLiteBrowserState.initialize(self.app, self.master, identity_digest=self.digest,
                                              public_origin=self.origin, capacity=self.capacity)
        self.a = self.controller(state)
        self.b = self.reopen()
        self.flow.db, self.flow.backend, self.flow.sso = self.path, self.app, self.a
        self.addCleanup(self.a.close)
        self.addCleanup(self.b.close)

    def controller(self, state):
        return BrowserSSO(self.flow.config, public_origin=self.origin, lifecycle=self.app,
                          clock=lambda: self.flow.now, capacity=self.capacity, state_store=state)

    def reopen(self, **options):
        return self.controller(SQLiteBrowserState(self.app, options.get('key', self.master),
                          identity_digest=options.get('identity_digest', self.digest), public_origin=options.get('public_origin', self.origin),
                          capacity=options.get('capacity', self.capacity)))

    def complete(self, worker=None, **options):
        self.flow.sso = worker or self.a
        return self.flow.complete(**options)

    def count(self, kind):
        with closing(sqlite3.connect(self.path)) as db:
            return db.execute('SELECT count(*) FROM ra_browser_records WHERE kind=?', (kind,)).fetchone()[0]

    def raw(self, sql, values=()):
        with closing(sqlite3.connect(self.path)) as db, db:
            return db.execute(sql, values).fetchall()

    def begin(self, worker=None):
        self.flow.sso = worker or self.a
        return self.flow.begin()

    def exchange_for(self, query, *, sid='session-one'):
        def exchange(code, verifier):
            self.assertEqual(query['code_challenge'], fixture.b64(hashlib.sha256(verifier.encode()).digest()))
            return self.flow.tokens(query['nonce'], sid=sid)
        return exchange

    def test_explicit_initialization_never_reinitializes_or_accepts_wrong_profile(self):
        before = self.raw('SELECT * FROM ra_browser_state_meta')
        with self.assertRaises(ValueError):
            SQLiteBrowserState.initialize(self.app, self.master, identity_digest=self.digest, public_origin=self.origin, capacity=self.capacity)
        self.assertEqual(self.raw('SELECT * FROM ra_browser_state_meta'), before)
        new = SQLiteApplicationStore.initialize(self.path.parent / 'uninitialized.db')
        with self.assertRaises(ValueError): SQLiteBrowserState(new, self.master, identity_digest=self.digest, public_origin=self.origin)
        self.assertEqual(new.current_revisions('missing'), None)
        with self.assertRaises(ValueError): SQLiteBrowserState(object(), self.master, identity_digest=self.digest, public_origin=self.origin)

    def test_session_resumes_on_other_worker_and_after_graceful_close(self):
        key, _ = self.complete()
        expected = self.a.session(key)
        self.assertEqual(self.b.session(key), expected)
        self.a.close()
        self.assertIsNone(self.a.session(key))
        reopened = self.reopen()
        self.assertEqual(reopened.session(key), expected)
        reopened.close()
        self.assertEqual(self.b.session(key), expected)
        self.assertEqual(self.flow.count(), 1)

    def test_login_transaction_crosses_workers_and_is_consumed_once(self):
        query, binding = self.begin(self.a)
        self.b.exchange = self.exchange_for(query)
        response = self.b.callback({'state': query['state'], 'code': 'c'}, binding)
        self.assertEqual(response.status, 303)
        self.assertEqual(self.flow.count(), 1)
        self.assertEqual(self.count('transaction'), 0)
        with self.assertRaises(ValueError): self.a.callback({'state': query['state'], 'code': 'c'}, binding)

    def test_concurrent_callbacks_exchange_the_code_once_across_workers(self):
        query, binding = self.begin()
        consumed, release = threading.Event(), threading.Event()
        result = []
        def exchange(*args):
            consumed.set()
            if not release.wait(3): raise AssertionError('fixture callback deadline')
            return self.flow.tokens(query['nonce'])
        self.a.exchange = exchange
        def callback():
            try: result.append(self.a.callback({'state': query['state'], 'code': 'c'}, binding).status)
            except Exception as error: result.append(type(error).__name__)
        thread = threading.Thread(target=callback, daemon=True); thread.start()
        try:
            self.assertTrue(consumed.wait(2))
            self.b.exchange = lambda *_: self.fail('consumed state reached a second exchange')
            with self.assertRaises(ValueError): self.b.callback({'state': query['state'], 'code': 'c'}, binding)
        finally:
            release.set(); thread.join(3)
        self.assertEqual(result, [303])
        self.assertEqual(self.flow.count(), 1)

    def test_exchange_failure_remains_consumed_after_restart(self):
        query, binding = self.begin()
        def unavailable(*_): raise Unavailable()
        self.a.exchange = unavailable
        with self.assertRaises(Unavailable): self.a.callback({'state': query['state'], 'code': 'c'}, binding)
        with self.assertRaises(ValueError): self.reopen().callback({'state': query['state'], 'code': 'c'}, binding)
        self.assertEqual(self.flow.count(), 0)

    def test_callback_install_failure_rolls_back_app_row_and_cookie_replacement(self):
        old_key, _ = self.complete()
        previous = self.b.session(old_key)
        self.raw("CREATE TRIGGER reject_browser_session BEFORE INSERT ON ra_browser_records WHEN NEW.kind='session' BEGIN SELECT RAISE(ABORT,'fixture'); END")
        with self.assertRaises(sqlite3.IntegrityError): self.complete(previous=old_key)
        self.assertEqual(self.b.session(old_key), previous)
        self.assertEqual(self.flow.count(), 1)
        self.assertEqual(self.count('session'), 1)

    def test_other_worker_logout_revokes_everywhere_and_return_state_is_shared(self):
        key, _ = self.complete()
        csrf = self.a.session(key)['csrf']
        self.assertEqual(self.b.logout(key, csrf).status, 200)
        self.assertIsNone(self.a.session(key))
        self.assertIsNone(self.reopen().session(key))
        self.assertEqual(self.flow.count(), 0)
        with self.b.lock:
            state, tx = next(iter(self.b.transactions.items()))
        self.assertEqual(self.a.logged_out({'state': state}, tx['binding']).status, 303)
        with self.assertRaises(ValueError): self.b.logged_out({'state': state}, tx['binding'])

    def test_logout_failure_rolls_back_new_state_and_preserves_current_session(self):
        key, _ = self.complete()
        previous = self.a.session(key)
        self.raw("CREATE TRIGGER reject_session_delete BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT,'fixture'); END")
        with self.assertRaises(sqlite3.IntegrityError): self.b.logout(key, previous['csrf'])
        self.assertEqual(self.count('transaction'), 0)
        self.assertEqual(self.a.session(key), previous)
        self.assertEqual(self.flow.count(), 1)

    def test_backchannel_tombstones_and_jti_replay_survive_worker_restart(self):
        key, _ = self.complete()
        token = self.flow.logout_token()
        self.assertEqual(self.b.backchannel(token).status, 200)
        reopened = self.reopen()
        self.assertIsNone(self.a.session(key))
        with self.assertRaises(ValueError): reopened.backchannel(token)
        with self.assertRaises(ValueError): self.complete(worker=reopened)
        self.assertEqual(self.flow.count(), 0)
        self.assertEqual(self.count('seen'), 1)
        self.assertEqual(self.count('revocation'), 1)

    def test_scoped_sid_and_subject_logout_preserve_other_users(self):
        first, _ = self.complete(sid='session-one')
        second, _ = self.complete(worker=self.b, sid='session-two')
        bob, _ = self.complete(sub='subject-bob', sid='session-bob')
        self.b.backchannel(self.flow.logout_token())
        self.assertIsNone(self.a.session(first))
        self.assertIsNotNone(self.a.session(second))
        self.assertIsNotNone(self.a.session(bob))
        self.b.backchannel(self.flow.logout_token(sid=None))
        self.assertIsNone(self.a.session(second))
        self.assertIsNotNone(self.b.session(bob))

    def test_backchannel_commits_while_exchange_is_inflight_and_wins_install_race(self):
        query, binding = self.begin()
        entered, release = threading.Event(), threading.Event()
        result = []
        def exchange(*_):
            entered.set()
            if not release.wait(3): raise AssertionError('fixture callback deadline')
            return self.flow.tokens(query['nonce'])
        self.a.exchange = exchange
        def callback():
            try: self.a.callback({'state': query['state'], 'code': 'c'}, binding); result.append('unexpected success')
            except ValueError: result.append('rejected')
        thread = threading.Thread(target=callback, daemon=True); thread.start()
        try:
            self.assertTrue(entered.wait(2))
            self.b.backchannel(self.flow.logout_token())
        finally: release.set(); thread.join(3)
        self.assertEqual(result, ['rejected'])
        self.assertEqual(self.flow.count(), 0)

    def test_failed_backchannel_does_not_burn_jti_or_partially_revoke(self):
        key, _ = self.complete()
        token = self.flow.logout_token()
        self.raw("CREATE TRIGGER reject_backchannel_delete BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT,'fixture'); END")
        with self.assertRaises(sqlite3.IntegrityError): self.b.backchannel(token)
        self.assertEqual((self.count('seen'), self.count('revocation')), (0, 0))
        self.assertIsNotNone(self.a.session(key))
        self.raw('DROP TRIGGER reject_backchannel_delete')
        self.assertEqual(self.b.backchannel(token).status, 200)
        self.assertIsNone(self.a.session(key))

    def test_expiry_and_external_app_revocation_are_seen_without_worker_cache(self):
        key, _ = self.complete()
        digest = self.a.session(key)['digest']
        self.app.revoke([digest])
        self.assertIsNone(self.b.session(key))
        self.assertIsNone(self.a.session(key))
        key, _ = self.complete()
        self.flow.now += 121
        self.assertIsNone(self.reopen().session(key))
        self.assertEqual((self.count('session'), self.flow.count()), (0, 0))
        query, binding = self.begin()
        self.flow.now += 301
        with self.assertRaises(ValueError): self.b.callback({'state': query['state'], 'code': 'c'}, binding)

    def test_wrong_key_identity_origin_capacity_and_binding_are_rejected(self):
        for changes in ({'key': b'x' * 32}, {'key': b'x' * 31}, {'identity_digest': 'a' * 64},
                        {'public_origin': 'https://other.example'}, {'capacity': self.capacity + 1}):
            with self.subTest(changes=list(changes)), self.assertRaises(ValueError): self.reopen(**changes)
        state = SQLiteBrowserState(self.app, self.master, identity_digest=self.digest, public_origin=self.origin, capacity=self.capacity)
        wrong = SQLiteApplicationStore.initialize(self.path.parent / 'different.db')
        with self.assertRaises(ValueError): BrowserSSO(self.flow.config, public_origin=self.origin, lifecycle=wrong, capacity=self.capacity, state_store=state)
        class CustomLifecycle(SQLiteApplicationStore):
            def active(self, *_): return False
        custom = CustomLifecycle(self.path)
        with self.assertRaises(ValueError):
            SQLiteBrowserState(custom, self.master, identity_digest=self.digest, public_origin=self.origin, capacity=self.capacity)
        with self.assertRaises(ValueError):
            BrowserSSO(self.flow.config, public_origin=self.origin, lifecycle=custom, capacity=self.capacity, state_store=state)

    def test_capacity_is_global_across_workers(self):
        for _ in range(self.capacity): self.a.login()
        with self.assertRaises(Unavailable): self.b.login()
        with self.assertRaises(Unavailable): self.reopen().login()
        self.flow.now += 301
        self.assertEqual(self.b.login().status, 303)
        self.assertEqual(self.count('transaction'), 1)

    def test_session_capacity_and_replacement_are_global(self):
        keys = [self.complete(worker=self.a if i % 2 else self.b, sid='sid-' + str(i))[0] for i in range(self.capacity)]
        with self.assertRaises(Unavailable): self.complete(worker=self.b, sid='extra-session')
        self.assertEqual(self.flow.count(), self.capacity)
        replacement, _ = self.complete(worker=self.b, sid='replacement', previous=keys[0])
        self.assertIsNone(self.a.session(keys[0]))
        self.assertIsNotNone(self.a.session(replacement))
        self.assertEqual(self.count('session'), self.capacity)

    def test_database_and_wal_contain_no_tokens_cookie_csrf_PKCE_or_master_key(self):
        key, _ = self.complete()
        session = self.a.session(key)
        query, binding = self.begin()
        with self.a.lock: tx = self.a.transactions[query['state']]
        forbidden = [self.master, *(v.encode() for v in (key, session['csrf'], session['access'], session['identity'],
                                                       query['state'], tx['nonce'], tx['verifier'], binding))]
        for path in self.path.parent.glob('shared.db*'):
            raw = path.read_bytes()
            self.assertTrue(all(value not in raw for value in forbidden), path.name)

    def test_ciphertext_expiry_and_row_substitution_fail_closed(self):
        key, _ = self.complete()
        second, _ = self.complete(sid='session-two')
        original = self.raw("SELECT record_key,expires_ms,digest,nonce,cipher FROM ra_browser_records WHERE kind='session'")
        for mutation in ('cipher', 'expiry', 'swap'):
            with self.subTest(mutation=mutation):
                if mutation == 'cipher':
                    self.raw("UPDATE ra_browser_records SET cipher=zeroblob(length(cipher)) WHERE kind='session'")
                elif mutation == 'expiry':
                    self.raw("UPDATE ra_browser_records SET expires_ms=expires_ms+1 WHERE kind='session'")
                else:
                    self.raw("UPDATE ra_browser_records SET cipher=? WHERE kind='session' AND record_key=?", (original[0][4], original[1][0]))
                with self.assertRaises(Unavailable): self.b.session(second if mutation == 'swap' and self.b._state_store._index('session', second) == original[1][0] else key)
                for index, expires, digest, nonce, cipher in original:
                    self.raw("UPDATE ra_browser_records SET expires_ms=?,digest=?,nonce=?,cipher=? WHERE kind='session' AND record_key=?", (expires, digest, nonce, cipher, index))
        self.assertIsNotNone(self.a.session(key))

    def test_nonce_collision_and_encryption_budget_fail_without_partial_records(self):
        original = secrets.token_bytes
        with patch('reverse_artex_guard.sqlite_browser_state.secrets.token_bytes', side_effect=lambda n: self.a._state_store.check_nonce if n == 12 else original(n)):
            with self.assertRaises(Unavailable): self.a.login()
        self.assertEqual(self.count('transaction'), 0)
        self.raw('UPDATE ra_browser_state_meta SET encryptions=1000000000')
        with self.assertRaises(Unavailable): self.b.login()
        self.assertEqual(self.count('transaction'), 0)

    def test_nested_caught_error_poisoning_rolls_back_outer_unit_of_work(self):
        with self.assertRaises(Unavailable):
            with self.a.lock:
                try:
                    with self.a.lock:
                        self.a._transaction('login')
                        raise ValueError('fixture')
                except ValueError:
                    pass
        self.assertEqual(self.count('transaction'), 0)

    def test_metadata_failure_releases_worker_lock_and_DB_busy_recovers(self):
        key, _ = self.complete()
        original = self.raw('SELECT key_check FROM ra_browser_state_meta')[0][0]
        self.raw('UPDATE ra_browser_state_meta SET key_check=zeroblob(length(key_check))')
        with self.assertRaises(Unavailable): self.a.session(key)
        self.raw('UPDATE ra_browser_state_meta SET key_check=?', (original,))
        result = []
        thread = threading.Thread(target=lambda: result.append(self.a.session(key)), daemon=True)
        thread.start(); thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertIsNotNone(result[0])
        with self.app._write():
            with self.assertRaises(sqlite3.OperationalError): self.b.session(key)
        self.assertIsNotNone(self.b.session(key))


if __name__ == '__main__':
    unittest.main()

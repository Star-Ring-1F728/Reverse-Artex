import copy
from contextlib import closing
import hashlib
import json
import secrets
import sqlite3
import threading
import unittest
from unittest.mock import patch

from reverse_artex_guard.browser_sso import BrowserSSO, Unavailable
from reverse_artex_guard.browser_state_migration import transition_browser_state
from reverse_artex_guard.oidc import OIDCVerifier
from reverse_artex_guard.sqlite_browser_state import SQLiteBrowserState
import test_sqlite_browser_state as shared


class BrowserStateMigrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        shared.SharedBrowserStateTests.setUpClass()

    def setUp(self):
        self.fx = shared.SharedBrowserStateTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.next = secrets.token_bytes(32)

    def state(self, key=None, *, extra=(), capacity=None, config=None, origin=None, minimum=0):
        f = self.fx
        return SQLiteBrowserState(f.app, key or f.master, additional_keys=extra,
            identity_digest=OIDCVerifier(config or f.flow.config).digest, public_origin=origin or f.origin,
            capacity=capacity or f.capacity, minimum_generation=minimum)

    def worker(self, key=None, *, extra=(), capacity=None, config=None, origin=None):
        f = self.fx
        result = BrowserSSO(config or f.flow.config, public_origin=origin or f.origin,
            lifecycle=f.app, capacity=capacity or f.capacity, clock=lambda: f.flow.now,
            state_store=self.state(key, extra=extra, capacity=capacity, config=config, origin=origin))
        self.addCleanup(result.close)
        return result

    def transition(self, **options):
        f = self.fx
        args = dict(identity_config=f.flow.config, public_origin=f.origin, capacity=f.capacity,
                    target_key=self.next, expected_epoch=f.a._state_store.epoch, operation_id='rotate-1')
        args.update(options)
        source_keys = args.pop('source_keys', (f.master,))
        return transition_browser_state(f.app, source_keys, **args)

    def snapshot(self):
        f = self.fx
        with closing(sqlite3.connect(f.path)) as db:
            result = {table: db.execute('SELECT * FROM ' + table + ' ORDER BY 1,2').fetchall()
                      for table in ('ra_browser_state_meta', 'ra_browser_records', 'sessions')}
            exists = db.execute("SELECT 1 FROM sqlite_master WHERE name='ra_browser_state_operations'").fetchone()
            result['operations'] = db.execute('SELECT * FROM ra_browser_state_operations ORDER BY generation').fetchall() if exists else None
            return result

    def plaintext(self, state):
        with state.lock:
            return {k: dict(state.maps[k].items()) for k in state.maps}

    def populate(self):
        f = self.fx
        f.complete()
        token = f.flow.logout_token()
        f.b.backchannel(token)
        cookie, _ = f.complete(sub='subject-bob', sid='bob-live')
        query, binding = f.begin()
        return cookie, query, binding, token

    def test_rotation_reencrypts_every_kind_reindexes_and_preserves_native_sessions(self):
        f = self.fx
        cookie, _, _, _ = self.populate()
        prepared = self.state(extra=(self.next,))
        plain = self.plaintext(prepared)
        physical = self.snapshot()
        receipt = self.transition()
        self.assertEqual(receipt['generation'], 1)
        self.assertEqual(receipt['result']['retained_counts'], {k: len(v) for k, v in plain.items()})
        self.assertEqual(receipt['result']['session_digests_revoked'], 0)
        current = self.state(self.next)
        self.assertEqual(self.plaintext(current), plain)
        self.assertEqual(self.plaintext(prepared), plain)
        after = self.snapshot()
        self.assertNotEqual(physical['ra_browser_state_meta'][0][4], after['ra_browser_state_meta'][0][4])
        self.assertTrue({r[1] for r in physical['ra_browser_records']}.isdisjoint({r[1] for r in after['ra_browser_records']}))
        self.assertTrue({r[5] for r in physical['ra_browser_records']}.isdisjoint({r[5] for r in after['ra_browser_records']}))
        self.assertEqual(physical['sessions'], after['sessions'])
        self.assertIsNotNone(self.worker(self.next).session(cookie))
        self.assertEqual(current.describe()['generation'], 1)
        self.assertEqual(prepared.describe()['epoch'], receipt['to_epoch'])

    def test_prepared_workers_preserve_pending_PKCE_replay_and_CSRF_logout(self):
        f = self.fx
        cookie, query, binding, token = self.populate()
        a, b = self.worker(extra=(self.next,)), self.worker(extra=(self.next,))
        expected = a.session(cookie)
        self.transition()
        self.assertEqual(b.session(cookie), expected)
        with self.assertRaises(ValueError): b.backchannel(token)
        b.exchange = f.exchange_for(query, sid='fresh-after-rotation')
        self.assertEqual(b.callback({'state': query['state'], 'code': 'c'}, binding).status, 303)
        with self.assertRaises(ValueError): a.callback({'state': query['state'], 'code': 'c'}, binding)
        self.assertEqual(a.logout(cookie, expected['csrf']).status, 200)
        self.assertIsNone(b.session(cookie))
        with b.lock:
            state, tx = next((k, v) for k, v in b.transactions.items() if v['kind'] == 'logout')
        self.assertEqual(b.logged_out({'state': state}, tx['binding']).status, 303)
        with self.assertRaises(ValueError): a.logged_out({'state': state}, tx['binding'])

    def test_rotation_during_code_exchange_allows_prepared_worker_to_commit_once(self):
        f = self.fx
        prepared = self.worker(extra=(self.next,))
        query, binding = f.begin(prepared)
        entered, release = threading.Event(), threading.Event()
        statuses = []
        def exchange(*_):
            entered.set()
            if not release.wait(4): raise AssertionError('fixture timeout')
            return f.flow.tokens(query['nonce'])
        prepared.exchange = exchange
        def callback():
            try: statuses.append(prepared.callback({'state': query['state'], 'code': 'c'}, binding).status)
            except Exception as error: statuses.append(type(error).__name__)
        thread = threading.Thread(target=callback, daemon=True)
        thread.start()
        try:
            self.assertTrue(entered.wait(2))
            self.transition()
        finally:
            release.set(); thread.join(5)
        self.assertEqual(statuses, [303])
        with self.assertRaises(ValueError): self.worker(self.next).callback({'state': query['state'], 'code': 'c'}, binding)
        self.assertEqual(f.flow.count(), 1)

    def test_retired_only_worker_and_wrong_key_cannot_read_or_write_current_epoch(self):
        f = self.fx
        cookie, _ = f.complete()
        self.transition()
        before = self.snapshot()
        for action in (lambda: f.a.session(cookie), f.b.login):
            with self.assertRaises(Unavailable): action()
        for key in (f.master, secrets.token_bytes(32)):
            with self.assertRaises(ValueError): self.state(key)
        self.assertEqual(self.snapshot(), before)
        self.assertIsNotNone(self.worker(self.next).session(cookie))

    def test_latest_operation_retry_is_idempotent_and_conflicting_id_is_rejected(self):
        self.populate()
        expected = self.fx.a._state_store.epoch
        receipt = self.transition()
        before = self.snapshot()
        repeated = self.transition()
        self.assertTrue(repeated.pop('replayed'))
        original = dict(receipt); self.assertFalse(original.pop('replayed'))
        self.assertEqual(repeated, original)
        self.assertEqual(self.snapshot(), before)
        self.assertTrue(self.transition(source_keys=(self.next,))['replayed'])
        self.assertEqual(self.snapshot(), before)
        with self.assertRaises(ValueError): self.transition(expected_epoch='f' * 64)
        with self.assertRaises(ValueError): self.transition(operation_id='different-operation', expected_epoch=expected, source_keys=(self.next,))
        self.assertEqual(self.snapshot(), before)

    def test_concurrent_admin_CAS_has_one_winner(self):
        self.fx.complete()
        results = []
        start = threading.Barrier(2)
        def run(name):
            start.wait()
            try: results.append(self.transition(operation_id=name)['generation'])
            except (ValueError, sqlite3.OperationalError): results.append('rejected')
        threads = [threading.Thread(target=run, args=(name,)) for name in ('race-a', 'race-b')]
        for thread in threads: thread.start()
        for thread in threads: thread.join(5)
        self.assertEqual(sorted(results, key=str), [1, 'rejected'])
        self.assertEqual(len(self.snapshot()['operations']), 1)

    def test_corrupt_even_expired_record_aborts_transition_without_any_changes(self):
        f = self.fx
        f.complete(); f.begin()
        f.raw("UPDATE ra_browser_records SET cipher=zeroblob(length(cipher)) WHERE kind='transaction'")
        f.flow.now += 301
        before = self.snapshot()
        with self.assertRaises(Unavailable): self.transition()
        self.assertEqual(self.snapshot(), before)

    def test_mid_transition_SQL_failure_rolls_back_revocations_metadata_rows_and_journal(self):
        f = self.fx
        cookie, _ = f.complete()
        f.begin()
        f.b.backchannel(f.flow.logout_token(sid='unrelated-sid'))
        f.raw("CREATE TRIGGER reject_epoch_insert BEFORE INSERT ON ra_browser_records BEGIN SELECT RAISE(ABORT,'fixture'); END")
        before = self.snapshot()
        changed = copy.deepcopy(f.flow.config); changed['subjects']['subject-alice']['principal'] = 'changed'
        with self.assertRaises(sqlite3.IntegrityError):
            self.transition(mode='migrate', target_identity_config=changed, session_policy='revoke')
        self.assertEqual(self.snapshot(), before)
        self.assertIsNotNone(f.a.session(cookie))
        f.raw('DROP TRIGGER reject_epoch_insert')
        self.assertEqual(self.transition()['generation'], 1)

    def test_failure_after_all_records_at_journal_commit_rolls_back_everything(self):
        f = self.fx
        f.complete()
        first = self.transition()
        f.raw("CREATE TRIGGER reject_journal BEFORE INSERT ON ra_browser_state_operations BEGIN SELECT RAISE(ABORT,'fixture'); END")
        before = self.snapshot()
        with self.assertRaises(sqlite3.IntegrityError):
            self.transition(source_keys=(self.next,), target_key=secrets.token_bytes(32), operation_id='rotate-2', expected_epoch=first['to_epoch'])
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.state(self.next).describe()['generation'], 1)

    def test_capacity_grow_preserves_all_state_and_requires_new_context_workers(self):
        f = self.fx
        cookie, _, _, _ = self.populate()
        plain = self.plaintext(f.a._state_store)
        self.transition(mode='migrate', target_capacity=8)
        current = self.state(self.next, capacity=8)
        self.assertEqual(self.plaintext(current), plain)
        self.assertIsNotNone(self.worker(self.next, capacity=8).session(cookie))
        with self.assertRaises(Unavailable): f.a.session(cookie)
        with self.assertRaises(ValueError): self.state(self.next)

    def test_capacity_shrink_does_not_evict_live_transactions_or_ledger(self):
        f = self.fx
        for _ in range(3): f.begin()
        before = self.snapshot()
        with self.assertRaises(ValueError): self.transition(mode='migrate', target_capacity=1)
        self.assertEqual(self.snapshot(), before)

    def test_context_migration_requires_explicit_revoke(self):
        f = self.fx
        f.complete()
        changed = copy.deepcopy(f.flow.config); changed['subjects']['subject-alice']['principal'] = 'changed'
        before = self.snapshot()
        for options in ({'target_identity_config': changed}, {'target_public_origin': 'https://new.example'}):
            with self.subTest(options=list(options)), self.assertRaises(ValueError): self.transition(mode='migrate', **options)
        self.assertEqual(self.snapshot(), before)

    def test_revoke_migration_preserves_same_namespace_logout_history_and_unrelated_app_sessions(self):
        f = self.fx
        cookie, _, _, token = self.populate()
        unrelated = hashlib.sha256(b'unrelated-app-session').hexdigest()
        f.app.create(unrelated, 'service', 'alpha', f.flow.now + 90)
        revisions = f.app.create_object('1', tenant='alpha', owner='alice', payload={'value': 'untouched'})
        changed = copy.deepcopy(f.flow.config); changed['subjects']['subject-alice']['principal'] = 'changed'
        old = self.plaintext(f.a._state_store)
        receipt = self.transition(mode='migrate', target_identity_config=changed,
                                  target_public_origin='https://new.example', session_policy='revoke')
        worker = self.worker(self.next, config=changed, origin='https://new.example')
        plain = self.plaintext(worker._state_store)
        self.assertEqual(plain['session'], {}); self.assertEqual(plain['transaction'], {})
        self.assertEqual(plain['revocation'], old['revocation']); self.assertEqual(plain['seen'], old['seen'])
        self.assertEqual(receipt['result']['session_digests_revoked'], 1)
        self.assertIsNone(worker.session(cookie))
        with self.assertRaises(ValueError): worker.backchannel(token)
        self.assertTrue(f.app.active(unrelated, 'service', 'alpha', f.flow.now))
        self.assertEqual(f.app.current_revisions('1'), revisions)
        with self.assertRaises(Unavailable): f.a.session(cookie)

    def test_emergency_rotation_can_revoke_sessions_without_changing_trust_context(self):
        f = self.fx
        cookie, _, _, token = self.populate()
        receipt = self.transition(session_policy='revoke')
        current = self.worker(self.next)
        self.assertIsNone(current.session(cookie))
        self.assertEqual(receipt['result']['retained_counts'], dict(session=0, transaction=0, revocation=1, seen=1))
        self.assertEqual(f.flow.count(), 0)
        with self.assertRaises(ValueError): current.backchannel(token)

    def test_new_issuer_client_namespace_migration_discards_old_ledger_explicitly(self):
        f = self.fx
        self.populate()
        changed = copy.deepcopy(f.flow.config); changed['client_id'] = 'new-browser'
        receipt = self.transition(mode='migrate', target_identity_config=changed, session_policy='revoke')
        current = self.state(self.next, config=changed)
        self.assertTrue(all(not values for values in self.plaintext(current).values()))
        self.assertEqual(receipt['result']['ledger_policy'], 'discard-new-namespace')
        self.assertEqual(f.flow.count(), 0)

    def test_expired_externally_revoked_and_tombstoned_sessions_are_never_resurrected(self):
        f = self.fx
        first, _ = f.complete(sid='first')
        inactive, _ = f.complete(sid='inactive')
        f.app.revoke([f.a.session(inactive)['digest']])
        with f.a.lock:
            f.a.revocations[(None, 'first')] = {'iat': int(f.flow.now), 'expires': f.flow.now + 200}
        expired, _ = f.complete(sid='expired')
        f.flow.now += 121
        receipt = self.transition()
        current = self.worker(self.next)
        for cookie in (first, inactive, expired): self.assertIsNone(current.session(cookie))
        self.assertEqual(receipt['result']['retained_counts']['session'], 0)
        self.assertEqual(f.flow.count(), 0)

    def test_exhausted_encryption_epoch_can_rotate_but_nonce_or_salt_failure_rolls_back(self):
        f = self.fx
        f.complete()
        f.raw('UPDATE ra_browser_state_meta SET encryptions=1000000000')
        before = self.snapshot()
        real_random = secrets.token_bytes
        for collision in ('nonce', 'salt'):
            old_salt = f.a._state_store.salt
            fixed_nonce = b'n' * 12
            def random(n):
                return old_salt if n == 32 and collision == 'salt' else fixed_nonce if n == 12 else real_random(n)
            with self.subTest(collision=collision), patch('reverse_artex_guard.browser_state_migration.secrets.token_bytes', side_effect=random):
                with self.assertRaises(Unavailable): self.transition()
            self.assertEqual(self.snapshot(), before)
        self.transition()
        self.assertEqual(self.snapshot()['ra_browser_state_meta'][0][-1], 2)

    def test_second_rotation_authenticates_history_and_prohibits_retired_key_reuse(self):
        self.populate()
        one = self.transition()
        last = secrets.token_bytes(32)
        two = self.transition(source_keys=(self.next,), target_key=last, expected_epoch=one['to_epoch'], operation_id='rotate-2')
        self.assertEqual(two['generation'], 2)
        self.assertEqual(self.state(last).describe()['generation'], 2)
        for old in (self.fx.master, self.next):
            with self.assertRaises(ValueError):
                self.transition(source_keys=(last,), target_key=old, expected_epoch=two['to_epoch'], operation_id='reuse-old-key')
        with self.assertRaises(ValueError): self.transition()
        self.assertEqual(len(self.snapshot()['operations']), 2)

    def test_capacity_migration_can_keep_current_master_with_fresh_derived_keys(self):
        f = self.fx
        cookie, _ = f.complete()
        before = self.snapshot()
        self.transition(mode='migrate', target_key=f.master, target_capacity=8)
        self.assertIsNotNone(self.worker(capacity=8).session(cookie))
        self.assertNotEqual(before['ra_browser_records'][0][1], self.snapshot()['ra_browser_records'][0][1])
        with self.assertRaises(ValueError): self.transition(target_key=f.master)

    def test_journal_tampering_or_deletion_is_fail_closed(self):
        f = self.fx
        cookie, _ = f.complete()
        self.transition()
        current = self.worker(self.next)
        original = f.raw('SELECT * FROM ra_browser_state_operations')[0]
        for mutation in ("UPDATE ra_browser_state_operations SET mac='" + '0' * 64 + "'",
                         "UPDATE ra_browser_state_operations SET document=replace(document,'preserve','revoked')",
                         'DELETE FROM ra_browser_state_operations'):
            f.raw(mutation)
            with self.assertRaises(Unavailable): current.session(cookie)
            f.raw('DELETE FROM ra_browser_state_operations')
            f.raw('INSERT INTO ra_browser_state_operations VALUES(?,?,?,?,?)', original)
            self.assertIsNotNone(current.session(cookie))

    def test_live_generation_and_external_minimum_reject_whole_snapshot_rollback(self):
        f = self.fx
        cookie, _ = f.complete()
        prepared = self.worker(extra=(self.next,))
        old = self.snapshot()
        self.transition()
        self.assertIsNotNone(prepared.session(cookie))
        f.raw('DELETE FROM ra_browser_records')
        f.raw('DELETE FROM ra_browser_state_meta')
        f.raw('DELETE FROM ra_browser_state_operations')
        for row in old['ra_browser_state_meta']: f.raw('INSERT INTO ra_browser_state_meta VALUES(?,?,?,?,?,?,?)', row)
        for row in old['ra_browser_records']: f.raw('INSERT INTO ra_browser_records VALUES(?,?,?,?,?,?)', row)
        with self.assertRaises(Unavailable): prepared.session(cookie)
        with self.assertRaises(ValueError): self.state(extra=(self.next,), minimum=1)
        with self.assertRaises(ValueError): self.state(self.next)

    def test_keyring_and_transition_parameters_are_bounded_and_non_mutating(self):
        before = self.snapshot()
        for extra in ((self.fx.master,), tuple(secrets.token_bytes(32) for _ in range(4)), (b'short',)):
            with self.assertRaises(ValueError): self.state(extra=extra)
        for options in ({'target_key': b'short'}, {'expected_epoch': 'short'}, {'operation_id': 'a' * 65},
                        {'operation_id': '../oops'}, {'session_policy': 'auto'}, {'mode': 'auto'},
                        {'target_capacity': 0, 'mode': 'migrate'}, {'target_key': self.fx.master}):
            with self.subTest(options=list(options)), self.assertRaises(ValueError): self.transition(**options)
        self.assertEqual(self.snapshot(), before)
        self.transition()
        public = json.dumps(self.state(self.next).describe())
        self.assertNotIn(self.next.hex(), public)
        self.assertNotIn(self.fx.master.hex(), public)


if __name__ == '__main__':
    unittest.main()

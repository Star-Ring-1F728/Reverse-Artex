import base64
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from reverse_artex_guard import Guard, ReadIdentity, ApplicationSnapshot
from reverse_artex_guard.sqlite_application import (
    PROFILE, MAX_PAYLOAD, Conflict, SQLiteApplicationStore, SQLiteApplicationResolver)
import test_guard as signed_fixture
import test_browser_sso as browser_fixture


class SQLiteApplicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ra-native-acl-unit-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'app.db'
        self.now = 100
        self.store = SQLiteApplicationStore.initialize(self.path, clock=lambda: self.now)
        self.resolver = SQLiteApplicationResolver(self.path, clock=lambda: self.now)
        self.store.create('a' * 64, 'alice', 'alpha', 200)
        self.identity = ReadIdentity('alice', 'alpha', 'a' * 64)
        self.initial = self.store.create_object('one', tenant='alpha', owner='bob', grants=('alice',), payload={'value': 'PRIVATE'})

    def snapshot(self, object_id='one'):
        return self.resolver(object_id, self.identity).object_snapshot

    def raw(self, sql, values=()):
        with closing(sqlite3.connect(self.path)) as db, db:
            return db.execute(sql, values).fetchall()

    def test_profile_initialization_is_exclusive_and_never_migrates_existing_database(self):
        before = self.path.read_bytes()
        with self.assertRaises(FileExistsError): SQLiteApplicationStore.initialize(self.path)
        self.assertEqual(self.path.read_bytes(), before)
        legacy = Path(self.temp.name) / 'legacy.db'
        with closing(sqlite3.connect(legacy)) as db: db.execute('CREATE TABLE objects(id INTEGER PRIMARY KEY)')
        before = legacy.read_bytes()
        with self.assertRaises(sqlite3.OperationalError): SQLiteApplicationResolver(legacy)
        self.assertEqual(legacy.read_bytes(), before)
        missing = Path(self.temp.name) / 'missing.db'
        for cls in (SQLiteApplicationResolver, SQLiteApplicationStore):
            with self.assertRaises(sqlite3.OperationalError): cls(missing)
        self.assertFalse(missing.exists())

    def test_persistent_grants_revisions_and_payload_survive_new_store_instances(self):
        value = self.snapshot()
        self.assertEqual((value.tenant, value.owner, value.grants, value.payload), ('alpha', 'bob', ('alice',), {'value': 'PRIVATE'}))
        self.assertEqual((value.authz_revision, value.content_revision), (self.initial.authz_revision, self.initial.content_revision))
        reopened = SQLiteApplicationResolver(self.path, clock=lambda: self.now)
        self.assertEqual(reopened('one', self.identity), self.resolver('one', self.identity))
        self.assertTrue(SQLiteApplicationStore(self.path).active('a' * 64, 'alice', 'alpha', self.now))
        reopened_store = SQLiteApplicationStore(self.path)
        self.assertEqual(reopened_store.current_revisions('one'), self.initial)
        self.assertIsNone(reopened_store.current_revisions('missing'))

    def test_acl_and_content_revisions_change_independently_and_noops_preserve_tokens(self):
        content = self.store.replace_content('one', expected_content_revision=self.initial.content_revision, payload={'value': 'AFTER'})
        self.assertEqual(content.authz_revision, self.initial.authz_revision)
        self.assertNotEqual(content.content_revision, self.initial.content_revision)
        acl = self.store.replace_acl('one', expected_authz_revision=self.initial.authz_revision, tenant='alpha', owner='bob', grants=())
        self.assertNotEqual(acl.authz_revision, self.initial.authz_revision)
        self.assertEqual(acl.content_revision, content.content_revision)
        self.assertEqual(self.store.replace_acl('one', expected_authz_revision=acl.authz_revision, tenant='alpha', owner='bob', grants=()), acl)
        self.assertEqual(self.store.replace_content('one', expected_content_revision=acl.content_revision, payload={'value': 'AFTER'}), acl)
        self.assertEqual(self.snapshot().payload, {'value': 'AFTER'})
        self.assertEqual(self.snapshot().grants, ())

    def test_returning_to_prior_acl_or_content_and_recreating_never_reuses_revisions(self):
        changed = self.store.replace_acl('one', expected_authz_revision=self.initial.authz_revision, tenant='alpha', owner='bob', grants=())
        restored = self.store.replace_acl('one', expected_authz_revision=changed.authz_revision, tenant='alpha', owner='bob', grants=('alice',))
        self.assertNotIn(restored.authz_revision, (self.initial.authz_revision, changed.authz_revision))
        c1 = self.store.replace_content('one', expected_content_revision=restored.content_revision, payload={})
        c2 = self.store.replace_content('one', expected_content_revision=c1.content_revision, payload={'value': 'PRIVATE'})
        self.assertNotIn(c2.content_revision, (self.initial.content_revision, c1.content_revision))
        self.store.delete_object('one', expected_authz_revision=c2.authz_revision, expected_content_revision=c2.content_revision)
        self.assertIsNone(self.snapshot())
        self.assertEqual(self.raw('SELECT * FROM object_grants'), [])
        recreated = self.store.create_object('one', tenant='alpha', owner='bob', grants=('alice',), payload={'value': 'PRIVATE'})
        self.assertNotEqual(recreated.authz_revision, self.initial.authz_revision)
        self.assertNotEqual(recreated.content_revision, self.initial.content_revision)
        with self.assertRaises(Conflict): self.store.delete_object('one', expected_authz_revision=self.initial.authz_revision, expected_content_revision=self.initial.content_revision)

    def test_combined_object_update_commits_ACL_and_content_with_two_revision_CAS(self):
        changed = self.store.replace_object('one', expected_authz_revision=self.initial.authz_revision,
            expected_content_revision=self.initial.content_revision, tenant='beta', owner='carol', grants=('bob',), payload={'value': 'COMBINED'})
        current = self.snapshot()
        self.assertEqual((current.tenant, current.owner, current.grants, current.payload), ('beta', 'carol', ('bob',), {'value': 'COMBINED'}))
        self.assertNotEqual(changed.authz_revision, self.initial.authz_revision)
        self.assertNotEqual(changed.content_revision, self.initial.content_revision)
        with self.assertRaises(Conflict):
            self.store.replace_object('one', expected_authz_revision=self.initial.authz_revision,
                expected_content_revision=changed.content_revision, tenant='alpha', owner='alice', payload={})
        self.assertEqual(self.snapshot(), current)
        self.assertEqual(self.store.replace_object('one', expected_authz_revision=changed.authz_revision,
            expected_content_revision=changed.content_revision, tenant='beta', owner='carol', grants=('bob',), payload={'value': 'COMBINED'}), changed)

    def test_failed_combined_object_update_rolls_back_every_field(self):
        self.raw("CREATE TRIGGER reject_combined BEFORE INSERT ON object_grants WHEN NEW.principal='carol' BEGIN SELECT RAISE(ABORT,'fixture failure'); END")
        before = self.snapshot()
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.replace_object('one', expected_authz_revision=self.initial.authz_revision,
                expected_content_revision=self.initial.content_revision, tenant='beta', owner='carol', grants=('carol',), payload={'value': 'must rollback'})
        self.assertEqual(self.snapshot(), before)

    def test_stale_compare_and_swap_and_duplicate_create_leave_state_unchanged(self):
        current = self.store.replace_acl('one', expected_authz_revision=self.initial.authz_revision, tenant='alpha', owner='alice', grants=())
        for callback in (
            lambda: self.store.replace_acl('one', expected_authz_revision=self.initial.authz_revision, tenant='beta', owner='bob'),
            lambda: self.store.delete_object('one', expected_authz_revision=self.initial.authz_revision, expected_content_revision=self.initial.content_revision),
            lambda: self.store.create_object('one', tenant='beta', owner='bob', payload={}),
            lambda: self.store.replace_content('missing', expected_content_revision=self.initial.content_revision, payload={})):
            with self.assertRaises(Conflict): callback()
        self.assertEqual(self.snapshot().owner, 'alice')
        self.assertEqual(self.snapshot().authz_revision, current.authz_revision)

    def test_concurrent_cas_writers_have_exactly_one_winner(self):
        barrier = threading.Barrier(3)
        results = []
        def writer(owner):
            barrier.wait()
            try:
                self.store.replace_acl('one', expected_authz_revision=self.initial.authz_revision, tenant='alpha', owner=owner)
                results.append(('success', owner))
            except Conflict: results.append(('conflict', owner))
        threads = [threading.Thread(target=writer, args=(p,)) for p in ('alice', 'carol')]
        for thread in threads: thread.start()
        barrier.wait()
        for thread in threads: thread.join(3)
        self.assertTrue(all(not t.is_alive() for t in threads))
        self.assertEqual(sorted(r[0] for r in results), ['conflict', 'success'])
        self.assertEqual(self.snapshot().owner, next(p for status, p in results if status == 'success'))

    def test_failed_acl_write_rolls_back_revision_grants_and_owner_together(self):
        self.raw("CREATE TRIGGER reject_grant BEFORE INSERT ON object_grants WHEN NEW.principal='carol' BEGIN SELECT RAISE(ABORT,'fixture failure'); END")
        before = self.snapshot()
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.replace_acl('one', expected_authz_revision=before.authz_revision, tenant='beta', owner='carol', grants=('carol',))
        self.assertEqual(self.snapshot(), before)

    def test_foreign_keys_prevent_cross_tenant_grants_and_tenant_move_replaces_grants(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('PRAGMA foreign_keys=ON')
            with self.assertRaises(sqlite3.IntegrityError): db.execute("INSERT INTO object_grants VALUES('one','beta','carol')")
        self.store.replace_acl('one', expected_authz_revision=self.initial.authz_revision, tenant='beta', owner='bob', grants=('carol',))
        changed = self.snapshot()
        self.assertEqual((changed.tenant, changed.grants), ('beta', ('carol',)))
        self.assertEqual(self.raw('SELECT tenant,principal FROM object_grants'), [('beta', 'carol')])

    def test_session_revoke_expiry_identity_mismatch_precede_all_object_reads(self):
        statements = []
        original = sqlite3.connect
        def connect(*args, **kwargs):
            db = original(*args, **kwargs); db.set_trace_callback(statements.append); return db
        for wrong in (ReadIdentity('alice', 'beta', 'a' * 64), ReadIdentity('bob', 'alpha', 'a' * 64)):
            with patch('reverse_artex_guard.sqlite_application.sqlite3.connect', connect):
                self.assertEqual(self.resolver('one', wrong), ApplicationSnapshot(False))
        self.now = 200
        with patch('reverse_artex_guard.sqlite_application.sqlite3.connect', connect):
            self.assertEqual(self.resolver('one', self.identity), ApplicationSnapshot(False))
        self.now = 100; self.store.revoke(['a' * 64])
        with patch('reverse_artex_guard.sqlite_application.sqlite3.connect', connect):
            self.assertEqual(self.resolver('one', self.identity), ApplicationSnapshot(False))
        self.assertFalse(any('FROM objects' in s or 'FROM object_grants' in s for s in statements))

    def test_session_object_acl_payload_share_snapshot_during_concurrent_commit(self):
        original = sqlite3.connect
        fired = []
        def connect(*args, **kwargs):
            db = original(*args, **kwargs)
            def trace(sql):
                if 'FROM object_grants' in sql and not fired:
                    fired.append(True)
                    # Separate connection commits after reader has pinned its snapshot.
                    with closing(original(self.path)) as writer, writer:
                        writer.execute('DELETE FROM sessions')
                        writer.execute("UPDATE objects SET owner='carol',payload_json='{}',authz_revision=?,content_revision=?", ('a_' + 'f' * 32, 'c_' + 'e' * 32))
                        writer.execute('DELETE FROM object_grants')
            db.set_trace_callback(trace)
            return db
        with patch('reverse_artex_guard.sqlite_application.sqlite3.connect', connect):
            first = self.resolver('one', self.identity)
        self.assertTrue(fired)
        self.assertEqual((first.object_snapshot.owner, first.object_snapshot.grants, first.object_snapshot.payload), ('bob', ('alice',), {'value': 'PRIVATE'}))
        self.assertEqual(first.object_snapshot.authz_revision, self.initial.authz_revision)
        self.assertEqual(self.resolver('one', self.identity), ApplicationSnapshot(False))

    def test_invalid_scope_grants_payload_and_revision_inputs_do_not_write(self):
        before = self.snapshot()
        for grants in (['alice', 'alice'], ['x'] * 257, ['wrong/name'], 'alice'):
            with self.assertRaises(ValueError): self.store.replace_acl('one', expected_authz_revision=before.authz_revision, tenant='alpha', owner='bob', grants=grants)
        nested = None
        for _ in range(34): nested = [nested]
        for payload in ({'x': float('nan')}, {'x': float('inf')}, {1: 'wrong key'}, {'x': 'z' * MAX_PAYLOAD}, nested, {'x': object()}, {'x': 1 << 500}):
            with self.assertRaises(ValueError): self.store.replace_content('one', expected_content_revision=before.content_revision, payload=payload)
        for oid in ('', '../one', "one'", 'x' * 65):
            with self.assertRaises(ValueError): self.store.create_object(oid, tenant='alpha', owner='alice', payload={})
        with self.assertRaises(ValueError): self.store.replace_acl('one', expected_authz_revision='unknown', tenant='alpha', owner='alice')
        self.assertEqual(self.snapshot(), before)

    def test_accepted_JSON_values_round_trip_at_integer_and_unicode_boundaries(self):
        payload = {'negative': -((1 << 425) - 1), 'positive': (1 << 425) - 1,
                   'nested': [None, True, False, 0.5, '한글'], 'map': {'b': 2, 'a': 1}}
        changed = self.store.replace_content('one', expected_content_revision=self.initial.content_revision, payload=payload)
        self.assertEqual(self.snapshot().payload, payload)
        self.assertEqual(self.snapshot().content_revision, changed.content_revision)
        # Object-key order is not a content change in this JSON profile.
        equivalent = dict(reversed(list(payload.items())))
        self.assertEqual(self.store.replace_content('one', expected_content_revision=changed.content_revision, payload=equivalent), changed)

    def test_session_inputs_bound_expiry_and_never_resurrect_duplicate_digest(self):
        for digest, expires in (('secret-token', 200), ('b' * 64, 100), ('b' * 64, 706), ('b' * 64, float('inf')), ('b' * 64, True)):
            with self.assertRaises(ValueError): self.store.create(digest, 'alice', 'alpha', expires)
        with self.assertRaises(sqlite3.IntegrityError): self.store.create('a' * 64, 'bob', 'beta', 201)
        self.assertTrue(self.store.active('a' * 64, 'alice', 'alpha', 100))
        self.assertFalse(self.store.active('a' * 64, 'bob', 'beta', 100))

    def guard_fixture(self):
        self.key = Ed25519PrivateKey.generate()
        guard = Guard(asset='asset', registry_digest='a' * 64, trust_epoch='e1', route_id='legacy', template='/legacy/objects/{id}',
                      namespace='objects', tenants=['alpha', 'beta'], key_id='sdk1', private_key=self.key.private_bytes_raw(),
                      identity_key=b'i' * 32, session_key=b'h' * 32, ingress_token='g' * 32, clock=lambda: self.now, resolver_version='session-snapshot-v1')
        credential = signed_fixture.token(now=self.now)
        self.store.create(hashlib.sha256(credential.encode()).hexdigest(), 'alice', 'alpha', self.now + 600)
        headers = {'Authorization': 'Bearer ' + credential, 'X-Lab-Ingress': 'g' * 32, 'X-RA-Registry': 'a' * 64,
                   'X-RA-Request-ID': 'request', 'X-RA-Nonce': 'b' * 48}
        return guard, headers

    def test_guard_uses_persisted_grants_and_signs_distinct_versions_on_revoke(self):
        guard, headers = self.guard_fixture()
        def read(): return guard.read_application('GET', '/legacy/objects/one', headers, self.resolver)
        allow = read()
        self.assertEqual(allow.status, 200)
        allow_proof = signed_fixture.GuardTests.proof(self, allow)
        self.store.replace_acl('one', expected_authz_revision=self.initial.authz_revision, tenant='alpha', owner='bob')
        deny = read()
        self.assertEqual(deny.status, 403)
        deny_proof = signed_fixture.GuardTests.proof(self, deny)
        self.assertNotEqual(allow_proof['authz_revision'], deny_proof['authz_revision'])
        self.assertEqual(allow_proof['content_revision'], deny_proof['content_revision'])
        self.assertNotIn(b'PRIVATE', deny.body)
        self.assertEqual(guard.read_application('HEAD', '/legacy/objects/one', headers, self.resolver).body, b'')

    def test_guard_rejects_foreign_tenant_even_with_same_named_principal_grant(self):
        guard, headers = self.guard_fixture()
        self.store.replace_acl('one', expected_authz_revision=self.initial.authz_revision, tenant='beta', owner='alice', grants=('alice',))
        rep = guard.read_application('GET', '/legacy/objects/one', headers, self.resolver)
        self.assertEqual(rep.status, 403)
        self.assertNotIn(b'PRIVATE', rep.body)

    def test_corrupt_profile_revision_grant_and_payload_fail_closed_at_guard(self):
        guard, headers = self.guard_fixture()
        corruptions = [
            ("UPDATE objects SET authz_revision='unknown'", ()),
            ("UPDATE objects SET payload_json=?", ('{"x":1,"x":2}',)),
            ("UPDATE objects SET payload_json=?", ('{"x":1e999}',)),
            ("UPDATE objects SET payload_json=?", ('[' * 1000 + '0' + ']' * 1000,)),
            ("UPDATE ra_application_schema SET profile='unsupported'", ()),
            ("UPDATE object_grants SET tenant='beta'", ())]
        for statement, values in corruptions:
            with self.subTest(statement=statement):
                # Every injection is scoped to this disposable DB and rolled back.
                with closing(sqlite3.connect(self.path)) as db, db:
                    db.execute('BEGIN'); db.execute(statement, values); db.commit()
                rep = guard.read_application('GET', '/legacy/objects/one', headers, self.resolver)
                self.assertEqual(rep.status, 503)
                self.assertNotIn(b'PRIVATE', rep.body)
                self.raw('UPDATE ra_application_schema SET profile=?', (PROFILE,))
                self.raw('UPDATE objects SET authz_revision=?,payload_json=?', (self.initial.authz_revision, '{"value":"PRIVATE"}'))
                self.raw("UPDATE object_grants SET tenant='alpha'")

    def test_denied_schema_access_read_only_query_mode_and_database_error(self):
        seen = []
        original = sqlite3.connect
        def connect(*args, **kwargs):
            self.assertIn('mode=ro', args[0])
            db = original(*args, **kwargs)
            db.set_trace_callback(seen.append)
            return db
        with patch('reverse_artex_guard.sqlite_application.sqlite3.connect', connect): self.snapshot()
        self.assertIn('PRAGMA query_only=ON', seen)
        self.assertIn('BEGIN', seen)
        guard, headers = self.guard_fixture()
        self.raw('ALTER TABLE object_grants RENAME TO unavailable_grants')
        rep = guard.read_application('GET', '/legacy/objects/one', headers, self.resolver)
        self.assertEqual(rep.status, 503)
        self.assertNotIn(b'PRIVATE', rep.body)


class NativeBrowserLifecycleTests(unittest.TestCase):
    def test_browser_sso_controller_uses_native_store_without_new_acl_authority(self):
        # Reuse signed OIDC transaction helpers, not the legacy session backend.
        flow = browser_fixture.BrowserSSOTests()
        flow.setUpClass(); flow.setUp()
        self.addCleanup(flow.doCleanups)
        native = Path(flow.temp.name) / 'native.db'
        store = SQLiteApplicationStore.initialize(native, clock=lambda: flow.now)
        revisions = store.create_object('one', tenant='alpha', owner='bob', grants=('alice',), payload={'shared': True})
        flow.backend, flow.sso.lifecycle = store, store
        key, _ = flow.complete()
        session = flow.sso.session(key)
        resolver = SQLiteApplicationResolver(native, clock=lambda: flow.now)
        identity = ReadIdentity(session['principal'], session['tenant'], session['digest'])
        self.assertEqual(resolver('one', identity).object_snapshot.grants, ('alice',))
        store.replace_acl('one', expected_authz_revision=revisions.authz_revision, tenant='alpha', owner='bob')
        self.assertEqual(resolver('one', identity).object_snapshot.grants, ())
        flow.sso.logout(key, session['csrf'])
        self.assertEqual(resolver('one', identity), ApplicationSnapshot(False))
        self.assertIsNone(flow.sso.session(key))


if __name__ == '__main__':
    unittest.main()

from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

from reverse_artex_guard import ApplicationSnapshot, ObjectSnapshot, ReadIdentity
import test_guard as fixture
from reverse_artex_guard import Guard

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))
from sqlite_session_adapter import SQLiteSessionResolver


class ApplicationTests(unittest.TestCase):
    # Reuse the signed request fixture, but do not inherit the old-mode tests.
    def setUp(self):
        fixture.GuardTests.setUp(self)
        self.guard = Guard(asset="asset", registry_digest="a" * 64, trust_epoch="e1", route_id="legacy",
                           template="/legacy/objects/{id}", namespace="objects", tenants=["alpha"],
                           key_id="sdk1", private_key=self.key.private_bytes_raw(),
                           identity_key=b"i" * 32, session_key=b"h" * 32, ingress_token="g" * 32,
                           max_body_bytes=1024, clock=lambda: self.now,
                           resolver_version="session-snapshot-v1")

    proof = fixture.GuardTests.proof

    def read_app(self, result, method="GET"):
        return self.guard.read_application(method, "/legacy/objects/one", self.headers,
                                           lambda oid, identity: result)

    def default_guard(self):
        return Guard(asset="asset", registry_digest="a" * 64, trust_epoch="e1", route_id="legacy",
                     template="/legacy/objects/{id}", namespace="objects", tenants=["alpha"],
                     key_id="sdk1", private_key=self.key.private_bytes_raw(),
                     identity_key=b"i" * 32, session_key=b"h" * 32, ingress_token="g" * 32,
                     max_body_bytes=1024, resolver_version="session-snapshot-v1")

    def test_default_proof_clock_can_lag_precise_authentication_clock(self):
        self.headers["Authorization"] = "Bearer " + fixture.token(now=123.5)
        with patch("reverse_artex_guard.guard.time.time", return_value=123.5), patch("reverse_artex_guard.guard.proof_time", return_value=123.0):
            guard = self.default_guard()
            rep = guard.read_application("GET", "/legacy/objects/one", self.headers,
                                         lambda *_: ApplicationSnapshot(False))
        self.assertEqual(rep.status, 401)
        self.assertEqual(self.proof(rep)["issued_ms"], 123000)
        self.assertEqual(self.proof(rep)["expires_ms"], 128000)

    def test_proof_clock_does_not_extend_token_expiry_at_second_boundary(self):
        self.headers["Authorization"] = "Bearer " + fixture.token(now=-477)  # exp=123
        def unreachable(*_): self.fail("expired credential reached application")
        with patch("reverse_artex_guard.guard.time.time", return_value=123.001), patch("reverse_artex_guard.guard.proof_time", return_value=122.999):
            guard = self.default_guard()
            rep = guard.read_application("GET", "/legacy/objects/one", self.headers, unreachable)
        self.assertEqual(rep.status, 401)
        self.assertNotIn("X-RA-Release-Proof", rep.headers)

    def test_application_receives_only_verified_identity_and_credential_digest(self):
        seen = []
        def resolver(oid, identity):
            seen.append((oid, identity))
            return ApplicationSnapshot(True, self.snapshot)
        rep = self.guard.read_application("GET", "/legacy/objects/one", self.headers, resolver)
        self.assertEqual(rep.status, 200)
        self.assertEqual(seen, [("one", ReadIdentity("alice", "alpha", hashlib.sha256(
            self.headers["Authorization"][7:].encode()).hexdigest()))])
        self.assertNotIn(self.headers["Authorization"], repr(seen))
        self.assertEqual(self.proof(rep)["decision"], "allow")

    def test_revoked_session_and_missing_object_are_distinct_signed_responses(self):
        for method in ("GET", "HEAD"):
            for snapshot, status, decision in ((ApplicationSnapshot(False), 401, "unauthenticated"),
                                               (ApplicationSnapshot(True), 404, "not_found")):
                with self.subTest(method=method, status=status):
                    rep = self.read_app(snapshot, method)
                    self.assertEqual(rep.status, status)
                    self.assertEqual(self.proof(rep)["decision"], decision)
                    self.assertEqual(rep.body == b"", method == "HEAD")
                    self.assertNotIn(b"OWNED_PRIVATE", rep.body)

    def test_application_cannot_supply_allow_for_a_foreign_snapshot(self):
        obj = ObjectSnapshot("one", "alpha", "bob", (), "acl2", "v1", object())
        rep = self.read_app(ApplicationSnapshot(True, obj))
        self.assertEqual(rep.status, 403)
        self.assertEqual(self.proof(rep)["decision"], "deny")

    def test_invalid_application_results_and_exceptions_are_unknown(self):
        for result in (self.snapshot, ApplicationSnapshot(1), ApplicationSnapshot(False, self.snapshot)):
            rep = self.read_app(result)
            self.assertEqual(rep.status, 503)
            self.assertEqual(self.proof(rep)["decision"], "unknown")
        def failed(*_): raise RuntimeError("private database details")
        rep = self.guard.read_application("GET", "/legacy/objects/one", self.headers, failed)
        self.assertEqual(rep.status, 503)
        self.assertNotIn(b"database details", rep.body)

    def test_wrong_resolver_mode_and_forged_identity_never_invoke_application(self):
        def unreachable(*_): self.fail("invalid request reached application")
        self.assertEqual(self.guard.read("GET", "/legacy/objects/one", self.headers, unreachable).status, 503)
        self.headers["Authorization"] = "Bearer forged"
        self.assertEqual(self.guard.read_application("GET", "/legacy/objects/one", self.headers, unreachable).status, 401)


class SQLiteSessionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ra-session-test-")
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "app.db"
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("CREATE TABLE sessions(digest TEXT PRIMARY KEY, principal TEXT, tenant TEXT, expires REAL);"
                             "CREATE TABLE objects(id INTEGER PRIMARY KEY, owner TEXT, tenant TEXT, value TEXT);")
            db.execute("INSERT INTO sessions VALUES(?,?,?,?)", ("a" * 64, "alice", "alpha", 200))
            db.execute("INSERT INTO objects VALUES(1,'alice','alpha','before')")
        self.identity = ReadIdentity("alice", "alpha", "a" * 64)
        self.resolver = SQLiteSessionResolver(self.path, clock=lambda: 100)

    def test_live_session_revocation_expiry_and_scope_mismatch(self):
        self.assertEqual(self.resolver("1", self.identity).object_snapshot.payload, {"value": "before"})
        for statement in ("UPDATE sessions SET expires=100", "UPDATE sessions SET tenant='beta'",
                          "UPDATE sessions SET principal='bob'", "DELETE FROM sessions"):
            with self.subTest(statement=statement):
                with closing(sqlite3.connect(self.path)) as db, db:
                    db.execute("DELETE FROM sessions")
                    db.execute("INSERT INTO sessions VALUES(?,?,?,?)", ("a" * 64, "alice", "alpha", 200))
                    db.execute(statement)
                self.assertEqual(self.resolver("1", self.identity), ApplicationSnapshot(False))

    def test_acl_and_payload_changes_advance_only_their_revision(self):
        first = self.resolver("1", self.identity).object_snapshot
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE objects SET owner='bob'")
        acl = self.resolver("1", self.identity).object_snapshot
        self.assertNotEqual(first.authz_revision, acl.authz_revision)
        self.assertEqual(first.content_revision, acl.content_revision)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE objects SET value='after'")
        changed = self.resolver("1", self.identity).object_snapshot
        self.assertEqual(acl.authz_revision, changed.authz_revision)
        self.assertNotEqual(acl.content_revision, changed.content_revision)
        self.assertEqual(changed.payload, {"value": "after"})

    def test_missing_objects_and_numeric_aliases_do_not_resolve(self):
        for oid in ("999", "01", "one", "1/2", "1" * 64):
            self.assertEqual(self.resolver(oid, self.identity), ApplicationSnapshot(True))

    def test_session_and_payload_share_snapshot_across_concurrent_commit(self):
        connect = sqlite3.connect
        def connected(*args, **kwargs):
            db = connect(*args, **kwargs)
            def before_object(sql):
                if sql.startswith("SELECT owner,tenant,value"):
                    with closing(connect(self.path)) as writer, writer:
                        writer.execute("DELETE FROM sessions")
                        writer.execute("UPDATE objects SET owner='bob',value='after'")
            db.set_trace_callback(before_object)
            return db
        with patch("sqlite_session_adapter.sqlite3.connect", connected):
            result = self.resolver("1", self.identity)
        self.assertTrue(result.session_valid)
        self.assertEqual(result.object_snapshot.owner, "alice")
        self.assertEqual(result.object_snapshot.payload, {"value": "before"})
        self.assertEqual(self.resolver("1", self.identity), ApplicationSnapshot(False))

    def test_missing_database_is_not_created(self):
        missing = self.path.parent / "missing.db"
        with self.assertRaises(sqlite3.OperationalError):
            SQLiteSessionResolver(missing)("1", self.identity)
        self.assertFalse(missing.exists())


if __name__ == "__main__":
    unittest.main()

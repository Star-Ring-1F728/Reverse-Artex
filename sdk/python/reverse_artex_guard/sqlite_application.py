"""Opt-in SQLite application profile with durable ACL/content revisions.

This is an explicit application schema, not a migration or a sidecar ACL that
supersedes another app's permissions. All object writers must use its CAS
transactions. The resolver owns one read-only session/object/grant snapshot.
"""
from contextlib import closing, contextmanager
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time

from .guard import ApplicationSnapshot, ObjectSnapshot, ReadIdentity
from .sqlite_runtime import require_wal_runtime

PROFILE = "sqlite-native-acl/1"
MAX_PAYLOAD = 1048576
_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ACL = re.compile(r"a_[0-9a-f]{32}\Z")
_CONTENT = re.compile(r"c_[0-9a-f]{32}\Z")
_SCHEMA = """
BEGIN IMMEDIATE;
CREATE TABLE ra_application_schema (profile TEXT NOT NULL PRIMARY KEY);
INSERT INTO ra_application_schema VALUES ('sqlite-native-acl/1');
CREATE TABLE sessions (
    digest TEXT NOT NULL PRIMARY KEY CHECK(length(digest)=64 AND digest NOT GLOB '*[^0-9a-f]*'),
    principal TEXT NOT NULL CHECK(length(principal) BETWEEN 1 AND 64 AND principal NOT GLOB '*[^A-Za-z0-9_-]*'),
    tenant TEXT NOT NULL CHECK(length(tenant) BETWEEN 1 AND 64 AND tenant NOT GLOB '*[^A-Za-z0-9_-]*'),
    expires REAL NOT NULL CHECK(expires>0 AND expires<1e20)
);
CREATE TABLE objects (
    id TEXT NOT NULL PRIMARY KEY CHECK(length(id) BETWEEN 1 AND 64 AND id NOT GLOB '*[^A-Za-z0-9_-]*'),
    tenant TEXT NOT NULL CHECK(length(tenant) BETWEEN 1 AND 64 AND tenant NOT GLOB '*[^A-Za-z0-9_-]*'),
    owner TEXT NOT NULL CHECK(length(owner) BETWEEN 1 AND 64 AND owner NOT GLOB '*[^A-Za-z0-9_-]*'),
    authz_revision TEXT NOT NULL,
    content_revision TEXT NOT NULL,
    payload_json TEXT NOT NULL CHECK(length(CAST(payload_json AS BLOB))<=1048576),
    UNIQUE(id,tenant)
);
CREATE TABLE object_grants (
    object_id TEXT NOT NULL,
    tenant TEXT NOT NULL,
    principal TEXT NOT NULL CHECK(length(principal) BETWEEN 1 AND 64 AND principal NOT GLOB '*[^A-Za-z0-9_-]*'),
    PRIMARY KEY(object_id,principal),
    FOREIGN KEY(object_id,tenant) REFERENCES objects(id,tenant) ON DELETE CASCADE
);
COMMIT;
"""


class Conflict(Exception):
    """Expected object revision is stale, missing or already exists."""
    def __init__(self):
        super().__init__("application object revision conflict")


@dataclass(frozen=True)
class Revisions:
    authz_revision: str
    content_revision: str


def _id(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("invalid application identifier")
    return value


def _digest(value):
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError("invalid application credential digest")
    return value


def _grants(values):
    if type(values) not in (tuple, list) or len(values) > 256:
        raise ValueError("bounded explicit application grants required")
    normalized = tuple(sorted(_id(v) for v in values))
    if len(set(normalized)) != len(normalized):
        raise ValueError("duplicate application grant")
    return normalized


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate application payload key")
        result[key] = value
    return result


def _json(value):
    def validate(item, depth=0):
        if depth > 32:
            raise ValueError("application payload depth limit")
        if type(item) is dict:
            for key, nested in item.items():
                if type(key) is not str:
                    raise ValueError("application JSON string keys required")
                validate(nested, depth + 1)
        elif type(item) is list:
            for nested in item: validate(nested, depth + 1)
        elif type(item) is float:
            if not math.isfinite(item): raise ValueError("finite application number required")
        elif type(item) is int:
            if item.bit_length() > 425: raise ValueError("application integer limit")
        elif item is not None and type(item) not in (str, bool):
            raise ValueError("application JSON value required")
    validate(value)
    raw = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
    if len(raw) > MAX_PAYLOAD:
        raise ValueError("application payload byte limit")
    return raw


def _payload(raw):
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_PAYLOAD:
        raise ValueError("bounded application payload required")
    def integer(value):
        if len(value.lstrip("-")) > 128: raise ValueError("application integer limit")
        return int(value)
    def constant(_): raise ValueError("finite application number required")
    value = json.loads(raw, object_pairs_hook=_unique, parse_constant=constant, parse_int=integer)
    _json(value)
    return value


def _schema(db):
    if db.execute("SELECT profile FROM ra_application_schema LIMIT 2").fetchall() != [(PROFILE,)]:
        raise ValueError("application database profile mismatch")


def _revisions(acl, content):
    if not isinstance(acl, str) or not _ACL.fullmatch(acl) or not isinstance(content, str) or not _CONTENT.fullmatch(content):
        raise ValueError("invalid persisted application revision")
    return Revisions(acl, content)


def _read_object(db, object_id):
    # Guard the payload length in SQLite before materializing it in Python.
    row = db.execute("SELECT id,tenant,owner,authz_revision,content_revision,"
                     "CASE WHEN length(CAST(payload_json AS BLOB))<=? THEN payload_json END "
                     "FROM objects WHERE id=?", (MAX_PAYLOAD, object_id)).fetchone()
    if row is None:
        return None
    oid, tenant, owner, acl, content, raw = row
    for value in (oid, tenant, owner): _id(value)
    _revisions(acl, content)
    rows = db.execute("SELECT tenant,principal FROM object_grants WHERE object_id=? ORDER BY principal LIMIT 257", (object_id,)).fetchall()
    if len(rows) > 256 or any(t != tenant for t, _ in rows):
        raise ValueError("invalid application grant scope")
    grants = _grants([p for _, p in rows])
    return ObjectSnapshot(oid, tenant, owner, grants, acl, content, _payload(raw))


class _Database:
    def __init__(self, database, *, clock=time.time):
        require_wal_runtime()
        path = Path(database).resolve()
        self._read_uri, self._write_uri = path.as_uri() + "?mode=ro", path.as_uri() + "?mode=rw"
        self._clock = clock
        with self._read():
            pass

    @contextmanager
    def _read(self):
        with closing(sqlite3.connect(self._read_uri, uri=True, timeout=.1, isolation_level=None)) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            _schema(db)
            yield db

    @contextmanager
    def _write(self):
        with closing(sqlite3.connect(self._write_uri, uri=True, timeout=.1, isolation_level=None)) as db:
            db.execute("PRAGMA foreign_keys=ON")
            if db.execute("PRAGMA foreign_keys").fetchone() != (1,):
                raise ValueError("application foreign key support required")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            try:
                _schema(db)
                yield db
                db.execute("COMMIT")
            except BaseException:
                if db.in_transaction: db.execute("ROLLBACK")
                raise


class SQLiteApplicationResolver(_Database):
    def __call__(self, object_id, identity):
        if not isinstance(identity, ReadIdentity):
            raise ValueError("verified application read identity required")
        _id(identity.principal); _id(identity.tenant); _digest(identity.credential_sha256)
        with self._read() as db:
            # This SELECT pins the same committed snapshot for session, object,
            # grants and revisions. Rejected sessions never read object tables.
            row = db.execute("SELECT principal,tenant FROM sessions WHERE digest=? AND expires>?",
                             (identity.credential_sha256, self._clock())).fetchone()
            if row != (identity.principal, identity.tenant):
                return ApplicationSnapshot(False)
            _id(object_id)
            return ApplicationSnapshot(True, _read_object(db, object_id))


def _create_session(db, digest, principal, tenant, expires, now):
    _digest(digest); _id(principal); _id(tenant)
    if type(expires) not in (int, float) or not math.isfinite(expires) or not now < expires <= now + 605:
        raise ValueError("bounded live application session required")
    db.execute("INSERT INTO sessions(digest,principal,tenant,expires) VALUES(?,?,?,?)", (digest, principal, tenant, expires))


def _active_session(db, digest, principal, tenant, now):
    _digest(digest); _id(principal); _id(tenant)
    if type(now) not in (int, float) or not math.isfinite(now):
        raise ValueError("invalid application clock")
    return db.execute("SELECT principal,tenant FROM sessions WHERE digest=? AND expires>?", (digest, now)).fetchone() == (principal, tenant)


def _revoke_sessions(db, digests):
    if type(digests) not in (list, tuple) or len(digests) > 4096:
        raise ValueError("bounded application session revocation required")
    values = tuple(_digest(d) for d in digests)
    db.executemany("DELETE FROM sessions WHERE digest=?", ((d,) for d in values))


class SQLiteApplicationStore(_Database):
    """Trusted application writer and BrowserSSO session lifecycle.

    No public HTTP mutation endpoint or end-user authorization is implied. A
    native app must authorize writes before invoking this store. Each ACL/content
    change uses CAS and its own new revision; unaffected revisions stay stable.
    """
    @classmethod
    def initialize(cls, database, *, clock=time.time):
        require_wal_runtime()
        path = Path(database).resolve()
        # Fail for every existing file, including another application database.
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        with closing(sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, isolation_level=None, timeout=.1)) as db:
            if db.execute("PRAGMA journal_mode=WAL").fetchone() != ("wal",):
                raise ValueError("application WAL mode required")
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA synchronous=FULL")
            db.executescript(_SCHEMA)
        return cls(path, clock=clock)

    def ready(self):
        """Read-only availability probe for the browser session lifecycle."""
        with self._read() as db:
            db.execute("SELECT digest,principal,tenant,expires FROM sessions LIMIT 0")
        return True

    def create(self, digest, principal, tenant, expires):
        with self._write() as db:
            _create_session(db, digest, principal, tenant, expires, self._clock())

    def active(self, digest, principal, tenant, now):
        with self._read() as db:
            return _active_session(db, digest, principal, tenant, now)

    def revoke(self, digests):
        with self._write() as db:
            _revoke_sessions(db, digests)

    def current_revisions(self, object_id):
        """Read CAS metadata for a trusted application writer after reopening."""
        _id(object_id)
        with self._read() as db:
            row = db.execute("SELECT authz_revision,content_revision FROM objects WHERE id=?", (object_id,)).fetchone()
            return None if row is None else _revisions(*row)

    def create_object(self, object_id, *, tenant, owner, grants=(), payload):
        _id(object_id); _id(tenant); _id(owner)
        grants, raw = _grants(grants), _json(payload)
        revisions = Revisions("a_" + secrets.token_hex(16), "c_" + secrets.token_hex(16))
        with self._write() as db:
            if db.execute("SELECT 1 FROM objects WHERE id=?", (object_id,)).fetchone(): raise Conflict()
            db.execute("INSERT INTO objects VALUES(?,?,?,?,?,?)", (object_id, tenant, owner, revisions.authz_revision, revisions.content_revision, raw))
            db.executemany("INSERT INTO object_grants VALUES(?,?,?)", ((object_id, tenant, p) for p in grants))
        return revisions

    def replace_acl(self, object_id, *, expected_authz_revision, tenant, owner, grants=()):
        _id(object_id); _id(tenant); _id(owner)
        if not isinstance(expected_authz_revision, str) or not _ACL.fullmatch(expected_authz_revision): raise ValueError("expected ACL revision required")
        grants = _grants(grants)
        with self._write() as db:
            current = _read_object(db, object_id)
            if current is None or current.authz_revision != expected_authz_revision: raise Conflict()
            if (current.tenant, current.owner, current.grants) == (tenant, owner, grants):
                return Revisions(current.authz_revision, current.content_revision)
            revisions = Revisions("a_" + secrets.token_hex(16), current.content_revision)
            db.execute("DELETE FROM object_grants WHERE object_id=?", (object_id,))
            db.execute("UPDATE objects SET tenant=?,owner=?,authz_revision=? WHERE id=?", (tenant, owner, revisions.authz_revision, object_id))
            db.executemany("INSERT INTO object_grants VALUES(?,?,?)", ((object_id, tenant, p) for p in grants))
        return revisions

    def replace_content(self, object_id, *, expected_content_revision, payload):
        _id(object_id)
        if not isinstance(expected_content_revision, str) or not _CONTENT.fullmatch(expected_content_revision): raise ValueError("expected content revision required")
        raw = _json(payload)
        with self._write() as db:
            current = _read_object(db, object_id)
            if current is None or current.content_revision != expected_content_revision: raise Conflict()
            if _json(current.payload) == raw:
                return Revisions(current.authz_revision, current.content_revision)
            revisions = Revisions(current.authz_revision, "c_" + secrets.token_hex(16))
            db.execute("UPDATE objects SET payload_json=?,content_revision=? WHERE id=?", (raw, revisions.content_revision, object_id))
        return revisions

    def replace_object(self, object_id, *, expected_authz_revision, expected_content_revision,
                       tenant, owner, grants=(), payload):
        """Atomically replace ACL and content when an app mutation needs both."""
        _id(object_id); _id(tenant); _id(owner)
        _revisions(expected_authz_revision, expected_content_revision)
        grants, raw = _grants(grants), _json(payload)
        with self._write() as db:
            current = _read_object(db, object_id)
            if current is None or (current.authz_revision, current.content_revision) != (expected_authz_revision, expected_content_revision):
                raise Conflict()
            acl_changed = (current.tenant, current.owner, current.grants) != (tenant, owner, grants)
            content_changed = _json(current.payload) != raw
            revisions = Revisions("a_" + secrets.token_hex(16) if acl_changed else current.authz_revision,
                                  "c_" + secrets.token_hex(16) if content_changed else current.content_revision)
            if not acl_changed and not content_changed:
                return revisions
            db.execute("DELETE FROM object_grants WHERE object_id=?", (object_id,))
            db.execute("UPDATE objects SET tenant=?,owner=?,authz_revision=?,content_revision=?,payload_json=? WHERE id=?",
                       (tenant, owner, revisions.authz_revision, revisions.content_revision, raw, object_id))
            db.executemany("INSERT INTO object_grants VALUES(?,?,?)", ((object_id, tenant, p) for p in grants))
        return revisions

    def delete_object(self, object_id, *, expected_authz_revision, expected_content_revision):
        _id(object_id)
        _revisions(expected_authz_revision, expected_content_revision)
        with self._write() as db:
            row = db.execute("SELECT authz_revision,content_revision FROM objects WHERE id=?", (object_id,)).fetchone()
            if row != (expected_authz_revision, expected_content_revision): raise Conflict()
            db.execute("DELETE FROM objects WHERE id=?", (object_id,))

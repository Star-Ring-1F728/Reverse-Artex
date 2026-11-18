"""Explicit encrypted browser state on the same native SQLite app database.

Shared BEGIN IMMEDIATE units of work cover browser records and app session
rows. Only same-host workers sharing this local WAL database are supported.
The master key stays outside SQLite; indexes use a separately derived HMAC key.
"""
from collections.abc import MutableMapping
from contextlib import closing
import hashlib
import hmac
import json
import math
import secrets
import sqlite3
import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .browser_sso import Unavailable, origin
from .oidc import _object, _ID, _TOKEN_ID, _OPAQUE
from .sqlite_application import (SQLiteApplicationStore, _create_session,
                                 _active_session, _revoke_sessions, _DIGEST)

PROFILE = "sqlite-browser-state/1"
_MAX_PLAIN = 32768
_MAX_ENCRYPTIONS = 1_000_000_000
_KINDS = ("session", "transaction", "revocation", "seen")
_CHECK = b"reverse-artex encrypted browser state key check v1"
_EPOCH_CHECK = b"reverse-artex browser epoch/1\n"
_MAX_OPERATIONS = 128
_ZERO = "0" * 64


def _key_id(key):
    if type(key) is not bytes or len(key) != 32:
        raise ValueError("external 32-byte browser state key required")
    return hashlib.sha256(b"reverse-artex browser master id/1\0" + key).hexdigest()


def _keyring(key, additional_keys):
    if type(additional_keys) not in (tuple, list) or len(additional_keys) > 3:
        raise ValueError("at most four distinct browser state keys allowed")
    keys = (key, *additional_keys)
    ids = tuple(_key_id(k) for k in keys)
    if len(set(ids)) != len(ids):
        raise ValueError("distinct browser state keys required")
    return keys


def _epoch(context, capacity, salt):
    return hashlib.sha256(_raw([PROFILE, context, capacity, salt.hex()])).hexdigest()


def _journal(db):
    exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ra_browser_state_operations'").fetchone()
    if not exists:
        return []
    rows = db.execute("SELECT generation,operation_id,CASE WHEN length(document)<=4096 THEN document END,record_hash,mac "
                      "FROM ra_browser_state_operations ORDER BY generation LIMIT ?", (_MAX_OPERATIONS + 1,)).fetchall()
    if len(rows) > _MAX_OPERATIONS:
        raise ValueError("browser state operation history limit")
    history, previous, last_epoch = [], _ZERO, None
    for number, operation_id, document, record_hash, mac in rows:
        if type(number) is not int or number != len(history) + 1 or not isinstance(document, str):
            raise ValueError("invalid browser state operation history")
        value = _object(document, 4096)
        if set(value) != {"generation", "previous_hash", "operation_id", "request_hash", "from_epoch", "to_epoch", "source_key_id", "target_key_id", "result"}:
            raise ValueError("invalid browser state operation history")
        if value["generation"] != number or type(value["generation"]) is not int or value["operation_id"] != operation_id or not isinstance(operation_id, str) or not _ID.fullmatch(operation_id):
            raise ValueError("invalid browser state operation history")
        if any(not isinstance(value[k], str) or not _DIGEST.fullmatch(value[k]) for k in ("previous_hash", "request_hash", "from_epoch", "to_epoch", "source_key_id", "target_key_id")):
            raise ValueError("invalid browser state operation history")
        calculated = hashlib.sha256(_raw(value)).hexdigest()
        if value["previous_hash"] != previous or (last_epoch is not None and value["from_epoch"] != last_epoch) or not isinstance(record_hash, str) or not hmac.compare_digest(calculated, record_hash) or not isinstance(mac, str) or not _DIGEST.fullmatch(mac):
            raise ValueError("invalid browser state operation history")
        if not isinstance(value["result"], dict) or _raw(value).decode("ascii") != document:
            raise ValueError("invalid browser state operation history")
        history.append(dict(value, record_hash=record_hash, mac=mac))
        previous, last_epoch = record_hash, value["to_epoch"]
    return history


def _journal_mac(index_key, record_hash):
    return hmac.new(index_key, _raw(["browser-state-epoch/1", record_hash]), hashlib.sha256).hexdigest()



def _raw(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def _context(identity_digest, public_origin, capacity):
    if not isinstance(identity_digest, str) or not _DIGEST.fullmatch(identity_digest):
        raise ValueError("pinned browser identity digest required")
    origin(public_origin)
    if type(capacity) is not int or not 1 <= capacity <= 4096:
        raise ValueError("bounded browser capacity required")
    return hashlib.sha256(_raw([PROFILE, identity_digest, public_origin, capacity])).hexdigest()


def _derive(master, salt):
    if type(master) is not bytes or len(master) != 32:
        raise ValueError("external 32-byte browser state key required")
    material = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=PROFILE.encode("ascii")).derive(master)
    return AESGCM(material[:32]), material[32:]


def _ms(value):
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value < 1e12:
        raise ValueError("invalid browser record expiry")
    return math.ceil(value * 1000)


class _UnitOfWork:
    def __init__(self, state):
        self.state = state
        self.local = threading.local()
        self.mutex = threading.RLock()

    def __enter__(self):
        self.mutex.acquire()
        depth = getattr(self.local, "depth", 0)
        if depth:
            self.local.depth += 1
            return self
        manager = self.state.application._write()
        try:
            db = manager.__enter__()
            self.local.db, self.local.manager = db, manager
            self.local.depth, self.local.failed = 1, False
            self.state._check_meta(db)
            return self
        except BaseException as error:
            try:
                if getattr(self.local, "depth", 0):
                    manager.__exit__(type(error), error, error.__traceback__)
            finally:
                self.local.depth = 0
                self.local.db = None
                self.local.manager = None
                self.mutex.release()
            raise

    def __exit__(self, kind, value, traceback):
        if kind is not None:
            self.local.failed = True
        self.local.depth -= 1
        try:
            if self.local.depth == 0:
                manager = self.local.manager
                if self.local.failed and kind is None:
                    error = Unavailable()
                    manager.__exit__(Unavailable, error, None)
                    raise error
                return manager.__exit__(kind, value, traceback)
        finally:
            if self.local.depth == 0:
                self.local.db = None
                self.local.manager = None
            self.mutex.release()
        return False

    def connection(self):
        if not getattr(self.local, "depth", 0):
            raise Unavailable()
        return self.local.db


class _Lifecycle:
    def __init__(self, state):
        self.state = state

    def create(self, digest, principal, tenant, expires):
        _create_session(self.state.lock.connection(), digest, principal, tenant, expires, self.state.clock())

    def active(self, digest, principal, tenant, now):
        return _active_session(self.state.lock.connection(), digest, principal, tenant, now)

    def revoke(self, digests):
        _revoke_sessions(self.state.lock.connection(), digests)


class _Records(MutableMapping):
    def __init__(self, state, kind):
        self.state, self.kind = state, kind

    def __getitem__(self, key):
        return self.state._get(self.kind, key)

    def __setitem__(self, key, value):
        self.state._set(self.kind, key, value)

    def __delitem__(self, key):
        digest = self.state._index(self.kind, key)
        result = self.state.lock.connection().execute("DELETE FROM ra_browser_records WHERE kind=? AND record_key=?", (self.kind, digest))
        if not result.rowcount:
            raise KeyError(key)

    def __len__(self):
        return self.state.lock.connection().execute("SELECT count(*) FROM ra_browser_records WHERE kind=?", (self.kind,)).fetchone()[0]

    def items(self):
        db = self.state.lock.connection()
        # Counts are constrained at writes, and checked before bulk decoding.
        if len(self) > self.state._limit(self.kind):
            raise Unavailable()
        rows = db.execute("SELECT record_key,expires_ms,digest,nonce,CASE WHEN length(cipher)<=? THEN cipher END "
                          "FROM ra_browser_records WHERE kind=?", (_MAX_PLAIN + 16, self.kind)).fetchall()
        return tuple(self.state._open(self.kind, *row) for row in rows)

    def __iter__(self):
        return iter(key for key, _ in self.items())


class SQLiteBrowserState:
    """Explicit auxiliary schema; opening never creates or migrates tables.

    Use initialize() once on a deliberately selected native app DB, then reopen
    with the same identity pin, public origin and capacity. Up to four preloaded
    keys allow authenticated atomic key epochs to be adopted between requests.
    Opening never transitions an epoch; use the explicit administrative API.
    BrowserSSO binds one state instance to one controller; workers open their own.
    """
    def __init__(self, application, key, *, identity_digest, public_origin, capacity=1024,
                 additional_keys=(), minimum_generation=0):
        self._setup(application, key, identity_digest, public_origin, capacity, additional_keys, minimum_generation)
        try:
            with application._read() as db:
                self._adopt(db, self._metadata(db))
        except (sqlite3.Error, ValueError, TypeError, InvalidTag, KeyError):
            raise ValueError("browser state configuration or key rejected") from None

    def _setup(self, application, key, identity_digest, public_origin, capacity, additional_keys=(), minimum_generation=0):
        if type(application) is not SQLiteApplicationStore:
            raise ValueError("native SQLite application lifecycle required")
        if type(minimum_generation) is not int or not 0 <= minimum_generation <= _MAX_OPERATIONS:
            raise ValueError("bounded minimum browser state generation required")
        self.keys = _keyring(key, additional_keys)
        self.application, self.capacity = application, capacity
        self.identity_digest, self.public_origin = identity_digest, public_origin
        self.context = _context(identity_digest, public_origin, capacity)
        self.minimum_generation, self.generation, self.epoch = minimum_generation, -1, None
        self.bound, self.clock = False, application._clock
        self.lock = _UnitOfWork(self)
        self.lifecycle = _Lifecycle(self)
        self.maps = {kind: _Records(self, kind) for kind in _KINDS}

    @classmethod
    def _in_transaction(cls, application, key, db, **options):
        state = cls.__new__(cls)
        state._setup(application, key, options['identity_digest'], options['public_origin'], options['capacity'],
                     options.get('additional_keys', ()), options.get('minimum_generation', 0))
        state._adopt(db, state._metadata(db))
        return state

    def ready(self):
        """Authenticate the epoch and probe required columns without pruning."""
        with self.lock:
            db = self.lock.connection()
            db.execute("SELECT digest,principal,tenant,expires FROM sessions LIMIT 0")
            db.execute("SELECT kind,record_key,expires_ms,digest,nonce,cipher FROM ra_browser_records LIMIT 0")
        return True

    def describe(self):
        """Authenticated public epoch/CAS receipt; never returns keys or records."""
        with self.lock:
            db = self.lock.connection()
            return dict(profile=PROFILE, epoch=self.epoch, generation=self.generation,
                        key_id=self.key_id, context=self.context, capacity=self.capacity,
                        counts={kind: len(self.maps[kind]) for kind in _KINDS})

    @classmethod
    def initialize(cls, application, key, *, identity_digest, public_origin, capacity=1024):
        if type(application) is not SQLiteApplicationStore:
            raise ValueError("native SQLite application lifecycle required")
        context = _context(identity_digest, public_origin, capacity)
        salt = secrets.token_bytes(32)
        crypto, _ = _derive(key, salt)
        nonce = secrets.token_bytes(12)
        check = nonce + crypto.encrypt(nonce, _CHECK, _raw([PROFILE, context, "meta", salt.hex()]))
        with application._write() as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE name IN ('ra_browser_state_meta','ra_browser_records','ra_browser_state_operations')").fetchone():
                raise ValueError("browser state already initialized; opening does not reinitialize it")
            db.execute("CREATE TABLE ra_browser_state_meta (id INTEGER PRIMARY KEY CHECK(id=1),profile TEXT NOT NULL,context TEXT NOT NULL,"
                       "capacity INTEGER NOT NULL,salt BLOB NOT NULL CHECK(length(salt)=32),key_check BLOB NOT NULL CHECK(length(key_check)<=1024),"
                       "encryptions INTEGER NOT NULL CHECK(encryptions BETWEEN 1 AND 1000000000))")
            db.execute("INSERT INTO ra_browser_state_meta VALUES(1,?,?,?,?,?,1)", (PROFILE, context, capacity, salt, check))
            db.execute("CREATE TABLE ra_browser_records (kind TEXT NOT NULL CHECK(kind IN ('session','transaction','revocation','seen')),"
                       "record_key TEXT NOT NULL CHECK(length(record_key)=64),expires_ms INTEGER NOT NULL,digest TEXT NOT NULL,"
                       "nonce BLOB NOT NULL UNIQUE CHECK(length(nonce)=12),cipher BLOB NOT NULL CHECK(length(cipher)<=32784),PRIMARY KEY(kind,record_key))")
            db.execute("CREATE INDEX ra_browser_expiry ON ra_browser_records(expires_ms)")
        return cls(application, key, identity_digest=identity_digest, public_origin=public_origin, capacity=capacity)

    def _metadata(self, db):
        rows = db.execute("SELECT profile,context,capacity,salt,CASE WHEN length(key_check)<=1024 THEN key_check END,encryptions "
                          "FROM ra_browser_state_meta LIMIT 2").fetchall()
        if len(rows) != 1:
            raise ValueError("invalid browser state metadata")
        row = rows[0]
        if row[0] != PROFILE or row[1] != self.context or type(row[2]) is not int or row[2] != self.capacity or type(row[3]) is not bytes or len(row[3]) != 32 or type(row[4]) is not bytes or not 28 <= len(row[4]) <= 1024 or type(row[5]) is not int or not 1 <= row[5] <= _MAX_ENCRYPTIONS:
            raise ValueError("invalid browser state metadata")
        return row

    def _adopt(self, db, meta):
        history = _journal(db)
        epoch = _epoch(self.context, self.capacity, meta[3])
        for key in self.keys:
            crypto, index_key = _derive(key, meta[3])
            try:
                plain = crypto.decrypt(meta[4][:12], meta[4][12:], _raw([PROFILE, self.context, "meta", meta[3].hex()]))
            except InvalidTag:
                continue
            key_id = _key_id(key)
            if hmac.compare_digest(plain, _CHECK):
                if history:
                    raise ValueError("browser state history missing from key check")
                generation = 0
            elif plain.startswith(_EPOCH_CHECK):
                check = _object(plain[len(_EPOCH_CHECK):], 512)
                if set(check) != {"generation", "operation_hash", "key_id"} or not history:
                    raise ValueError("invalid browser state epoch check")
                last = history[-1]
                generation = last['generation']
                if type(check['generation']) is not int or check['generation'] != generation or check['operation_hash'] != last['record_hash'] or check['key_id'] != key_id or last['target_key_id'] != key_id or last['to_epoch'] != epoch or not hmac.compare_digest(last['mac'], _journal_mac(index_key, last['record_hash'])):
                    raise ValueError("invalid browser state authenticated history")
            else:
                raise ValueError("invalid browser state key check")
            if generation < max(self.minimum_generation, self.generation) or (generation == self.generation and self.epoch != epoch):
                raise ValueError("browser state epoch rollback rejected")
            self.salt, self.check_cipher = meta[3], meta[4]
            self.crypto, self.index_key, self.key_id = crypto, index_key, key_id
            self.check_nonce = meta[4][:12]
            self.epoch, self.generation, self.history = epoch, generation, history
            return
        raise ValueError("browser state key rejected")

    def _check_meta(self, db):
        try:
            self._adopt(db, self._metadata(db))
        except (ValueError, TypeError, KeyError, InvalidTag, UnicodeError, RecursionError):
            raise Unavailable() from None

    def bind(self, controller, lifecycle):
        if self.bound or type(lifecycle) is not SQLiteApplicationStore or lifecycle._write_uri != self.application._write_uri:
            raise ValueError("browser state requires the same native SQLite lifecycle")
        if _context(controller.tokens.access.digest, controller.public_origin, controller.capacity) != self.context:
            raise ValueError("browser state trust context mismatch")
        self.bound, self.clock = True, controller.clock

    def _limit(self, kind):
        return self.capacity * (2 if kind in ("revocation", "seen") else 1)

    def _index(self, kind, key):
        if kind == "revocation":
            if type(key) is not tuple or len(key) != 2 or key == (None, None) or any(v is not None and (not isinstance(v, str) or not _TOKEN_ID.fullmatch(v)) for v in key):
                raise KeyError(key)
        elif not isinstance(key, str) or not (re_key(key) if kind in ("session", "transaction") else _TOKEN_ID.fullmatch(key)):
            raise KeyError(key)
        return hmac.new(self.index_key, _raw([kind, key]), hashlib.sha256).hexdigest()

    def _value(self, kind, value):
        if type(value) is not dict:
            raise ValueError("invalid browser record")
        expiry = value.get("exp" if kind == "session" else "expires")
        expiry_ms = _ms(expiry)
        if kind == "session":
            if set(value) != {"principal", "tenant", "jti", "iat", "exp", "sub", "sid", "access", "identity", "csrf", "digest"}:
                raise ValueError("invalid browser session record")
            if any(not isinstance(value[k], str) or not _ID.fullmatch(value[k]) for k in ("principal", "tenant")) or not isinstance(value["sub"], str) or not _OPAQUE.fullmatch(value["sub"]):
                raise ValueError("invalid browser session scope")
            if any(not isinstance(value[k], str) or not _TOKEN_ID.fullmatch(value[k]) for k in ("jti", "sid")) or not re_key(value["csrf"]) or not isinstance(value["digest"], str) or not _DIGEST.fullmatch(value["digest"]):
                raise ValueError("invalid browser session binding")
            if any(not isinstance(value[k], str) or not 1 <= len(value[k]) <= 8192 or not value[k].isascii() for k in ("access", "identity")):
                raise ValueError("invalid browser session tokens")
            if type(value["iat"]) is not int or type(value["exp"]) is not int or not 0 < value["iat"] < value["exp"] <= value["iat"] + 600:
                raise ValueError("invalid browser session lifetime")
            if hashlib.sha256(value["access"].encode("ascii")).hexdigest() != value["digest"]:
                raise ValueError("invalid browser credential digest")
        elif kind == "transaction":
            if set(value) != {"kind", "binding", "expires", "created", "nonce", "verifier"} or value["kind"] not in ("login", "logout") or any(not re_key(value[k]) for k in ("binding", "nonce", "verifier")) or type(value["created"]) is not int or not 0 < expiry - value["created"] <= 301:
                raise ValueError("invalid browser transaction record")
        elif kind == "revocation":
            if set(value) != {"iat", "expires"} or type(value["iat"]) is not int or value["iat"] <= 0:
                raise ValueError("invalid browser revocation record")
        elif kind == "seen" and set(value) != {"expires"}:
            raise ValueError("invalid browser replay record")
        return expiry_ms, value["digest"] if kind == "session" else ""

    def _aad(self, kind, index, expires, digest):
        return _raw([PROFILE, self.context, self.salt.hex(), kind, index, expires, digest])

    def _open(self, kind, index, expires, digest, nonce, cipher):
        try:
            if type(nonce) is not bytes or len(nonce) != 12 or type(cipher) is not bytes or not 16 <= len(cipher) <= _MAX_PLAIN + 16:
                raise ValueError()
            envelope = _object(self.crypto.decrypt(nonce, cipher, self._aad(kind, index, expires, digest)), _MAX_PLAIN)
            if set(envelope) != {"key", "value"}:
                raise ValueError()
            key = tuple(envelope["key"]) if kind == "revocation" else envelope["key"]
            if not hmac.compare_digest(self._index(kind, key), index) or self._value(kind, envelope["value"]) != (expires, digest):
                raise ValueError()
            return key, envelope["value"]
        except (ValueError, TypeError, KeyError, InvalidTag, UnicodeError, RecursionError):
            raise Unavailable() from None

    def _get(self, kind, key):
        index = self._index(kind, key)
        row = self.lock.connection().execute("SELECT expires_ms,digest,nonce,CASE WHEN length(cipher)<=? THEN cipher END "
                                             "FROM ra_browser_records WHERE kind=? AND record_key=?", (_MAX_PLAIN + 16, kind, index)).fetchone()
        if row is None:
            raise KeyError(key)
        return self._open(kind, index, *row)[1]

    def _set(self, kind, key, value):
        self._store(self.lock.connection(), kind, key, value)

    def _store(self, db, kind, key, value):
        try:
            index = self._index(kind, key)
            expires, digest = self._value(kind, value)
            raw = _raw({"key": key, "value": value})
            if len(raw) > _MAX_PLAIN:
                raise ValueError()
        except (ValueError, TypeError, KeyError, RecursionError):
            raise Unavailable() from None
        exists = db.execute("SELECT 1 FROM ra_browser_records WHERE kind=? AND record_key=?", (kind, index)).fetchone()
        count = db.execute("SELECT count(*) FROM ra_browser_records WHERE kind=?", (kind,)).fetchone()[0]
        if not exists and count >= self._limit(kind):
            raise Unavailable()
        nonce = None
        for _ in range(8):
            candidate = secrets.token_bytes(12)
            if candidate != self.check_nonce and not db.execute("SELECT 1 FROM ra_browser_records WHERE nonce=?", (candidate,)).fetchone():
                nonce = candidate
                break
        if nonce is None:
            raise Unavailable()
        if db.execute("UPDATE ra_browser_state_meta SET encryptions=encryptions+1 WHERE id=1 AND encryptions<?", (_MAX_ENCRYPTIONS,)).rowcount != 1:
            raise Unavailable()
        cipher = self.crypto.encrypt(nonce, raw, self._aad(kind, index, expires, digest))
        db.execute("INSERT INTO ra_browser_records VALUES(?,?,?,?,?,?) ON CONFLICT(kind,record_key) DO UPDATE SET "
                   "expires_ms=excluded.expires_ms,digest=excluded.digest,nonce=excluded.nonce,cipher=excluded.cipher",
                   (kind, index, expires, digest, nonce, cipher))

    def prune(self, now):
        db = self.lock.connection()
        cutoff = math.floor(now * 1000)
        # Only expired records are decoded; normal reads do not scan tokens.
        rows = db.execute("SELECT record_key,expires_ms,digest,nonce,CASE WHEN length(cipher)<=? THEN cipher END "
                          "FROM ra_browser_records WHERE kind='session' AND expires_ms<=? LIMIT ?",
                          (_MAX_PLAIN + 16, cutoff, self.capacity + 1)).fetchall()
        if len(rows) > self.capacity:
            raise Unavailable()
        digests = [self._open("session", *row)[1]["digest"] for row in rows]
        _revoke_sessions(db, digests)
        db.execute("DELETE FROM ra_browser_records WHERE expires_ms<=?", (cutoff,))

    def blocked(self, claims):
        for key in ((claims["sub"], claims["sid"]), (claims["sub"], None), (None, claims["sid"])):
            marker = self.maps["revocation"].get(key)
            if marker is not None and (key[1] is not None or claims["iat"] <= marker["iat"]):
                return True
        return False


def re_key(value):
    return isinstance(value, str) and len(value) == 43 and _OPAQUE.fullmatch(value) is not None

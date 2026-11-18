"""Read-only adapter for the existing lab sessions/objects SQLite schema.

No schema migration, token issuance, session cache or arbitrary SQL callback.
Use only for this schema; production apps provide their own trusted resolver.
"""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import time

from reverse_artex_guard import ApplicationSnapshot, ObjectSnapshot


def revision(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, separators=(",", ":"),
                                     allow_nan=False).encode("ascii")).hexdigest()


class SQLiteSessionResolver:
    def __init__(self, database, *, clock=time.time):
        self._uri = Path(database).resolve().as_uri() + "?mode=ro"
        self._clock = clock

    def __call__(self, object_id, identity):
        # BEGIN pins session and object to the same committed snapshot. Every
        # request opens a new read-only connection; missing DBs are not created.
        with closing(sqlite3.connect(self._uri, uri=True, timeout=.1)) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            row = db.execute("SELECT principal,tenant FROM sessions WHERE digest=? AND expires>?",
                             (identity.credential_sha256, self._clock())).fetchone()
            if row != (identity.principal, identity.tenant):
                return ApplicationSnapshot(False)
            # Preserve the app's integer IDs without creating path aliases.
            if not object_id.isascii() or not object_id.isdecimal() or len(object_id) > 18 or str(int(object_id)) != object_id:
                return ApplicationSnapshot(True)
            obj = db.execute("SELECT owner,tenant,value FROM objects WHERE id=?", (int(object_id),)).fetchone()
            if obj is None:
                return ApplicationSnapshot(True)
            owner, tenant, value = obj
            return ApplicationSnapshot(True, ObjectSnapshot(
                object_id, tenant, owner, (), revision([tenant, owner]),
                revision(value), {"value": value}))

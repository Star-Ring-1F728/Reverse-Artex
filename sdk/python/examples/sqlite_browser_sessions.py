"""Explicit session lifecycle adapter for the example lab SQLite schema.

Existing objects and ACLs are untouched. Only digests of verified access tokens
are written; the BrowserSSO process owns token/cookie material in memory.
"""
from contextlib import closing
from pathlib import Path
import sqlite3


class SQLiteBrowserSessions:
    def __init__(self, database):
        path = Path(database).resolve().as_uri()
        self.uri, self.read_uri = path + "?mode=rw", path + "?mode=ro"

    def ready(self):
        with closing(sqlite3.connect(self.read_uri, uri=True, timeout=.1, isolation_level=None)) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("SELECT digest,principal,tenant,expires FROM sessions LIMIT 0")
        return True

    def create(self, digest, principal, tenant, expires):
        with closing(sqlite3.connect(self.uri, uri=True, timeout=.1)) as db, db:
            db.execute("INSERT INTO sessions(digest,principal,tenant,expires) VALUES(?,?,?,?)", (digest, principal, tenant, expires))

    def active(self, digest, principal, tenant, now):
        with closing(sqlite3.connect(self.uri, uri=True, timeout=.1)) as db:
            row = db.execute("SELECT principal,tenant FROM sessions WHERE digest=? AND expires>?", (digest, now)).fetchone()
            return row == (principal, tenant)

    def revoke(self, digests):
        with closing(sqlite3.connect(self.uri, uri=True, timeout=.1)) as db, db:
            db.executemany("DELETE FROM sessions WHERE digest=?", ((d,) for d in digests))

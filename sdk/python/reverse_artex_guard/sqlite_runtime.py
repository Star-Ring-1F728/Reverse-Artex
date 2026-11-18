"""Known-safe SQLite WAL runtime gate for the native application profile.

SQLite documents a WAL-reset corruption race through 3.51.2, with named
backports. Refuse unpatched engines instead of treating functional tests as
proof of safety. No runtime override or global DLL replacement is performed.
"""
import sqlite3


def require_wal_runtime():
    version = sqlite3.sqlite_version_info
    fixed = (version >= (3, 51, 3) or
             version[:2] == (3, 50) and version >= (3, 50, 7) or
             version[:2] == (3, 44) and version >= (3, 44, 6))
    if not fixed:
        raise ValueError("native WAL profile requires SQLite 3.51.3+ or fixed backport 3.50.7/3.44.6")

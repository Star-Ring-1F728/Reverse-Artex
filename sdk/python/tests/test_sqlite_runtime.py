from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reverse_artex_guard.sqlite_runtime import require_wal_runtime
from reverse_artex_guard.sqlite_application import SQLiteApplicationStore


class SQLiteRuntimeTests(unittest.TestCase):
    def test_known_fixed_and_unfixed_branches(self):
        for version in ((3, 44, 6), (3, 50, 7), (3, 51, 3), (3, 52, 0), (4, 0, 0)):
            with self.subTest(version=version), patch('reverse_artex_guard.sqlite_runtime.sqlite3.sqlite_version_info', version):
                require_wal_runtime()
        for version in ((3, 7, 0), (3, 44, 5), (3, 45, 4), (3, 50, 4), (3, 50, 6), (3, 51, 2)):
            with self.subTest(version=version), patch('reverse_artex_guard.sqlite_runtime.sqlite3.sqlite_version_info', version):
                with self.assertRaises(ValueError): require_wal_runtime()

    def test_unpatched_runtime_never_creates_or_opens_native_profile(self):
        with tempfile.TemporaryDirectory(prefix='ra-sqlite-runtime-') as directory:
            path = Path(directory) / 'not-created.db'
            with patch('reverse_artex_guard.sqlite_runtime.sqlite3.sqlite_version_info', (3, 50, 4)):
                with self.assertRaises(ValueError): SQLiteApplicationStore.initialize(path)
                with self.assertRaises(ValueError): SQLiteApplicationStore(path)
            self.assertFalse(path.exists())


if __name__ == '__main__':
    unittest.main()

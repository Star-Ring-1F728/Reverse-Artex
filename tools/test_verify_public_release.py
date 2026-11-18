"""Negative integrity checks for public-release verification before execution."""
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import signal
import subprocess
from pathlib import Path
import tempfile
import stat
import threading
from types import SimpleNamespace
from unittest import mock
import unittest

from verify_public_release import MAX_MANIFEST_BYTES, request, stop_process, verify_manifest


class ManifestIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.payload = self.root / 'VERSION'
        self.payload.write_bytes(b'0.1.0-beta.1\n')
        self.row = {'path': 'VERSION', 'size': self.payload.stat().st_size,
                    'sha256': hashlib.sha256(self.payload.read_bytes()).hexdigest(), 'mode': '0644'}
        self.manifest = {'schema_version': 1, 'version': '0.1.0-beta.1',
                         'target': 'windows-amd64', 'files': [self.row]}
        self.save()

    def save(self):
        (self.root / 'manifest.json').write_text(json.dumps(self.manifest), encoding='utf-8')

    def test_intact_payload(self):
        self.assertEqual(verify_manifest(self.root)['version'], '0.1.0-beta.1')

    def test_equal_size_tamper(self):
        self.payload.write_bytes(b'9.9.9-beta.1\n')
        with self.assertRaisesRegex(ValueError, 'integrity mismatch'):
            verify_manifest(self.root)

    def test_absent_payload(self):
        self.payload.rename(self.root / 'missing-version')
        with self.assertRaisesRegex(ValueError, 'missing'):
            verify_manifest(self.root)

    def test_unlisted_executable(self):
        (self.root / 'extra.exe').write_bytes(b'untrusted')
        with self.assertRaisesRegex(ValueError, 'unlisted'):
            verify_manifest(self.root)

    def test_parent_and_windows_path_rejected(self):
        for path in ('../VERSION', '/VERSION', 'C:/VERSION', 'folder\\VERSION', './VERSION', '.', 'folder//VERSION',
                     'VERSION.', 'VERSION ', 'NUL.txt', 'folder/COM1', 'bad\x00name'):
            with self.subTest(path=path):
                self.row['path'] = path
                self.save()
                with self.assertRaisesRegex(ValueError, 'unsafe'):
                    verify_manifest(self.root)

    def test_case_colliding_manifest_rejected(self):
        self.manifest['files'].append({**self.row, 'path': 'version'})
        self.save()
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            verify_manifest(self.root)

    def test_actual_case_collision_rejected(self):
        other = self.root / 'version'
        other.write_bytes(self.payload.read_bytes())
        if other.samefile(self.payload):
            self.skipTest('filesystem is case-insensitive')
        with self.assertRaisesRegex(ValueError, 'case-colliding'):
            verify_manifest(self.root)

    def test_manifest_cannot_list_itself(self):
        self.row['path'] = 'manifest.json'
        self.save()
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            verify_manifest(self.root)

    def test_invalid_record_metadata_rejected(self):
        for field, value in (('size', True), ('size', -1), ('size', '12'),
                             ('sha256', 'f' * 63), ('sha256', 'F' * 64),
                             ('sha256', None), ('mode', '0777'), ('mode', 644)):
            with self.subTest(field=field, value=value):
                original = self.row[field]
                self.row[field] = value
                self.save()
                with self.assertRaisesRegex(ValueError, 'metadata'):
                    verify_manifest(self.root)
                self.row[field] = original

    def test_invalid_manifest_structure_rejected(self):
        original = self.manifest
        for invalid in ([], {'schema_version': True}, {**original, 'target': 'darwin-arm64'},
                        {**original, 'version': '../private'}, {**original, 'files': []},
                        {**original, 'files': {}}, {**original, 'files': [None]},
                        {**original, 'files': [{**self.row, 'extra': 'ignored?'}]}):
            with self.subTest(manifest=invalid):
                self.manifest = invalid
                self.save()
                with self.assertRaises(ValueError):
                    verify_manifest(self.root)
        self.manifest = original

    def test_duplicate_json_keys_rejected(self):
        path = self.root / 'manifest.json'
        path.write_text('{"schema_version": 1, "schema_version": 1}', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            verify_manifest(self.root)

    def test_oversized_manifest_rejected_before_parsing(self):
        with (self.root / 'manifest.json').open('wb') as stream:
            stream.truncate(MAX_MANIFEST_BYTES + 1)
        with self.assertRaisesRegex(ValueError, 'too large'):
            verify_manifest(self.root)

    def test_reparse_manifest_and_payload_directories_rejected(self):
        original_lstat = Path.lstat
        for relative in ('manifest.json', 'nested'):
            with self.subTest(relative=relative):
                nested = self.root / 'nested'
                nested.mkdir(exist_ok=True)
                def attributes(path, *args, **kwargs):
                    current = original_lstat(path, *args, **kwargs)
                    if path == self.root / relative:
                        return SimpleNamespace(st_mode=current.st_mode, st_size=current.st_size,
                                               st_file_attributes=1024)
                    return current
                with mock.patch.object(Path, 'lstat', attributes):
                    with self.assertRaisesRegex(ValueError, 'linked'):
                        verify_manifest(self.root)

    def test_linked_manifest_rejected(self):
        manifest = self.root / 'manifest.json'
        original = self.root / 'original-manifest'
        manifest.rename(original)
        try:
            manifest.symlink_to(original)
        except OSError:
            self.skipTest('symlink creation is unavailable for this Windows token')
        with self.assertRaisesRegex(ValueError, 'linked'):
            verify_manifest(self.root)

    def test_linked_payload_rejected(self):
        original = self.root / 'original'
        self.payload.rename(original)
        try:
            self.payload.symlink_to(original)
        except OSError:
            self.skipTest('symlink creation is unavailable for this Windows token')
        with self.assertRaisesRegex(ValueError, 'linked'):
            verify_manifest(self.root)


class SmokeRequestTests(unittest.TestCase):
    def test_redirect_keeps_authorization_on_original_endpoint(self):
        observed = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                observed.append((self.path, self.headers.get('Authorization')))
                self.send_response(302 if self.path == '/console/api/status' else 200)
                if self.path == '/console/api/status':
                    self.send_header('Location', '/redirected')
                self.end_headers()

            def log_message(self, *args):
                pass

        with HTTPServer(('127.0.0.1', 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                status, _ = request(f'http://127.0.0.1:{server.server_port}', '/console/api/status', 'fixture-key')
            finally:
                server.shutdown()
                thread.join()
        self.assertEqual(status, 302)
        self.assertEqual(observed, [('/console/api/status', 'Bearer fixture-key')])


class ShutdownReportingTests(unittest.TestCase):
    @mock.patch('verify_public_release.os.name', 'posix')
    def test_forced_kill_is_recorded(self):
        process = mock.Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired('fixture', 10), -9]
        self.assertEqual(stop_process(process), 'forced-kill')
        process.send_signal.assert_called_once_with(signal.SIGTERM)
        process.kill.assert_called_once_with()

    def test_already_exited_process_is_never_signalled(self):
        process = mock.Mock()
        process.poll.return_value = 0
        self.assertEqual(stop_process(process), 'already-exited')
        process.send_signal.assert_not_called()
        process.terminate.assert_not_called()


if __name__ == '__main__':
    unittest.main()

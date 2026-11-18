"""Checks freshness and provenance failures without running a binary or network request."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_release_readiness as checker


class ReleaseReadinessTests(unittest.TestCase):
    def setUp(self):
        # Retain tiny synthetic fixtures; no project files are removed.
        self.root = Path(tempfile.mkdtemp(prefix='reverse-artex-readiness-test-'))
        self.source, self.release = self.root/'source', self.root/'release'
        self.source.mkdir(); self.release.mkdir()
        (self.source/'VERSION').write_bytes(b'0.1.0-beta.1\n')
        (self.source/'README.md').write_bytes(b'Current instructions\n')
        self.records = [{'path': p.name, 'size': p.stat().st_size,
                         'sha256': checker.digest(p), 'mode': '0644'}
                        for p in sorted(self.source.iterdir())]
        self.source_info = {'revision': 'test', 'dirty': True, 'inputs': self.records}
        self.archive = self.release/'reverse-artex-0.1.0-beta.1-windows-amd64.zip'
        self.archive.write_bytes(b'synthetic archive; payload execution is tested elsewhere')
        self.build = {'schema_version': 1, 'version': '0.1.0-beta.1',
                      'source': self.source_info, 'archives': [{'path': self.archive.name,
                      'target': 'windows-amd64', 'size': self.archive.stat().st_size,
                      'sha256': checker.digest(self.archive)}]}
        self.save_metadata()
        self.selected = patch.object(checker, 'current_input_names',
                                     side_effect=lambda root: {p.name for p in root.iterdir() if p.is_file()})
        self.selected.start()
        self.addCleanup(self.selected.stop)

    def save_metadata(self):
        self.source_info['sha256'] = hashlib.sha256(json.dumps(
            self.records,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        (self.release/'source-inputs.json').write_text(json.dumps(self.source_info),encoding='utf-8')
        (self.release/'build-manifest.json').write_text(json.dumps(self.build),encoding='utf-8')
        self.save_checksums()

    def save_checksums(self):
        names=sorted([self.archive.name,'build-manifest.json','source-inputs.json'])
        (self.release/'SHA256SUMS').write_text(''.join(
            checker.digest(self.release/name)+'  '+name+'\n' for name in names),encoding='ascii')

    def audit(self):
        return checker.audit_release(self.source,self.release)

    def test_intact_release(self):
        self.assertTrue(self.audit()['passed'])

    def test_changed_readme_rejected_as_stale(self):
        (self.source/'README.md').write_bytes(b'Updated instructions\n')
        report=self.audit()
        self.assertFalse(report['passed'])
        self.assertIn({'path':'README.md','reason':'changed'},report['current_tree_drift'])

    def test_new_input_rejected_as_stale(self):
        (self.source/'new-source.go').write_bytes(b'package main\n')
        report=self.audit()
        self.assertFalse(report['passed'])
        self.assertIn({'path':'new-source.go','reason':'new-release-input'},report['current_tree_drift'])

    def test_missing_input_rejected_as_stale(self):
        (self.source/'README.md').rename(self.root/'preserved-old-readme')
        self.assertFalse(self.audit()['passed'])

    def test_archive_tampering_rejected(self):
        self.archive.write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError,'archive does not match'):
            self.audit()

    def test_recomputed_checksums_cannot_hide_wrong_archive_binding(self):
        self.archive.write_bytes(b'tampered')
        self.save_checksums()
        with self.assertRaisesRegex(ValueError,'archive does not match'):
            self.audit()

    def test_source_inventory_fingerprint_rejected(self):
        self.source_info['sha256']='0'*64
        (self.release/'source-inputs.json').write_text(json.dumps(self.source_info),encoding='utf-8')
        (self.release/'build-manifest.json').write_text(json.dumps(self.build),encoding='utf-8')
        self.save_checksums()
        with self.assertRaisesRegex(ValueError,'fingerprint'):
            self.audit()

    def test_version_mismatch_rejected(self):
        (self.source/'VERSION').write_bytes(b'0.1.0-beta.2\n')
        with self.assertRaisesRegex(ValueError,'version'):
            self.audit()

    def test_duplicate_checksum_rejected(self):
        path=self.release/'SHA256SUMS'
        path.write_text(path.read_text()+path.read_text().splitlines()[0]+'\n',encoding='ascii')
        with self.assertRaisesRegex(ValueError,'duplicate checksum'):
            self.audit()

    def test_non_object_metadata_rejected(self):
        (self.release/'build-manifest.json').write_text('[]',encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'JSON objects'):
            self.audit()

    def test_unhashable_archive_target_rejected(self):
        self.build['archives'][0]['target']=['windows-amd64']
        self.save_metadata()
        with self.assertRaisesRegex(ValueError,'archive target'):
            self.audit()

    def test_inventory_escape_rejected(self):
        self.records[0]['path']='../outside'
        self.save_metadata()
        with self.assertRaisesRegex(ValueError,'unsafe release input path'):
            self.audit()


if __name__=='__main__':
    unittest.main()

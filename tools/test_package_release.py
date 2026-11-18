"""Release boundary tests; tiny fixtures are retained in the system temp directory."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile
import tarfile
import stat
from types import SimpleNamespace

SPEC = importlib.util.spec_from_file_location("package_release", Path(__file__).with_name("package_release.py"))
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="reverse-artex-package-test-"))
        for name in release.ROOT_FILES + release.CONFIGS:
            path = self.root / name
            path.write_text("0.1.0-beta.1\n" if name == "VERSION" else "{}\n", encoding="utf-8")
        for name in ("start.bat", "start.sh", "go.mod", "go.sum", "tools/verify_public_release.py", "tools/package_release.py",
                     "docs/examples/http-sample.jsonl",
                     "web/index.html", "web/app.js", "web/styles.css",
                     "cmd/reverse-artex/main.go", "internal/example/example.go",
                     "sdk/python/pyproject.toml", "sdk/python/reverse_artex_windows_service.py",
                     "sdk/python/reverse_artex_guard/__init__.py", "sdk/python/examples/demo.py",
                     "sensors/linux/linux_isolation.py", "sensors/linux/proc_sensor.py",
                     "db/migrations/0001.sql"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("public fixture\n", encoding="utf-8")
        for name in release.PUBLIC_ASSETS:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('<svg xmlns="http://www.w3.org/2000/svg"/>\n', encoding="utf-8")
        for name in release.REQUIRED_DOCS:
            (self.root / "docs" / name).write_text("public usage fixture\n", encoding="utf-8")
        for name in ("config.json", ".env", "config.custom.example.json", "docs/PRIVATE.md",
                     "data/key.pem", "artifacts/old/results.json", ".git/config",
                     "sdk/python/tests/key.py", "sdk/python/reverse_artex_guard/__pycache__/x.pyc",
                     "internal/example/example_test.go", "web/private.txt"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("SECRET-SENTINEL", encoding="utf-8")

    def fake_build(self, args, **kwargs):
        self.assertEqual(kwargs['env']['GOEXPERIMENT'], '')
        binary = Path(args[args.index("-o") + 1])
        binary.write_bytes(b"MZ fixture executable\n")
        return mock.Mock(returncode=0)

    def package(self, output, targets=None):
        with mock.patch.object(release, "source_identity", return_value={"revision": "test", "dirty": True}), \
             mock.patch.object(release, "run", return_value="go version fixture"), \
             mock.patch.object(release, "licenses", side_effect=lambda source, stage, env: None), \
             mock.patch.object(release.subprocess, "run", side_effect=self.fake_build), mock.patch("builtins.print"):
            return release.package(self.root, self.root / "artifacts" / output,
                                   targets or list(release.TARGETS), 0)

    def test_release_excludes_private_inputs_and_tracks_every_payload(self):
        output = self.package("release")
        manifest = json.loads((output / "build-manifest.json").read_text())
        self.assertTrue(manifest["source"]["dirty"])
        self.assertEqual(len(manifest["archives"]), 2)
        for item in manifest["archives"]:
            bundle = output / item["path"]
            self.assertEqual(release.digest(bundle), item["sha256"])
            if bundle.suffix == ".zip":
                with zipfile.ZipFile(bundle) as stream:
                    contents = {name.split("/", 1)[1]: stream.read(name) for name in stream.namelist()}
                    self.assertTrue(all(".." not in Path(name).parts for name in stream.namelist()))
            else:
                with tarfile.open(bundle) as stream:
                    contents = {member.name.split("/", 1)[1]: stream.extractfile(member).read() for member in stream}
                    executable = next(member for member in stream.getmembers() if member.name.endswith("/reverse-artex"))
                    self.assertEqual(executable.mode, 0o755)
            for asset in release.PUBLIC_ASSETS:
                self.assertIn(asset, contents)
            self.assertNotIn("config.json", contents)
            self.assertNotIn("docs/PRIVATE.md", contents)
            self.assertNotIn("config.custom.example.json", contents)
            verifier = "bin/v2-journal-check.exe" if bundle.suffix == ".zip" else "bin/v2-journal-check"
            self.assertIn(verifier, contents)
            self.assertFalse(any(b"SECRET-SENTINEL" in raw for raw in contents.values()))
            payload_manifest = json.loads(contents.pop("manifest.json"))
            self.assertEqual(set(contents), {record["path"] for record in payload_manifest["files"]})
            for record in payload_manifest["files"]:
                raw = contents[record["path"]]
                self.assertEqual(record["size"], len(raw))
                self.assertEqual(record["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(payload_manifest["source"]["sha256"], manifest["source"]["sha256"])
        sums = dict(line.split("  ", 1)[::-1] for line in (output / "SHA256SUMS").read_text().splitlines())
        for name, expected in sums.items():
            self.assertEqual(release.digest(output / name), expected)
        snapshot = output / "_build/source"
        self.assertFalse((snapshot / "internal/example/example_test.go").exists())
        self.assertFalse((snapshot / "web/private.txt").exists())

    def test_reproducible_archives(self):
        one = self.package("first")
        with mock.patch.dict(os.environ, {"GOEXPERIMENT": "nojsonv2"}):
            two = self.package("second")
        for extension in ("windows-amd64.zip", "linux-amd64.tar.gz"):
            name = f"reverse-artex-0.1.0-beta.1-{extension}"
            self.assertEqual(release.digest(one / name), release.digest(two / name))

    def test_current_uncommitted_input_changes_archive_identity(self):
        one = self.package("first", ["windows-amd64"])
        (self.root / "web/app.js").write_text("changed current tree\n")
        two = self.package("second", ["windows-amd64"])
        a = json.loads((one / "source-inputs.json").read_text())
        b = json.loads((two / "source-inputs.json").read_text())
        self.assertNotEqual(a["sha256"], b["sha256"])

    def test_packager_changes_are_part_of_source_identity(self):
        one = self.package("first", ["windows-amd64"])
        (self.root / "tools/package_release.py").write_text("changed packager\n")
        two = self.package("second", ["windows-amd64"])
        a = json.loads((one / "source-inputs.json").read_text())
        b = json.loads((two / "source-inputs.json").read_text())
        self.assertNotEqual(a["sha256"], b["sha256"])
        self.assertIn("tools/package_release.py", {row["path"] for row in b["inputs"]})
        self.assertTrue((two / "_build/source/tools/package_release.py").is_file())

    def test_excluded_source_docs_are_marked_only_in_packaged_copy(self):
        readme = self.root / "README.md"
        original = ("[Details](docs/PRIVATE.md#scope) [Included](docs/OPERATIONS.md) "
                    "[Local](artifacts/old/results.json) [Web](https://example.test/docs/x.md)\n")
        readme.write_text(original, encoding="utf-8")
        (self.root / "docs/OPERATIONS.md").write_text("[Details](PRIVATE.md)\n", encoding="utf-8")
        output = self.package("references", ["windows-amd64"])
        stage = output / "_build/windows-amd64"
        packaged = (stage / "README.md").read_text(encoding="utf-8")
        self.assertIn("Details (source checkout: `docs/PRIVATE.md#scope`)", packaged)
        self.assertIn("[Included](docs/OPERATIONS.md)", packaged)
        self.assertIn("[Local](artifacts/old/results.json)", packaged)
        self.assertIn("[Web](https://example.test/docs/x.md)", packaged)
        self.assertEqual(readme.read_text(encoding="utf-8"), original)
        self.assertEqual((output / "_build/public/README.md").read_text(encoding="utf-8"), original)
        manifest = json.loads((stage / "manifest.json").read_text())
        transformed = {row["path"]: row for row in manifest["documentation_transforms"]}
        self.assertEqual(transformed["README.md"]["source_sha256"], release.digest(readme))
        self.assertEqual(transformed["README.md"]["packaged_sha256"], release.digest(stage / "README.md"))
        self.assertEqual(transformed["docs/OPERATIONS.md"]["links"][0]["source_path"], "docs/PRIVATE.md")
        self.assertFalse((stage / "docs/PRIVATE.md").exists())

    def test_required_validation_summary_cannot_be_silently_omitted(self):
        (self.root / "docs/VALIDATION.md").rename(self.root / "preserved-validation.md")
        with self.assertRaisesRegex(ValueError, "required release input missing: docs/VALIDATION.md"):
            self.package("missing-validation")

    def test_required_readme_chart_cannot_be_silently_omitted(self):
        asset = release.PUBLIC_ASSETS[0]
        (self.root / asset).rename(self.root / "preserved-chart.svg")
        with self.assertRaisesRegex(ValueError, "required release input missing: docs/assets/"):
            self.package("missing-chart")

    def test_rejects_private_keys_in_allowed_inputs(self):
        (self.root / "config.example.json").write_text("-----BEGIN RSA PRIVATE KEY-----\n")
        with self.assertRaisesRegex(ValueError, "private key"):
            self.package("private-key")

    def test_rejects_output_overwrite_and_escape(self):
        self.package("release", ["windows-amd64"])
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.package("release")
        with self.assertRaisesRegex(ValueError, "subdirectory"):
            release.package(self.root, self.root.parent / "unsafe-release", ["windows-amd64"], 0)

    def test_rejects_traversal_and_links(self):
        for name in ("../config.json", "/etc/passwd", "C:/private", "web\\private"):
            with self.assertRaises(ValueError):
                release.safe_path(self.root, name)
        link = self.root / "linked"
        try:
            link.symlink_to(self.root / "config.json")
        except OSError:
            self.skipTest("symlink privilege unavailable")
        with self.assertRaisesRegex(ValueError, "links"):
            release.safe_path(self.root, "linked")

    def test_rejects_windows_reparse_inputs_without_symlink_privilege(self):
        record = SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=1024)
        with mock.patch.object(Path, "lstat", return_value=record):
            with self.assertRaisesRegex(ValueError, "links"):
                release.safe_path(self.root, "config.example.json")

    def test_missing_required_file_and_invalid_target(self):
        # An explicit VERSION file is required; no silent git-tag fallback.
        with self.assertRaises(ValueError):
            release.package(self.root, self.root / "artifacts" / "bad", ["darwin-arm64"], 0)
        (self.root / "VERSION").write_text("../../private")
        with self.assertRaisesRegex(ValueError, "semantic version"):
            self.package("bad-version")


if __name__ == "__main__":
    unittest.main()

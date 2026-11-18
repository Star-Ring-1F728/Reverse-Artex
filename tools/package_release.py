#!/usr/bin/env python3
"""Build allowlisted, traceable binary bundles from the CURRENT working tree."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import stat
import subprocess
import tarfile
import time
import zipfile

TOOLS = (
    "policy-control", "policy-edge", "case-api", "case-ledger", "case-snapshot",
    "case-source-check", "source-ledger", "control-audit-sync", "incident-sync",
    "incident-export", "incident-plan", "incident-retention", "defense-analyzer",
    "defense-mode", "defense-v2", "v2-journal-check", "decisions-check", "decisions-connect",
    "proposal-check", "approval-gate", "action-execute", "host-response",
    "learning-control", "learning-evaluate", "learning-context",
    "learning-context-prepare", "learning-context-quality",
    "learning-context-release", "learning-context-canary",
    "learning-context-production", "context-shadow",
)
TARGETS = ("windows-amd64", "linux-amd64")
ROOT_FILES = (
    "README.md", "README.ko.md", "LICENSE", "SECURITY.md", "SECURITY.ko.md",
    "CONTRIBUTING.md", "CONTRIBUTING.ko.md", "VERSION", "CHANGELOG.md", "THIRD_PARTY_NOTICES.md",
)
PUBLIC_ASSETS = ("docs/assets/artex-defense-summary.svg", "docs/assets/artex-defense-summary.ko.svg")
REQUIRED_DOCS = (
    "QUICKSTART.md", "QUICKSTART.ko.md", "BETA-SCOPE.md", "BETA-SCOPE.ko.md",
    "COMPATIBILITY.md", "RELEASING.md", "PUBLIC-RELEASE-CHECKLIST.md", "VALIDATION.md",
)
DOCS = (
    "QUICKSTART.md", "COMPATIBILITY.md", "RELEASING.md", "PUBLIC-RELEASE-CHECKLIST.md", "VALIDATION.md", "OPERATIONS.md", "SENSOR.md",
    "CAPABILITIES.md", "DEFENSE-LAYERS.md", "CURRENT-QUALIFICATION-20261115.md", "SHORT-REFERENCE-VALIDATION-20261115.md", "UPSTREAM-CONNECTION-REUSE-20261115.md", "CASE-MEMORY.md", "OFFLINE-LEARNING.md", "DEFENSE-VALIDATION-20261114.md", "MODEL-DEFENSE-VALIDATION-20261114.md",
    "SHADOW-LEARNING.md", "CANDIDATE-REVIEW.md", "LEARNING-LIFECYCLE.md",
    "LOCAL-QWEN.md", "PROTECTION-CONTRACT.md", "SESSION-ADAPTER.md",
    "OIDC-COVERAGE.md", "BROWSER-SSO.md", "SQLITE-NATIVE-ACL.md",
    "SHARED-BROWSER-STATE.md", "BROWSER-STATE-MIGRATION.md",
    "BROWSER-WORKER-RUNTIME.md", "WINDOWS-BROWSER-SERVICE.md",
    "ATTACK-FEEDBACK-LEARNING.md", "VERIFIED-LEARNING.md",
    "PRODUCTION-LEARNING.md", "V2-DECISIONS.md", "V2-RETAINED-JOURNAL.md",
    "V2-L3-OUTCOMES.md", "ADAPTIVE-DEFENSE-STRATEGY.ko.md", "G09-CONTEXT-V2.md", "G09-FEATURE-DIAGNOSTICS.md",
    "G09-CONTEXT-SHADOW.md", "G09-CONTEXT-LIVE.md",
    "G09-CONTEXT-QUALITY-ADMISSION.md", "G09-CONTEXT-CANARY-RELEASE.md",
    "G09-CONTEXT-CANARY-EVALUATION.md", "G09-CONTEXT-PRODUCTION.md",
)
CONFIGS = (
    "config.example.json", "config.action-context-trust.example.json",
    "config.context-canary-approvers.example.json",
    "config.context-canary-profile.example.json",
    "config.context-production-approvers.example.json",
    "config.context-production-profile.example.json",
    "config.context-quality-policy.example.json", "config.context-shadow.example.json",
    "config.decisions.example.json", "config.l3.example.json",
    "config.learning-production.example.json", "config.learning-trust.example.json",
    "config.oidc.example.json", "config.oidc.protection.example.json",
    "config.protection.example.json", "config.route-coverage.example.json", "config.v2-retention.example.json",
)
BUILD_FLAGS = ("-trimpath", "-buildvcs=false", "-mod=readonly", "-ldflags=-s -w")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
BLOCKED_PARTS = {".git", ".tools", ".workspace-copy", "__pycache__", "artifacts", "data", "lab", "tests"}
PRIVATE_KEY_RE = re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def safe_path(root: Path, relative: str) -> Path:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or not pure.parts or any(p in ("..", ".") for p in pure.parts):
        raise ValueError(f"unsafe relative path: {relative}")
    if "\\" in relative or ":" in relative:
        raise ValueError(f"unsafe relative path: {relative}")
    current = root
    for part in pure.parts:
        current = current / part
        try:
            attributes = getattr(current.lstat(), "st_file_attributes", 0)
        except FileNotFoundError:
            attributes = 0
        if current.is_symlink() or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024):
            raise ValueError(f"links are not release inputs: {relative}")
    if not current.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"path escapes root: {relative}")
    return current


def copy_input(root: Path, destination: Path, relative: str) -> None:
    source = safe_path(root, relative)
    if not source.is_file():
        raise ValueError(f"required release input missing: {relative}")
    raw = source.read_bytes()
    if PRIVATE_KEY_RE.search(raw):
        raise ValueError(f"private key found in release input: {relative}")
    target = safe_path(destination, relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)


def public_inputs(root: Path) -> list[str]:
    # No directory-wide copies: adding a private file never implicitly publishes it.
    result = list(ROOT_FILES) + list(CONFIGS) + list(PUBLIC_ASSETS)
    result += [f"docs/{name}" for name in REQUIRED_DOCS]
    result += [f"docs/{name}" for name in DOCS if (root / "docs" / name).is_file()]
    result += ["start.bat", "start.sh", "tools/verify_public_release.py", "docs/examples/http-sample.jsonl"]
    result += [
        "sdk/python/pyproject.toml", "sdk/python/reverse_artex_windows_service.py",
        "sensors/linux/linux_isolation.py", "sensors/linux/proc_sensor.py",
    ]
    for folder in ("sdk/python/reverse_artex_guard", "sdk/python/examples"):
        for source in sorted((root / folder).glob("*.py")):
            result.append(source.relative_to(root).as_posix())
    for source in sorted((root / "db/migrations").glob("*.sql")):
        result.append(source.relative_to(root).as_posix())
    return sorted(set(result))


def document_source_references(root: Path, stage: Path, inputs: list[str]) -> list[dict]:
    """Mark excluded source-only docs explicitly; never invent a public URL."""
    included = set(inputs)
    transforms = []
    pattern = re.compile(r'(?<!!)\[([^]\n]+)\]\(([^)\s]+)\)')
    for relative in inputs:
        if not relative.endswith('.md') or not (stage / relative).is_file():
            continue
        path = safe_path(stage, relative)
        original = path.read_bytes()
        links = []

        def replacement(match):
            destination = match.group(2)
            local = destination.split('#', 1)[0]
            if not local or ':' in local or '\\' in local or '?' in local or local.startswith('/'):
                return match.group(0)
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(relative), local))
            parts = PurePosixPath(resolved).parts
            # Only known source documentation is converted. Local artifacts and
            # private paths must never acquire a source/public download claim.
            if (resolved in included or not resolved.startswith('docs/') or not resolved.endswith('.md')
                    or set(parts) & BLOCKED_PARTS or not re.fullmatch(r'[A-Za-z0-9_./-]+', resolved)):
                return match.group(0)
            source = safe_path(root, resolved)
            if not source.is_file():
                return match.group(0)
            reference = resolved + ('#' + destination.split('#', 1)[1] if '#' in destination else '')
            links.append({'destination': destination, 'source_path': resolved})
            return match.group(1) + ' (source checkout: `' + reference + '`)'

        changed = pattern.sub(replacement, original.decode('utf-8-sig'))
        if links:
            path.write_bytes(changed.encode('utf-8'))
            transforms.append({'path': relative, 'kind': 'excluded-source-document-reference',
                               'source_sha256': hashlib.sha256(original).hexdigest(),
                               'packaged_sha256': digest(path), 'links': links})
    return transforms


def build_inputs(root: Path) -> list[str]:
    result = ["go.mod", "go.sum", "tools/package_release.py"]
    for folder in ("cmd", "internal", "web"):
        for source in sorted((root / folder).rglob("*.go")):
            if source.name.endswith("_test.go"):
                continue
            relative = source.relative_to(root).as_posix()
            if set(PurePosixPath(relative).parts) & BLOCKED_PARTS:
                raise ValueError(f"unexpected build input: {relative}")
            result.append(relative)
    result += ["web/index.html", "web/app.js", "web/styles.css"]
    return sorted(result)


def run(args: list[str], cwd: Path, env: dict[str, str] | None = None) -> str:
    return subprocess.check_output(args, cwd=cwd, env=env, text=True, encoding="utf-8").strip()


def source_identity(root: Path) -> dict:
    # Git metadata is useful context; the input inventory is the actual source identity.
    try:
        revision = run(["git", "rev-parse", "--verify", "--quiet", "HEAD"], root)
    except (FileNotFoundError, subprocess.CalledProcessError):
        revision = None
    try:
        dirty = bool(run(["git", "status", "--porcelain", "--untracked-files=normal"], root))
    except (FileNotFoundError, subprocess.CalledProcessError):
        dirty = None
    return {"revision": revision, "dirty": dirty}


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def inventory(root: Path) -> list[dict]:
    records = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        safe_path(root, relative)
        executable = relative in ("reverse-artex", "start.sh") or relative.startswith("bin/")
        records.append({"path": relative, "size": path.stat().st_size,
                        "sha256": digest(path), "mode": "0755" if executable else "0644"})
    return records


def licenses(source: Path, stage: Path, env: dict[str, str]) -> None:
    commands = ["./cmd/reverse-artex"] + [f"./cmd/{name}" for name in TOOLS]
    fmt = "{{if .Module}}{{.Module.Path}}|{{.Module.Version}}|{{.Module.Dir}}{{end}}"
    entries = set(run(["go", "list", "-buildvcs=false", "-mod=readonly", "-deps", "-f", fmt, *commands], source, env).splitlines())
    notices = ["# Third-party notices", "", "The Go runtime and the following Go modules are included.",
               "License texts are retained in this directory. Python SDK dependencies are",
               "installed separately and are not vendored in this binary bundle.", ""]
    goroot = Path(run(["go", "env", "GOROOT"], source, env))
    license_root = stage / "third_party"
    license_root.mkdir()
    go_license = goroot / "LICENSE"
    if not go_license.is_file():
        raise ValueError("Go runtime LICENSE not found")
    (license_root / "Go-LICENSE").write_bytes(go_license.read_bytes())
    for entry in sorted(entries):
        if not entry:
            continue
        module, version, location = entry.split("|", 2)
        if module == "reverse-artex":
            continue
        if not version or not location:
            raise ValueError(f"unversioned or replaced dependency: {module}")
        module_root = Path(location)
        names = [name for name in ("LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "NOTICE", "PATENTS")
                 if (module_root / name).is_file()]
        if not any(name.startswith(("LICENSE", "COPYING")) for name in names):
            raise ValueError(f"dependency license not found: {module}@{version}")
        prefix = re.sub(r"[^a-zA-Z0-9._-]", "_", module + "@" + version)
        for name in names:
            candidate = module_root / name
            if candidate.is_symlink():
                raise ValueError(f"linked dependency license: {module}")
            (license_root / (prefix + "-" + name)).write_bytes(candidate.read_bytes())
        notices.append(f"- {module}@{version}: {prefix}-*")
    (license_root / "NOTICES.md").write_text("\n".join(notices) + "\n", encoding="utf-8")


def archive(stage: Path, output: Path, bundle_name: str, target: str, epoch: int) -> Path:
    files = inventory(stage)
    if target.startswith("windows"):
        path = output / (bundle_name + ".zip")
        stamp = time.gmtime(max(315532800, epoch))[:6]
        with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive_file:
            for item in files:
                info = zipfile.ZipInfo(bundle_name + "/" + item["path"], stamp)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | int(item["mode"], 8)) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                with (stage / item["path"]).open("rb") as source, archive_file.open(info, "w") as dest:
                    shutil.copyfileobj(source, dest, 1024 * 1024)
    else:
        path = output / (bundle_name + ".tar.gz")
        with path.open("xb") as stream, gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=epoch, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive_file:
                for item in files:
                    info = tarfile.TarInfo(bundle_name + "/" + item["path"])
                    info.size = item["size"]
                    info.mode = int(item["mode"], 8)
                    info.mtime = epoch
                    with (stage / item["path"]).open("rb") as source:
                        archive_file.addfile(info, source)
    return path


def package(root: Path, output: Path, targets: list[str], epoch: int) -> Path:
    root, output = root.resolve(), output.resolve()
    artifact_root = root / "artifacts"
    if output == artifact_root or not output.is_relative_to(artifact_root):
        raise ValueError("--out must be a new subdirectory of this project's artifacts/")
    if output.exists():
        raise ValueError("output already exists; choose a new directory (nothing is overwritten)")
    if not targets or len(set(targets)) != len(targets) or any(t not in TARGETS for t in targets):
        raise ValueError("targets must be unique supported targets")
    if epoch < 0 or epoch > 4354819198:
        raise ValueError("SOURCE_DATE_EPOCH must be between 0 and 4354819198")
    version = safe_path(root, "VERSION").read_text(encoding="utf-8-sig").strip()
    if not VERSION_RE.fullmatch(version):
        raise ValueError("VERSION must be a semantic version without the v prefix")
    inputs = public_inputs(root)
    sources = build_inputs(root)
    # Validate everything before creating any output.
    for relative in sorted(set(inputs + sources)):
        path = safe_path(root, relative)
        if not path.is_file():
            raise ValueError(f"required release input missing: {relative}")
    identity = source_identity(root)
    output.mkdir(parents=True)
    work = output / "_build"
    source = work / "source"
    public = work / "public"
    source.mkdir(parents=True)
    public.mkdir()
    for relative in sources:
        copy_input(root, source, relative)
    for relative in inputs:
        copy_input(root, public, relative)
    source_records = inventory(source)
    public_records = inventory(public)
    all_records = sorted(source_records + public_records, key=lambda item: item["path"])
    # VERSION and any other shared paths appear in public only.
    identity["sha256"] = hashlib.sha256(json.dumps(all_records, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    identity["inputs"] = all_records
    write_json(output / "source-inputs.json", identity)
    env = dict(os.environ, CGO_ENABLED="0", GOMAXPROCS="2", GOFLAGS="-p=2",
               GOWORK="off", GOTOOLCHAIN="local", GOENV="off", GOAMD64="v1", GOEXPERIMENT="")
    go_version = run(["go", "version"], source, env)
    results = []
    for target in targets:
        goos, goarch = target.split("-")
        target_env = dict(env, GOOS=goos, GOARCH=goarch)
        stage = work / target
        stage.mkdir()
        for relative in inputs:
            if relative == ("start.sh" if goos == "windows" else "start.bat"):
                continue
            copy_input(public, stage, relative)
        extension = ".exe" if goos == "windows" else ""
        for name in ("reverse-artex", *TOOLS):
            relative = ("" if name == "reverse-artex" else "bin/") + name + extension
            binary = stage / relative
            binary.parent.mkdir(exist_ok=True)
            print(f"Building {target}: {name}", flush=True)
            subprocess.run(["go", "build", *BUILD_FLAGS, "-o", str(binary), f"./cmd/{name}"],
                           cwd=source, env=target_env, check=True)
        transforms = document_source_references(root, stage, inputs)
        licenses(source, stage, target_env)
        manifest = {"schema_version": 1, "version": version, "target": target,
                    "source": {key: identity[key] for key in ("revision", "dirty", "sha256")},
                    "build": {"go_version": go_version, "cgo_enabled": "0",
                              "flags": list(BUILD_FLAGS), "source_date_epoch": epoch},
                    "documentation_transforms": transforms, "files": inventory(stage)}
        write_json(stage / "manifest.json", manifest)
        bundle_name = f"reverse-artex-{version}-{target}"
        bundle = archive(stage, output, bundle_name, target, epoch)
        results.append({"path": bundle.name, "size": bundle.stat().st_size,
                        "sha256": digest(bundle), "target": target})
    build_manifest = {"schema_version": 1, "version": version, "source": identity,
                      "archives": results}
    write_json(output / "build-manifest.json", build_manifest)
    checksum_names = [entry["path"] for entry in results] + ["build-manifest.json", "source-inputs.json"]
    (output / "SHA256SUMS").write_text("".join(f"{digest(output / name)}  {name}\n" for name in sorted(checksum_names)), encoding="ascii")
    print(f"Packaged {len(results)} target(s) in {output}", flush=True)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path, help="new subdirectory under artifacts/")
    parser.add_argument("--target", action="append", choices=TARGETS, help="repeat to select targets; default: both")
    parser.add_argument("--source-date-epoch", type=int, default=int(os.environ.get("SOURCE_DATE_EPOCH", "0")))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.out if args.out.is_absolute() else root / args.out
    try:
        package(root, output, args.target or list(TARGETS), args.source_date_epoch)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Packaging failed: {error}\n")


if __name__ == "__main__":
    main()

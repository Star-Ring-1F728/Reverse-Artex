# Building release bundles

Reverse Artex 0.1.0-beta.1 is a prerelease. Packaging and startup checks do not
establish production security effectiveness or a general operating SLO. The
completed, configuration-specific latency qualification is summarized in
[VALIDATION.md](VALIDATION.md).
These instructions create local files; they do not publish a GitHub Release.

## Requirements and command

Use Python 3.10+ and the patched Go 1.27.4 toolchain used by the packaging workflow, with the module dependencies available. No Python
packages or Node.js installation are needed to build the console and public CLI.
The optional Python integration SDK has its own pinned dependencies in
`sdk/python/pyproject.toml`.

From the project root:

```powershell
python -m unittest discover -s tools -p test_package_release.py
python -m unittest discover -s tools -p test_verify_public_release.py
python -m unittest discover -s tools -p test_check_release_readiness.py
python tools/package_release.py --out artifacts/release-new
```

For Go regressions in a development checkout with retained run artifacts, use
`go test ./cmd/... ./internal/... ./web/...` to select the live packages.

The default builds Windows amd64 ZIP and Linux amd64 tar.gz bundles. To build one:

```sh
python tools/package_release.py --out artifacts/release-linux --target linux-amd64
```

Every output directory must be new and live under this project's `artifacts/`.
Existing outputs are never replaced or removed. A failed attempt leaves its
snapshot and diagnostics available; choose another directory for the next attempt.
Keep active performance acceptance runs isolated from builds. The packager sets
`GOMAXPROCS=2` and `GOFLAGS=-p=2` and builds tools sequentially.

## Contents and verification

Each archive has one top-level directory containing:

- The console/collector executable and the platform's `start.bat` or `start.sh`.
- The 30 public policy, case, learning, investigation and response CLI tools in `bin/`.
- Explicit configuration examples, user documentation, LICENSE, SECURITY,
  CONTRIBUTING, VERSION, database migrations and Python SDK/sensor source.
- Go runtime/module license texts in `third_party/` and a `manifest.json`.

The included tools/verify_public_release.py is an optional standard-library verifier (Python 3.10+). It rejects malformed or oversized manifests, linked/reparse-point entries, unsafe paths, case collisions, and missing, modified or unlisted files before executing anything. Run it on a freshly extracted directory before creating config/data inside that directory:

```sh
python tools/verify_public_release.py --directory . --out ../release-smoke-20261114
```

Use `--static-only` when checking a package built for another operating system. The smoke check uses isolated state outside the package, tests authentication and sample isolation, sends one synthetic event, and opens a verified copy of the stopped collector's state. On Linux it invokes the packaged `start.sh` and checks clean SIGTERM exit. The Windows path invokes the executable directly and tests process termination and restore. A native Windows Ctrl+C check is a separate platform test. Reports retain hashes and counts.

The web UI is embedded in the executable. Running the console needs neither Go
nor Python. Extract the whole archive into a writable directory before starting.
The first start creates `config.json` and `data/`; retain both when upgrading.
Use the access URL printed by the running process.

The output folder also contains `SHA256SUMS`, `build-manifest.json` and
`source-inputs.json`. Verify hashes before extracting:

```sh
sha256sum -c SHA256SUMS
```

On Windows:

```powershell
Get-Content SHA256SUMS | ForEach-Object {
  $expected, $name = $_ -split '  ', 2
  if ((Get-FileHash -Algorithm SHA256 -LiteralPath $name).Hash.ToLowerInvariant() -ne $expected) {
    throw "SHA-256 mismatch: $name"
  }
}
```

Run these checks in the output directory. Checksums detect modification relative
to the supplied manifest; authenticate their source separately before trusting a
download. No signing key is included.

`manifest.json` schema version 1 records version, target, build flags/toolchain,
source identity and every payload file's relative path, byte size, SHA-256 and
Unix mode. It excludes itself to avoid a recursive hash. The outer build
manifest records archive hashes and the full input inventory. `SHA256SUMS`
covers archives and both outer JSON manifests.

From the source checkout, also run the maintainer readiness check against the
completed output before sharing it:

```sh
python tools/check_release_readiness.py --release-dir artifacts/release-new --out artifacts/release-new-readiness.json
```

This source-only tool binds outer checksums, archive metadata, version and source
input identity to the current allowlisted tree. It catches stale archives after
a source or documentation edit. Its report path must be new. Passing this check
does not authenticate a distributor or replace native runtime verification.

## Source boundary and reproducibility

The packager snapshots the CURRENT working tree, including uncommitted allowed
changes. It does not substitute `git archive HEAD`. It records Git revision and
dirty state as context and hashes every copied source and public input, including
the packaging tool itself. The input inventory records the original public files;
archive documentation may have the explicit transformations described below. Builds
run from that frozen snapshot in `_build/source`. The `_build/` directory is
local diagnostic material and is never uploaded by the packaging workflow.

Some detailed validation/development documents remain source-only. In packaged
Markdown, a relative link to an existing, excluded `docs/*.md` file is rendered
as “label (source checkout: `docs/FILE.md`)” instead of a broken download link.
The original source document stays unchanged. Each archive manifest records the
changed document path, original and packaged SHA-256 values, and source-link
destinations in `documentation_transforms`. No public URL is invented, and local
artifacts, data and private paths are not converted into source download links.

Files are selected by explicit names or narrow source extensions in designated
directories. User `config.json`, `.env`, data, caches, existing binaries,
artifacts, Git metadata, test fixtures/keys and dated research/benchmark reports
are excluded. Unexpected links and PEM private keys in selected inputs cause
failure. Adding a new public document/config requires reviewing the allowlist
in `tools/package_release.py`; never replace it with a broad directory copy.
This boundary does not replace review of public source and example values.

Builds use `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`, read-only module
resolution, the selected toolchain's default Go experiments, and stripped debug symbols. Dependencies remain pinned by go.mod and
go.sum. Record the exact Go version from the manifest when reproducing a build.
Archive members are ordered; owner fields, executable modes, timestamps and gzip
headers are normalized. `SOURCE_DATE_EPOCH` (or `--source-date-epoch`) controls
timestamps and defaults to zero; ZIP uses its earliest supported 1980 timestamp.
Identical input contents, metadata, toolchain and environment should produce
identical archive bytes. Unit tests verify this for controlled payloads;
cross-host binary reproducibility is not asserted without comparison.

## Workflow and promotion

`.github/workflows/package.yml` runs manually and on version tags. It executes
release-boundary tests, cross-builds both targets, verifies the extracted Linux
bundle natively, and uploads only archives and public manifests as a review
artifact after the source/readiness check passes. A dependent Windows job downloads that same artifact, checks its outer
SHA-256 checksums, extracts the Windows ZIP and runs its packaged verifier
natively. Both jobs retain their credential-free smoke reports. These are
startup/authentication/sample/ingestion/restart checks; the Windows job uses
process termination/reopen and does not qualify Ctrl+C or service drain. It has read-only repository permissions and
does not push, create tags, create releases or publish packages.

Before a public upload, review the input inventory and archive file list,
perform the runtime verification described in the project README, review
licenses/notices, and confirm the documented prerelease limitations. Version
tags must match `v` plus the VERSION file. Change VERSION deliberately for the
next distribution; packaging never modifies it automatically.

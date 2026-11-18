# Contributing

English · [한국어](CONTRIBUTING.ko.md)

Start with [the quick start](docs/QUICKSTART.md), [capabilities (Korean)](docs/CAPABILITIES.md), and [compatibility](docs/COMPATIBILITY.md). Read `AGENTS.md` in the source checkout before making changes; binary archives are for running the product and do not contain the complete development tree. Reverse Artex is a defensive project; reproduce issues with synthetic data and systems you are authorized to operate.

## Build and validate

Use Go 1.26+. On Windows run `build.bat`; on Linux run `sh build.sh`. Web assets are embedded directly from `web/`; no npm build is required.

```sh
go test ./...
go vet ./...
```

Run targeted tests during development and the applicable full checks before proposing code changes. For the optional SDK, install its pinned dependencies with `python -m pip install -e sdk/python` and run `python -m unittest discover -s sdk/python/tests`. Changes to Linux isolation, V2 retention, filesystem durability, or a Windows service require checks on the actual affected OS; cross-compilation alone does not establish runtime support. Use [release instructions](docs/RELEASING.md) for distributable archives.

## Propose a change

Keep each change focused. Explain the concrete failing behavior, the resulting behavior, how it was checked, and remaining limitations. Include synthetic steps and the source revision for a bug. Do not imply general security effectiveness from one synthetic result. Preserve dated failure reports and do not change acceptance criteria to turn a failure into a pass. Use [the security policy](SECURITY.md) for vulnerabilities rather than a public reproduction.

Never include real `config.json`, `.env`, data stores, credentials, production captures, model caches, generated binaries, or test-run evidence in a source contribution. Keep public examples synthetic and default response integrations disabled. Preserve copyright and third-party notices when changing dependencies. Repository access and publication are managed separately; these instructions do not authorize a remote push or release.

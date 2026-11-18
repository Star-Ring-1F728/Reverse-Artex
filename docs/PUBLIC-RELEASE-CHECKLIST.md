# Public beta release checklist

This is a maintainer checklist for **0.1.0-beta.1**. Preparing local archives does not publish source, create a tag, or publish a release. Complete the applicable checks against the exact files selected for publication.

## Source publication

- Review the exact source file list independently of the binary allowlist. Excluding a file from a binary archive does not exclude it from a repository or source download.
- Keep private configuration, credentials, real captures, runtime stores, model/tool caches, test-run artifacts, and private fixtures out of the public source selection. Keep examples synthetic; do not publish raw private logs as validation evidence.
- Preserve LICENSE and third-party notices, and review dependency/license changes.
- Confirm English and Korean entry documentation agrees on defaults, integration requirements, supported platforms, and validation scope. Do not replace dated failure records with an unqualified success claim.
- Run applicable source checks and record the revision plus any uncommitted inputs that will be distributed. Do not treat an old archive as current after changing documentation or code.

## Binary archives

- Build from the reviewed current tree using [release packaging](RELEASING.md). Use a new output directory; preserve earlier outputs and diagnostics.
- Review the frozen source inventory, target/version/build metadata, payload file list, dependency notices, and excluded private paths. Confirm the README and guides match the reviewed current tree.
- Check the outer archive hashes and manifests. On a fresh extraction, verify every payload hash before starting it. Preserve the resulting verification report without access URLs or tokens.
- Run the verifier on each actual supported target, or clearly record static/cross-build checks separately from native runtime checks. Report Windows forced-process restart separately from graceful shutdown/drain.
- Follow the first-run guide from the extracted package. Confirm source-only paths are labeled, local links resolve, examples exist, and no source build or Docker step is presented as available inside the binary archive.
- Retain the basic launch's loopback binding and observation-only defaults. Reconfirm that optional response, identity/ACL, model, database, and host-isolation integrations need explicit setup.

## Claims and promotion

- Attribute the 2026-11-12 authorization results to their explicit SDK/session/ACL integration and original workload. They are feature-level results, not a complete defense rerun on the final packaged binaries.
- Use the [public validation summary](VALIDATION.md) for the completed 2026-11-14 one-hour trial: 360,000 HTTP 200 responses, zero errors, whole-run p99 198.867 ms; C: NVMe/native WSL ext4, evidence/V2 batching 15/25 ms, defaults 0. Preserve its workload, internal-audit scope, per-window exceptions, and failed/interrupted history. Do not promote it into a general operating SLO or a final-archive defense rerun.
- Include `docs/VALIDATION.md` in the binary documentation allowlist. Keep dated source evidence references labeled when those reports are omitted. Review public source independently: the raw dated reports can contain local paths and are not the sanitized public summary.
- Record actual native archive verification separately from cross-build/static checks. The packaging CI has Windows/Linux runtime paths; configuration alone is not a successful remote workflow run, and it has not been dispatched in this preparation.
- Describe native Linux, macOS, Windows V2 retention, and graceful shutdown limitations accurately. Packaging success does not establish general attack prevention, model quality, production capacity, or an availability SLO.
- Decide the public source/repository destination and the binary distribution destination. Obtain explicit authorization before remote publication; this checklist does not authorize GitHub changes.
- At promotion, identify the exact version and files, publish their matching checksums/manifests and relevant limitations, and authenticate the checksum source. Do not upload local `_build/` snapshots or private test state.

See [compatibility](COMPATIBILITY.md), [security](../SECURITY.md), and [contributing](../CONTRIBUTING.md) for the underlying boundaries. Completion evidence and publication decisions should be recorded separately; unchecked or in-progress work must remain visibly pending.

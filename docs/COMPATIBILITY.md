# Compatibility and known limitations

This beta distinguishes a usable local workflow from a qualified deployment. A command compiling successfully does not establish runtime or filesystem guarantees.

Protected upstream representations require exactly one `Content-Type`, at most one `Content-Encoding` (empty/identity only), and no `Content-Range` field, including an empty field. Ambiguous duplicate metadata is rejected before any representation is released. This does not imply a demonstrated payload-signature bypass in previous versions.

The optional deterministic `-v2-native` policy engine coalesces renewals on already covered exact scopes within five seconds. This reduces burst writes and consumed-evidence pressure; idle expiry can be up to five seconds earlier than the newest violation's one-minute window. The two-minute episode hard end, three-minute cooldown boundary, ownership and current-case checks are unchanged. SDK-only, native-auto and native-auto plus L3 AI are distinct modes and must be labeled separately in comparisons.

Optional [adaptive defense strategy](ADAPTIVE-DEFENSE-STRATEGY.ko.md) adds bounded, verified-outcome-based replanning to explicitly requested L3 investigations. Existing records remain readable by the new version. Journals containing the new `strategy` or `revised_strategy` fields require a reader supporting those fields; older strict readers cannot directly replay them.

| Environment or feature | Beta scope |
| --- | --- |
| Windows amd64 | Native console, collector evidence, file analysis, and Windows CLI builds. Target-specific optional integrations require their own setup. |
| Linux | Native console/CLI builds. Some durability and response paths are Linux-specific; use the filesystem and privileges documented for that path. |
| macOS | Source-build entry point exists; runtime qualification and advanced feature parity are not established. |
| V2 retained journals | Explicit `policy-edge -v2-state ... -v2-retention` mode supports Linux and fixed local Windows NTFS volumes. Journal verification and stopped backups use the writer's ownership lock. [Retained journal operation](V2-RETAINED-JOURNAL.md) |
| Real host isolation | Explicit single-workload Linux network-namespace/nftables adapter, scope, privileges, and trust setup. Simulation is the default; generic Windows host isolation is not supplied by this adapter. |
| Docker Compose | API-only collector, loopback port publication, persistent named volume. It does not serve the native operator console. |
| Local Ollama | Already installed tool-capable local model and sufficient model-specific memory; analysis-only by default. No automatic model download. |
| Application SDK | Optional Python 3.10+ integration with pinned dependencies, explicit identity/ACL/registry contracts. Not an automatic application retrofit. |
| PostgreSQL case API | Separately deployed database, migrations, roles, and services. Not required by the basic local console. |

## Source checkout and binary archives

The supplied binary archive targets are Windows amd64 and Linux amd64. A source checkout can be built for another target, but compilation does not qualify that target at runtime. Select the matching OS and architecture; do not run a Windows executable on Linux.

Archives contain the console, `bin/` CLI executables, selected configuration and integration sources, and user guides. They omit the Go source/build scripts, Docker profile, private runtime state, and dated development/validation reports. Source-build and Docker instructions require the source checkout. Source-only document references in a binary archive identify their checkout path instead of promising a local file. The archive's `manifest.json` lists the actual included files; see [release packaging](RELEASING.md).

## Data and UI limits

File analysis accepts at most 1 MiB, 1,024 events, and 16 KiB per record. It uses a separate in-memory rules engine, validates against each event's `ingest_time`, and does not add records to the live journal or execute policies. Live ingestion instead requires current timestamps and configured sensor/tenant/asset scope.

Event and alert lists read the latest 200 completed records from active files. Sealed historical segments remain on disk and are not a full searchable history in these views. Bounded stores can refuse new work when limits are reached; they do not silently delete original evidence to continue forever. Back up stopped stores and monitor usage.

The interface is primarily Korean. English documentation does not mean every screen, generated model response, or detailed integration guide is localized. A current browser is required; a mobile or accessibility certification is not claimed.

## Edge and SDK input contracts

The `lab-hmac-v1` verifier requires canonical Base64URL payload/signature text and exact, unique claim fields. Tokens issued by the supplied canonical signer satisfy this contract. Direct Python Guard calls reject duplicate authentication, ingress, registry, request-ID, and nonce headers case-insensitively.

The configured `-upstream` URL selects the upstream virtual host. The edge replaces the client Host with that host and strips client `Forwarded`, `X-Forwarded-*`, and `X-Real-IP` metadata before constructing upstream forwarding information.

General forwarded request bodies are buffered within the existing 8 KiB limit before upstream dispatch. Oversized bodies receive 413, malformed or incomplete bodies receive 400, and request trailers receive 400. Route inventory admission can reject an unregistered path before body validation. Registered protected object reads require their configured method, empty-body, and signed-proof contract.

Optional L3 `diagnostic_timings` records include a bounded provider failure kind and HTTP status for failed service calls. These fields support outage diagnosis and journal replay. Native executions have a thirty-second deadline. Reopening failure diagnostic records requires a reader supporting the optional `provider_failure` field.

## Security and acceptance limits

Starting the console does not capture all network traffic, protect arbitrary application routes, or make authorization decisions for an unintegrated app. Rule coverage depends on the sensor supplying the required facts. Absence of alerts is not evidence of safety. Optional learning recommendations do not automatically deploy protection policies. A model investigation is not an independent verdict or security guarantee.

Automatic response and host isolation remain off in the default launch. Enabling a particular policy profile requires its own operator trust and scope. Cancelling a running investigation is separate from revoking a policy already applied. Validate the actual edge/application response when assessing effect.

Local synthetic results and journal integrity checks do not establish general defense efficacy, independent model quality, a production throughput rating, or an availability SLO. A completed one-hour 100 RPS trial returned 360,000 HTTP 200 responses with zero errors and whole-run p99 198.867 ms in the selected C: NVMe/native WSL ext4 configuration with evidence/V2 batching of 15/25 ms (both defaults remain 0). Some 50-second windows exceeded 250 ms. This is an environment-specific backend/SDK result, not a general operating SLO or an external independent security audit. See the included [validation summary](VALIDATION.md). No automatic update, public download, support SLA, or production sizing guarantee is assumed.

See [operations](OPERATIONS.md), [capabilities](CAPABILITIES.md), and [security](../SECURITY.md) before enabling advanced integrations.

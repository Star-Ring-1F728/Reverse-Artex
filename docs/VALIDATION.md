# Validation summary — 0.1.0-beta.1

This public summary separates dated feature trials, latency qualification, and verification of a particular release archive. All results below are project-run local checks. A separate signature/journal verifier is an integrity check, not an external independent security audit. These results do not establish general attack prevention, independent model quality, or a production availability/latency SLO.

## November 18 ARTEX simulation

The controlled simulation used an owned loopback app, synthetic accounts and data, the application SDK, and edge verification of signed responses. The completed comparison covered 3,036 supported scenario rows, including 2,988 fixed rows and 48 matched variants from completed AI runs. The vulnerable baseline exposed fixture data in **486 rows**. The protected paths exposed **zero**, and all **192 fixed normal controls** returned exact responses.

### Original Luna integrated trial

**Four of six `gpt-6-luna` runs completed**, including four of the five planned runs. The additional transport follow-up also ended early. The two incomplete runs involved response delivery or session state. In completed runs, containment plus assessment took **9.1–12.4 seconds**, and release plus assessment took **10.5–12.3 seconds**. Both stages had a 30-second deadline. The SDK and edge remained active throughout the matched comparison, and the AI policy prevented **zero additional fixture-data exposures** in that sample.

## November 19 defense transport follow-up

The source-only defensive qualification transport stores each synced response with a completion marker, resumes from the first uncommitted call, and uses polls of at most eight seconds. Its host reader requires the original record and a consistent completion marker. The native host still validates the response schema, its input digest and worker identity, and the original 30-second stage deadline.

### Luna defense-only trial

**Six of six** planned runs completed with `gpt-6-luna` at low reasoning effort. One worker served six fresh Windows fixtures, and every queue command started a fresh Node process. The test wrapper discarded one commit acknowledgment per run. The worker resumed from disk and finished without resubmitting a decision.

Containment plus assessment took **15.9–18.8 seconds**, and release plus assessment took **17.5–22.3 seconds**. All six runs verified targeted containment and explicit release before policy expiration. The offline check matched **24 original model responses** and **180 SDK signatures** and confirmed that **120/120** normal control responses were preserved. One setup attempt ended before the first response was committed because the shell could not parse the submission. The six-run plan was frozen after the wrapper input was corrected. [Original Luna integrated trial](#original-luna-integrated-trial)

### Qwen3 defense-only trial

**Six of six** fresh Windows fixtures completed with the local `qwen3:4b-instruct-2507-q4_K_M` model. Containment plus assessment took **2.93–3.57 seconds**, and release plus assessment took **4.37–5.64 seconds**. A fresh Node process reconstructed the queue for every command. Each run intentionally discarded one commit acknowledgment, then resumed without resending a decision. In total, **24 original model responses** and **180 SDK signatures** matched the native records. All six runs verified targeted containment and explicit release before the policy expired, with **120/120** normal control responses preserved.

The follow-up used owned loopback fixtures and verified defense transport and completion under those conditions. The [original Luna integrated trial](#original-luna-integrated-trial) retains its own scope and result.

## November 18 beta runtime and load

The **Linux beta candidate** processed **18,000 protected HTTPS reads** during a **100 requests/s** peak for about three minutes, with **p99 223.9 ms**. The full run included 18,757 correctly matched client responses, SDK signatures, and journal completions.

The **Windows evaluation ZIP**, built with Go 1.27.4, completed a separate synthetic signed-read test at 20, 100, and 20 requests/s for ten seconds each. Both profiles returned **1,400/1,400** exact responses and matched all SDK signatures. At 100 requests/s, p99 was **724.4 ms** with default 0/0 ms batching and **259.8 ms** with optional 15/25 ms evidence and V2 batching. Both missed the **250 ms per-phase gate**. The Windows profile used a non-retained V2 journal. The extracted ZIP also passed 29 smoke checks, four browser flow checks, and a separate Ctrl+C drain of one in-flight signed read. [Beta platform scope](BETA-SCOPE.md)

These short load trials used different workloads and configurations. Production acceptance remains open for sustained load, operational retention, and failover between hosts.

### Windows retained V2 follow-up

On November 18, Windows development ZIPs processed an owned synthetic signed HTTP workload with V2 retention on fixed local NTFS NVMe storage. Each of three trials used 20 workers, HTTP persistent connections, 8 ms evidence batching, and 15 ms V2 batching. Each trial ran at 20 requests/s for 10 seconds, 100 requests/s for 180 seconds, and 20 requests/s for 10 seconds.

All three trials passed the 250 ms per-phase gate. Across the trials, all **55,200 responses** matched the expected body, SDK signature, and V2 completion. There were **zero HTTP 503s, timeouts, or unresolved write records**. The last development ZIP returned **18,400/18,400** exact responses with p99 of **65.6 ms** at baseline, **54.8 ms** at peak, and **55.7 ms** during recovery. Its journal reached generation 8. SATA pilot trials missed the latency gate during long disk syncs. These measurements apply to the development ZIPs and the storage and connection profile above. [Retained V2 setup](V2-RETAINED-JOURNAL.md)

## Packaged authorization evaluation — 2026-11-15

The clock-integrity-fixed Windows validation archive and its bundled Python SDK passed an independently recomputed evaluation of 2,016 planned HTTP requests across three fresh synthetic fixtures. Protected legitimate responses matched exactly in **954/954** cases; **69/69** prescribed attacks returned no fixture canary data, with zero normal false positives or unauthorized exposures. All 24 deliberate fault cases matched their fail-closed oracle. Baseline attack controls exposed data in 60 bodies; nine HEAD controls returned 200 with empty bodies.

A separate auditor verified 1,008 original SDK Ed25519 responses and exact HTTP/oracle/host-ledger joins. Its 17 current-archive positive/negative tests include rejection of tampered/missing/duplicate evidence and a spoofed passing summary. Workload: eight workers, mean target 10 RPS, functional authorization and boundary coverage. The supplemental plan was frozen separately after primary results and before its own execution. These are scripted SDK/edge checks, not autonomous ARTEX performance or added model-driven prevention. Full conditions, archive pin and frozen hashes.

## Authorization protection — 2026-11-12

| Planned rate | Legitimate requests succeeded | Legitimate requests blocked | Unauthorized object responses |
| --- | ---: | ---: | ---: |
| 30 RPS | 113/113 | 0 | 0 |
| 100 RPS | 375/375 | 0 | 0 |

The Python SDK was explicitly integrated with the application's session and object ACL snapshot. The workload covered new-session bypass, another owner's object in the same tenant, and cross-tenant access. Totals aggregate three fixed seeds, 3-second stages, 16 workers, and 12 mixed cases. They are feature-level results, not a complete attack-suite rerun against the final release archive, maximum throughput, or long-duration availability. A strengthened rerun passed 69 checks and 125/125 legitimate requests per seed; repeated seeds are not added as independent samples.

A separate fixed local-model/SDK regression matched expected outcomes for 15/15 prescribed business requests and 3,000/3,000 normal-load requests. The model selected a temporary restriction and released its own claim. The SDK already denied unauthorized reads; the result does not establish additional leak prevention by the model or general model quality.

Source evidence: authorization validation, L3 regression. Dated source reports may be omitted from binary archives.

## Windows operating challenge — 2026-11-15

Two later, separate native Windows challenges did **not** meet their declared whole-run and per-phase availability/latency gates. The second recorded 2,182/2,200 exact normal HTTP 200 responses and 18 transport failures returning 503; whole-run p99 was 260.7145 ms and pressure-phase p99 was 358.7983 ms against a 250 ms limit. Four admitted shutdown controls completed with 200 after the test observer's timing was corrected. These failures remain separate from the earlier one-hour WSL result and from low-rate authorization checks. Current scope and failed denominators, connection reuse and diagnostic improvement.

## Earlier completed latency qualification — 2026-11-14

| Measurement | Requests | Scheduled-to-completion p99 | Maximum latency |
| --- | ---: | ---: | ---: |
| 10 seconds | 1,000 | 110.880 ms | 116.524 ms |
| 120 seconds A | 12,000 | 116.541 ms | 193.317 ms |
| 120 seconds B | 12,000 | 147.593 ms | 291.882 ms |
| 600 seconds | 60,000 | 130.123 ms | 328.963 ms |
| 3,600 seconds | 360,000 | **198.867 ms** | 1,491.432 ms |

All five trials returned HTTP 200 for every measured request with zero errors and passed the recorded operational criteria plus separate signature/journal checks. The one-hour measurement lasted **3,600.087006 seconds**. It recorded all 360,000 planned reads without missing, duplicate, or out-of-range rows; all 28 planned session renewals succeeded and the original TTL-gap condition passed. Retention, signed evidence/audit records, typed V2 Go replay, and owned-process/listener cleanup checks also passed.

### Fixed configuration

- C: NVMe-backed native WSL ext4; Go 1.27.2, Python 3.12.3.
- 100 RPS, 20 workers, 50 warmup requests, `v2-combined`, mixed 1 KiB/16 KiB/1 MiB responses.
- Separate SDK process, persistent SDK audit, prestarted workers, and timing diagnostics.
- Optional evidence batching **15 ms**, V2 batching **25 ms**. Both configuration defaults remain **0**. Successful callers returned after full Sync; durability acknowledgement was retained.

This measures the tested local backend/SDK path. It does not measure browser rendering, model inference, arbitrary applications, native Windows retained journals, or another storage configuration. The completed trial did not change the pinned application source or binaries during that experiment. Its binary pins are not the identity of a later release archive.

### Acceptance and interpretation

The original criteria included whole-run request p99 ≤250 ms, maximum ≤2,000 ms, worker-dispatch p99 ≤100 ms, no producer delays over 100 ms, zero HTTP errors, and successful evidence/audit/cleanup checks. The one-hour trial passed those recorded criteria; worker-dispatch p99 was 2.931 ms. Some 50-second windows exceeded 250 ms. The whole-run percentile therefore does **not** promise p99 ≤250 ms in every interval or a general operating SLO.

Warmup and setup are separate from the 360,000 measured reads. Evidence rows, V2 calls, batches, Sync counts, session renewals, and measured requests have different denominators and are not combined as additional successful reads.

### Earlier attempts remain part of the record

The earlier 5/5 ms profile on an NVMe-backed ext4 loop image completed trials through 600 seconds, then its one-hour attempt was interrupted by WSL termination after approximately 400 seconds and 39,997 HTTP 200 responses. It has no completed full-run p99 or final audit.

On the later native-ext4 environment, a 5/5 ms attempt stopped after 2,151.884 seconds and 214,402 HTTP 200 responses with queue overflow; a 15/5 ms attempt stopped after 743.174 seconds and 72,892 HTTP 200 responses. Neither passed. Their terminal rows for unsent/no-response work are not counted as successful requests. The final 15/25 ms profile completed the one-hour trial above.

These environments, batching profiles, timing, cache state, and file placement differ. The successful result establishes an absolute pass for the selected configuration; it does not isolate a causal speedup or prove that hardware alone caused earlier failures. The original failed and interrupted records remain preserved.

## Release archive qualification

An archive must be identified by its exact checksum and payload manifest. Cross-compilation and static payload verification are separate from a native runtime test. A dated feature trial or an earlier archive check does not certify a later archive. Windows forced-process restart also does not establish graceful Ctrl+C or service drain.

Consult the verification report supplied with a beta archive for its exact checksums and runtime results.

## Defaults and integration boundary

The basic launch remains loopback-bound and observation-only, with no automatic blocking or host isolation. Authorization protection requires explicit SDK/session/ACL/registry integration. Optional model, response, identity, database, learning, and host-isolation workflows require their own setup and validation. Starting the console does not protect an arbitrary application.

See [compatibility](COMPATIBILITY.md), [operations](OPERATIONS.md), and the [release checklist](PUBLIC-RELEASE-CHECKLIST.md).

# Changelog

## 0.1.0-beta.1 — beta preparation

This version identifies the first public-facing beta packaging baseline. It is not a claim that a GitHub release has been published.

- Embedded local web console, authenticated normalized HTTP collection, evidence-backed alerts, and separate JSONL sample/file analysis.
- Incident memory, label corrections, bounded offline candidates, and explicitly started observation/review workflows.
- Optional local Ollama investigation and separately configured policy, application SDK, identity, and Linux host-response integrations.
- English entry documentation, Korean guide, quick start, compatibility boundaries, security/contribution guidance, and reproducible archive tooling.
- Completed an environment-specific 100 RPS one-hour SDK/backend trial: 360,000 HTTP 200 responses, zero errors, whole-run p99 198.867 ms, with separate signature/journal verification. See the [validation summary](docs/VALIDATION.md) for the selected storage/batching profile and limitations.
- The default console runs in observation mode. Automatic blocking, host isolation, Decisions, and local-model response require separate configuration.
- Linux beta qualification covers the packaged launcher, collector backup and restore, and a single-host signed-read trial. See the [public beta scope](docs/BETA-SCOPE.md) for conditions and platform coverage.
- Opening the new console access link in an existing tab reconnects it after a restart. The page clears the key from the address bar and preserves the new session if a request using the previous key returns late.
- The extracted-package verifier keeps authenticated smoke requests on their original loopback endpoint. Release builds use the selected Go toolchain's default experiments.
- Beta bundles and the container build use Go 1.27.4 for standard library security fixes.

### Simulation-driven improvements

- Added disabled-by-default, analyze-only grounded assessment: actual signed observation ages, supported classes and canonical citations are checked again before durable commitment. Raw Gemma quality failures remain recorded separately from guided qualification.
- Added bounded policy-edge shutdown so admitted requests can drain before writers close; failed or timed-out cleanup returns an error instead of a graceful-success claim.
- Corrected downstream close propagation to preserve upstream HTTP/1.1 reuse, with a real signed-response connection-reuse regression and fixed, privacy-safe transport failure counters. Earlier Windows availability/latency failures remain preserved; see [current qualification](docs/VALIDATION.md#windows-operating-challenge--2026-11-15).
- Added a separate source-only PolyStrata/Gemma readiness and closed-JSON probe with a five-minute response allowance and fifteen-minute total response budget. Its format checks do not establish native defense-tool or containment performance.
- Explicitly state the defensive purpose in English and Korean: protect owned or authorized applications, using owned synthetic ARTEX fixtures for validation.
- Reject journal timestamp rollback before committing bytes and reject nonchronological legacy input before publishing retained state. Strict replay, proof freshness and recovery fences remain enforced; clock-dependent capacity fixtures now use deterministic private test clocks. Full affected suites passed on Windows and native Linux.
- Increased only the private management HTTP write allowance from one to five seconds, so a slow durable commit/read can return its acknowledgment. SDK authorization, L3, evidence freshness and policy TTL limits are unchanged. Real-handler regressions preserve the old lost-ack control and verify one commit per request.
- Repeated all 2,016 frozen authorization checks against the post-fix Windows validation archive: 954 exact legitimate responses, 69 attack checks without exposure and 24 expected fault responses. Independent proof/journal and tamper checks passed. See [current validation](docs/VALIDATION.md#packaged-authorization-evaluation--2026-11-15).
- Added strict test-only model framing, UTF-8 plan handling, late-action rejection, source/payload provenance and scoped native PostgreSQL test support. Current full ARTEX/AI response qualification remains incomplete; model results retain real outcomes and failures.

### Known limitations

Independent production acceptance, general attack-prevention efficacy, model quality, and general latency/capacity guarantees are not established. Retained V2 journals require Linux; native Windows support is pending. macOS runtime qualification is not claimed. The completed one-hour trial uses C: NVMe/native WSL ext4 with optional evidence/V2 batching of 15/25 ms; both defaults remain 0. Some 50-second windows exceeded 250 ms. It is an internal validation, not an external independent security audit or a general operating SLO. The [completed source record](docs/VALIDATION.md#earlier-completed-latency-qualification--2026-11-14) supplements the preserved [earlier progress, failed profiles, and interrupted trial](docs/VALIDATION.md#earlier-attempts-remain-part-of-the-record); it does not overwrite them or qualify a final archive as a complete defense rerun.

Previous implementation and validation notes are preserved in development history and the dated documents it links to. They are not retroactive release certifications.

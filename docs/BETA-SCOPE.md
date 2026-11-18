# Reverse Artex 0.1.0-beta.1

English · [한국어](BETA-SCOPE.ko.md)

Reverse Artex helps operators observe and investigate HTTP activity on applications they own or are authorized to defend. The first public beta is for local evaluation and single-host integration. Start with the local console in observation mode, then connect an authorized sensor or try the bundled JSONL sample.

| Included workflow | Beta scope |
| --- | --- |
| Local console and collector | Loopback console, authenticated sensor ingestion, file/sample analysis, evidence review, and stopped backup and restore. |
| Signed protected reads | Optional policy-edge and application SDK integration. Configure the application’s session and authorization checks and register the routes being evaluated. |
| Retained V2 journal | Optional on Linux. Run one writer for each state directory and verify stopped backups before restoring. |
| AI-assisted review | Optional local-model analysis requires separate configuration. Decisions is off by default. Automatic containment, policy forwarding, and host isolation require explicit setup. |

Use the [quick start](QUICKSTART.md) to verify, extract, and start the package. Keep the generated console link and sensor token private. Back up `config.json` and the whole `data/` directory together with the collector stopped. Follow the [operations guide (Korean)](OPERATIONS.md) for storage errors and [retained journal instructions](V2-RETAINED-JOURNAL.md) for optional V2 state.

The latest Linux qualification used controlled HTTPS reads through the native edge and an application with the packaged SDK. It processed 18,000 peak requests in 180.2 seconds at a read p99 of 223.9 ms. A drained writer restart on one host reached its first successful read in 8.34 seconds. The audit matched all 18,757 responses in the full run. These figures depend on that workload, application and storage configuration. See [ARTEX qualification evidence](VALIDATION.md#november-18-beta-runtime-and-load).

The release handoff records exact archive checks and runtime coverage per platform. Linux is the distribution target for single-host integration, including retained V2 and its offline verifier. The Windows amd64 ZIP is for local console evaluation. Windows sustained-load qualification remains open. See [compatibility](COMPATIBILITY.md).

Production qualification remains open for the full deployed ARTEX browser and logging path, 24-hour load and actual seven-day storage volume, and failover between two independent hosts. Report suspected security issues through the process in [SECURITY.md](../SECURITY.md) without including private captures or credentials in a public report.

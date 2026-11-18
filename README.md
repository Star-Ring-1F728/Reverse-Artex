# Reverse Artex

**Beta version · 0.1.0-beta.1**

Reverse Artex collects HTTP evidence, detects suspicious activity, and helps protect applications you own or are authorized to assess.

English · [한국어](README.ko.md)

[MIT](LICENSE) · Linux amd64 for single-host integration · Windows amd64 for local console evaluation. [Beta scope](docs/BETA-SCOPE.md)

## ARTEX simulation and beta performance

November 18–19, 2026 · Owned synthetic environments

| Check | Result |
| --- | --- |
| **SDK authorization + edge verification** | Fixture data was exposed in **486 scenario rows** on the vulnerable baseline and **0** on protected paths. All **192/192** fixed normal controls returned the expected response. |
| **Luna defense transport follow-up** | **6 of 6** defense-only runs completed with `gpt-6-luna`. Containment plus assessment took **15.9–18.8 s** and release plus assessment took **17.5–22.3 s**. |
| **Linux beta candidate load** | At **100 requests/s** for about **3 minutes**, **18,000** protected HTTPS reads succeeded with **p99 223.9 ms**. |
| **Windows retained V2 candidate load** | Three local NVMe trials at **100 requests/s for 3 minutes** each returned **55,200/55,200** exact responses across all phases, with **zero 503s or timeouts** and p99 below **250 ms** in every phase. |

The simulation used explicit SDK, session, and ACL integration. Linux and Windows load results reflect their respective workloads. [Simulation scope and beta load conditions](docs/VALIDATION.md#november-18-artex-simulation) · [Luna and Qwen3 transport runs](docs/VALIDATION.md#november-19-defense-transport-follow-up)

## Quick start

### 1. Launch the console

With a trusted beta archive, verify the supplied SHA-256 checksum and extract the whole archive to a writable folder. Run `.\start.bat` on Windows or `sh start.sh` on Linux. The prebuilt console needs a browser.

To build from source, install Go 1.26 or newer and run the commands below from the checkout root.

**Windows PowerShell**

```powershell
.\build.bat
.\start.bat
```

**Linux**

```sh
sh build.sh
sh start.sh
```

### 2. Try the sample

The web console is available in Korean. The [Korean quick start](docs/QUICKSTART.ko.md) shows the exact menu and button labels.

1. Open the **full URL** printed in the terminal, including `#token=...`. The default address is `127.0.0.1:9081`.
2. Open **File analysis** and select **Try 12 sample events**, or upload the [sample JSONL](docs/examples/http-sample.jsonl).
3. Review the 12 analyzed events and their rule evidence. The sample stays isolated from live evidence and applies zero policies.

The console starts in observation mode. Keep the access link and sensor token private. [First-run checks and troubleshooting](docs/QUICKSTART.md)

### 3. Connect an application

- **Collect evidence.** In **Connection settings**, check the sensor ID, asset, tenants, and token. Send normalized events to `POST /v1/events`, or use `POST /v1/events/batch` for bulk input. Check **Overview**, **Events**, and **Alerts** after ingestion. [Sensor API and data contract (Korean)](docs/SENSOR.md)
- **Enable protection.** Register the routes to protect and connect the application SDK to its session, identity, and object ACL checks. [Protection contract (Korean)](docs/PROTECTION-CONTRACT.md) · [Session and ACL adapter (Korean)](docs/SESSION-ADAPTER.md) · [OIDC (Korean)](docs/OIDC-COVERAGE.md)
- **Investigate a case.** Synchronize evidence in **Incident memory**. For optional local AI analysis, select an installed, tool-capable Ollama model in **Qwen investigation**. [Local investigation and scoped response (Korean)](docs/LOCAL-QWEN.md)

### 4. Stop, back up, and recover

Press **Ctrl+C** and wait for the collector to exit. Back up `config.json` and the entire `data/` directory together. Use one writer per data directory and open the new access link after restart.

To check a stopped default collector store, run `.\reverse-artex.exe -recover-check -out data/collector` on Windows or `./reverse-artex -recover-check -out data/collector` on Linux. Preserve the original files and logs if recovery fails. [Storage and recovery (Korean)](docs/OPERATIONS.md)

## Features and compatibility

- **Evidence and detection:** authenticated HTTP collection, rule-based alerts, incident history, reviewed labels, and explicitly started shadow learning. [Capabilities (Korean)](docs/CAPABILITIES.md)
- **File analysis:** isolated JSONL analysis up to 1 MiB, 1,024 events, and 16 KiB per record. [File-analysis guide](docs/QUICKSTART.md#3-try-sample-and-file-analysis)
- **Optional integrations:** Python 3.10+ for the SDK, Ollama for local investigation, and PostgreSQL for the case API. The Docker Compose profile runs the collector API. Retained V2 journals support Linux and fixed local Windows NTFS volumes. Network-namespace isolation requires Linux. macOS has a source-build script and remains outside beta runtime qualification. [Compatibility](docs/COMPATIBILITY.md)

## Validation details

- **November 18:** the ARTEX run exercised SDK authorization, signed responses, and AI containment and release. Two AI runs ended early due to response-delivery or session-state failures. Windows remains scoped to local evaluation. [Current results and limits](docs/VALIDATION.md#november-18-artex-simulation)
- **November 15:** a historical Windows archive returned **954/954** exact normal responses and denied **69/69** prescribed checks without fixture exposure. Earlier Windows load failures are summarized with their original results. [Authorization evaluation](docs/VALIDATION.md#packaged-authorization-evaluation--2026-11-15) · [Windows load history](docs/VALIDATION.md#windows-operating-challenge--2026-11-15)
- **November 14:** a separate WSL2/ext4 trial at **100 requests/s** returned **360,000 HTTP 200 responses**, with **zero errors** and a whole-run **p99 of 198.867 ms**. Some 50-second windows exceeded 250 ms. [One-hour trial and configuration](docs/VALIDATION.md#earlier-completed-latency-qualification--2026-11-14)

## Documentation

- [Quick start](docs/QUICKSTART.md) · [Operations (Korean)](docs/OPERATIONS.md) · [Defense layers and the ARTEX simulator](docs/DEFENSE-LAYERS.md)
- [Release packaging](docs/RELEASING.md) · [Public release checklist](docs/PUBLIC-RELEASE-CHECKLIST.md) · [Changelog](CHANGELOG.md)
- [Security](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Third-party notices](THIRD_PARTY_NOTICES.md)

## License and provenance

Reverse Artex is a separate defensive project under the [MIT License](LICENSE). Its single-binary, embedded-console, and launcher layout draws on [ARTEX Global Edition](https://github.com/jiwoochris/artex-global).

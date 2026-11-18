# Quick start

This guide gets a local observation console running, analyzes synthetic sample events, and points to the contracts for real sensors. The beta defaults do not enable automatic blocking or host isolation. The web console is available in Korean. The [Korean guide](QUICKSTART.ko.md) shows the exact menu and button labels.

See the [public beta scope](BETA-SCOPE.md) for Linux single-host integration and the Windows local console evaluation package.

## 1. Install or build

Use a trusted beta archive for your operating system if one has been supplied. A public release download is not assumed. Extract the entire archive to a writable local folder; keep its configuration examples and documentation alongside the executable. Verify its checksums using the distributor's published values before running it. See [release packaging](RELEASING.md) for locally producing an archive.

For a source checkout, install **Go 1.26+** and run from the repository root. The first build may fetch Go modules. Do not copy the Windows `.exe` to Linux.

Windows PowerShell:

```powershell
.\build.bat
.\start.bat
```

Linux:

```sh
sh build.sh
sh start.sh
```

In a prebuilt archive, run just `.\start.bat` on Windows PowerShell or `sh start.sh` on Linux. The supplied release targets are **Windows amd64 and Linux amd64**; use a binary matching both your OS and architecture. No Go, Python, Node.js, database, or LLM is required for this basic workflow. A source build on macOS is possible via the shell script, but runtime qualification is not claimed for this beta.

A binary archive includes executables, selected integration source/configuration examples, and user documentation. It does not include the Go source tree, build scripts, Docker profile, or every development/validation report. Building, running `go run ./cmd/...`, or following the Docker profile requires a source checkout. Historical source-only references in packaged documentation are labeled as such. The included [validation summary](VALIDATION.md) explains the measured beta results; exact archive qualification is recorded separately from those feature tests.

## 2. Open and check the console

Open the exact URL printed by the process, including `#token=...`; by default it uses `http://127.0.0.1:9081`. Keep that URL private. Merely opening the bare address does not provide the console key.

First run creates `config.json` and `data/collector/` in the application folder. The sensor token persists in configuration; the console access key changes on restart. In **Overview** check that the collector is running. An empty event list is expected until you connect a sensor. Leave the terminal running.

If another local application uses the port, stop this instance and choose another loopback port:

```powershell
.\start.bat -listen 127.0.0.1:9091
```

Linux uses `sh start.sh -listen 127.0.0.1:9091`. Open the newly printed URL. Do not run two instances against the same data path.

## 3. Try sample and file analysis

1. Open **File analysis**.
2. Choose **Try 12 sample events**. Confirm the result reports 12 analyzed events and zero policy actions; inspect the rule evidence shown.
3. To exercise file upload, save [http-sample.jsonl](examples/http-sample.jsonl) as a local file, select it, and choose **Analyze file**. This is synthetic normalized HTTP data, not a production capture.
4. To analyze your own input, provide one complete normalized event per line in the [sensor schema (Korean)](SENSOR.md). Limits: 1 MiB per file, 1,024 events, 16 KiB per record. File analysis uses the recorded `ingest_time`, allowing time-ordered historical data.

These paths run in separate memory. They do not populate the live Events/Alerts views or Incident memory, call Ollama, or apply a policy. A file that produces no alert may still lack facts required by a rule; it is not a safety assessment.

## 4. Connect an authorized HTTP sensor

Open **Connection settings** and confirm the registered sensor ID, asset, tenant list, and sensor token. The shipped example uses `lab-app`, `lab-api`, and tenants `alpha`, `beta`, `public`. Your application/WAF adapter must normalize its observations and use the matching scope; the console does not automatically capture application traffic.

Submit JSON events to `POST http://127.0.0.1:9081/v1/events`, with `Content-Type: application/json` and `Authorization: Bearer <private sensor token>`. Batch input is a JSON array at `/v1/events/batch`. Keep time synchronized: live event timestamps must be within the accepted one-hour window. Do not upload the fixed historical sample to the live endpoint.

Read [the full sensor contract (Korean)](SENSOR.md) for required fields, HMAC identifiers, statuses, and host-event separation before implementing an adapter. Then check **Overview**, **Events**, and **Alerts** for actual observations. Sensor integration alone does not enable response policies.

## 5. Optional local-model investigation

Run your existing local Ollama service, normally at `http://127.0.0.1:11434`. Install and evaluate a tool-capable model separately; Reverse Artex does not download one. Hardware needs depend on that model.

For collected incidents, open **Incident memory**, synchronize collector evidence, and select an incident. In **Qwen investigation** select an installed model and start an analysis. Review its cited evidence and verified tool results. This flow is analysis-only by default and does not create a confirmed label or train a model. The menu name also covers supported local models other than Qwen.

Cancellation stops a running investigation but does not itself revoke an already-applied optional policy. See [local investigation and bounded response (Korean)](LOCAL-QWEN.md) before configuring response credentials. The file-analysis sample does not create an incident for this workflow.

## 6. Stop, back up, and restart

Press **Ctrl+C** in the running terminal and wait for exit. Back up private `config.json` and the complete `data/` directory together while stopped. Restart using the same start script and open the new access URL. Do not share one evidence directory between writers.

If startup reports evidence or recovery errors, preserve the original files and logs. With the process stopped, verify a default collector store without opening the console:

```powershell
.\reverse-artex.exe -recover-check -out data/collector
```

Linux: `./reverse-artex -recover-check -out data/collector`. This read/check path does not replace the procedures for separately configured shared storage or policy state. Do not delete data to bypass a recovery failure. See [operations (Korean)](OPERATIONS.md) for recovery, capacity, configuration precedence, optional services, and the API-only Docker profile.

## 7. Find optional CLI tools

The start script launches only the console/collector. Optional services and administrative tools are in `bin/`; read their help and integration contracts before configuring them. For example, from the extracted archive or built project root:

Windows PowerShell:

```powershell
.\bin\policy-edge.exe -h
```

Linux:

```sh
./bin/policy-edge -h
```

Use the matching executable when a source-oriented guide shows `go run ./cmd/policy-edge`; retain only the arguments supported by that executable's current help. Starting a policy service is separate from routing application traffic through it and integrating application authorization. See [operations (Korean)](OPERATIONS.md) and [capabilities (Korean)](CAPABILITIES.md).

## Common first-run problems

| Symptom | Action |
| --- | --- |
| Binary missing | Build for this OS, or extract the complete matching archive. |
| Browser cannot connect | Keep the process running; use the newly printed URL and actual port. Review the terminal's startup error. |
| Console access rejected | Open the full current access URL. A prior process's console key and the sensor token are not interchangeable. |
| Live input returns 400/403 | Check the full schema, current timestamps, and registered sensor/tenant/asset scope. |
| No events after sample analysis | Expected: sample/file analysis does not write the collector journal. Connect a real authorized adapter. |
| Ollama unavailable/no eligible model | Basic collection still works. Start the local service and select an already installed tool-capable model. |
| Store full or recovery fails | Stop and preserve the store; inspect [operations (Korean)](OPERATIONS.md). Do not silently remove evidence. |

Read [compatibility and limitations](COMPATIBILITY.md) and [security](../SECURITY.md) before extending the local setup.

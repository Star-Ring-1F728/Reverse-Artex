param([switch]$AllTools)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if (-not (Get-Command go -ErrorAction SilentlyContinue)) { throw 'Go 1.26+ is required to build; running the prebuilt app does not require Go.' }
New-Item -ItemType Directory -Path 'bin' -Force | Out-Null
& go build -trimpath '-ldflags=-s -w' -o reverse-artex.exe ./cmd/reverse-artex
if ($LASTEXITCODE -ne 0) { throw 'Reverse Artex build failed' }
$releaseTools = @('policy-control','policy-edge','case-api','case-ledger','case-snapshot','case-source-check','source-ledger','control-audit-sync','incident-sync','incident-export','incident-plan','incident-retention','defense-analyzer','defense-mode','defense-v2','decisions-check','decisions-connect','proposal-check','approval-gate','action-execute','host-response','learning-control','learning-evaluate','learning-context','learning-context-prepare','learning-context-quality','learning-context-release','learning-context-canary','learning-context-production','context-shadow')
if ($AllTools) { $releaseTools = @(Get-ChildItem -LiteralPath cmd -Directory | Where-Object Name -ne 'reverse-artex' | Select-Object -ExpandProperty Name) }
foreach ($tool in $releaseTools) {
  & go build -trimpath '-ldflags=-s -w' -o "bin/$tool.exe" "./cmd/$tool"
  if ($LASTEXITCODE -ne 0) { throw "Build failed: $tool" }
}
Write-Output 'Build complete. Run start.bat and open the access URL printed by the app.'

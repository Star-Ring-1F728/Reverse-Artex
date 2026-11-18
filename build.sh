#!/usr/bin/env sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
command -v go >/dev/null 2>&1 || { echo 'Go 1.26+ required' >&2; exit 1; }
mkdir -p bin
suffix=''
if [ "$(go env GOOS)" = windows ]; then suffix=.exe; fi
go build -trimpath '-ldflags=-s -w' -o "reverse-artex${suffix}" ./cmd/reverse-artex
for tool in policy-control policy-edge case-api case-ledger case-snapshot case-source-check source-ledger control-audit-sync incident-sync incident-export incident-plan incident-retention defense-analyzer defense-mode defense-v2 decisions-check decisions-connect proposal-check approval-gate action-execute host-response learning-control learning-evaluate learning-context learning-context-prepare learning-context-quality learning-context-release learning-context-canary learning-context-production context-shadow; do
  go build -trimpath '-ldflags=-s -w' -o "bin/${tool}${suffix}" "./cmd/${tool}"
done
echo 'Build complete. Run sh start.sh.'

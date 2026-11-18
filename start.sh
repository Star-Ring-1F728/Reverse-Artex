#!/usr/bin/env sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [ ! -x ./reverse-artex ]; then
  echo "Reverse Artex binary not found. Run sh build.sh first." >&2
  exit 1
fi
exec ./reverse-artex -console -config config.json "$@"

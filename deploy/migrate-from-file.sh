#!/usr/bin/env bash
# Copy secrets from a running secrets-file gRPC endpoint into secrets-vault.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SOURCE_ADDR="${SOURCE_ADDR:-127.0.0.1:9550}"
DEST_ADDR="${DEST_ADDR:-127.0.0.1:9551}"
MUXCORE_INSECURE="${MUXCORE_INSECURE:-true}"

echo "==> migrate secrets-file (${SOURCE_ADDR}) -> secrets-vault (${DEST_ADDR})"
nix-shell -p go --run "go run ./cmd/migrate --source ${SOURCE_ADDR} --dest ${DEST_ADDR} --insecure=${MUXCORE_INSECURE}"

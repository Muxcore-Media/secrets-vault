#!/usr/bin/env bash
# Start local OpenBao via deploy/docker-compose.yml and exercise KV v2 CRUD.
# Skips cleanly when Docker is unavailable.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export PATH="${HOME}/.local/go/bin:${PATH:-}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found — skipping OpenBao compose smoke"
  echo "Unit tests: nix-shell -p go --run 'go test ./...'"
  exit 0
fi

if ! docker info >/dev/null 2>&1; then
  echo "docker daemon not reachable — skipping OpenBao compose smoke"
  exit 0
fi

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-secrets-vault-openbao}"

cleanup() {
  docker compose -f deploy/docker-compose.yml stop openbao >/dev/null 2>&1 || true
  docker compose -f deploy/docker-compose.yml rm -f openbao >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> docker compose up (OpenBao on 127.0.0.1:8200)"
docker compose -f deploy/docker-compose.yml up -d --wait openbao

export VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
export VAULT_TOKEN="${VAULT_TOKEN:-root}"
export VAULT_SKIP_VERIFY=true

echo "==> go test OpenBao smoke"
nix-shell -p go --run 'go test -count=1 -timeout 5m ./internal/backend/vault/ -run TestOpenBaoComposeSmoke -v'

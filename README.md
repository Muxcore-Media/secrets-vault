# Secrets Vault

[![CI](https://git.zem.systems/muxcore/secrets-vault/actions/workflows/ci.yml/badge.svg)](https://git.zem.systems/muxcore/secrets-vault/actions)
[![Go Version](https://img.shields.io/badge/Go-1.26-blue)](https://go.dev/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

**Multi-provider secrets sidecar for MuxCore** — Vault/OpenBao, Infisical, AWS Secrets Manager, GCP Secret Manager, and Azure Key Vault behind the existing `SecretsService` gRPC contract.

Does **not** replace [`secrets-file`](https://git.zem.systems/muxcore/secrets-file). Run **only one** module advertising the `secrets` capability per mesh.

---

## How It Works

```
muxcored ──DialSecretsProvider──▶ secrets-vault (gRPC)
                                       │
                                       ▼
                                    Backend
                          ┌───────────┼───────────┐
                       Vault      Infisical    AWS/GCP/Azure
                     (OpenBao)
```

Flat MuxCore keys (e.g. `api_key`) are namespaced with `SECRETS_PREFIX` (default `muxcore/`) before talking to the provider.

Admin settings (`backend`, `prefix`) reconnect the active provider at runtime. **Provider credentials are read from process environment only** — they are not stored in module settings.

---

## Backend matrix

| `SECRETS_BACKEND` | Provider | Auth | Notes |
|-------------------|----------|------|-------|
| `vault` | HashiCorp Vault **or OpenBao** KV v2 | `VAULT_TOKEN` or AppRole | Same HTTP API; official `vault/api` client |
| `infisical` | Infisical | Universal Auth or token | REST `/api/v3/secrets/raw` |
| `aws` | AWS Secrets Manager | Default AWS credential chain | Optional `AWS_SECRETS_REGION`; see delete recovery below |
| `gcp` | GCP Secret Manager | ADC / service account | Requires `GCP_PROJECT_ID`; `/` → `-` in IDs |
| `azure` | Azure Key Vault | Default Azure credential | Requires `AZURE_KEY_VAULT_URL`; `/` → `-` in names |

All backends support Get / Set / Delete / List in v1 where the API allows. IAM/policy failures map to gRPC `PermissionDenied` / `FailedPrecondition`. **Secret values are never logged** — only key names and errors.

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRETS_BACKEND` | _(required)_ | `vault` \| `infisical` \| `aws` \| `gcp` \| `azure` |
| `SECRETS_PREFIX` | `muxcore/` | Key namespace prefix |
| `SECRETS_GRPC_ADDR` | `127.0.0.1:9551` | gRPC listen address |

### Vault / OpenBao

| Variable | Description |
|----------|-------------|
| `VAULT_ADDR` | API address (required) |
| `VAULT_TOKEN` | Token auth |
| `VAULT_ROLE_ID` / `VAULT_SECRET_ID` | AppRole auth (alternative to token; auto-renewed) |
| `VAULT_KV_MOUNT` | KV v2 mount (default `secret`) |
| `VAULT_SKIP_VERIFY` | Skip TLS verify (`true`/`1`) |

OpenBao speaks the Vault HTTP API; point `VAULT_ADDR` at OpenBao — no separate SDK.

### Infisical

| Variable | Description |
|----------|-------------|
| `INFISICAL_API_URL` | API base (default `https://app.infisical.com`) |
| `INFISICAL_PROJECT_ID` | Project / workspace id |
| `INFISICAL_ENV` | Environment slug (default `dev`) |
| `INFISICAL_TOKEN` | Bearer token |
| `INFISICAL_CLIENT_ID` / `INFISICAL_CLIENT_SECRET` | Universal Auth |

### AWS

Standard AWS SDK env/role/instance profile. Optional `AWS_SECRETS_REGION`.

Delete uses the AWS recovery window by default (secret can be restored). Set `AWS_SECRETS_FORCE_DELETE=true` to force immediate deletion without recovery.

### GCP

`GCP_PROJECT_ID` plus Application Default Credentials (`GOOGLE_APPLICATION_CREDENTIALS` or workload identity).

### Azure

`AZURE_KEY_VAULT_URL` (e.g. `https://my-vault.vault.azure.net/`) plus Default Azure Credential.

---

## Quick Start

### Local binary (Vault / OpenBao)

```bash
go build -o secrets-vault ./cmd/module

export MUXCORE_INSECURE_DISABLE_TLS=true
export SECRETS_BACKEND=vault
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=dev-root-token
export SECRETS_GRPC_ADDR=127.0.0.1:9551
./secrets-vault --muxcore-mesh-addr localhost:9090
```

### Docker Compose (core + OpenBao + secrets-vault)

`deploy/docker-compose.yml` starts OpenBao in dev mode, core, and this module with:

- `SECRETS_BACKEND=vault`
- `VAULT_ADDR=http://openbao:8200`
- `VAULT_TOKEN=root`

OpenBao KV smoke (Get/Set/Delete/List/Ping):

```bash
bash deploy/run-openbao-smoke.sh
```

---

## Migrate from secrets-file

When swapping `secrets-file` → `secrets-vault`, copy keys from the file backend gRPC endpoint into this module:

```bash
# secrets-file on :9550, secrets-vault on :9551
bash deploy/migrate-from-file.sh

# or
go run ./cmd/migrate --source 127.0.0.1:9550 --dest 127.0.0.1:9551
```

Both modules must be running and reachable. Then stop `secrets-file`, enable `MVP_ENABLE_SECRETS_VAULT=1`, and restart the mesh.

---

## Capabilities

- `secrets` — SecretsProvider contract
- `secrets.vault` — multi-provider vault module marker
- `settings` — runtime backend/prefix selection (credentials stay in env)

## License

GPL-3.0

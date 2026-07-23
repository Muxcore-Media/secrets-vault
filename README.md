# Secrets Vault

[![CI](https://github.com/Muxcore-Media/secrets-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/Muxcore-Media/secrets-vault/actions)
[![Go Version](https://img.shields.io/badge/Go-1.26-blue)](https://go.dev/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

**Multi-provider secrets sidecar for MuxCore** — Vault/OpenBao, Infisical, AWS Secrets Manager, GCP Secret Manager, and Azure Key Vault behind the existing `SecretsService` gRPC contract.

Does **not** replace [`secrets-file`](https://github.com/Muxcore-Media/secrets-file). Run **only one** module advertising the `secrets` capability per mesh.

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

---

## Backend matrix

| `SECRETS_BACKEND` | Provider | Auth | Notes |
|-------------------|----------|------|-------|
| `vault` | HashiCorp Vault **or OpenBao** KV v2 | `VAULT_TOKEN` or AppRole | Same HTTP API; official `vault/api` client |
| `infisical` | Infisical | Universal Auth or token | REST `/api/v3/secrets/raw` |
| `aws` | AWS Secrets Manager | Default AWS credential chain | Optional `AWS_SECRETS_REGION` |
| `gcp` | GCP Secret Manager | ADC / service account | Requires `GCP_PROJECT_ID`; `/` → `-` in IDs |
| `azure` | Azure Key Vault | Default Azure credential | Requires `AZURE_KEY_VAULT_URL`; `/` → `-` in names |

All backends support Get / Set / Delete / List in v1 where the API allows. IAM/policy failures map to gRPC `PermissionDenied` / `FailedPrecondition`. **Secret values are never logged** — only key names and errors.

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRETS_BACKEND` | _(required)_ | `vault` \| `infisical` \| `aws` \| `gcp` \| `azure` |
| `SECRETS_PREFIX` | `muxcore/` | Key namespace prefix |
| `SECRETS_GRPC_ADDR` | `:9500` | gRPC listen address |

### Vault / OpenBao

| Variable | Description |
|----------|-------------|
| `VAULT_ADDR` | API address (required) |
| `VAULT_TOKEN` | Token auth |
| `VAULT_ROLE_ID` / `VAULT_SECRET_ID` | AppRole auth (alternative to token) |
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

### GCP

`GCP_PROJECT_ID` plus Application Default Credentials (`GOOGLE_APPLICATION_CREDENTIALS` or workload identity).

### Azure

`AZURE_KEY_VAULT_URL` (e.g. `https://my-vault.vault.azure.net/`) plus Default Azure Credential.

---

## Quick Start

```bash
go build -o secrets-vault ./cmd/module

export MUXCORE_INSECURE_DISABLE_TLS=true
export SECRETS_BACKEND=vault
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=dev-token
./secrets-vault --muxcore-mesh-addr localhost:9090
```

---

## Capabilities

- `secrets` — SecretsProvider contract
- `secrets.vault` — multi-provider vault module marker

## License

GPL-3.0

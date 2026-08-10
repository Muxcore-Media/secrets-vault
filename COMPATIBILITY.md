# Compatibility

Requires MuxCore `core` ≥ 0.4.0 with `SecretsService` gRPC (`muxcore.secrets.v1`).

## Multi-backend (no embedded server)

This module is a **client sidecar only**. It does **not** embed Vault, OpenBao, Infisical, or any cloud secrets service. Operators must run (or subscribe to) an external backend and set `SECRETS_BACKEND` plus that provider’s env vars.

| Backend | MuxCore capability | External dependency |
|---------|--------------------|---------------------|
| `vault` | `secrets` | HashiCorp Vault **or OpenBao** KV v2 HTTP API |
| `infisical` | `secrets` | Infisical API |
| `aws` | `secrets` | AWS Secrets Manager |
| `gcp` | `secrets` | GCP Secret Manager |
| `azure` | `secrets` | Azure Key Vault |

**Mutual exclusion:** advertise only one `secrets` provider per mesh. Prefer [`secrets-file`](https://github.com/Muxcore-Media/secrets-file) for local/dev; use `secrets-vault` when secrets live in an external KMS/secrets manager.

Flat MuxCore keys are prefixed with `SECRETS_PREFIX` (default `muxcore/`) before provider calls. IAM/policy failures map to gRPC `PermissionDenied` / `FailedPrecondition`. Secret **values** are never logged.

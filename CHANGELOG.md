# Changelog

## [0.1.1] - 2026-08-10

### Added

- SettingsProvider for `backend` / `prefix` (`SECRETS_BACKEND` / `SECRETS_PREFIX`) with live backend reconnect via `ReplaceBackend`
- Advertises `settings` capability for admin-ui discovery

## [Unreleased]

## 0.1.0

- Initial multi-provider SecretsService sidecar (Vault/OpenBao, Infisical, AWS, GCP, Azure).
- COMPATIBILITY: multi-backend matrix; no embedded secrets server; mutual exclusion with `secrets-file`.

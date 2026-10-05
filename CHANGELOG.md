# Changelog

## [0.1.1] - 2026-08-10

### Added

- SettingsProvider for `backend` / `prefix` (`SECRETS_BACKEND` / `SECRETS_PREFIX`) with live backend reconnect via `ReplaceBackend`
- Advertises `settings` capability for admin-ui discovery

## [0.1.3] - 2026-10-05


### Changed
- Reported version comes from muxcore.json (ADR-0021); built on core v0.6.12 / sdk/go/module v0.6.3 (mesh enrollment, ADR-0017).

## [0.1.2] - 2026-10-05

### Changed
- CI runs on GitHub-hosted runners from the umbrella template; retired-origin workflows removed.
- Dependencies resolve from published GitHub tags (no filesystem `replace`); requires core v0.6.0.

## 0.1.0

- Initial multi-provider SecretsService sidecar (Vault/OpenBao, Infisical, AWS, GCP, Azure).
- COMPATIBILITY: multi-backend matrix; no embedded secrets server; mutual exclusion with `secrets-file`.

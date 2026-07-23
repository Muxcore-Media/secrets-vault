# Contributing to secrets-vault

## Development Setup

### Prerequisites

- Go 1.26.x
- golangci-lint (optional but recommended)

### Clone and build

```bash
git clone https://github.com/Muxcore-Media/secrets-vault.git
cd secrets-vault
# sibling checkout of core required for replace directives
make build
```

### Run against a local muxcored

```bash
# Terminal 1: start core in dev mode
cd ../core
MUXCORE_INSECURE_DISABLE_TLS=true ./muxcored

# Terminal 2: start module
make build
export MUXCORE_INSECURE_DISABLE_TLS=true
export SECRETS_BACKEND=vault
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=dev-token
MUXCORE_GRPC_ADDR=localhost:9090 ./secrets-vault
```

## Running Tests

```bash
make test
```

Tests must not depend on a running muxcored instance. Use mocks / httptest where needed.
Cloud backends require live credentials for integration; unit tests use fakes.

## Linting

```bash
make lint
```

## License

By contributing, you agree that your contributions will be licensed under the GPL-3.0 License.

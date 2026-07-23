package backend

import (
	"context"
	"errors"
	"strings"
)

var (
	ErrNotFound         = errors.New("secret not found")
	ErrEmptyKey         = errors.New("secret key must not be empty")
	ErrPermissionDenied = errors.New("permission denied")
	ErrUnsupported      = errors.New("operation not supported")
)

// Backend stores and retrieves secrets from an external provider.
type Backend interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string) error
	Delete(ctx context.Context, key string) error
	List(ctx context.Context) ([]string, error)
	Ping(ctx context.Context) error
	Close() error
}

const (
	BackendVault     = "vault"
	BackendInfisical = "infisical"
	BackendAWS       = "aws"
	BackendGCP       = "gcp"
	BackendAzure     = "azure"
)

// DefaultPrefix is applied when SECRETS_PREFIX is unset.
const DefaultPrefix = "muxcore/"

// PrefixedName joins prefix and key without duplicating separators.
func PrefixedName(prefix, key string) string {
	if prefix == "" {
		return key
	}
	if strings.HasSuffix(prefix, "/") {
		return prefix + key
	}
	return prefix + "/" + key
}

// StripPrefix removes prefix from a provider name when present.
func StripPrefix(prefix, name string) (string, bool) {
	if prefix == "" {
		return name, true
	}
	p := prefix
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	if !strings.HasPrefix(name, p) {
		if name == strings.TrimSuffix(p, "/") {
			return "", true
		}
		return "", false
	}
	return strings.TrimPrefix(name, p), true
}

package internal

import (
	"context"
	"fmt"
	"strings"

	"github.com/Muxcore-Media/secrets-vault/internal/backend"
	"github.com/Muxcore-Media/secrets-vault/internal/backend/aws"
	"github.com/Muxcore-Media/secrets-vault/internal/backend/azure"
	"github.com/Muxcore-Media/secrets-vault/internal/backend/gcp"
	"github.com/Muxcore-Media/secrets-vault/internal/backend/infisical"
	"github.com/Muxcore-Media/secrets-vault/internal/backend/vault"
)

func newBackend(ctx context.Context, name, prefix string) (backend.Backend, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case backend.BackendVault:
		return vault.NewFromEnv(ctx, prefix)
	case backend.BackendInfisical:
		return infisical.NewFromEnv(ctx, prefix)
	case backend.BackendAWS:
		return aws.NewFromEnv(ctx, prefix)
	case backend.BackendGCP:
		return gcp.NewFromEnv(ctx, prefix)
	case backend.BackendAzure:
		return azure.NewFromEnv(ctx, prefix)
	default:
		return nil, fmt.Errorf("unknown SECRETS_BACKEND %q (vault|infisical|aws|gcp|azure)", name)
	}
}

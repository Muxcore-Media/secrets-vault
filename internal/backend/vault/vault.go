package vault

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/Muxcore-Media/secrets-vault/internal/backend"
)

// Client implements backend.Backend against Vault/OpenBao KV v2.
type Client struct {
	client *vaultapi.Client
	mount  string
	prefix string
}

// NewFromEnv builds a Vault/OpenBao client from environment variables.
func NewFromEnv(ctx context.Context, prefix string) (*Client, error) {
	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		return nil, fmt.Errorf("VAULT_ADDR is required")
	}
	mount := os.Getenv("VAULT_KV_MOUNT")
	if mount == "" {
		mount = "secret"
	}

	cfg := vaultapi.DefaultConfig()
	cfg.Address = addr
	if err := cfg.ReadEnvironment(); err != nil {
		return nil, fmt.Errorf("vault config: %w", err)
	}
	if skip := os.Getenv("VAULT_SKIP_VERIFY"); skip == "true" || skip == "1" {
		tlsCfg := &vaultapi.TLSConfig{Insecure: true}
		if err := cfg.ConfigureTLS(tlsCfg); err != nil {
			return nil, fmt.Errorf("vault tls: %w", err)
		}
	}

	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("vault client: %w", err)
	}

	token := os.Getenv("VAULT_TOKEN")
	roleID := os.Getenv("VAULT_ROLE_ID")
	secretID := os.Getenv("VAULT_SECRET_ID")
	switch {
	case token != "":
		client.SetToken(token)
	case roleID != "" && secretID != "":
		secret, err := client.Logical().WriteWithContext(ctx, "auth/approle/login", map[string]interface{}{
			"role_id":   roleID,
			"secret_id": secretID,
		})
		if err != nil {
			return nil, fmt.Errorf("vault approle login: %w", err)
		}
		if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
			return nil, fmt.Errorf("vault approle login: empty token")
		}
		client.SetToken(secret.Auth.ClientToken)
	default:
		return nil, fmt.Errorf("set VAULT_TOKEN or VAULT_ROLE_ID and VAULT_SECRET_ID")
	}

	return &Client{client: client, mount: mount, prefix: prefix}, nil
}

// NewWithClient is used by tests.
func NewWithClient(client *vaultapi.Client, mount, prefix string) *Client {
	return &Client{client: client, mount: mount, prefix: prefix}
}

func (c *Client) pathFor(key string) string {
	return strings.Trim(backend.PrefixedName(c.prefix, key), "/")
}

func (c *Client) Get(ctx context.Context, key string) (string, error) {
	if key == "" {
		return "", backend.ErrEmptyKey
	}
	secret, err := c.client.KVv2(c.mount).Get(ctx, c.pathFor(key))
	if err != nil {
		return "", mapVaultErr(err)
	}
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("%w: %s", backend.ErrNotFound, key)
	}
	if v, ok := secret.Data["value"]; ok {
		return fmt.Sprint(v), nil
	}
	if v, ok := secret.Data["data"]; ok {
		return fmt.Sprint(v), nil
	}
	for _, v := range secret.Data {
		return fmt.Sprint(v), nil
	}
	return "", fmt.Errorf("%w: %s", backend.ErrNotFound, key)
}

func (c *Client) Set(ctx context.Context, key, value string) error {
	if key == "" {
		return backend.ErrEmptyKey
	}
	_, err := c.client.KVv2(c.mount).Put(ctx, c.pathFor(key), map[string]interface{}{
		"value": value,
	})
	return mapVaultErr(err)
}

func (c *Client) Delete(ctx context.Context, key string) error {
	if key == "" {
		return backend.ErrEmptyKey
	}
	err := c.client.KVv2(c.mount).Delete(ctx, c.pathFor(key))
	return mapVaultErr(err)
}

func (c *Client) List(ctx context.Context) ([]string, error) {
	listPath := strings.Trim(c.prefix, "/")
	full := path.Join(c.mount, "metadata", listPath)
	secret, err := c.client.Logical().ListWithContext(ctx, full)
	if err != nil {
		return nil, mapVaultErr(err)
	}
	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}
	raw, _ := secret.Data["keys"].([]interface{})
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		name, ok := item.(string)
		if !ok || name == "" || strings.HasSuffix(name, "/") {
			continue
		}
		fullName := path.Join(listPath, name)
		if key, ok := backend.StripPrefix(c.prefix, fullName); ok && key != "" {
			out = append(out, key)
		} else if c.prefix == "" {
			out = append(out, name)
		}
	}
	return out, nil
}

func (c *Client) Ping(ctx context.Context) error {
	_, err := c.client.Sys().HealthWithContext(ctx)
	return mapVaultErr(err)
}

func (c *Client) Close() error {
	return nil
}

func mapVaultErr(err error) error {
	if err == nil {
		return nil
	}
	var respErr *vaultapi.ResponseError
	if errors.As(err, &respErr) {
		switch respErr.StatusCode {
		case 403, 401:
			return fmt.Errorf("%w: %v", backend.ErrPermissionDenied, err)
		case 404:
			return fmt.Errorf("%w: %v", backend.ErrNotFound, err)
		}
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "permission denied") || strings.Contains(msg, "forbidden") {
		return fmt.Errorf("%w: %v", backend.ErrPermissionDenied, err)
	}
	if strings.Contains(msg, "not found") || strings.Contains(msg, "no value found") {
		return fmt.Errorf("%w: %v", backend.ErrNotFound, err)
	}
	return err
}

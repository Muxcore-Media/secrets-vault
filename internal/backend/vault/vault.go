package vault

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"strings"
	"sync"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/Muxcore-Media/secrets-vault/internal/backend"
)

// Client implements backend.Backend against Vault/OpenBao KV v2.
type Client struct {
	client    *vaultapi.Client
	mount     string
	prefix    string
	stopRenew context.CancelFunc
	renewWg   sync.WaitGroup
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
	var loginSecret *vaultapi.Secret
	switch {
	case token != "":
		client.SetToken(token)
	case roleID != "" && secretID != "":
		loginSecret, err = client.Logical().WriteWithContext(ctx, "auth/approle/login", map[string]interface{}{
			"role_id":   roleID,
			"secret_id": secretID,
		})
		if err != nil {
			return nil, fmt.Errorf("vault approle login: %w", err)
		}
		if loginSecret == nil || loginSecret.Auth == nil || loginSecret.Auth.ClientToken == "" {
			return nil, fmt.Errorf("vault approle login: empty token")
		}
		client.SetToken(loginSecret.Auth.ClientToken)
	default:
		return nil, fmt.Errorf("set VAULT_TOKEN or VAULT_ROLE_ID and VAULT_SECRET_ID")
	}

	c := &Client{client: client, mount: mount, prefix: prefix}
	if loginSecret != nil {
		if err := c.startTokenRenewal(loginSecret); err != nil {
			return nil, fmt.Errorf("vault token renewal: %w", err)
		}
	}
	return c, nil
}

func (c *Client) startTokenRenewal(loginSecret *vaultapi.Secret) error {
	if loginSecret.Auth == nil || !loginSecret.Auth.Renewable {
		return nil
	}
	watcher, err := c.client.NewLifetimeWatcher(&vaultapi.LifetimeWatcherInput{
		Secret: loginSecret,
	})
	if err != nil {
		return err
	}
	renewCtx, cancel := context.WithCancel(context.Background())
	c.stopRenew = cancel
	c.renewWg.Add(1)
	go func() {
		defer c.renewWg.Done()
		go watcher.Start()
		defer watcher.Stop()
		for {
			select {
			case <-renewCtx.Done():
				return
			case err := <-watcher.DoneCh():
				if err != nil && !errors.Is(err, context.Canceled) {
					slog.Error("vault token renewal stopped", "error", err)
				}
				return
			case renewal := <-watcher.RenewCh():
				if renewal != nil && renewal.Secret != nil && renewal.Secret.Auth != nil && renewal.Secret.Auth.ClientToken != "" {
					c.client.SetToken(renewal.Secret.Auth.ClientToken)
				}
			}
		}
	}()
	return nil
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
	return c.listRecursive(ctx, listPath)
}

func (c *Client) listRecursive(ctx context.Context, relPath string) ([]string, error) {
	full := path.Join(c.mount, "metadata", relPath)
	secret, err := c.client.Logical().ListWithContext(ctx, full)
	if err != nil {
		return nil, mapVaultErr(err)
	}
	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}
	raw, _ := secret.Data["keys"].([]interface{})
	var out []string
	for _, item := range raw {
		name, ok := item.(string)
		if !ok || name == "" {
			continue
		}
		childRel := path.Join(relPath, name)
		if strings.HasSuffix(name, "/") {
			childRel = strings.TrimSuffix(childRel, "/")
			nested, err := c.listRecursive(ctx, childRel)
			if err != nil {
				return nil, err
			}
			out = append(out, nested...)
			continue
		}
		if key, ok := backend.StripPrefix(c.prefix, childRel); ok && key != "" {
			out = append(out, key)
		} else if c.prefix == "" {
			out = append(out, path.Join(relPath, name))
		}
	}
	return out, nil
}

func (c *Client) Ping(ctx context.Context) error {
	_, err := c.client.Sys().HealthWithContext(ctx)
	return mapVaultErr(err)
}

func (c *Client) Close() error {
	if c.stopRenew != nil {
		c.stopRenew()
		c.renewWg.Wait()
		c.stopRenew = nil
	}
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

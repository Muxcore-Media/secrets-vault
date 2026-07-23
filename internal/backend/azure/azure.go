package azure

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/Muxcore-Media/secrets-vault/internal/backend"
)

// Client implements backend.Backend against Azure Key Vault.
type Client struct {
	client *azsecrets.Client
	prefix string
}

// NewFromEnv builds an Azure Key Vault secrets client.
func NewFromEnv(ctx context.Context, prefix string) (*Client, error) {
	vaultURL := os.Getenv("AZURE_KEY_VAULT_URL")
	if vaultURL == "" {
		return nil, fmt.Errorf("AZURE_KEY_VAULT_URL is required")
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure credential: %w", err)
	}
	client, err := azsecrets.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure key vault client: %w", err)
	}
	_ = ctx
	return &Client{client: client, prefix: prefix}, nil
}

func sanitizeName(name string) string {
	r := strings.NewReplacer("/", "-", " ", "-", "_", "-")
	out := r.Replace(name)
	var b strings.Builder
	for _, ch := range out {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' {
			b.WriteRune(ch)
		}
	}
	s := b.String()
	if s == "" {
		return "secret"
	}
	return s
}

func (c *Client) name(key string) string {
	return sanitizeName(backend.PrefixedName(c.prefix, key))
}

func (c *Client) Get(ctx context.Context, key string) (string, error) {
	if key == "" {
		return "", backend.ErrEmptyKey
	}
	resp, err := c.client.GetSecret(ctx, c.name(key), "", nil)
	if err != nil {
		return "", mapAzureErr(err)
	}
	if resp.Value == nil {
		return "", fmt.Errorf("%w: %s", backend.ErrNotFound, key)
	}
	return *resp.Value, nil
}

func (c *Client) Set(ctx context.Context, key, value string) error {
	if key == "" {
		return backend.ErrEmptyKey
	}
	_, err := c.client.SetSecret(ctx, c.name(key), azsecrets.SetSecretParameters{Value: &value}, nil)
	return mapAzureErr(err)
}

func (c *Client) Delete(ctx context.Context, key string) error {
	if key == "" {
		return backend.ErrEmptyKey
	}
	_, err := c.client.DeleteSecret(ctx, c.name(key), nil)
	return mapAzureErr(err)
}

func (c *Client) List(ctx context.Context) ([]string, error) {
	pager := c.client.NewListSecretPropertiesPager(nil)
	wantPrefix := sanitizeName(strings.TrimSuffix(c.prefix, "/"))
	var out []string
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, mapAzureErr(err)
		}
		for _, item := range page.Value {
			if item == nil || item.ID == nil {
				continue
			}
			id := item.ID.Name()
			if wantPrefix != "" && !strings.HasPrefix(id, wantPrefix) {
				continue
			}
			key := strings.TrimPrefix(id, wantPrefix+"-")
			if wantPrefix != "" && key == id {
				key = strings.TrimPrefix(id, wantPrefix)
				key = strings.TrimPrefix(key, "-")
			}
			if key != "" {
				out = append(out, key)
			}
		}
	}
	return out, nil
}

func (c *Client) Ping(ctx context.Context) error {
	pager := c.client.NewListSecretPropertiesPager(nil)
	if pager.More() {
		_, err := pager.NextPage(ctx)
		return mapAzureErr(err)
	}
	return nil
}

func (c *Client) Close() error {
	return nil
}

func mapAzureErr(err error) error {
	if err == nil {
		return nil
	}
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		switch respErr.StatusCode {
		case 404:
			return fmt.Errorf("%w: %v", backend.ErrNotFound, err)
		case 401, 403:
			return fmt.Errorf("%w: %v", backend.ErrPermissionDenied, err)
		}
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "not found") || strings.Contains(msg, "secretenotfound") {
		return fmt.Errorf("%w: %v", backend.ErrNotFound, err)
	}
	if strings.Contains(msg, "forbidden") || strings.Contains(msg, "unauthorized") {
		return fmt.Errorf("%w: %v", backend.ErrPermissionDenied, err)
	}
	return err
}

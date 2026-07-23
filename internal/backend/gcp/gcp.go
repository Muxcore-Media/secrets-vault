package gcp

import (
	"context"
	"fmt"
	"os"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Muxcore-Media/secrets-vault/internal/backend"
)

type api interface {
	AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error)
	CreateSecret(ctx context.Context, req *secretmanagerpb.CreateSecretRequest) (*secretmanagerpb.Secret, error)
	AddSecretVersion(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest) (*secretmanagerpb.SecretVersion, error)
	DeleteSecret(ctx context.Context, req *secretmanagerpb.DeleteSecretRequest) error
	ListSecrets(ctx context.Context, req *secretmanagerpb.ListSecretsRequest) SecretIterator
	Close() error
}

// SecretIterator abstracts the GCP secret list iterator for tests.
type SecretIterator interface {
	Next() (*secretmanagerpb.Secret, error)
}

type liveAPI struct {
	c *secretmanager.Client
}

func (a *liveAPI) AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	return a.c.AccessSecretVersion(ctx, req)
}
func (a *liveAPI) CreateSecret(ctx context.Context, req *secretmanagerpb.CreateSecretRequest) (*secretmanagerpb.Secret, error) {
	return a.c.CreateSecret(ctx, req)
}
func (a *liveAPI) AddSecretVersion(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest) (*secretmanagerpb.SecretVersion, error) {
	return a.c.AddSecretVersion(ctx, req)
}
func (a *liveAPI) DeleteSecret(ctx context.Context, req *secretmanagerpb.DeleteSecretRequest) error {
	return a.c.DeleteSecret(ctx, req)
}
func (a *liveAPI) ListSecrets(ctx context.Context, req *secretmanagerpb.ListSecretsRequest) SecretIterator {
	return a.c.ListSecrets(ctx, req)
}
func (a *liveAPI) Close() error { return a.c.Close() }

// Client implements backend.Backend against GCP Secret Manager.
type Client struct {
	api     api
	project string
	prefix  string
}

// NewFromEnv builds a GCP Secret Manager client.
func NewFromEnv(ctx context.Context, prefix string) (*Client, error) {
	project := os.Getenv("GCP_PROJECT_ID")
	if project == "" {
		return nil, fmt.Errorf("GCP_PROJECT_ID is required")
	}
	c, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp secretmanager client: %w", err)
	}
	return &Client{api: &liveAPI{c: c}, project: project, prefix: prefix}, nil
}

// NewWithAPI is used by tests.
func NewWithAPI(a api, project, prefix string) *Client {
	return &Client{api: a, project: project, prefix: prefix}
}

func sanitizeID(name string) string {
	r := strings.NewReplacer("/", "-", " ", "-", "_", "_")
	out := r.Replace(name)
	var b strings.Builder
	for _, ch := range out {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' {
			b.WriteRune(ch)
		}
	}
	s := b.String()
	if s == "" {
		return "secret"
	}
	return s
}

func (c *Client) secretID(key string) string {
	return sanitizeID(backend.PrefixedName(c.prefix, key))
}

func (c *Client) parent() string {
	return "projects/" + c.project
}

func (c *Client) Get(ctx context.Context, key string) (string, error) {
	if key == "" {
		return "", backend.ErrEmptyKey
	}
	name := fmt.Sprintf("%s/secrets/%s/versions/latest", c.parent(), c.secretID(key))
	out, err := c.api.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{Name: name})
	if err != nil {
		return "", mapGCPErr(err)
	}
	if out.Payload == nil {
		return "", fmt.Errorf("%w: %s", backend.ErrNotFound, key)
	}
	return string(out.Payload.Data), nil
}

func (c *Client) Set(ctx context.Context, key, value string) error {
	if key == "" {
		return backend.ErrEmptyKey
	}
	id := c.secretID(key)
	secretName := fmt.Sprintf("%s/secrets/%s", c.parent(), id)
	_, err := c.api.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent:  secretName,
		Payload: &secretmanagerpb.SecretPayload{Data: []byte(value)},
	})
	if err == nil {
		return nil
	}
	if status.Code(err) == codes.NotFound {
		_, createErr := c.api.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{
			Parent:   c.parent(),
			SecretId: id,
			Secret:   &secretmanagerpb.Secret{Replication: &secretmanagerpb.Replication{Replication: &secretmanagerpb.Replication_Automatic_{Automatic: &secretmanagerpb.Replication_Automatic{}}}},
		})
		if createErr != nil && status.Code(createErr) != codes.AlreadyExists {
			return mapGCPErr(createErr)
		}
		_, err = c.api.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
			Parent:  secretName,
			Payload: &secretmanagerpb.SecretPayload{Data: []byte(value)},
		})
	}
	return mapGCPErr(err)
}

func (c *Client) Delete(ctx context.Context, key string) error {
	if key == "" {
		return backend.ErrEmptyKey
	}
	name := fmt.Sprintf("%s/secrets/%s", c.parent(), c.secretID(key))
	return mapGCPErr(c.api.DeleteSecret(ctx, &secretmanagerpb.DeleteSecretRequest{Name: name}))
}

func (c *Client) List(ctx context.Context) ([]string, error) {
	it := c.api.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{Parent: c.parent()})
	wantPrefix := sanitizeID(strings.TrimSuffix(c.prefix, "/"))
	var out []string
	for {
		sec, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, mapGCPErr(err)
		}
		parts := strings.Split(sec.Name, "/")
		id := parts[len(parts)-1]
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
	return out, nil
}

func (c *Client) Ping(ctx context.Context) error {
	it := c.api.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{Parent: c.parent(), PageSize: 1})
	_, err := it.Next()
	if err == iterator.Done {
		return nil
	}
	return mapGCPErr(err)
}

func (c *Client) Close() error {
	return c.api.Close()
}

func mapGCPErr(err error) error {
	if err == nil {
		return nil
	}
	switch status.Code(err) {
	case codes.NotFound:
		return fmt.Errorf("%w: %v", backend.ErrNotFound, err)
	case codes.PermissionDenied, codes.Unauthenticated:
		return fmt.Errorf("%w: %v", backend.ErrPermissionDenied, err)
	default:
		return err
	}
}

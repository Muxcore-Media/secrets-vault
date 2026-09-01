package gcp_test

import (
	"context"
	"errors"
	"testing"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Muxcore-Media/secrets-vault/internal/backend"
	gcpbackend "github.com/Muxcore-Media/secrets-vault/internal/backend/gcp"
)

type fakeIterator struct {
	secrets []*secretmanagerpb.Secret
	idx     int
	err     error
}

func (it *fakeIterator) Next() (*secretmanagerpb.Secret, error) {
	if it.err != nil {
		return nil, it.err
	}
	if it.idx >= len(it.secrets) {
		return nil, iterator.Done
	}
	s := it.secrets[it.idx]
	it.idx++
	return s, nil
}

type fakeAPI struct {
	secrets map[string]string
}

func (f *fakeAPI) AccessSecretVersion(_ context.Context, req *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	for id, val := range f.secrets {
		name := "projects/test/secrets/" + id + "/versions/latest"
		if req.Name == name {
			return &secretmanagerpb.AccessSecretVersionResponse{
				Payload: &secretmanagerpb.SecretPayload{Data: []byte(val)},
			}, nil
		}
	}
	return nil, status.Error(codes.NotFound, "missing")
}

func (f *fakeAPI) CreateSecret(_ context.Context, req *secretmanagerpb.CreateSecretRequest) (*secretmanagerpb.Secret, error) {
	id := req.SecretId
	if _, ok := f.secrets[id]; ok {
		return nil, status.Error(codes.AlreadyExists, "exists")
	}
	f.secrets[id] = ""
	return &secretmanagerpb.Secret{Name: req.Parent + "/secrets/" + id}, nil
}

func (f *fakeAPI) AddSecretVersion(_ context.Context, req *secretmanagerpb.AddSecretVersionRequest) (*secretmanagerpb.SecretVersion, error) {
	parts := splitSecretParent(req.Parent)
	if parts == "" {
		return nil, status.Error(codes.NotFound, "missing")
	}
	if _, ok := f.secrets[parts]; !ok {
		return nil, status.Error(codes.NotFound, "missing")
	}
	f.secrets[parts] = string(req.Payload.Data)
	return &secretmanagerpb.SecretVersion{Name: req.Parent + "/versions/1"}, nil
}

func (f *fakeAPI) DeleteSecret(_ context.Context, req *secretmanagerpb.DeleteSecretRequest) error {
	id := splitSecretParent(req.Name)
	if id == "" {
		return status.Error(codes.NotFound, "missing")
	}
	if _, ok := f.secrets[id]; !ok {
		return status.Error(codes.NotFound, "missing")
	}
	delete(f.secrets, id)
	return nil
}

func (f *fakeAPI) ListSecrets(_ context.Context, _ *secretmanagerpb.ListSecretsRequest) gcpbackend.SecretIterator {
	var secrets []*secretmanagerpb.Secret
	for id := range f.secrets {
		secrets = append(secrets, &secretmanagerpb.Secret{Name: "projects/test/secrets/" + id})
	}
	return &fakeIterator{secrets: secrets}
}

func (f *fakeAPI) Close() error { return nil }

func splitSecretParent(name string) string {
	const prefix = "projects/test/secrets/"
	if len(name) >= len(prefix) && name[:len(prefix)] == prefix {
		rest := name[len(prefix):]
		for i, ch := range rest {
			if ch == '/' {
				return rest[:i]
			}
		}
		return rest
	}
	return ""
}

func TestPrefixedNameForGCP(t *testing.T) {
	got := backend.PrefixedName("muxcore/", "api_key")
	if got != "muxcore/api_key" {
		t.Fatalf("got %q", got)
	}
}

func TestGCPBackendCRUD(t *testing.T) {
	api := &fakeAPI{secrets: map[string]string{}}
	c := gcpbackend.NewWithAPI(api, "test", "muxcore/")
	ctx := context.Background()

	if err := c.Set(ctx, "api_key", "v"); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := c.Get(ctx, "api_key")
	if err != nil || got != "v" {
		t.Fatalf("get: %v %q", err, got)
	}
	keys, err := c.List(ctx)
	if err != nil || len(keys) != 1 || keys[0] != "api_key" {
		t.Fatalf("list: %v %#v", err, keys)
	}
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if err := c.Delete(ctx, "api_key"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := c.Get(ctx, "api_key"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestGCPBackendPermissionDenied(t *testing.T) {
	api := &fakeAPI{secrets: map[string]string{}}
	c := gcpbackend.NewWithAPI(api, "test", "muxcore/")
	ctx := context.Background()
	it := &fakeIterator{err: status.Error(codes.PermissionDenied, "denied")}
	apiList := &listErrAPI{it: it}
	c2 := gcpbackend.NewWithAPI(apiList, "test", "muxcore/")
	if err := c2.Ping(ctx); !errors.Is(err, backend.ErrPermissionDenied) {
		t.Fatalf("ping: %v", err)
	}
	_ = c
}

type listErrAPI struct {
	it gcpbackend.SecretIterator
}

func (a *listErrAPI) AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	return nil, status.Error(codes.NotFound, "missing")
}
func (a *listErrAPI) CreateSecret(ctx context.Context, req *secretmanagerpb.CreateSecretRequest) (*secretmanagerpb.Secret, error) {
	return nil, status.Error(codes.PermissionDenied, "denied")
}
func (a *listErrAPI) AddSecretVersion(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest) (*secretmanagerpb.SecretVersion, error) {
	return nil, status.Error(codes.PermissionDenied, "denied")
}
func (a *listErrAPI) DeleteSecret(ctx context.Context, req *secretmanagerpb.DeleteSecretRequest) error {
	return status.Error(codes.PermissionDenied, "denied")
}
func (a *listErrAPI) ListSecrets(ctx context.Context, req *secretmanagerpb.ListSecretsRequest) gcpbackend.SecretIterator {
	return a.it
}
func (a *listErrAPI) Close() error { return nil }

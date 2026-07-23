package server_test

import (
	"context"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	secretsv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/secrets/v1"
	"github.com/Muxcore-Media/secrets-vault/internal/backend"
	"github.com/Muxcore-Media/secrets-vault/internal/server"
)

type fakeBackend struct {
	mu   sync.Mutex
	data map[string]string
	ping error
}

func newFake() *fakeBackend {
	return &fakeBackend{data: make(map[string]string)}
}

func (f *fakeBackend) Get(_ context.Context, key string) (string, error) {
	if key == "" {
		return "", backend.ErrEmptyKey
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.data[key]
	if !ok {
		return "", backend.ErrNotFound
	}
	return v, nil
}

func (f *fakeBackend) Set(_ context.Context, key, value string) error {
	if key == "" {
		return backend.ErrEmptyKey
	}
	f.mu.Lock()
	f.data[key] = value
	f.mu.Unlock()
	return nil
}

func (f *fakeBackend) Delete(_ context.Context, key string) error {
	if key == "" {
		return backend.ErrEmptyKey
	}
	f.mu.Lock()
	delete(f.data, key)
	f.mu.Unlock()
	return nil
}

func (f *fakeBackend) List(_ context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	keys := make([]string, 0, len(f.data))
	for k := range f.data {
		keys = append(keys, k)
	}
	return keys, nil
}

func (f *fakeBackend) Ping(context.Context) error { return f.ping }
func (f *fakeBackend) Close() error               { return nil }

func TestServerCRUD(t *testing.T) {
	fb := newFake()
	srv := server.New(fb)
	ctx := context.Background()

	if _, err := srv.Get(ctx, &secretsv1.GetRequest{Key: "k"}); status.Code(err) != codes.NotFound {
		t.Fatalf("get missing: %v", err)
	}
	if _, err := srv.Set(ctx, &secretsv1.SetRequest{Key: "k", Value: "v"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := srv.Get(ctx, &secretsv1.GetRequest{Key: "k"})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Value != "v" {
		t.Fatalf("value %q", got.Value)
	}
	list, err := srv.List(ctx, &secretsv1.ListRequest{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if list.Count != 1 || len(list.Keys) != 1 || list.Keys[0] != "k" {
		t.Fatalf("list: %+v", list)
	}
	if _, err := srv.Delete(ctx, &secretsv1.DeleteRequest{Key: "k"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := srv.Get(ctx, &secretsv1.GetRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty key: %v", err)
	}
}

func TestServerPermissionDenied(t *testing.T) {
	fb := newFake()
	fb.data = nil
	srv := server.New(&denyBackend{})
	_, err := srv.Set(context.Background(), &secretsv1.SetRequest{Key: "k", Value: "v"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v", err)
	}
}

type denyBackend struct{}

func (d *denyBackend) Get(context.Context, string) (string, error) {
	return "", backend.ErrPermissionDenied
}
func (d *denyBackend) Set(context.Context, string, string) error {
	return backend.ErrPermissionDenied
}
func (d *denyBackend) Delete(context.Context, string) error { return backend.ErrPermissionDenied }
func (d *denyBackend) List(context.Context) ([]string, error) {
	return nil, backend.ErrPermissionDenied
}
func (d *denyBackend) Ping(context.Context) error { return nil }
func (d *denyBackend) Close() error               { return nil }

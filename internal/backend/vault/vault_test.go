package vault_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/Muxcore-Media/secrets-vault/internal/backend/vault"
)

type kvStore struct {
	mu   sync.Mutex
	data map[string]map[string]interface{}
}

func newKVHandler(store *kvStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/sys/health"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"initialized": true, "sealed": false})
		case (r.Method == http.MethodPost || r.Method == http.MethodPut) && r.URL.Path == "/v1/auth/approle/login":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "approle-token",
					"renewable":      true,
					"lease_duration": 3600,
				},
			})
		case (r.Method == http.MethodPost || r.Method == http.MethodPut) && strings.HasSuffix(r.URL.Path, "/auth/token/renew-self"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "approle-token",
					"renewable":      true,
					"lease_duration": 3600,
				},
			})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/data/"):
			key := strings.TrimPrefix(r.URL.Path, "/v1/secret/data/")
			store.mu.Lock()
			entry, ok := store.data[key]
			store.mu.Unlock()
			if !ok {
				http.Error(w, `{"errors":["not found"]}`, http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"data": entry,
					"metadata": map[string]interface{}{
						"version": 1,
					},
				},
			})
		case (r.Method == http.MethodPost || r.Method == http.MethodPut) && strings.Contains(r.URL.Path, "/data/"):
			key := strings.TrimPrefix(r.URL.Path, "/v1/secret/data/")
			var body struct {
				Data map[string]interface{} `json:"data"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			store.mu.Lock()
			store.data[key] = body.Data
			store.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"version": 1},
			})
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/data/"):
			key := strings.TrimPrefix(r.URL.Path, "/v1/secret/data/")
			store.mu.Lock()
			delete(store.data, key)
			store.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": nil})
		case r.Method == "LIST" || (r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/metadata/")):
			prefix := strings.TrimPrefix(r.URL.Path, "/v1/secret/metadata/")
			prefix = strings.Trim(prefix, "/")
			store.mu.Lock()
			keys := listMetadataKeys(store.data, prefix)
			store.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": keys},
			})
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}
}

func listMetadataKeys(data map[string]map[string]interface{}, prefix string) []string {
	seen := map[string]struct{}{}
	var keys []string
	for k := range data {
		rel := k
		if prefix != "" {
			if !strings.HasPrefix(k, prefix+"/") && k != prefix {
				continue
			}
			rel = strings.TrimPrefix(k, prefix+"/")
		}
		if rel == "" {
			continue
		}
		parts := strings.SplitN(rel, "/", 2)
		name := parts[0]
		if len(parts) == 2 {
			name += "/"
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		keys = append(keys, name)
	}
	return keys
}

func TestVaultKVv2CRUD(t *testing.T) {
	store := &kvStore{data: make(map[string]map[string]interface{})}
	srv := httptest.NewServer(newKVHandler(store))
	defer srv.Close()

	cfg := vaultapi.DefaultConfig()
	cfg.Address = srv.URL
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken("test-token")

	c := vault.NewWithClient(client, "secret", "muxcore/")
	ctx := context.Background()

	if err := c.Set(ctx, "api_key", "s3cret"); err != nil {
		t.Fatalf("set: %v", err)
	}
	val, err := c.Get(ctx, "api_key")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if val != "s3cret" {
		t.Fatalf("value %q", val)
	}
	keys, err := c.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 || keys[0] != "api_key" {
		t.Fatalf("keys %#v", keys)
	}
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if err := c.Delete(ctx, "api_key"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := c.Get(ctx, "api_key"); err == nil {
		t.Fatal("expected not found")
	}
}

func TestVaultKVv2NestedList(t *testing.T) {
	store := &kvStore{data: make(map[string]map[string]interface{})}
	store.data["muxcore/a/b"] = map[string]interface{}{"value": "nested"}
	srv := httptest.NewServer(newKVHandler(store))
	defer srv.Close()

	cfg := vaultapi.DefaultConfig()
	cfg.Address = srv.URL
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken("test-token")

	c := vault.NewWithClient(client, "secret", "muxcore/")
	keys, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 || keys[0] != "a/b" {
		t.Fatalf("keys %#v", keys)
	}
}

func TestVaultAppRoleFromEnv(t *testing.T) {
	store := &kvStore{data: make(map[string]map[string]interface{})}
	srv := httptest.NewServer(newKVHandler(store))
	defer srv.Close()

	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("VAULT_ROLE_ID", "role")
	t.Setenv("VAULT_SECRET_ID", "secret")

	c, err := vault.NewFromEnv(context.Background(), "muxcore/")
	if err != nil {
		t.Fatalf("NewFromEnv: %v", err)
	}
	defer func() { _ = c.Close() }()

	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

func TestVaultAppRoleFromEnvMissingCreds(t *testing.T) {
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:8200")
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("VAULT_ROLE_ID", "")
	t.Setenv("VAULT_SECRET_ID", "")
	_, err := vault.NewFromEnv(context.Background(), "muxcore/")
	if err == nil {
		t.Fatal("expected error")
	}
}

func init() {
	_ = os.Getenv
}

package vault_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestVaultKVv2CRUD(t *testing.T) {
	store := &kvStore{data: make(map[string]map[string]interface{})}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/sys/health"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"initialized": true, "sealed": false})
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
		case r.Method == "LIST" || (r.Method == http.MethodGet && r.URL.Query().Get("list") == "true"):
			prefix := strings.TrimPrefix(r.URL.Path, "/v1/secret/metadata/")
			prefix = strings.Trim(prefix, "/")
			store.mu.Lock()
			var keys []string
			for k := range store.data {
				if prefix == "" || strings.HasPrefix(k, prefix+"/") || k == prefix {
					name := k
					if prefix != "" && strings.HasPrefix(k, prefix+"/") {
						name = strings.TrimPrefix(k, prefix+"/")
					}
					if !strings.Contains(name, "/") {
						keys = append(keys, name)
					}
				}
			}
			store.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": keys},
			})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/metadata/"):
			prefix := strings.TrimPrefix(r.URL.Path, "/v1/secret/metadata/")
			prefix = strings.Trim(prefix, "/")
			store.mu.Lock()
			var keys []string
			for k := range store.data {
				if prefix == "" || strings.HasPrefix(k, prefix+"/") || k == prefix {
					name := k
					if prefix != "" && strings.HasPrefix(k, prefix+"/") {
						name = strings.TrimPrefix(k, prefix+"/")
					}
					if !strings.Contains(name, "/") {
						keys = append(keys, name)
					}
				}
			}
			store.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": keys},
			})
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
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

package infisical_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Muxcore-Media/secrets-vault/internal/backend/infisical"
)

func TestInfisicalCRUD(t *testing.T) {
	store := map[string]string{}
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v3/secrets/raw/") && r.URL.Path != "/api/v3/secrets/raw":
			name := strings.TrimPrefix(r.URL.Path, "/api/v3/secrets/raw/")
			mu.Lock()
			val, ok := store[name]
			mu.Unlock()
			if !ok {
				http.Error(w, "missing", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"secret": map[string]string{"secretValue": val},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v3/secrets/raw":
			mu.Lock()
			secrets := make([]map[string]string, 0, len(store))
			for k := range store {
				secrets = append(secrets, map[string]string{"secretKey": k})
			}
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"secrets": secrets})
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v3/secrets/raw/"):
			name := strings.TrimPrefix(r.URL.Path, "/api/v3/secrets/raw/")
			var body struct {
				SecretValue string `json:"secretValue"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			if _, exists := store[name]; exists {
				mu.Unlock()
				http.Error(w, "conflict", http.StatusConflict)
				return
			}
			store[name] = body.SecretValue
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/api/v3/secrets/raw/"):
			name := strings.TrimPrefix(r.URL.Path, "/api/v3/secrets/raw/")
			var body struct {
				SecretValue string `json:"secretValue"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			store[name] = body.SecretValue
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v3/secrets/raw/"):
			name := strings.TrimPrefix(r.URL.Path, "/api/v3/secrets/raw/")
			mu.Lock()
			delete(store, name)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, 404)
		}
	}))
	defer srv.Close()

	c := infisical.NewWithHTTP(srv.Client(), srv.URL, "proj", "dev", "tok", "muxcore/")
	ctx := context.Background()
	if err := c.Set(ctx, "api_key", "val"); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := c.Get(ctx, "api_key")
	if err != nil || got != "val" {
		t.Fatalf("get: %v %q", err, got)
	}
	keys, err := c.List(ctx)
	if err != nil || len(keys) != 1 || keys[0] != "api_key" {
		t.Fatalf("list: %v %#v", err, keys)
	}
	if err := c.Delete(ctx, "api_key"); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

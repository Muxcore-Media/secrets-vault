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
	store := map[string]map[string]string{}
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
			path := strings.Trim(r.URL.Query().Get("secretPath"), "/")
			mu.Lock()
			val, ok := store[path+"/"+name]
			mu.Unlock()
			if !ok {
				http.Error(w, "missing", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"secret": map[string]string{"secretValue": val["value"]},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v3/secrets/raw":
			path := strings.Trim(r.URL.Query().Get("secretPath"), "/")
			mu.Lock()
			secrets := make([]map[string]string, 0)
			for k, v := range store {
				if strings.HasPrefix(k, path+"/") || (path == "" && !strings.Contains(k, "/")) {
					parts := strings.SplitN(k, "/", 2)
					if len(parts) == 2 {
						secrets = append(secrets, map[string]string{
							"secretKey":  parts[1],
							"secretPath": "/" + parts[0],
						})
					}
				}
				_ = v
			}
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"secrets": secrets})
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v3/secrets/raw/"):
			var body struct {
				SecretPath  string `json:"secretPath"`
				SecretName  string `json:"secretName"`
				SecretValue string `json:"secretValue"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			key := strings.Trim(body.SecretPath, "/") + "/" + body.SecretName
			mu.Lock()
			if _, exists := store[key]; exists {
				mu.Unlock()
				http.Error(w, "conflict", http.StatusConflict)
				return
			}
			store[key] = map[string]string{"value": body.SecretValue}
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/api/v3/secrets/raw/"):
			var body struct {
				SecretPath  string `json:"secretPath"`
				SecretName  string `json:"secretName"`
				SecretValue string `json:"secretValue"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			key := strings.Trim(body.SecretPath, "/") + "/" + body.SecretName
			mu.Lock()
			store[key] = map[string]string{"value": body.SecretValue}
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v3/secrets/raw/"):
			var body struct {
				SecretPath string `json:"secretPath"`
				SecretName string `json:"secretName"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			key := strings.Trim(body.SecretPath, "/") + "/" + body.SecretName
			mu.Lock()
			delete(store, key)
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

func TestInfisicalUniversalAuthRetry(t *testing.T) {
	var mu sync.Mutex
	token := "fresh-token"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth/universal-auth/login":
			_ = json.NewEncoder(w).Encode(map[string]string{"accessToken": "fresh-token"})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v3/secrets/raw/"):
			auth := r.Header.Get("Authorization")
			mu.Lock()
			current := token
			mu.Unlock()
			if auth != "Bearer "+current {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"secret": map[string]string{"secretValue": "ok"},
			})
		default:
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := infisical.NewWithAuth(srv.Client(), srv.URL, "proj", "dev", "muxcore/", "cid", "csecret")
	mu.Lock()
	token = "fresh-token"
	mu.Unlock()

	got, err := c.Get(context.Background(), "api_key")
	if err != nil || got != "ok" {
		t.Fatalf("get after refresh: %v %q", err, got)
	}
}

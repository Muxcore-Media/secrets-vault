package vault_test

import (
	"context"
	"os"
	"testing"

	"github.com/Muxcore-Media/secrets-vault/internal/backend/vault"
)

func TestOpenBaoComposeSmoke(t *testing.T) {
	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		t.Skip("VAULT_ADDR not set")
	}
	if os.Getenv("VAULT_TOKEN") == "" {
		t.Skip("VAULT_TOKEN not set")
	}

	c, err := vault.NewFromEnv(context.Background(), "muxcore/")
	if err != nil {
		t.Fatalf("NewFromEnv: %v", err)
	}
	defer func() { _ = c.Close() }()

	ctx := context.Background()
	key := "smoke_key"
	if err := c.Set(ctx, key, "smoke-value"); err != nil {
		t.Fatalf("set: %v", err)
	}
	val, err := c.Get(ctx, key)
	if err != nil || val != "smoke-value" {
		t.Fatalf("get: %v %q", err, val)
	}
	keys, err := c.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	found := false
	for _, k := range keys {
		if k == key {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("key %q not in list %#v", key, keys)
	}
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if err := c.Delete(ctx, key); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

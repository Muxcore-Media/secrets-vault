package backend_test

import (
	"testing"

	"github.com/Muxcore-Media/secrets-vault/internal/backend"
)

func TestPrefixedName(t *testing.T) {
	if got := backend.PrefixedName("muxcore/", "api_key"); got != "muxcore/api_key" {
		t.Fatalf("got %q", got)
	}
	if got := backend.PrefixedName("muxcore", "api_key"); got != "muxcore/api_key" {
		t.Fatalf("got %q", got)
	}
	if got := backend.PrefixedName("", "api_key"); got != "api_key" {
		t.Fatalf("got %q", got)
	}
}

func TestStripPrefix(t *testing.T) {
	key, ok := backend.StripPrefix("muxcore/", "muxcore/api_key")
	if !ok || key != "api_key" {
		t.Fatalf("got %q ok=%v", key, ok)
	}
	_, ok = backend.StripPrefix("muxcore/", "other/api_key")
	if ok {
		t.Fatal("expected not ok")
	}
}

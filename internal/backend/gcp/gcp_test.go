package gcp_test

import (
	"testing"

	"github.com/Muxcore-Media/secrets-vault/internal/backend"
)

func TestPrefixedNameForGCP(t *testing.T) {
	got := backend.PrefixedName("muxcore/", "api_key")
	if got != "muxcore/api_key" {
		t.Fatalf("got %q", got)
	}
}

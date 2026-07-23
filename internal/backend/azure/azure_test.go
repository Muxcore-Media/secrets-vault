package azure_test

import (
	"testing"

	"github.com/Muxcore-Media/secrets-vault/internal/backend"
)

// Ensures prefix joining stays stable for Azure name sanitization expectations.
func TestPrefixedNameForAzure(t *testing.T) {
	got := backend.PrefixedName("muxcore/", "api_key")
	if got != "muxcore/api_key" {
		t.Fatalf("got %q", got)
	}
}

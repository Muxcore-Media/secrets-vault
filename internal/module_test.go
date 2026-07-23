package internal

import (
	"context"
	"testing"
)

func TestModuleInfo(t *testing.T) {
	m := NewModule(Config{Backend: "vault"})
	info := m.Info()
	if info.ID != "secrets-vault" {
		t.Fatalf("id %q", info.ID)
	}
	foundSecrets := false
	foundVault := false
	for _, c := range info.Capabilities {
		if c == "secrets" {
			foundSecrets = true
		}
		if c == "secrets.vault" {
			foundVault = true
		}
	}
	if !foundSecrets || !foundVault {
		t.Fatalf("capabilities %#v", info.Capabilities)
	}
	if len(info.Roles) != 1 || info.Roles[0] != "security" {
		t.Fatalf("roles %#v", info.Roles)
	}
}

func TestModuleInitRequiresBackend(t *testing.T) {
	m := NewModule(Config{GRPCAddr: ":0", Insecure: true})
	if err := m.Init(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}

package internal

import (
	"context"
	"testing"

	"github.com/Muxcore-Media/secrets-vault/internal/backend"
)

func TestModuleInfo(t *testing.T) {
	m := NewModule(Config{Backend: "vault"})
	info := m.Info()
	if info.ID != "secrets-vault" {
		t.Fatalf("id %q", info.ID)
	}
	if info.Version != "0.1.1" {
		t.Fatalf("version %q", info.Version)
	}
	foundSecrets := false
	foundVault := false
	foundSettings := false
	for _, c := range info.Capabilities {
		if c == "secrets" {
			foundSecrets = true
		}
		if c == "secrets.vault" {
			foundVault = true
		}
		if c == "settings" {
			foundSettings = true
		}
	}
	if !foundSecrets || !foundVault {
		t.Fatalf("capabilities %#v", info.Capabilities)
	}
	if !foundSettings {
		t.Fatal("expected settings capability")
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

func TestSettings_PreInit(t *testing.T) {
	m := NewModule(Config{Backend: "vault", Prefix: "app/"})
	defs := m.Settings()
	byKey := map[string]string{}
	for _, d := range defs {
		byKey[d.Key] = d.Value
	}
	if byKey["backend"] != "vault" || byKey["prefix"] != "app/" {
		t.Fatalf("%v", byKey)
	}
	if err := m.UpdateSetting("prefix", "prod/"); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateSetting("backend", "aws"); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateSetting("backend", "nope"); err == nil {
		t.Fatal("expected invalid backend")
	}
	defs = m.Settings()
	for _, d := range defs {
		switch d.Key {
		case "backend":
			if d.Value != backend.BackendAWS {
				t.Fatalf("backend=%q", d.Value)
			}
		case "prefix":
			if d.Value != "prod/" {
				t.Fatalf("prefix=%q", d.Value)
			}
		}
	}
}

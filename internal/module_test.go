package internal

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/Muxcore-Media/secrets-vault/internal/backend"
)

type trackingBackend struct {
	id      int
	closed  atomic.Bool
	pingErr error
}

func (b *trackingBackend) Get(_ context.Context, key string) (string, error) {
	return "", backend.ErrNotFound
}

func (b *trackingBackend) Set(_ context.Context, key, value string) error { return nil }

func (b *trackingBackend) Delete(_ context.Context, key string) error { return nil }

func (b *trackingBackend) List(_ context.Context) ([]string, error) { return nil, nil }

func (b *trackingBackend) Ping(_ context.Context) error { return b.pingErr }

func (b *trackingBackend) Close() error {
	b.closed.Store(true)
	return nil
}

func TestModuleInfo(t *testing.T) {
	m := NewModule(Config{Backend: "vault"})
	info := m.Info()
	if info.ID != "secrets-vault" {
		t.Fatalf("id %q", info.ID)
	}
	if info.Version != Version {
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

func TestModuleDefaultGRPCAddr(t *testing.T) {
	m := NewModule(Config{Backend: "vault"})
	if m.grpcAddr != "127.0.0.1:9551" {
		t.Fatalf("grpc addr %q", m.grpcAddr)
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

func TestApplyProviderAfterInitClosesOldBackend(t *testing.T) {
	first := &trackingBackend{id: 1}
	second := &trackingBackend{id: 2}
	call := 0
	backendFactoryHook = func(_ context.Context, name, prefix string) (backend.Backend, error) {
		call++
		if call == 1 {
			return first, nil
		}
		return second, nil
	}
	t.Cleanup(func() { backendFactoryHook = nil })

	m := NewModule(Config{Backend: "vault", GRPCAddr: "127.0.0.1:0", Insecure: true})
	if err := m.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := m.UpdateSetting("prefix", "prod/"); err != nil {
		t.Fatalf("update prefix: %v", err)
	}
	if !first.closed.Load() {
		t.Fatal("expected first backend Close after prefix change")
	}
	if m.backend != second {
		t.Fatal("expected active backend swap")
	}
}

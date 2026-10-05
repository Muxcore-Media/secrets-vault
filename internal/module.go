package internal

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"

	"google.golang.org/grpc"

	modulesdk "github.com/Muxcore-Media/core/sdk/go/module"
	manifest "github.com/Muxcore-Media/secrets-vault"

	"github.com/Muxcore-Media/core/pkg/contracts"
	"github.com/Muxcore-Media/secrets-vault/internal/backend"
	"github.com/Muxcore-Media/secrets-vault/internal/server"
)

type Module struct {
	backend  backend.Backend
	srv      *server.Server
	grpcSrv  *grpc.Server
	lis      net.Listener
	id       string
	grpcAddr string
	cfgMu    sync.RWMutex
	backendN string
	prefix   string
	insecure bool
}

type Config struct {
	ID       string
	GRPCAddr string
	Backend  string
	Prefix   string
	Insecure bool
}

func NewModule(cfg Config) *Module {
	if cfg.ID == "" {
		cfg.ID = "secrets-vault"
	}
	if cfg.GRPCAddr == "" {
		cfg.GRPCAddr = ":9551"
	}
	if v := os.Getenv("SECRETS_GRPC_ADDR"); v != "" {
		cfg.GRPCAddr = v
	}
	if v := os.Getenv("SECRETS_BACKEND"); v != "" && cfg.Backend == "" {
		cfg.Backend = v
	}
	prefix := cfg.Prefix
	if prefix == "" {
		prefix = os.Getenv("SECRETS_PREFIX")
	}
	if prefix == "" {
		prefix = backend.DefaultPrefix
	}
	return &Module{
		id:       cfg.ID,
		grpcAddr: cfg.GRPCAddr,
		backendN: strings.ToLower(strings.TrimSpace(cfg.Backend)),
		prefix:   prefix,
		insecure: cfg.Insecure,
	}
}

func (m *Module) Info() contracts.ModuleInfo {
	return contracts.ModuleInfo{
		ID:           m.id,
		Name:         "Secrets Vault",
		Version:      modulesdk.ManifestVersion(manifest.ManifestJSON),
		Roles:        []string{"security"},
		Description:  "Multi-provider secrets sidecar (Vault/OpenBao, Infisical, AWS, GCP, Azure)",
		Author:       "MuxCore",
		Capabilities: []string{contracts.CapabilitySecrets, "secrets.vault", "settings"},
		HTTPAddr:     m.grpcAddr,
	}
}

func (m *Module) Init(ctx context.Context) error {
	m.cfgMu.RLock()
	backendN := m.backendN
	prefix := m.prefix
	m.cfgMu.RUnlock()
	if backendN == "" {
		return fmt.Errorf("SECRETS_BACKEND is required (vault|infisical|aws|gcp|azure)")
	}
	b, err := newBackend(ctx, backendN, prefix)
	if err != nil {
		return fmt.Errorf("create secrets backend: %w", err)
	}
	m.backend = b
	m.srv = server.New(b)

	lis, err := net.Listen("tcp", m.grpcAddr)
	if err != nil {
		_ = b.Close()
		return fmt.Errorf("listen %s: %w", m.grpcAddr, err)
	}
	m.lis = lis
	m.grpcAddr = lis.Addr().String()

	slog.Info("secrets-vault initialized", "backend", backendN, "prefix", prefix, "addr", m.grpcAddr)
	return nil
}

func (m *Module) Start(ctx context.Context) error {
	grpcSrv, err := modulesdk.NewGRPCServer(m.insecure)
	if err != nil {
		return fmt.Errorf("create gRPC server: %w", err)
	}
	m.grpcSrv = grpcSrv
	m.srv.RegisterWithGRPC(m.grpcSrv)
	modulesdk.RegisterSettings(m.grpcSrv, m.id, m)

	go func() {
		slog.Info("secrets-vault gRPC service started", "addr", m.grpcAddr, "backend", m.backendN)
		if err := m.grpcSrv.Serve(m.lis); err != nil {
			slog.Error("secrets-vault gRPC serve error", "error", err)
		}
	}()
	return nil
}

func (m *Module) Stop(ctx context.Context) error {
	if m.grpcSrv != nil {
		m.grpcSrv.GracefulStop()
	}
	if m.backend != nil {
		if err := m.backend.Close(); err != nil {
			slog.Error("secrets-vault backend close", "error", err)
		}
	}
	slog.Info("secrets-vault stopped")
	return nil
}

func (m *Module) Health(ctx context.Context) error {
	if m.backend == nil {
		return fmt.Errorf("not initialized")
	}
	return m.backend.Ping(ctx)
}

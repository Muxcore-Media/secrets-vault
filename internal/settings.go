package internal

import (
	"context"
	"fmt"
	"strings"

	"github.com/Muxcore-Media/core/pkg/contracts"
	"github.com/Muxcore-Media/secrets-vault/internal/backend"
)

func (m *Module) Settings() []contracts.SettingDef {
	return m.settingsDefs()
}

func (m *Module) UpdateSetting(key, value string) error {
	return m.updateSetting(key, value)
}

func (m *Module) settingsDefs() []contracts.SettingDef {
	m.cfgMu.RLock()
	backendN := m.backendN
	prefix := m.prefix
	m.cfgMu.RUnlock()
	return []contracts.SettingDef{
		{
			Key:         "backend",
			Label:       "Secrets Backend",
			Type:        contracts.SettingTypeSelect,
			Value:       backendN,
			Default:     "",
			Description: "External provider (SECRETS_BACKEND); reconnects using provider env credentials",
			Group:       "Provider",
			Options: []string{
				backend.BackendVault,
				backend.BackendInfisical,
				backend.BackendAWS,
				backend.BackendGCP,
				backend.BackendAzure,
			},
		},
		{
			Key:         "prefix",
			Label:       "Key Prefix",
			Type:        contracts.SettingTypeString,
			Value:       prefix,
			Default:     backend.DefaultPrefix,
			Description: "Prefix prepended to secret keys (SECRETS_PREFIX)",
			Group:       "Provider",
		},
	}
}

func (m *Module) updateSetting(key, value string) error {
	value = strings.TrimSpace(value)
	m.cfgMu.RLock()
	backendN := m.backendN
	prefix := m.prefix
	m.cfgMu.RUnlock()

	switch key {
	case "backend", "SECRETS_BACKEND":
		value = strings.ToLower(value)
		switch value {
		case backend.BackendVault, backend.BackendInfisical, backend.BackendAWS, backend.BackendGCP, backend.BackendAzure:
			backendN = value
		default:
			return fmt.Errorf("invalid backend %q (vault|infisical|aws|gcp|azure)", value)
		}
	case "prefix", "SECRETS_PREFIX":
		if value == "" {
			value = backend.DefaultPrefix
		}
		prefix = value
	default:
		return fmt.Errorf("unknown setting %q", key)
	}
	return m.applyProvider(backendN, prefix)
}

func (m *Module) applyProvider(backendN, prefix string) error {
	m.cfgMu.Lock()
	defer m.cfgMu.Unlock()
	if m.srv == nil {
		m.backendN = backendN
		m.prefix = prefix
		return nil
	}
	if backendN == m.backendN && prefix == m.prefix {
		return nil
	}
	b, err := newBackend(context.Background(), backendN, prefix)
	if err != nil {
		return fmt.Errorf("create secrets backend: %w", err)
	}
	old := m.srv.ReplaceBackend(b)
	m.backend = b
	m.backendN = backendN
	m.prefix = prefix
	if old != nil {
		_ = old.Close()
	}
	return nil
}

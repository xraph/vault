package confy

import (
	"context"
	"fmt"

	confypkg "github.com/xraph/confy"

	"github.com/xraph/vault"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/secret"
)

// Compile-time interface check.
var _ confypkg.SecretProvider = (*VaultSecretProvider)(nil)

// VaultSecretProvider is a confy SecretProvider backed by vault's secret store.
type VaultSecretProvider struct {
	name  string
	store secret.Store
	appID string
}

// NewVaultSecretProvider creates a new VaultSecretProvider.
func NewVaultSecretProvider(store secret.Store, appID string) *VaultSecretProvider {
	return &VaultSecretProvider{
		name:  "vault",
		store: store,
		appID: appID,
	}
}

// Name returns the provider name.
func (p *VaultSecretProvider) Name() string { return p.name }

// GetSecret retrieves a decrypted secret value as a string.
func (p *VaultSecretProvider) GetSecret(ctx context.Context, key string) (string, error) {
	sec, err := p.store.GetSecret(ctx, key, p.appID)
	if err != nil {
		return "", fmt.Errorf("vault secret provider: get: %w", err)
	}
	return string(sec.Value), nil
}

// SetSecret creates or updates a secret.
func (p *VaultSecretProvider) SetSecret(ctx context.Context, key, value string) error {
	s := &secret.Secret{
		Entity: vault.NewEntity(),
		ID:     id.NewSecretID(),
		Key:    key,
		Value:  []byte(value),
		AppID:  p.appID,
	}
	if err := p.store.SetSecret(ctx, s); err != nil {
		return fmt.Errorf("vault secret provider: set: %w", err)
	}
	return nil
}

// DeleteSecret removes a secret.
func (p *VaultSecretProvider) DeleteSecret(ctx context.Context, key string) error {
	if err := p.store.DeleteSecret(ctx, key, p.appID); err != nil {
		return fmt.Errorf("vault secret provider: delete: %w", err)
	}
	return nil
}

// ListSecrets returns all secret keys for the app.
func (p *VaultSecretProvider) ListSecrets(ctx context.Context) ([]string, error) {
	metas, err := p.store.ListSecrets(ctx, p.appID, secret.ListOpts{})
	if err != nil {
		return nil, fmt.Errorf("vault secret provider: list: %w", err)
	}

	keys := make([]string, len(metas))
	for i, m := range metas {
		keys[i] = m.Key
	}
	return keys, nil
}

// HealthCheck verifies the secret store is accessible.
func (p *VaultSecretProvider) HealthCheck(ctx context.Context) error {
	_, err := p.store.ListSecrets(ctx, p.appID, secret.ListOpts{Limit: 1})
	return err
}

// SupportsRotation returns false — rotation is managed by vault's rotation service.
func (p *VaultSecretProvider) SupportsRotation() bool { return false }

// SupportsCaching returns false — the vault store handles its own caching.
func (p *VaultSecretProvider) SupportsCaching() bool { return false }

// Initialize is a no-op — the provider is fully configured via constructor.
func (p *VaultSecretProvider) Initialize(_ context.Context, _ map[string]any) error { return nil }

// Close is a no-op — the store lifecycle is managed by the extension.
func (p *VaultSecretProvider) Close(_ context.Context) error { return nil }

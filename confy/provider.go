package confy

import (
	"context"
	"fmt"

	confypkg "github.com/xraph/confy"

	"github.com/xraph/vault/secret"
)

// Compile-time interface check.
var _ confypkg.SecretProvider = (*VaultSecretProvider)(nil)

// secretWriter is the write and list surface VaultSecretProvider needs
// beyond SecretReader, so confy's SecretProvider contract (set, delete,
// list, health check) keeps working. *secret.Service satisfies it too.
type secretWriter interface {
	Set(ctx context.Context, key string, value []byte, appID string, opts ...secret.SetOption) (*secret.Meta, error)
	Delete(ctx context.Context, key, appID string) error
	List(ctx context.Context, appID string, opts secret.ListOpts) ([]*secret.Meta, error)
}

// VaultSecretProvider is a confy SecretProvider backed by vault's secret service.
type VaultSecretProvider struct {
	name    string
	secrets SecretReader
	writer  secretWriter // set when secrets also satisfies secretWriter, e.g. *secret.Service
	appID   string
}

// NewVaultSecretProvider creates a new VaultSecretProvider. secrets reads
// through vault's secret service rather than a raw secret.Store, because no
// store backend keeps a decrypted value.
func NewVaultSecretProvider(secrets SecretReader, appID string) *VaultSecretProvider {
	p := &VaultSecretProvider{
		name:    "vault",
		secrets: secrets,
		appID:   appID,
	}
	if w, ok := secrets.(secretWriter); ok {
		p.writer = w
	}
	return p
}

// Name returns the provider name.
func (p *VaultSecretProvider) Name() string { return p.name }

// GetSecret retrieves and decrypts a secret value as a string.
func (p *VaultSecretProvider) GetSecret(ctx context.Context, key string) (string, error) {
	sec, err := p.secrets.Get(ctx, key, p.appID)
	if err != nil {
		return "", fmt.Errorf("vault secret provider: get: %w", err)
	}
	return string(sec.Value), nil
}

// SetSecret creates or updates a secret.
func (p *VaultSecretProvider) SetSecret(ctx context.Context, key, value string) error {
	if p.writer == nil {
		return fmt.Errorf("vault secret provider: secrets reader does not support writes")
	}
	if _, err := p.writer.Set(ctx, key, []byte(value), p.appID); err != nil {
		return fmt.Errorf("vault secret provider: set: %w", err)
	}
	return nil
}

// DeleteSecret removes a secret.
func (p *VaultSecretProvider) DeleteSecret(ctx context.Context, key string) error {
	if p.writer == nil {
		return fmt.Errorf("vault secret provider: secrets reader does not support deletes")
	}
	if err := p.writer.Delete(ctx, key, p.appID); err != nil {
		return fmt.Errorf("vault secret provider: delete: %w", err)
	}
	return nil
}

// ListSecrets returns all secret keys for the app.
func (p *VaultSecretProvider) ListSecrets(ctx context.Context) ([]string, error) {
	if p.writer == nil {
		return nil, fmt.Errorf("vault secret provider: secrets reader does not support listing")
	}
	metas, err := p.writer.List(ctx, p.appID, secret.ListOpts{})
	if err != nil {
		return nil, fmt.Errorf("vault secret provider: list: %w", err)
	}

	keys := make([]string, len(metas))
	for i, m := range metas {
		keys[i] = m.Key
	}
	return keys, nil
}

// HealthCheck verifies the secret service is accessible.
func (p *VaultSecretProvider) HealthCheck(ctx context.Context) error {
	if p.writer == nil {
		return fmt.Errorf("vault secret provider: secrets reader does not support listing")
	}
	_, err := p.writer.List(ctx, p.appID, secret.ListOpts{Limit: 1})
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

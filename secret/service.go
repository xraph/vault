package secret

import (
	"context"
	"fmt"
	"time"

	"github.com/xraph/vault"
	"github.com/xraph/vault/crypto"
	"github.com/xraph/vault/id"
)

// OnAccessFunc is called after a secret is accessed.
type OnAccessFunc func(ctx context.Context, key, appID string)

// OnMutateFunc is called after a secret is set or deleted.
type OnMutateFunc func(ctx context.Context, action, key, appID string)

// ServiceOption configures the Service.
type ServiceOption func(*Service)

// WithAppID sets the default app ID for the service.
func WithAppID(appID string) ServiceOption {
	return func(s *Service) { s.appID = appID }
}

// WithOnAccess registers a callback invoked after Get/GetVersion.
func WithOnAccess(fn OnAccessFunc) ServiceOption {
	return func(s *Service) { s.onAccess = fn }
}

// WithOnMutate registers a callback invoked after Set/Delete.
func WithOnMutate(fn OnMutateFunc) ServiceOption {
	return func(s *Service) { s.onMutate = fn }
}

// Service provides secret CRUD with encryption, auto-versioning, and audit callbacks.
type Service struct {
	store     Store
	encryptor *crypto.Encryptor
	appID     string
	onAccess  OnAccessFunc
	onMutate  OnMutateFunc
}

// NewService creates a secret service.
func NewService(store Store, encryptor *crypto.Encryptor, opts ...ServiceOption) *Service {
	svc := &Service{
		store:     store,
		encryptor: encryptor,
	}
	for _, o := range opts {
		o(svc)
	}
	return svc
}

// resolveAppID returns appID from argument or service default.
func (s *Service) resolveAppID(appID string) string {
	if appID != "" {
		return appID
	}
	return s.appID
}

// Get retrieves and decrypts a secret by key.
func (s *Service) Get(ctx context.Context, key, appID string) (*Secret, error) {
	appID = s.resolveAppID(appID)

	sec, err := s.store.GetSecret(ctx, key, appID)
	if err != nil {
		return nil, err
	}

	if s.encryptor != nil && len(sec.EncryptedValue) > 0 {
		plaintext, decErr := s.encryptor.Decrypt(sec.EncryptedValue)
		if decErr != nil {
			return nil, fmt.Errorf("secret: decrypt %q: %w", key, decErr)
		}
		sec.Value = plaintext
	}

	if s.onAccess != nil {
		s.onAccess(ctx, key, appID)
	}

	return sec, nil
}

// GetMeta retrieves secret metadata without the value.
func (s *Service) GetMeta(ctx context.Context, key, appID string) (*Meta, error) {
	appID = s.resolveAppID(appID)

	sec, err := s.store.GetSecret(ctx, key, appID)
	if err != nil {
		return nil, err
	}

	return sec.ToMeta(), nil
}

// SetOption configures a Set operation.
type SetOption func(*setConfig)

type setConfig struct {
	metadata  map[string]string
	expiresAt *time.Time
}

// WithMetadata sets metadata on the secret.
func WithMetadata(m map[string]string) SetOption {
	return func(c *setConfig) { c.metadata = m }
}

// WithExpiresAt sets an expiration time on the secret.
func WithExpiresAt(t time.Time) SetOption {
	return func(c *setConfig) { c.expiresAt = &t }
}

// Set creates or updates a secret, encrypting the value and auto-versioning.
func (s *Service) Set(ctx context.Context, key string, value []byte, appID string, opts ...SetOption) (*Meta, error) {
	appID = s.resolveAppID(appID)

	var cfg setConfig
	for _, o := range opts {
		o(&cfg)
	}

	sec := &Secret{
		Entity: vault.NewEntity(),
		ID:     id.NewSecretID(),
		Key:    key,
		Value:  value,
		AppID:  appID,
	}

	if cfg.metadata != nil {
		sec.Metadata = cfg.metadata
	}
	if cfg.expiresAt != nil {
		sec.ExpiresAt = cfg.expiresAt
	}

	// Encrypt the value.
	if s.encryptor != nil {
		ct, encErr := s.encryptor.Encrypt(value)
		if encErr != nil {
			return nil, fmt.Errorf("secret: encrypt %q: %w", key, encErr)
		}
		sec.EncryptedValue = ct
		sec.EncryptionAlg = "AES-256-GCM"
	} else {
		// No encryptor: store plaintext in EncryptedValue as fallback.
		sec.EncryptedValue = value
	}

	if err := s.store.SetSecret(ctx, sec); err != nil {
		return nil, err
	}

	if s.onMutate != nil {
		s.onMutate(ctx, "secret.set", key, appID)
	}

	return sec.ToMeta(), nil
}

// Delete removes a secret and all its versions.
func (s *Service) Delete(ctx context.Context, key, appID string) error {
	appID = s.resolveAppID(appID)

	if err := s.store.DeleteSecret(ctx, key, appID); err != nil {
		return err
	}

	if s.onMutate != nil {
		s.onMutate(ctx, "secret.delete", key, appID)
	}

	return nil
}

// List returns secret metadata for an app.
func (s *Service) List(ctx context.Context, appID string, opts ListOpts) ([]*Meta, error) {
	appID = s.resolveAppID(appID)
	return s.store.ListSecrets(ctx, appID, opts)
}

// GetVersion retrieves a specific version of a secret and decrypts it.
func (s *Service) GetVersion(ctx context.Context, key, appID string, version int64) (*Secret, error) {
	appID = s.resolveAppID(appID)

	sec, err := s.store.GetSecretVersion(ctx, key, appID, version)
	if err != nil {
		return nil, err
	}

	if s.encryptor != nil && len(sec.EncryptedValue) > 0 {
		plaintext, decErr := s.encryptor.Decrypt(sec.EncryptedValue)
		if decErr != nil {
			return nil, fmt.Errorf("secret: decrypt %q v%d: %w", key, version, decErr)
		}
		sec.Value = plaintext
	}

	if s.onAccess != nil {
		s.onAccess(ctx, key, appID)
	}

	return sec, nil
}

// ListVersions returns all versions of a secret.
func (s *Service) ListVersions(ctx context.Context, key, appID string) ([]*Version, error) {
	appID = s.resolveAppID(appID)
	return s.store.ListSecretVersions(ctx, key, appID)
}

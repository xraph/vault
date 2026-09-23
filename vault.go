package vault

import (
	"context"
	"fmt"
	"strings"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/vault/audit"
	"github.com/xraph/vault/config"
	"github.com/xraph/vault/crypto"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/override"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/scope"
	"github.com/xraph/vault/secret"
	"github.com/xraph/vault/store"
)

// Vault is the central type. It composes one store into the six subsystem
// services, wires the audit logger into secret mutations, and hands the
// whole thing out through accessors.
type Vault struct {
	config Config
	logger log.Logger
	store  store.Store

	encryptor *crypto.Encryptor

	secrets   *secret.Service
	engine    *flag.Engine
	flags     *flag.Service
	resolver  *override.Resolver
	configSvc *config.Service
	rotation  *rotation.Manager
	auditLog  *audit.Logger
}

// New creates a Vault from a store and options.
//
// An absent encryption key is not an error: secrets fall back to being stored
// as given, which is the documented behaviour for development. A key that is
// present but cannot be decoded IS an error, because silently falling back
// there would store secrets in the clear while the caller believes they are
// encrypted.
func New(opts ...Option) (*Vault, error) {
	v := &Vault{
		config: DefaultConfig(),
		logger: log.NewNoopLogger(),
	}
	for _, opt := range opts {
		opt(v)
	}

	if v.store == nil {
		return nil, ErrNoStore
	}

	enc, err := buildEncryptor(v.config)
	if err != nil {
		return nil, err
	}
	v.encryptor = enc

	// The audit logger first: the secret service's hooks take it.
	v.auditLog = audit.NewLogger(v.store, audit.WithLogger(v.logger))

	v.secrets = secret.NewService(v.store, v.encryptor,
		secret.WithAppID(v.config.AppID),
		secret.WithOnAccess(func(ctx context.Context, key, appID string) {
			v.auditLog.LogAccess(scope.WithAppID(ctx, appID), key, "secret.get", "secret")
		}),
		secret.WithOnMutate(func(ctx context.Context, action, key, appID string) {
			v.auditLog.LogAccess(scope.WithAppID(ctx, appID), key, action, "secret")
		}),
	)

	v.engine = flag.NewEngine(v.store, flag.WithCacheTTL(v.config.FlagCacheTTL))
	v.flags = flag.NewService(v.engine, flag.WithAppID(v.config.AppID))

	v.resolver = override.NewResolver(v.store, v.store,
		override.WithLogger(v.logger),
	)
	v.configSvc = config.NewService(v.store,
		config.WithAppID(v.config.AppID),
		config.WithResolver(v.resolver),
	)

	v.rotation = rotation.NewManager(v.store, v.secrets,
		rotation.WithAppID(v.config.AppID),
		rotation.WithLogger(v.logger),
	)

	return v, nil
}

// buildEncryptor resolves the encryption key from the config.
// It returns (nil, nil) when no key is configured at all.
func buildEncryptor(cfg Config) (*crypto.Encryptor, error) {
	key := cfg.EncryptionKey

	if len(key) == 0 && cfg.EncryptionKeyEnv != "" {
		provider := crypto.NewEnvKeyProvider(cfg.EncryptionKeyEnv)
		fromEnv, err := provider.GetKey(context.Background())
		if err != nil {
			// An unset variable means "no key configured", which is the
			// fallback. Anything else means the operator meant to configure
			// one and it is broken, which must not be silent.
			if isUnsetEnv(err) {
				return nil, nil
			}
			return nil, fmt.Errorf("vault: encryption key from %s: %w", cfg.EncryptionKeyEnv, err)
		}
		key = fromEnv
	}

	if len(key) == 0 {
		return nil, nil
	}

	enc, err := crypto.NewEncryptor(key)
	if err != nil {
		return nil, fmt.Errorf("vault: encryption key: %w", err)
	}
	return enc, nil
}

// isUnsetEnv reports whether err is EnvKeyProvider's "empty or not set".
// The provider returns a formatted error rather than a sentinel, so this
// matches on the text it produces.
func isUnsetEnv(err error) bool {
	return err != nil && strings.Contains(err.Error(), "is empty or not set")
}

// EncryptionEnabled reports whether secrets are encrypted at rest.
// False means a key was not configured and values are stored as given.
func (v *Vault) EncryptionEnabled() bool { return v.encryptor != nil }

// Secrets returns the secret service.
func (v *Vault) Secrets() *secret.Service { return v.secrets }

// Flags returns the type-safe flag evaluation service.
func (v *Vault) Flags() *flag.Service { return v.flags }

// FlagEngine returns the underlying flag engine, which is what a caller
// needs for EvaluateDetail. Flags() covers the typed read path.
func (v *Vault) FlagEngine() *flag.Engine { return v.engine }

// Config returns the runtime config service.
func (v *Vault) Config() *config.Service { return v.configSvc }

// Overrides returns the per-tenant config resolver.
func (v *Vault) Overrides() *override.Resolver { return v.resolver }

// Rotation returns the rotation manager.
func (v *Vault) Rotation() *rotation.Manager { return v.rotation }

// Audit returns the audit logger.
func (v *Vault) Audit() *audit.Logger { return v.auditLog }

// Store returns the configured store backend.
func (v *Vault) Store() store.Store { return v.store }

// Health checks the health of the Vault by pinging its store.
func (v *Vault) Health(ctx context.Context) error {
	if v.store == nil {
		return ErrNoStore
	}
	return v.store.Ping(ctx)
}

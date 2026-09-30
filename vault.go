package vault

import (
	"context"
	"fmt"
	"time"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/vault/audit"
	audithook "github.com/xraph/vault/audit_hook"
	"github.com/xraph/vault/config"
	"github.com/xraph/vault/configmgr"
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
	flagMgr   *flag.Manager
	flags     *flag.Service
	resolver  *override.Resolver
	configSvc *config.Service
	configMgr *configmgr.Manager
	rotation  *rotation.Manager
	auditLog  *audit.Logger
}

// New creates a Vault from a store and options.
//
// An absent encryption key is not an error: secrets fall back to being stored
// as given, which is the documented behaviour for development. A key that is
// present but cannot be decoded IS an error, because silently falling back
// there would store secrets in the clear while the caller believes they are
// encrypted. The same holds for a named key env var that is missing or
// empty: naming the variable is a statement of intent, so New refuses to
// start rather than writing plaintext the caller thinks is encrypted.
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
	if enc == nil {
		// Library callers get no other signal that secrets are about to be
		// stored in the clear when no key is configured at all.
		v.logger.Warn("vault: no encryption key configured; secrets will be stored unencrypted",
			log.String("encryption_key_env", v.config.EncryptionKeyEnv))
	}

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
	v.flagMgr = flag.NewManager(v.store, v.engine,
		flag.WithManagerAppID(v.config.AppID),
		flag.WithOnFlagMutate(func(ctx context.Context, action, key, appID string) {
			v.auditLog.LogAccess(scope.WithAppID(ctx, appID), key, action, audithook.ResourceFlag)
		}),
	)

	v.resolver = override.NewResolver(v.store, v.store,
		override.WithLogger(v.logger),
	)
	v.configSvc = config.NewService(v.store,
		config.WithAppID(v.config.AppID),
		config.WithResolver(v.resolver),
	)
	v.configMgr = configmgr.NewManager(v.store, v.store, v.resolver, v.configSvc,
		configmgr.WithManagerAppID(v.config.AppID),
		configmgr.WithOnConfigMutate(func(ctx context.Context, action, resource, key, appID, tenantID string) {
			ctx = scope.WithAppID(ctx, appID)
			// An override write is attributed to the tenant it targets, not
			// the one acting; a write to the entry keeps the caller's scope.
			if tenantID != "" {
				ctx = scope.WithTenantID(ctx, tenantID)
			}
			v.auditLog.LogAccess(ctx, key, action, resource)
		}),
	)

	v.rotation = rotation.NewManager(v.store, v.secrets,
		rotation.WithAppID(v.config.AppID),
		rotation.WithLogger(v.logger),
		// Every attempt leaves a row, so a failing rotation is something an
		// operator can find by filtering on outcome.
		rotation.WithOnRotate(func(ctx context.Context, key, appID string, err error) {
			ctx = scope.WithAppID(ctx, appID)
			if err != nil {
				v.auditLog.LogFailure(ctx, key, audithook.ActionSecretRotated, audithook.ResourceSecret, err)
				return
			}
			v.auditLog.LogAccess(ctx, key, audithook.ActionSecretRotated, audithook.ResourceSecret)
		}),
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
			// Naming the variable is a statement of intent: a missing,
			// empty, or undecodable value is a deployment mistake to
			// surface now, not permission to fall back to plaintext.
			return nil, fmt.Errorf("vault: encryption_key_env names %s but it holds no usable key: %w", cfg.EncryptionKeyEnv, err)
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

// AppID returns the vault's configured application id. Every contract
// handler operates on this app and this app alone; no request carries an
// app id of its own.
func (v *Vault) AppID() string { return v.config.AppID }

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

// FlagManager returns the flag write service: the one path that creates,
// changes and deletes flags with validation, cache invalidation and audit.
func (v *Vault) FlagManager() *flag.Manager { return v.flagMgr }

// FlagCacheTTL returns how long the flag engine keeps an evaluation in its
// cache. A flag write invalidates it in this process at once; another
// replica serves the old value for up to this long.
func (v *Vault) FlagCacheTTL() time.Duration { return v.config.FlagCacheTTL }

// Config returns the runtime config service.
func (v *Vault) Config() *config.Service { return v.configSvc }

// ConfigManager returns the config write service: the one path that creates,
// changes, rolls back and deletes config entries and their tenant overrides
// with validation, cache invalidation, watchers and audit.
func (v *Vault) ConfigManager() *configmgr.Manager { return v.configMgr }

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

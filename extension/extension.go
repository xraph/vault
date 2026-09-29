// Package extension provides the Forge extension adapter for Vault.
//
// It implements the forge.Extension interface to integrate Vault
// into a Forge application with automatic dependency discovery,
// route registration, and lifecycle management.
//
// Configuration can be provided programmatically via Option functions
// or via YAML configuration files under "extensions.vault" or "vault" keys.
package extension

import (
	"context"
	"errors"
	"fmt"

	"github.com/xraph/forge"
	dashboard "github.com/xraph/forge/extensions/dashboard"
	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/forge/extensions/dashboard/contract/dispatcher"
	"github.com/xraph/forge/extensions/dashboard/contributor"
	"github.com/xraph/grove"
	"github.com/xraph/vessel"

	"github.com/xraph/confy"

	"github.com/xraph/vault"
	vaultconfy "github.com/xraph/vault/confy"
	vaultdash "github.com/xraph/vault/dashboard"
	vaultcontract "github.com/xraph/vault/extension/contract"
	"github.com/xraph/vault/store"
	mongostore "github.com/xraph/vault/store/mongo"
	pgstore "github.com/xraph/vault/store/postgres"
	sqlitestore "github.com/xraph/vault/store/sqlite"
)

// ExtensionName is the name registered with Forge.
const ExtensionName = "vault"

// ExtensionDescription is the human-readable description.
const ExtensionDescription = "Composable secrets management, feature flags, and runtime configuration"

// ExtensionVersion is the semantic version.
const ExtensionVersion = "0.1.0"

// Ensure Extension implements forge.Extension and the dashboard awareness
// interfaces at compile time.
var (
	_ forge.Extension                    = (*Extension)(nil)
	_ dashboard.DashboardAware           = (*Extension)(nil)
	_ dashboard.ContractContributorAware = (*Extension)(nil)
)

// Extension adapts Vault as a Forge extension.
type Extension struct {
	*forge.BaseExtension

	config    Config
	v         *vault.Vault
	vaultOpts []vault.Option
	store     store.Store
	useGrove  bool
}

// New creates a new Vault Forge extension with the given options.
func New(opts ...Option) *Extension {
	e := &Extension{
		BaseExtension: forge.NewBaseExtension(ExtensionName, ExtensionVersion, ExtensionDescription),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Vault returns the underlying Vault instance.
// This is nil until Register is called.
func (e *Extension) Vault() *vault.Vault { return e.v }

// Store returns the configured store backend.
// This is nil if no store was provided.
func (e *Extension) Store() store.Store { return e.store }

// Register implements [forge.Extension]. It loads configuration,
// initializes the vault, and registers it in the DI container.
func (e *Extension) Register(fapp forge.App) error {
	if err := e.BaseExtension.Register(fapp); err != nil {
		return err
	}

	if err := e.loadConfiguration(); err != nil {
		return err
	}

	// Resolve store from grove DI if configured.
	if e.store == nil && e.useGrove {
		groveDB, err := e.resolveGroveDB(fapp)
		if err != nil {
			return fmt.Errorf("vault: %w", err)
		}
		s, err := e.buildStoreFromGroveDB(groveDB)
		if err != nil {
			return err
		}
		e.store = s
	}
	if e.store == nil {
		if db, err := vessel.Inject[*grove.DB](fapp.Container()); err == nil {
			// Auto-discover default grove.DB from container (matches authsome/cortex pattern).
			s, err := e.buildStoreFromGroveDB(db)
			if err != nil {
				return err
			}
			e.store = s
			e.Logger().Info("vault: auto-discovered grove.DB from container",
				forge.F("driver", db.Driver().Name()),
			)
		}
	}

	v, err := e.buildVault()
	if err != nil {
		return err
	}
	e.v = v

	if !e.v.EncryptionEnabled() {
		e.Logger().Warn("vault: no encryption key configured; secrets are stored unencrypted",
			forge.F("encryption_key_env", e.config.EncryptionKeyEnv),
		)
	}

	// Register the Vault instance in the DI container.
	if err := vessel.Provide(fapp.Container(), func() (*vault.Vault, error) {
		return e.v, nil
	}); err != nil {
		return err
	}

	// Register the store in the DI container if available.
	if e.store != nil {
		if err := vessel.Provide(fapp.Container(), func() (store.Store, error) {
			return e.store, nil
		}); err != nil {
			return err
		}
	}

	// Mount vault as a confy ConfigSource and SecretProvider if enabled.
	if e.config.MountToConfy && e.store != nil {
		e.mountToConfy(fapp)
	}

	e.Logger().Debug("vault: extension registered",
		forge.F("app_id", e.config.AppID),
		forge.F("disable_routes", e.config.DisableRoutes),
		forge.F("disable_migrate", e.config.DisableMigrate),
		forge.F("base_path", e.config.BasePath),
		forge.F("mount_to_confy", e.config.MountToConfy),
	)

	return nil
}

// buildVault assembles the vault options from the extension's merged
// configuration and constructs the underlying [vault.Vault]. It does not
// touch the forge app or logger, so it can be exercised in tests without a
// live forge.App.
func (e *Extension) buildVault() (*vault.Vault, error) {
	// Build vault options from merged config.
	if e.config.AppID != "" {
		e.vaultOpts = append(e.vaultOpts, vault.WithAppID(e.config.AppID))
	}
	if e.config.EncryptionKeyEnv != "" {
		e.vaultOpts = append(e.vaultOpts, vault.WithEncryptionKeyEnv(e.config.EncryptionKeyEnv))
	}
	if e.config.FlagCacheTTL != 0 {
		e.vaultOpts = append(e.vaultOpts, vault.WithConfig(vault.Config{
			AppID:              e.config.AppID,
			EncryptionKeyEnv:   e.config.EncryptionKeyEnv,
			FlagCacheTTL:       e.config.FlagCacheTTL,
			SourcePollInterval: e.config.SourcePollInterval,
		}))
	}

	if e.store != nil {
		e.vaultOpts = append(e.vaultOpts, vault.WithStore(e.store))
	}

	v, err := vault.New(e.vaultOpts...)
	if err != nil {
		if errors.Is(err, vault.ErrNoStore) {
			return nil, fmt.Errorf("%w: pass extension.WithStore, set extension.WithGroveDatabase or grove_database in config, or register a *grove.DB in the DI container", vault.ErrNoStore)
		}
		return nil, err
	}
	return v, nil
}

// Start implements [forge.Extension]. It starts the rotation manager's
// background loop, without which a policy with an enabled, due rotation
// and a registered rotator never rotates on schedule. The loop is started
// with context.Background() rather than the context Start receives, which
// may be cancelled or time out well before the extension itself stops.
func (e *Extension) Start(_ context.Context) error {
	if e.v != nil {
		if err := e.v.Rotation().Start(context.Background()); err != nil {
			return err
		}
	}
	e.MarkStarted()
	return nil
}

// Stop implements [forge.Extension]. The rotation loop is stopped before
// the store is closed, so no in-flight rotation check can run against a
// closed store.
func (e *Extension) Stop(ctx context.Context) error {
	if e.v != nil {
		if err := e.v.Rotation().Stop(ctx); err != nil {
			e.MarkStopped()
			return err
		}
	}
	if e.store != nil {
		if err := e.store.Close(); err != nil {
			e.MarkStopped()
			return err
		}
	}
	e.MarkStopped()
	return nil
}

// Health implements [forge.Extension].
func (e *Extension) Health(ctx context.Context) error {
	if e.store != nil {
		return e.store.Ping(ctx)
	}
	return nil
}

// RegisterContractContributor implements dashboard.ContractContributorAware.
// It registers the vault contract contributor, which is what the React
// shell reads. The templ LocalContributor below is unaffected, and both run
// side by side until the templ dashboard is retired.
func (e *Extension) RegisterContractContributor(
	disp *dispatcher.Dispatcher,
	reg dashcontract.Registry,
	wreg dashcontract.WardenRegistry,
) error {
	if e.v == nil {
		// Nothing to wire yet. A quiet skip, not a panic that takes the
		// dashboard down with it. The logger may not exist either on an
		// extension that was never registered.
		if logger := e.Logger(); logger != nil {
			logger.Warn("vault: not initialised; skipping contract contributor registration")
		}
		return nil
	}
	// Logger may be nil on an extension that was never registered;
	// Deps treats nil as "log nothing".
	deps := vaultcontract.Deps{Vault: e.v}
	if logger := e.Logger(); logger != nil {
		deps.Logger = logger
	}
	if err := vaultcontract.Register(disp, reg, wreg, deps); err != nil {
		return fmt.Errorf("vault: register contract contributor: %w", err)
	}
	return nil
}

// DashboardContributor implements dashboard.DashboardAware. It returns a
// LocalContributor that renders vault pages, widgets, and settings in the
// Forge dashboard using templ + ForgeUI.
func (e *Extension) DashboardContributor() contributor.LocalContributor {
	return vaultdash.New(
		vaultdash.NewManifest(),
		e.store,
		e.config.AppID,
	)
}

// mountToConfy registers vault as a confy ConfigSource and SecretProvider
// in the forge ConfigManager. If the ConfigManager is not available in the
// DI container, this is a no-op.
func (e *Extension) mountToConfy(fapp forge.App) {
	cm, err := vessel.Inject[confy.Confy](fapp.Container())
	if err != nil {
		e.Logger().Debug("vault: confy not available in container, skipping mount",
			forge.F("error", err.Error()),
		)
		return
	}

	// Build source options from config.
	sourceOpts := []vaultconfy.VaultSourceOption{
		vaultconfy.WithSourcePollInterval(e.config.SourcePollInterval),
	}
	if e.config.ConfyKeyPrefix != "" {
		sourceOpts = append(sourceOpts, vaultconfy.WithKeyPrefix(e.config.ConfyKeyPrefix))
	}
	if len(e.config.ConfyMountKeys) > 0 {
		sourceOpts = append(sourceOpts, vaultconfy.WithKeys(e.config.ConfyMountKeys...))
	}
	if len(e.config.ConfyMountPatterns) > 0 {
		sourceOpts = append(sourceOpts, vaultconfy.WithKeyPatterns(e.config.ConfyMountPatterns...))
	}

	src := vaultconfy.NewVaultConfigSource(
		e.store, e.v.Secrets(), e.config.AppID,
		sourceOpts...,
	)

	if err := cm.LoadFrom(src); err != nil {
		e.Logger().Warn("vault: failed to mount config source to confy",
			forge.F("error", err.Error()),
		)
		return
	}

	// Register secret provider if confy has a secrets manager.
	sm := cm.SecretsManager()
	if sm != nil {
		provider := vaultconfy.NewVaultSecretProvider(e.v.Secrets(), e.config.AppID)
		if err := sm.RegisterProvider("vault", provider); err != nil {
			e.Logger().Warn("vault: failed to register secret provider with confy",
				forge.F("error", err.Error()),
			)
		} else {
			e.Logger().Info("vault: registered secret provider with confy")
		}
	}

	e.Logger().Info("vault: mounted config source to confy",
		forge.F("app_id", e.config.AppID),
	)
}

// --- Config Loading (mirrors grove extension pattern) ---

// loadConfiguration loads config from YAML files or programmatic sources.
func (e *Extension) loadConfiguration() error {
	programmaticConfig := e.config

	// Try loading from config file.
	fileConfig, configLoaded := e.tryLoadFromConfigFile()

	if !configLoaded {
		if programmaticConfig.RequireConfig {
			return errors.New("vault: configuration is required but not found in config files; " +
				"ensure 'extensions.vault' or 'vault' key exists in your config")
		}

		// Use programmatic config merged with defaults.
		e.config = e.mergeWithDefaults(programmaticConfig)
	} else {
		// Config loaded from YAML -- merge with programmatic options.
		e.config = e.mergeConfigurations(fileConfig, programmaticConfig)
	}

	// Enable grove resolution if YAML config specifies a grove database.
	if e.config.GroveDatabase != "" {
		e.useGrove = true
	}

	e.Logger().Debug("vault: configuration loaded",
		forge.F("disable_routes", e.config.DisableRoutes),
		forge.F("disable_migrate", e.config.DisableMigrate),
		forge.F("base_path", e.config.BasePath),
		forge.F("app_id", e.config.AppID),
		forge.F("grove_database", e.config.GroveDatabase),
	)

	return nil
}

// tryLoadFromConfigFile attempts to load config from YAML files.
func (e *Extension) tryLoadFromConfigFile() (Config, bool) {
	cm := e.App().Config()
	var cfg Config

	// Try "extensions.vault" first (namespaced pattern).
	if cm.IsSet("extensions.vault") {
		if err := cm.Bind("extensions.vault", &cfg); err == nil {
			e.Logger().Debug("vault: loaded config from file",
				forge.F("key", "extensions.vault"),
			)
			return cfg, true
		}
		e.Logger().Warn("vault: failed to bind extensions.vault config",
			forge.F("error", "bind failed"),
		)
	}

	// Try legacy "vault" key.
	if cm.IsSet("vault") {
		if err := cm.Bind("vault", &cfg); err == nil {
			e.Logger().Debug("vault: loaded config from file",
				forge.F("key", "vault"),
			)
			return cfg, true
		}
		e.Logger().Warn("vault: failed to bind vault config",
			forge.F("error", "bind failed"),
		)
	}

	return Config{}, false
}

// mergeWithDefaults fills zero-valued fields with defaults.
func (e *Extension) mergeWithDefaults(cfg Config) Config {
	defaults := DefaultConfig()
	if cfg.FlagCacheTTL == 0 {
		cfg.FlagCacheTTL = defaults.FlagCacheTTL
	}
	if cfg.SourcePollInterval == 0 {
		cfg.SourcePollInterval = defaults.SourcePollInterval
	}
	return cfg
}

// mergeConfigurations merges YAML config with programmatic options.
// YAML config takes precedence for most fields; programmatic bool flags fill gaps.
func (e *Extension) mergeConfigurations(yamlConfig, programmaticConfig Config) Config {
	// Programmatic bool flags override when true.
	if programmaticConfig.DisableRoutes {
		yamlConfig.DisableRoutes = true
	}
	if programmaticConfig.DisableMigrate {
		yamlConfig.DisableMigrate = true
	}
	if programmaticConfig.EnableAudit {
		yamlConfig.EnableAudit = true
	}
	if programmaticConfig.MountToConfy {
		yamlConfig.MountToConfy = true
	}

	// String fields: YAML takes precedence.
	if yamlConfig.BasePath == "" && programmaticConfig.BasePath != "" {
		yamlConfig.BasePath = programmaticConfig.BasePath
	}
	if yamlConfig.AppID == "" && programmaticConfig.AppID != "" {
		yamlConfig.AppID = programmaticConfig.AppID
	}
	if yamlConfig.EncryptionKeyEnv == "" && programmaticConfig.EncryptionKeyEnv != "" {
		yamlConfig.EncryptionKeyEnv = programmaticConfig.EncryptionKeyEnv
	}
	if yamlConfig.GroveDatabase == "" && programmaticConfig.GroveDatabase != "" {
		yamlConfig.GroveDatabase = programmaticConfig.GroveDatabase
	}
	if yamlConfig.ConfyKeyPrefix == "" && programmaticConfig.ConfyKeyPrefix != "" {
		yamlConfig.ConfyKeyPrefix = programmaticConfig.ConfyKeyPrefix
	}

	// Slice fields: programmatic fills gaps.
	if len(yamlConfig.ConfyMountKeys) == 0 && len(programmaticConfig.ConfyMountKeys) > 0 {
		yamlConfig.ConfyMountKeys = programmaticConfig.ConfyMountKeys
	}
	if len(yamlConfig.ConfyMountPatterns) == 0 && len(programmaticConfig.ConfyMountPatterns) > 0 {
		yamlConfig.ConfyMountPatterns = programmaticConfig.ConfyMountPatterns
	}

	// Duration fields: YAML takes precedence, programmatic fills gaps.
	if yamlConfig.FlagCacheTTL == 0 && programmaticConfig.FlagCacheTTL != 0 {
		yamlConfig.FlagCacheTTL = programmaticConfig.FlagCacheTTL
	}
	if yamlConfig.SourcePollInterval == 0 && programmaticConfig.SourcePollInterval != 0 {
		yamlConfig.SourcePollInterval = programmaticConfig.SourcePollInterval
	}

	// Fill remaining zeros with defaults.
	return e.mergeWithDefaults(yamlConfig)
}

// resolveGroveDB resolves a *grove.DB from the DI container.
// If GroveDatabase is set, it looks up the named DB; otherwise it uses the default.
func (e *Extension) resolveGroveDB(fapp forge.App) (*grove.DB, error) {
	if e.config.GroveDatabase != "" {
		db, err := vessel.InjectNamed[*grove.DB](fapp.Container(), e.config.GroveDatabase)
		if err != nil {
			return nil, fmt.Errorf("grove database %q not found in container: %w", e.config.GroveDatabase, err)
		}
		return db, nil
	}
	db, err := vessel.Inject[*grove.DB](fapp.Container())
	if err != nil {
		return nil, fmt.Errorf("default grove database not found in container: %w", err)
	}
	return db, nil
}

// buildStoreFromGroveDB constructs the appropriate store backend
// based on the grove driver type (pg, sqlite, mongo).
func (e *Extension) buildStoreFromGroveDB(db *grove.DB) (store.Store, error) {
	driverName := db.Driver().Name()
	switch driverName {
	case "pg":
		return pgstore.New(db), nil
	case "sqlite":
		return sqlitestore.New(db), nil
	case "mongo":
		return mongostore.New(db), nil
	default:
		return nil, fmt.Errorf("vault: unsupported grove driver %q", driverName)
	}
}

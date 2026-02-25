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
	"github.com/xraph/grove"
	"github.com/xraph/vessel"

	"github.com/xraph/vault"
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

// Ensure Extension implements forge.Extension at compile time.
var _ forge.Extension = (*Extension)(nil)

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

	v := vault.NewVault(e.vaultOpts...)
	e.v = v

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

	e.Logger().Debug("vault: extension registered",
		forge.F("app_id", e.config.AppID),
		forge.F("disable_routes", e.config.DisableRoutes),
		forge.F("disable_migrate", e.config.DisableMigrate),
		forge.F("base_path", e.config.BasePath),
	)

	return nil
}

// Start implements [forge.Extension].
func (e *Extension) Start(_ context.Context) error {
	e.MarkStarted()
	return nil
}

// Stop implements [forge.Extension].
func (e *Extension) Stop(_ context.Context) error {
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

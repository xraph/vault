package extension

import (
	"github.com/xraph/vault"
	"github.com/xraph/vault/store"
)

// Option configures the Vault Forge extension.
type Option func(*Extension)

// WithStore sets the composite store backend for the vault.
func WithStore(s store.Store) Option {
	return func(e *Extension) {
		e.store = s
	}
}

// WithVaultOption passes a vault option through to the underlying Vault instance.
func WithVaultOption(opt vault.Option) Option {
	return func(e *Extension) {
		e.vaultOpts = append(e.vaultOpts, opt)
	}
}

// WithConfig sets the Forge extension configuration.
func WithConfig(cfg Config) Option {
	return func(e *Extension) { e.config = cfg }
}

// WithDisableRoutes prevents HTTP route registration.
func WithDisableRoutes() Option {
	return func(e *Extension) { e.config.DisableRoutes = true }
}

// WithDisableMigrate prevents auto-migration on start.
func WithDisableMigrate() Option {
	return func(e *Extension) { e.config.DisableMigrate = true }
}

// WithBasePath sets the URL prefix for vault routes.
func WithBasePath(path string) Option {
	return func(e *Extension) { e.config.BasePath = path }
}

// WithRequireConfig requires config to be present in YAML files.
// If true and no config is found, Register returns an error.
func WithRequireConfig(require bool) Option {
	return func(e *Extension) { e.config.RequireConfig = require }
}

// WithAppID sets the application identifier used for scoping.
func WithAppID(appID string) Option {
	return func(e *Extension) { e.config.AppID = appID }
}

// WithEncryptionKeyEnv sets the environment variable name for the encryption key.
func WithEncryptionKeyEnv(envVar string) Option {
	return func(e *Extension) { e.config.EncryptionKeyEnv = envVar }
}

// WithEnableAudit enables or disables audit logging.
func WithEnableAudit(enable bool) Option {
	return func(e *Extension) { e.config.EnableAudit = enable }
}

// WithGroveDatabase sets the name of the grove.DB to resolve from the DI container.
// The extension will auto-construct the appropriate store backend (postgres/sqlite/mongo)
// based on the grove driver type. Pass an empty string to use the default (unnamed) grove.DB.
func WithGroveDatabase(name string) Option {
	return func(e *Extension) {
		e.config.GroveDatabase = name
		e.useGrove = true
	}
}

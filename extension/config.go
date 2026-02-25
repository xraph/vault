package extension

import "time"

// Config holds the Vault extension configuration.
// Fields can be set programmatically via Option functions or loaded from
// YAML configuration files (under "extensions.vault" or "vault" keys).
type Config struct {
	// DisableRoutes prevents HTTP route registration.
	DisableRoutes bool `json:"disable_routes" mapstructure:"disable_routes" yaml:"disable_routes"`

	// DisableMigrate prevents auto-migration on start.
	DisableMigrate bool `json:"disable_migrate" mapstructure:"disable_migrate" yaml:"disable_migrate"`

	// BasePath is the URL prefix for vault routes (default: "/vault").
	BasePath string `json:"base_path" mapstructure:"base_path" yaml:"base_path"`

	// AppID is the application identifier used for scoping secrets, flags, and config.
	AppID string `json:"app_id" mapstructure:"app_id" yaml:"app_id"`

	// EncryptionKeyEnv is the environment variable name for the encryption key.
	// Used to load the master encryption key at startup.
	EncryptionKeyEnv string `json:"encryption_key_env" mapstructure:"encryption_key_env" yaml:"encryption_key_env"`

	// FlagCacheTTL is the TTL for the flag evaluation cache.
	// Defaults to 30 seconds.
	FlagCacheTTL time.Duration `json:"flag_cache_ttl" mapstructure:"flag_cache_ttl" yaml:"flag_cache_ttl"`

	// SourcePollInterval is the interval for polling database sources.
	// Defaults to 30 seconds.
	SourcePollInterval time.Duration `json:"source_poll_interval" mapstructure:"source_poll_interval" yaml:"source_poll_interval"`

	// EnableAudit enables audit logging for vault operations.
	EnableAudit bool `json:"enable_audit" mapstructure:"enable_audit" yaml:"enable_audit"`

	// GroveDatabase is the name of a grove.DB registered in the DI container.
	// When set, the extension resolves this named database and auto-constructs
	// the appropriate store based on the driver type (pg/sqlite/mongo).
	// When empty and WithGroveDatabase was called, the default (unnamed) DB is used.
	GroveDatabase string `json:"grove_database" mapstructure:"grove_database" yaml:"grove_database"`

	// RequireConfig requires config to be present in YAML files.
	// If true and no config is found, Register returns an error.
	RequireConfig bool `json:"-" yaml:"-"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		FlagCacheTTL:       30 * time.Second,
		SourcePollInterval: 30 * time.Second,
		EnableAudit:        true,
	}
}

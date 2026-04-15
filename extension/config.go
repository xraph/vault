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

	// MountToConfy registers vault as a confy ConfigSource and SecretProvider
	// so vault-managed config and secrets are accessible via the forge ConfigManager.
	MountToConfy bool `json:"mount_to_confy" mapstructure:"mount_to_confy" yaml:"mount_to_confy"`

	// ConfyKeyPrefix is prepended to all vault keys when exposed through confy.
	// For example, "vault." causes vault key "db.host" to appear as "vault.db.host".
	ConfyKeyPrefix string `json:"confy_key_prefix" mapstructure:"confy_key_prefix" yaml:"confy_key_prefix"`

	// ConfyMountKeys restricts which vault keys are mounted into confy.
	// Only the listed keys will be included; all others are filtered out.
	// When empty, all keys are included (unless ConfyMountPatterns is set).
	ConfyMountKeys []string `json:"confy_mount_keys" mapstructure:"confy_mount_keys" yaml:"confy_mount_keys"`

	// ConfyMountPatterns restricts which vault keys are mounted into confy
	// using glob patterns (e.g. "db.*", "auth.*"). Multiple patterns are OR-ed.
	// When empty, all keys are included (unless ConfyMountKeys is set).
	ConfyMountPatterns []string `json:"confy_mount_patterns" mapstructure:"confy_mount_patterns" yaml:"confy_mount_patterns"`

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

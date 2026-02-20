package vault

import "time"

// Config holds the configuration for a Vault instance.
type Config struct {
	// AppID is the application identifier used for scoping secrets, flags, and config.
	AppID string `json:"app_id" yaml:"app_id"`

	// EncryptionKey is the master encryption key (32 bytes for AES-256-GCM).
	// If empty, encryption is disabled (not recommended for production).
	EncryptionKey []byte `json:"-" yaml:"-"`

	// EncryptionKeyEnv is the environment variable name for the encryption key.
	// Used as a fallback if EncryptionKey is not set directly.
	EncryptionKeyEnv string `json:"encryption_key_env" yaml:"encryption_key_env"`

	// FlagCacheTTL is the TTL for the flag evaluation cache.
	// Defaults to 30 seconds.
	FlagCacheTTL time.Duration `json:"flag_cache_ttl" yaml:"flag_cache_ttl"`

	// SourcePollInterval is the interval for polling database sources.
	// Defaults to 30 seconds.
	SourcePollInterval time.Duration `json:"source_poll_interval" yaml:"source_poll_interval"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		FlagCacheTTL:       30 * time.Second,
		SourcePollInterval: 30 * time.Second,
	}
}

package vault

import (
	log "github.com/xraph/go-utils/log"

	"github.com/xraph/vault/store"
)

// Option configures a Vault instance.
type Option func(*Vault)

// WithAppID sets the application identifier used for scoping.
func WithAppID(appID string) Option {
	return func(v *Vault) {
		v.config.AppID = appID
	}
}

// WithEncryptionKey sets the master encryption key (32 bytes for AES-256-GCM).
func WithEncryptionKey(key []byte) Option {
	return func(v *Vault) {
		v.config.EncryptionKey = key
	}
}

// WithEncryptionKeyEnv sets the environment variable name for the encryption key.
func WithEncryptionKeyEnv(envVar string) Option {
	return func(v *Vault) {
		v.config.EncryptionKeyEnv = envVar
	}
}

// WithLogger sets the structured logger.
func WithLogger(l log.Logger) Option {
	return func(v *Vault) {
		v.logger = l
	}
}

// WithConfig overlays the given Config onto the Vault's current
// configuration. A non-zero field in cfg overrides the current value; a
// zero-valued field leaves whatever an earlier option (or DefaultConfig)
// already set. It does not replace the whole Config wholesale, so it is
// safe to combine with WithAppID, WithEncryptionKey, and friends in any
// order without one silently erasing the other.
func WithConfig(cfg Config) Option {
	return func(v *Vault) {
		if cfg.AppID != "" {
			v.config.AppID = cfg.AppID
		}
		if len(cfg.EncryptionKey) > 0 {
			v.config.EncryptionKey = cfg.EncryptionKey
		}
		if cfg.EncryptionKeyEnv != "" {
			v.config.EncryptionKeyEnv = cfg.EncryptionKeyEnv
		}
		if cfg.FlagCacheTTL != 0 {
			v.config.FlagCacheTTL = cfg.FlagCacheTTL
		}
		if cfg.SourcePollInterval != 0 {
			v.config.SourcePollInterval = cfg.SourcePollInterval
		}
	}
}

// WithStore sets the store backend. Required: New cannot compose the
// subsystem services without one.
func WithStore(s store.Store) Option {
	return func(v *Vault) { v.store = s }
}

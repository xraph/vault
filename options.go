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

// WithConfig sets the vault configuration directly.
func WithConfig(cfg Config) Option {
	return func(v *Vault) {
		v.config = cfg
	}
}

// WithStore sets the store backend. Required: New cannot compose the
// subsystem services without one.
func WithStore(s store.Store) Option {
	return func(v *Vault) { v.store = s }
}

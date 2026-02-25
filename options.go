package vault

import (
	"log/slog"
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
func WithLogger(l *slog.Logger) Option {
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

// Storer is the interface that store backends must implement.
// It is defined here to avoid import cycles — the store package
// composes subsystem store interfaces into a concrete type.
type Storer interface {
	Ping(ctx interface{ Deadline() (interface{}, bool) }) error
	Close() error
}

// Vault is the central type. It is defined here as a forward declaration
// so that options can reference it. The full implementation is in vault.go
// (created in a later phase).
type Vault struct {
	config Config
	logger *slog.Logger
}

// NewVault creates a new Vault instance with the given options.
func NewVault(opts ...Option) *Vault {
	v := &Vault{
		config: DefaultConfig(),
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

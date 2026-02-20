// Package plugin provides the plugin system for extending Vault functionality.
// Plugins implement the base Plugin interface and optionally implement
// additional capability interfaces for specific subsystems.
package plugin

import (
	"context"

	"github.com/xraph/vault/crypto"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/source"
)

// Plugin is the base interface all plugins must implement.
type Plugin interface {
	Name() string
}

// OnInit is implemented by plugins that need initialization.
type OnInit interface {
	OnInit(ctx context.Context) error
}

// OnShutdown is implemented by plugins that need cleanup.
type OnShutdown interface {
	OnShutdown(ctx context.Context) error
}

// SourceProvider provides a configuration source with a priority.
type SourceProvider interface {
	Source() source.Source
	Priority() int
}

// EncryptionProvider provides an encryption key provider.
type EncryptionProvider interface {
	EncryptionKeyProvider() crypto.EncryptionKeyProvider
}

// FlagEvaluator provides a custom flag rule evaluator.
type FlagEvaluator interface {
	EvaluatorName() string
	Evaluate(ctx context.Context, rule *flag.Rule, tenantID, userID string) (bool, error)
}

// OnSecretAccess is called when a secret is accessed.
type OnSecretAccess interface {
	OnSecretAccess(ctx context.Context, key, action string) error
}

// OnConfigChange is called when a config entry changes.
type OnConfigChange interface {
	OnConfigChange(ctx context.Context, key string, oldValue, newValue any) error
}

// RotationStrategy provides a custom secret rotation strategy.
type RotationStrategy interface {
	RotationName() string
	Rotate(ctx context.Context, key string, current []byte) ([]byte, error)
}

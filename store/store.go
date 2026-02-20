// Package store defines the composite store interface that all backends implement.
package store

import (
	"context"

	"github.com/xraph/vault/audit"
	"github.com/xraph/vault/config"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/override"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/secret"
)

// Store is the composite interface that all Vault store backends must implement.
// It embeds all subsystem store interfaces plus lifecycle methods.
type Store interface {
	secret.Store
	flag.Store
	config.Store
	override.Store
	rotation.Store
	audit.Store

	// Migrate runs any pending database migrations.
	Migrate(ctx context.Context) error

	// Ping checks connectivity to the underlying store.
	Ping(ctx context.Context) error

	// Close releases any resources held by the store.
	Close() error
}

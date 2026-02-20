package bunstore

import (
	"context"
	"log/slog"

	"github.com/uptrace/bun"

	"github.com/xraph/vault/audit"
	"github.com/xraph/vault/config"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/override"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/secret"
)

// Compile-time interface checks.
var (
	_ secret.Store   = (*Store)(nil)
	_ flag.Store     = (*Store)(nil)
	_ config.Store   = (*Store)(nil)
	_ override.Store = (*Store)(nil)
	_ rotation.Store = (*Store)(nil)
	_ audit.Store    = (*Store)(nil)
)

// StoreOption configures the Store.
type StoreOption func(*Store)

// WithLogger sets the logger for the store.
func WithLogger(l *slog.Logger) StoreOption {
	return func(s *Store) { s.logger = l }
}

// Store is a Bun ORM implementation of all Vault store interfaces.
type Store struct {
	db     *bun.DB
	logger *slog.Logger
}

// New creates a new Bun store using the given bun.DB instance.
func New(db *bun.DB, opts ...StoreOption) *Store {
	s := &Store{db: db, logger: slog.Default()}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Migrate creates all tables using Bun's CreateTable with IfNotExists.
func (s *Store) Migrate(ctx context.Context) error {
	models := []interface{}{
		(*SecretModel)(nil),
		(*SecretVersionModel)(nil),
		(*FlagModel)(nil),
		(*FlagRuleModel)(nil),
		(*FlagOverrideModel)(nil),
		(*ConfigModel)(nil),
		(*ConfigVersionModel)(nil),
		(*OverrideModel)(nil),
		(*RotationPolicyModel)(nil),
		(*RotationRecordModel)(nil),
		(*AuditModel)(nil),
	}

	for _, model := range models {
		if _, err := s.db.NewCreateTable().Model(model).IfNotExists().Exec(ctx); err != nil {
			return err
		}
	}

	s.logger.Info("bunstore: migrations complete")
	return nil
}

// Ping checks the database connection.
func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// Close releases the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// Package postgres provides a PostgreSQL implementation of all Vault store interfaces.
package postgres

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xraph/vault/audit"
	"github.com/xraph/vault/config"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/override"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/secret"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

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

// Store is a PostgreSQL implementation of all Vault store interfaces.
type Store struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// New creates a new PostgreSQL store by connecting to the given connection string.
func New(ctx context.Context, connString string, opts ...StoreOption) (*Store, error) {
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}
	s := &Store{pool: pool, logger: slog.Default()}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// NewFromPool creates a store using an existing connection pool.
func NewFromPool(pool *pgxpool.Pool, opts ...StoreOption) *Store {
	s := &Store{pool: pool, logger: slog.Default()}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Migrate runs embedded SQL migration files in order.
// It creates a tracking table and skips already-applied migrations.
func (s *Store) Migrate(ctx context.Context) error {
	// Create tracking table.
	const createTracker = `CREATE TABLE IF NOT EXISTS vault_migrations (
		name TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`
	if _, err := s.pool.Exec(ctx, createTracker); err != nil {
		return fmt.Errorf("postgres: create migration tracker: %w", err)
	}

	// List and sort migration files.
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("postgres: read migrations: %w", err)
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		// Check if already applied.
		var exists bool
		err := s.pool.QueryRow(ctx,
			"SELECT EXISTS(SELECT 1 FROM vault_migrations WHERE name = $1)", name,
		).Scan(&exists)
		if err != nil {
			return fmt.Errorf("postgres: check migration %q: %w", name, err)
		}
		if exists {
			continue
		}

		// Read and execute migration.
		data, rErr := migrationsFS.ReadFile("migrations/" + name)
		if rErr != nil {
			return fmt.Errorf("postgres: read migration %q: %w", name, rErr)
		}

		if _, err := s.pool.Exec(ctx, string(data)); err != nil {
			return fmt.Errorf("postgres: exec migration %q: %w", name, err)
		}

		// Record migration.
		if _, err := s.pool.Exec(ctx,
			"INSERT INTO vault_migrations (name) VALUES ($1)", name,
		); err != nil {
			return fmt.Errorf("postgres: record migration %q: %w", name, err)
		}

		s.logger.Info("postgres: applied migration", "name", name)
	}

	return nil
}

// Ping checks the database connection.
func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// Close releases the connection pool.
func (s *Store) Close() error {
	s.pool.Close()
	return nil
}

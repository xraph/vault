package postgres

import (
	"context"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/pgdriver"

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
func WithLogger(l log.Logger) StoreOption {
	return func(s *Store) { s.logger = l }
}

// Store is a Grove ORM implementation of all Vault store interfaces.
type Store struct {
	db     *grove.DB
	logger log.Logger
}

// New creates a new Grove store using the given grove.DB instance.
func New(db *grove.DB, opts ...StoreOption) *Store {
	s := &Store{db: db, logger: log.NewNoopLogger()}
	for _, o := range opts {
		o(s)
	}
	return s
}

// pgdb returns the underlying pgdriver.PgDB for typed query builder access.
func (s *Store) pgdb() *pgdriver.PgDB {
	return pgdriver.Unwrap(s.db)
}

// Migrate creates all tables using Grove's migration system.
// This method is kept for backward compatibility; prefer using the
// Migrations group with grove's migrator for production deployments.
func (s *Store) Migrate(ctx context.Context) error {
	pgdb := s.pgdb()

	tables := []string{
		createSecretsTable,
		createSecretVersionsTable,
		createFlagsTable,
		createFlagRulesTable,
		createFlagOverridesTable,
		createConfigTable,
		createConfigVersionsTable,
		createOverridesTable,
		createRotationPoliciesTable,
		createRotationRecordsTable,
		createAuditTable,
		createIndexes,
	}

	for _, ddl := range tables {
		if _, err := pgdb.Exec(ctx, ddl); err != nil {
			return err
		}
	}

	s.logger.Info("postgres: migrations complete")
	return nil
}

// Ping checks the database connection.
func (s *Store) Ping(ctx context.Context) error {
	return s.db.Ping(ctx)
}

// Close releases the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// DDL statements for Migrate().
const (
	createSecretsTable = `CREATE TABLE IF NOT EXISTS vault_secrets (
		id              TEXT        PRIMARY KEY,
		key             TEXT        NOT NULL,
		app_id          TEXT        NOT NULL,
		encrypted_value BYTEA       NOT NULL DEFAULT '',
		encryption_alg  TEXT        NOT NULL DEFAULT '',
		encryption_key_id TEXT      NOT NULL DEFAULT '',
		version         BIGINT      NOT NULL DEFAULT 1,
		metadata        JSONB       DEFAULT '{}',
		expires_at      TIMESTAMPTZ,
		created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		UNIQUE (key, app_id)
	)`

	createSecretVersionsTable = `CREATE TABLE IF NOT EXISTS vault_secret_versions (
		id              TEXT        PRIMARY KEY,
		secret_key      TEXT        NOT NULL,
		app_id          TEXT        NOT NULL,
		version         BIGINT      NOT NULL,
		encrypted_value BYTEA       NOT NULL DEFAULT '',
		created_by      TEXT        NOT NULL DEFAULT '',
		created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		UNIQUE (secret_key, app_id, version)
	)`

	createFlagsTable = `CREATE TABLE IF NOT EXISTS vault_flags (
		id              TEXT        PRIMARY KEY,
		key             TEXT        NOT NULL,
		type            TEXT        NOT NULL DEFAULT 'bool',
		default_value   JSONB       NOT NULL DEFAULT 'false',
		description     TEXT        NOT NULL DEFAULT '',
		tags            JSONB       DEFAULT '[]',
		variants        JSONB       DEFAULT '[]',
		enabled         BOOLEAN     NOT NULL DEFAULT TRUE,
		app_id          TEXT        NOT NULL,
		metadata        JSONB       DEFAULT '{}',
		created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		UNIQUE (key, app_id)
	)`

	createFlagRulesTable = `CREATE TABLE IF NOT EXISTS vault_flag_rules (
		id          TEXT        PRIMARY KEY,
		flag_key    TEXT        NOT NULL,
		app_id      TEXT        NOT NULL,
		priority    INT         NOT NULL DEFAULT 0,
		type        TEXT        NOT NULL,
		config      JSONB       NOT NULL DEFAULT '{}',
		return_value JSONB      NOT NULL,
		created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`

	createFlagOverridesTable = `CREATE TABLE IF NOT EXISTS vault_flag_overrides (
		id          TEXT        PRIMARY KEY,
		flag_key    TEXT        NOT NULL,
		app_id      TEXT        NOT NULL,
		tenant_id   TEXT        NOT NULL,
		value       JSONB       NOT NULL,
		created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		UNIQUE (flag_key, app_id, tenant_id)
	)`

	createConfigTable = `CREATE TABLE IF NOT EXISTS vault_config (
		id          TEXT        PRIMARY KEY,
		key         TEXT        NOT NULL,
		value       JSONB       NOT NULL,
		value_type  TEXT        NOT NULL DEFAULT '',
		version     BIGINT      NOT NULL DEFAULT 1,
		description TEXT        NOT NULL DEFAULT '',
		app_id      TEXT        NOT NULL,
		metadata    JSONB       DEFAULT '{}',
		created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		UNIQUE (key, app_id)
	)`

	createConfigVersionsTable = `CREATE TABLE IF NOT EXISTS vault_config_versions (
		id          TEXT        PRIMARY KEY,
		config_key  TEXT        NOT NULL,
		app_id      TEXT        NOT NULL,
		version     BIGINT      NOT NULL,
		value       JSONB       NOT NULL,
		created_by  TEXT        NOT NULL DEFAULT '',
		created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		UNIQUE (config_key, app_id, version)
	)`

	createOverridesTable = `CREATE TABLE IF NOT EXISTS vault_overrides (
		id          TEXT        PRIMARY KEY,
		key         TEXT        NOT NULL,
		value       JSONB       NOT NULL,
		app_id      TEXT        NOT NULL,
		tenant_id   TEXT        NOT NULL,
		metadata    JSONB       DEFAULT '{}',
		created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		UNIQUE (key, app_id, tenant_id)
	)`

	createRotationPoliciesTable = `CREATE TABLE IF NOT EXISTS vault_rotation_policies (
		id                TEXT        PRIMARY KEY,
		secret_key        TEXT        NOT NULL,
		app_id            TEXT        NOT NULL,
		interval_ns       BIGINT      NOT NULL DEFAULT 0,
		enabled           BOOLEAN     NOT NULL DEFAULT FALSE,
		last_rotated_at   TIMESTAMPTZ,
		next_rotation_at  TIMESTAMPTZ,
		created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		UNIQUE (secret_key, app_id)
	)`

	createRotationRecordsTable = `CREATE TABLE IF NOT EXISTS vault_rotation_records (
		id          TEXT        PRIMARY KEY,
		secret_key  TEXT        NOT NULL,
		app_id      TEXT        NOT NULL,
		old_version BIGINT      NOT NULL,
		new_version BIGINT      NOT NULL,
		rotated_by  TEXT        NOT NULL DEFAULT '',
		rotated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`

	createAuditTable = `CREATE TABLE IF NOT EXISTS vault_audit (
		id          TEXT        PRIMARY KEY,
		action      TEXT        NOT NULL,
		resource    TEXT        NOT NULL,
		key         TEXT        NOT NULL DEFAULT '',
		app_id      TEXT        NOT NULL DEFAULT '',
		tenant_id   TEXT        NOT NULL DEFAULT '',
		user_id     TEXT        NOT NULL DEFAULT '',
		ip          TEXT        NOT NULL DEFAULT '',
		outcome     TEXT        NOT NULL DEFAULT 'success',
		metadata    JSONB       DEFAULT '{}',
		created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`

	createIndexes = `
		CREATE INDEX IF NOT EXISTS idx_secret_versions_key ON vault_secret_versions (secret_key, app_id);
		CREATE INDEX IF NOT EXISTS idx_flag_rules_key ON vault_flag_rules (flag_key, app_id, priority);
		CREATE INDEX IF NOT EXISTS idx_config_versions_key ON vault_config_versions (config_key, app_id);
		CREATE INDEX IF NOT EXISTS idx_rotation_records_key ON vault_rotation_records (secret_key, app_id, rotated_at DESC);
		CREATE INDEX IF NOT EXISTS idx_audit_app ON vault_audit (app_id, created_at DESC);
		CREATE INDEX IF NOT EXISTS idx_audit_key ON vault_audit (key, app_id, created_at DESC)
	`
)

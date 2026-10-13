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

	// The CREATE statements above do not alter a table that already exists, so
	// a column added after the first release is added here as well, mirroring
	// the "add_secret_version_encryption_alg" migration.
	if _, err := pgdb.Exec(ctx, alterVersionsAddAlg); err != nil {
		return err
	}

	// These indexes come after the ALTER because one of them covers the
	// column it adds. They mirror "add_secret_expiry_and_version_alg_indexes".
	for _, ddl := range []string{createExpiryIndex, createVersionAlgIndex} {
		if _, err := pgdb.Exec(ctx, ddl); err != nil {
			return err
		}
	}

	// The tables above still carry the shape they first shipped with, unique
	// per key and app. This scopes them by tenant, mirroring
	// "scope_secrets_by_tenant"; on a table already scoped it changes nothing.
	for _, ddl := range secretTenantDDL {
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
	alterVersionsAddAlg = `ALTER TABLE vault_secret_versions ADD COLUMN IF NOT EXISTS encryption_alg TEXT`

	// createExpiryIndex serves the expiry filter on ListSecrets and
	// CountSecretsMatching.
	createExpiryIndex = `CREATE INDEX IF NOT EXISTS idx_secrets_app_expires ON vault_secrets (app_id, expires_at)`

	// createVersionAlgIndex serves CountVersionEncryption, which counts
	// an app's version rows by recorded algorithm.
	createVersionAlgIndex = `CREATE INDEX IF NOT EXISTS idx_secret_versions_app_alg ON vault_secret_versions (app_id, encryption_alg)`

	// addSecretsTenant adds tenant_id to vault_secrets and moves the table's
	// uniqueness from (key, app_id) to (key, app_id, tenant_id), so each
	// tenant and the app itself can hold their own secret under one key.
	// Existing rows get '', which is what an app-level secret is.
	//
	// The old constraint was declared inline and never named, so it is found
	// by its columns rather than by the name Postgres generated for it. The
	// new one is named, the same name Postgres would give it, and only added
	// when missing. A DO block runs as one transaction, so the table never
	// sits without a unique constraint, and running it again changes
	// nothing.
	//nolint:gosec // G101: SQL DDL; "secret" in the name is the table, not a credential.
	addSecretsTenant = `DO $$
DECLARE
	c record;
BEGIN
	ALTER TABLE vault_secrets ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT '';
	FOR c IN
		SELECT con.conname
		  FROM pg_constraint con
		 WHERE con.conrelid = 'vault_secrets'::regclass
		   AND con.contype = 'u'
		   AND ARRAY(SELECT a.attname::text
		               FROM pg_attribute a
		              WHERE a.attrelid = con.conrelid AND a.attnum = ANY (con.conkey)
		              ORDER BY a.attname) = ARRAY['app_id', 'key']
	LOOP
		EXECUTE format('ALTER TABLE vault_secrets DROP CONSTRAINT %I', c.conname);
	END LOOP;
	IF NOT EXISTS (SELECT 1 FROM pg_constraint
	                WHERE conrelid = 'vault_secrets'::regclass
	                  AND conname = 'vault_secrets_key_app_id_tenant_id_key') THEN
		ALTER TABLE vault_secrets
			ADD CONSTRAINT vault_secrets_key_app_id_tenant_id_key UNIQUE (key, app_id, tenant_id);
	END IF;
END
$$`

	// addSecretVersionsTenant does for vault_secret_versions what
	// addSecretsTenant does for vault_secrets: a version number is unique per
	// key, app and tenant, not per key and app.
	//nolint:gosec // G101: SQL DDL; "secret" in the name is the table, not a credential.
	addSecretVersionsTenant = `DO $$
DECLARE
	c record;
BEGIN
	ALTER TABLE vault_secret_versions ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT '';
	FOR c IN
		SELECT con.conname
		  FROM pg_constraint con
		 WHERE con.conrelid = 'vault_secret_versions'::regclass
		   AND con.contype = 'u'
		   AND ARRAY(SELECT a.attname::text
		               FROM pg_attribute a
		              WHERE a.attrelid = con.conrelid AND a.attnum = ANY (con.conkey)
		              ORDER BY a.attname) = ARRAY['app_id', 'secret_key', 'version']
	LOOP
		EXECUTE format('ALTER TABLE vault_secret_versions DROP CONSTRAINT %I', c.conname);
	END LOOP;
	IF NOT EXISTS (SELECT 1 FROM pg_constraint
	                WHERE conrelid = 'vault_secret_versions'::regclass
	                  AND conname = 'vault_secret_versions_secret_key_app_id_tenant_id_version_key') THEN
		ALTER TABLE vault_secret_versions
			ADD CONSTRAINT vault_secret_versions_secret_key_app_id_tenant_id_version_key
			UNIQUE (secret_key, app_id, tenant_id, version);
	END IF;
END
$$`

	// createSecretsTenantIndex serves ListSecrets, which reads one app and
	// tenant in key order. The unique constraints above serve the lookups by
	// key, and the version reads, which lead with the key.
	//nolint:gosec // G101: SQL DDL; "secret" in the name is the table, not a credential.
	createSecretsTenantIndex = `CREATE INDEX IF NOT EXISTS idx_secrets_app_tenant ON vault_secrets (app_id, tenant_id, key)`

	// dropSecretsTenant is the way back from the three statements above. It
	// puts the old constraints back before it drops anything, so a database
	// where two tenants (or a tenant and the app) share a key refuses to roll
	// back, rather than losing which secret was whose. Delete the tenant
	// rows first if rolling back is really what you want.
	//nolint:gosec // G101: SQL DDL; "secret" in the name is the table, not a credential.
	dropSecretsTenant = `DO $$
BEGIN
	ALTER TABLE vault_secrets ADD CONSTRAINT vault_secrets_key_app_id_key UNIQUE (key, app_id);
	ALTER TABLE vault_secret_versions
		ADD CONSTRAINT vault_secret_versions_secret_key_app_id_version_key UNIQUE (secret_key, app_id, version);
	DROP INDEX IF EXISTS idx_secrets_app_tenant;
	ALTER TABLE vault_secret_versions DROP COLUMN IF EXISTS tenant_id;
	ALTER TABLE vault_secrets DROP COLUMN IF EXISTS tenant_id;
END
$$`

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

// secretTenantDDL scopes the secret tables by tenant, in order. Migrate and
// the "scope_secrets_by_tenant" migration both run it, and each statement is
// safe to run again on a table it has already changed.
var secretTenantDDL = []string{addSecretsTenant, addSecretVersionsTenant, createSecretsTenantIndex}

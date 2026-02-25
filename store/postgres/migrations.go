package postgres

import (
	"context"

	"github.com/xraph/grove/migrate"
)

// Migrations is the migration group for the Vault store.
// Register this group with the grove migrator to manage schema changes.
var Migrations = migrate.NewGroup("vault")

func init() {
	Migrations.MustRegister(
		&migrate.Migration{
			Name:    "create_secrets_table",
			Version: "20240101120000",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `CREATE TABLE IF NOT EXISTS vault_secrets (
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
				)`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS vault_secrets`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_secret_versions_table",
			Version: "20240101120001",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `CREATE TABLE IF NOT EXISTS vault_secret_versions (
					id              TEXT        PRIMARY KEY,
					secret_key      TEXT        NOT NULL,
					app_id          TEXT        NOT NULL,
					version         BIGINT      NOT NULL,
					encrypted_value BYTEA       NOT NULL DEFAULT '',
					created_by      TEXT        NOT NULL DEFAULT '',
					created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
					UNIQUE (secret_key, app_id, version)
				)`)
				if err != nil {
					return err
				}
				_, err = exec.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_secret_versions_key ON vault_secret_versions (secret_key, app_id)`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS vault_secret_versions`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_flags_table",
			Version: "20240101120002",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `CREATE TABLE IF NOT EXISTS vault_flags (
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
				)`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS vault_flags`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_flag_rules_table",
			Version: "20240101120003",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `CREATE TABLE IF NOT EXISTS vault_flag_rules (
					id          TEXT        PRIMARY KEY,
					flag_key    TEXT        NOT NULL,
					app_id      TEXT        NOT NULL,
					priority    INT         NOT NULL DEFAULT 0,
					type        TEXT        NOT NULL,
					config      JSONB       NOT NULL DEFAULT '{}',
					return_value JSONB      NOT NULL,
					created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
					updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
				)`)
				if err != nil {
					return err
				}
				_, err = exec.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_flag_rules_key ON vault_flag_rules (flag_key, app_id, priority)`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS vault_flag_rules`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_flag_overrides_table",
			Version: "20240101120004",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `CREATE TABLE IF NOT EXISTS vault_flag_overrides (
					id          TEXT        PRIMARY KEY,
					flag_key    TEXT        NOT NULL,
					app_id      TEXT        NOT NULL,
					tenant_id   TEXT        NOT NULL,
					value       JSONB       NOT NULL,
					created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
					updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
					UNIQUE (flag_key, app_id, tenant_id)
				)`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS vault_flag_overrides`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_config_table",
			Version: "20240101120005",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `CREATE TABLE IF NOT EXISTS vault_config (
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
				)`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS vault_config`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_config_versions_table",
			Version: "20240101120006",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `CREATE TABLE IF NOT EXISTS vault_config_versions (
					id          TEXT        PRIMARY KEY,
					config_key  TEXT        NOT NULL,
					app_id      TEXT        NOT NULL,
					version     BIGINT      NOT NULL,
					value       JSONB       NOT NULL,
					created_by  TEXT        NOT NULL DEFAULT '',
					created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
					UNIQUE (config_key, app_id, version)
				)`)
				if err != nil {
					return err
				}
				_, err = exec.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_config_versions_key ON vault_config_versions (config_key, app_id)`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS vault_config_versions`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_overrides_table",
			Version: "20240101120007",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `CREATE TABLE IF NOT EXISTS vault_overrides (
					id          TEXT        PRIMARY KEY,
					key         TEXT        NOT NULL,
					value       JSONB       NOT NULL,
					app_id      TEXT        NOT NULL,
					tenant_id   TEXT        NOT NULL,
					metadata    JSONB       DEFAULT '{}',
					created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
					updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
					UNIQUE (key, app_id, tenant_id)
				)`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS vault_overrides`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_rotation_policies_table",
			Version: "20240101120008",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `CREATE TABLE IF NOT EXISTS vault_rotation_policies (
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
				)`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS vault_rotation_policies`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_rotation_records_table",
			Version: "20240101120009",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `CREATE TABLE IF NOT EXISTS vault_rotation_records (
					id          TEXT        PRIMARY KEY,
					secret_key  TEXT        NOT NULL,
					app_id      TEXT        NOT NULL,
					old_version BIGINT      NOT NULL,
					new_version BIGINT      NOT NULL,
					rotated_by  TEXT        NOT NULL DEFAULT '',
					rotated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
				)`)
				if err != nil {
					return err
				}
				_, err = exec.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_rotation_records_key ON vault_rotation_records (secret_key, app_id, rotated_at DESC)`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS vault_rotation_records`)
				return err
			},
		},
		&migrate.Migration{
			Name:    "create_audit_table",
			Version: "20240101120010",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `CREATE TABLE IF NOT EXISTS vault_audit (
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
				)`)
				if err != nil {
					return err
				}
				if _, err = exec.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_audit_app ON vault_audit (app_id, created_at DESC)`); err != nil {
					return err
				}
				_, err = exec.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_audit_key ON vault_audit (key, app_id, created_at DESC)`)
				return err
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				_, err := exec.Exec(ctx, `DROP TABLE IF EXISTS vault_audit`)
				return err
			},
		},
	)
}

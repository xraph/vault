package sqlite

import (
	"context"
	"fmt"

	"github.com/xraph/grove/migrate"
)

// SQLite cannot drop or change a table constraint in place, and the secret
// tables declared theirs inline: UNIQUE (key, app_id) on vault_secrets and
// UNIQUE (secret_key, app_id, version) on vault_secret_versions. Scoping
// secrets by tenant therefore rebuilds both tables, the way the SQLite manual
// describes: create the new shape under another name, copy the rows across,
// drop the old table and rename the new one into its place. Dropping a table
// drops its indexes, so they are created again once it is back.
//
// The grove orchestrator runs a migration outside any transaction and does
// not hand it a connection to hold one on, so each step is written to be safe
// to run again from wherever an earlier run stopped:
//
//   - the old table still lacks tenant_id: build the new table if it is not
//     there yet, copy the rows it does not already hold, drop, rename;
//   - the old table is gone and the new one is left: the run stopped between
//     the drop and the rename, so only the rename is left to do;
//   - the table already has tenant_id: nothing to rebuild.
//
// Every step is one statement, and SQLite runs each statement atomically, so
// a stopped run always leaves one of those three states.

// tableRebuild describes rebuilding one table into a new shape.
type tableRebuild struct {
	// table is the table being rebuilt.
	table string
	// tmp is the name the new shape is built under before the rename.
	tmp string
	// create creates tmp in the new shape, IF NOT EXISTS.
	create string
	// columns lists the columns copied from table into tmp, comma
	// separated. A column tmp has and table lacks takes its default.
	columns string
	// indexes are created on table once the rebuild is done, IF NOT EXISTS.
	indexes []string
}

// secretsTenantRebuild gives vault_secrets a tenant_id and makes a key unique
// per app and tenant. Existing rows get ”, the app-level tenant.
var secretsTenantRebuild = tableRebuild{
	table: "vault_secrets",
	tmp:   "vault_secrets_tenant_rebuild",
	create: `
CREATE TABLE IF NOT EXISTS vault_secrets_tenant_rebuild (
    id                TEXT PRIMARY KEY,
    key               TEXT NOT NULL,
    app_id            TEXT NOT NULL,
    tenant_id         TEXT NOT NULL DEFAULT '',
    encrypted_value   BLOB NOT NULL DEFAULT x'',
    encryption_alg    TEXT NOT NULL DEFAULT '',
    encryption_key_id TEXT NOT NULL DEFAULT '',
    version           INTEGER NOT NULL DEFAULT 1,
    metadata          TEXT DEFAULT '{}',
    expires_at        TEXT,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at        TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (key, app_id, tenant_id)
)`,
	columns: "id, key, app_id, encrypted_value, encryption_alg, encryption_key_id, " +
		"version, metadata, expires_at, created_at, updated_at",
	indexes: []string{
		`CREATE INDEX IF NOT EXISTS idx_secrets_app_expires ON vault_secrets (app_id, expires_at)`,
		// Serves ListSecrets, which reads one app and tenant in key order.
		`CREATE INDEX IF NOT EXISTS idx_secrets_app_tenant ON vault_secrets (app_id, tenant_id, key)`,
	},
}

// secretVersionsTenantRebuild does for vault_secret_versions what
// secretsTenantRebuild does for vault_secrets: a version number is unique per
// key, app and tenant.
var secretVersionsTenantRebuild = tableRebuild{
	table: "vault_secret_versions",
	tmp:   "vault_secret_versions_tenant_rebuild",
	create: `
CREATE TABLE IF NOT EXISTS vault_secret_versions_tenant_rebuild (
    id              TEXT PRIMARY KEY,
    secret_key      TEXT NOT NULL,
    app_id          TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT '',
    version         INTEGER NOT NULL,
    encrypted_value BLOB NOT NULL DEFAULT x'',
    created_by      TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    encryption_alg  TEXT,
    UNIQUE (secret_key, app_id, tenant_id, version)
)`,
	columns: "id, secret_key, app_id, version, encrypted_value, created_by, created_at, encryption_alg",
	indexes: []string{
		`CREATE INDEX IF NOT EXISTS idx_secret_versions_key ON vault_secret_versions (secret_key, app_id)`,
		`CREATE INDEX IF NOT EXISTS idx_secret_versions_app_alg ON vault_secret_versions (app_id, encryption_alg)`,
	},
}

// secretsUntenantRebuild is the way back: vault_secrets as it was before,
// unique per key and app. The copy fails on a key two tenants (or a tenant
// and the app) share, and the table is left as it is, rather than losing
// which secret was whose.
var secretsUntenantRebuild = tableRebuild{
	table: "vault_secrets",
	tmp:   "vault_secrets_tenant_rollback",
	create: `
CREATE TABLE IF NOT EXISTS vault_secrets_tenant_rollback (
    id                TEXT PRIMARY KEY,
    key               TEXT NOT NULL,
    app_id            TEXT NOT NULL,
    encrypted_value   BLOB NOT NULL DEFAULT x'',
    encryption_alg    TEXT NOT NULL DEFAULT '',
    encryption_key_id TEXT NOT NULL DEFAULT '',
    version           INTEGER NOT NULL DEFAULT 1,
    metadata          TEXT DEFAULT '{}',
    expires_at        TEXT,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at        TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (key, app_id)
)`,
	columns: secretsTenantRebuild.columns,
	indexes: secretsTenantRebuild.indexes[:1],
}

// secretVersionsUntenantRebuild is the way back for vault_secret_versions.
var secretVersionsUntenantRebuild = tableRebuild{
	table: "vault_secret_versions",
	tmp:   "vault_secret_versions_tenant_rollback",
	create: `
CREATE TABLE IF NOT EXISTS vault_secret_versions_tenant_rollback (
    id              TEXT PRIMARY KEY,
    secret_key      TEXT NOT NULL,
    app_id          TEXT NOT NULL,
    version         INTEGER NOT NULL,
    encrypted_value BLOB NOT NULL DEFAULT x'',
    created_by      TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    encryption_alg  TEXT,
    UNIQUE (secret_key, app_id, version)
)`,
	columns: secretVersionsTenantRebuild.columns,
	indexes: secretVersionsTenantRebuild.indexes,
}

// scopeSecretsByTenant is the Up of "scope_secrets_by_tenant".
func scopeSecretsByTenant(ctx context.Context, exec migrate.Executor) error {
	for _, r := range []tableRebuild{secretsTenantRebuild, secretVersionsTenantRebuild} {
		if err := rebuildUnlessColumn(ctx, exec, r, "tenant_id"); err != nil {
			return err
		}
	}
	return nil
}

// unscopeSecretsByTenant is the Down of "scope_secrets_by_tenant".
func unscopeSecretsByTenant(ctx context.Context, exec migrate.Executor) error {
	for _, r := range []tableRebuild{secretsUntenantRebuild, secretVersionsUntenantRebuild} {
		has, err := hasColumn(ctx, exec, r.table, "tenant_id")
		if err != nil {
			return err
		}
		if !has {
			continue
		}
		// A rollback that failed before leaves its half-built table behind.
		// Start that one from nothing: the rows it holds may be stale.
		if _, err := exec.Exec(ctx, "DROP TABLE IF EXISTS "+r.tmp); err != nil {
			return fmt.Errorf("vault/sqlite: drop %s: %w", r.tmp, err)
		}
		if err := rebuild(ctx, exec, r); err != nil {
			return err
		}
	}
	return nil
}

// rebuildUnlessColumn rebuilds r.table into r's shape unless it already has
// column, picking up from wherever an earlier run stopped.
func rebuildUnlessColumn(ctx context.Context, exec migrate.Executor, r tableRebuild, column string) error {
	exists, err := hasTable(ctx, exec, r.table)
	if err != nil {
		return err
	}
	if !exists {
		tmpExists, tmpErr := hasTable(ctx, exec, r.tmp)
		if tmpErr != nil {
			return tmpErr
		}
		if !tmpExists {
			return fmt.Errorf("vault/sqlite: neither %s nor %s exists", r.table, r.tmp)
		}
		// An earlier run dropped the old table and stopped before renaming
		// the new one, which already holds every row.
		return renameAndIndex(ctx, exec, r)
	}

	has, err := hasColumn(ctx, exec, r.table, column)
	if err != nil {
		return err
	}
	if has {
		return createIndexes(ctx, exec, r)
	}
	return rebuild(ctx, exec, r)
}

// rebuild builds r.tmp, copies into it every row of r.table it does not hold
// yet, drops r.table and renames r.tmp into its place.
func rebuild(ctx context.Context, exec migrate.Executor, r tableRebuild) error {
	if _, err := exec.Exec(ctx, r.create); err != nil {
		return fmt.Errorf("vault/sqlite: create %s: %w", r.tmp, err)
	}
	// NOT EXISTS rather than INSERT OR IGNORE: OR IGNORE would also skip a
	// row that broke some other constraint, silently, and a row must never
	// go missing here. A row already copied by an earlier run is skipped by
	// its id; anything else that fails, fails the migration.
	copyRows := "INSERT INTO " + r.tmp + " (" + r.columns + ") SELECT " + r.columns +
		" FROM " + r.table + " WHERE NOT EXISTS (SELECT 1 FROM " + r.tmp +
		" done WHERE done.id = " + r.table + ".id)"
	if _, err := exec.Exec(ctx, copyRows); err != nil {
		return fmt.Errorf("vault/sqlite: copy %s into %s: %w", r.table, r.tmp, err)
	}
	if _, err := exec.Exec(ctx, "DROP TABLE "+r.table); err != nil {
		return fmt.Errorf("vault/sqlite: drop %s: %w", r.table, err)
	}
	return renameAndIndex(ctx, exec, r)
}

// renameAndIndex renames r.tmp to r.table and creates r's indexes on it.
func renameAndIndex(ctx context.Context, exec migrate.Executor, r tableRebuild) error {
	if _, err := exec.Exec(ctx, "ALTER TABLE "+r.tmp+" RENAME TO "+r.table); err != nil {
		return fmt.Errorf("vault/sqlite: rename %s to %s: %w", r.tmp, r.table, err)
	}
	return createIndexes(ctx, exec, r)
}

// createIndexes creates r's indexes on r.table.
func createIndexes(ctx context.Context, exec migrate.Executor, r tableRebuild) error {
	for _, ddl := range r.indexes {
		if _, err := exec.Exec(ctx, ddl); err != nil {
			return fmt.Errorf("vault/sqlite: index %s: %w", r.table, err)
		}
	}
	return nil
}

// hasTable reports whether a table named name exists.
func hasTable(ctx context.Context, exec migrate.Executor, name string) (bool, error) {
	n, err := count(ctx, exec, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name)
	return n > 0, err
}

// hasColumn reports whether table has a column named column.
func hasColumn(ctx context.Context, exec migrate.Executor, table, column string) (bool, error) {
	n, err := count(ctx, exec, `SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`, table, column)
	return n > 0, err
}

// count runs a query that returns one integer and returns it.
func count(ctx context.Context, exec migrate.Executor, query string, args ...any) (int64, error) {
	rows, err := exec.Query(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("vault/sqlite: inspect schema: %w", err)
	}
	defer rows.Close()

	var n int64
	if rows.Next() {
		if err := rows.Scan(&n); err != nil {
			return 0, fmt.Errorf("vault/sqlite: inspect schema: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("vault/sqlite: inspect schema: %w", err)
	}
	return n, nil
}

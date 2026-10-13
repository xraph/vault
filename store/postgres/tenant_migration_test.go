//go:build integration

package postgres_test

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/pgdriver"
	"github.com/xraph/grove/migrate"

	// Registers the "pg" migration executor.
	_ "github.com/xraph/grove/drivers/pgdriver/pgmigrate"

	"github.com/xraph/vault/core"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/secret"
	pgstore "github.com/xraph/vault/store/postgres"
)

// tenantMigrationVersion is the version of "scope_secrets_by_tenant".
const tenantMigrationVersion = "20240101120013"

// pgSchemaDB opens VAULT_TEST_PG_URL with search_path set to a schema of its
// own, created here and dropped when the test ends, so a migration test
// starts from an empty database whatever the shared one holds. The URL must
// be in URL form (postgres://...).
func pgSchemaDB(t *testing.T) (*grove.DB, *pgdriver.PgDB) {
	t.Helper()

	connStr := os.Getenv("VAULT_TEST_PG_URL")
	if connStr == "" {
		t.Skip("VAULT_TEST_PG_URL not set; skipping integration test")
	}
	u, err := url.Parse(connStr)
	if err != nil || u.Scheme == "" {
		t.Skipf("VAULT_TEST_PG_URL is not a URL (%v); the migration tests need one to set search_path", err)
	}

	schema := fmt.Sprintf("vault_mig_%d", time.Now().UnixNano())
	admin := pgdriver.New()
	if err := admin.Open(t.Context(), connStr); err != nil {
		t.Fatalf("pgdriver open: %v", err)
	}
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop schema %s: %v", schema, err)
		}
		admin.Close()
	})

	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	pgdb := pgdriver.New()
	if err := pgdb.Open(t.Context(), u.String()); err != nil {
		t.Fatalf("pgdriver open %s: %v", schema, err)
	}
	db, err := grove.Open(pgdb)
	if err != nil {
		t.Fatalf("grove open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, pgdb
}

// tenantMigration returns "scope_secrets_by_tenant" from the group.
func tenantMigration(t *testing.T) *migrate.Migration {
	t.Helper()
	for _, m := range pgstore.Migrations.Migrations() {
		if m.Version == tenantMigrationVersion {
			return m
		}
	}
	t.Fatal("scope_secrets_by_tenant is not in the migration group")
	return nil
}

// pgLegacy is a database migrated the way the release before tenants left
// it, holding rows that release wrote.
type pgLegacy struct {
	db    *grove.DB
	pgdb  *pgdriver.PgDB
	exec  migrate.Executor
	store *pgstore.Store
}

// newPGLegacy runs every migration older than scope_secrets_by_tenant and
// writes "db" at version 2 (with metadata and an expiry) and its two version
// rows, one recorded as encrypted and one never recorded.
func newPGLegacy(t *testing.T) *pgLegacy {
	t.Helper()
	ctx := t.Context()
	db, pgdb := pgSchemaDB(t)

	exec, err := migrate.NewExecutorFor(pgdb)
	if err != nil {
		t.Fatalf("executor: %v", err)
	}
	before := migrate.NewGroup("vault")
	for _, m := range pgstore.Migrations.Migrations() {
		if m.Version < tenantMigrationVersion {
			cp := *m
			before.MustRegister(&cp)
		}
	}
	if _, err := migrate.NewOrchestrator(exec, before).Migrate(ctx); err != nil {
		t.Fatalf("migrate to the release before tenants: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	for _, stmt := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO vault_secrets (id, key, app_id, encrypted_value, encryption_alg, encryption_key_id, version, metadata, expires_at)
		  VALUES ($1, 'db', 'app', $2, $3, 'k1', 2, '{"env":"prod"}', $4)`,
			[]any{id.NewSecretID().String(), []byte("sealed-v2"), secret.EncryptionAlgorithm, now.Add(time.Hour)}},
		{`INSERT INTO vault_secret_versions (id, secret_key, app_id, version, encrypted_value, encryption_alg)
		  VALUES ($1, 'db', 'app', 1, $2, NULL)`,
			[]any{id.NewVersionID().String(), []byte("sealed-v1")}},
		{`INSERT INTO vault_secret_versions (id, secret_key, app_id, version, encrypted_value, encryption_alg)
		  VALUES ($1, 'db', 'app', 2, $2, $3)`,
			[]any{id.NewVersionID().String(), []byte("sealed-v2"), secret.EncryptionAlgorithm}},
	} {
		if _, err := pgdb.Exec(ctx, stmt.query, stmt.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	return &pgLegacy{db: db, pgdb: pgdb, exec: exec, store: pgstore.New(db)}
}

// wantAppLevel fails unless the seeded rows read back as the app-level "db".
func (l *pgLegacy) wantAppLevel(t *testing.T) {
	t.Helper()
	got, err := l.store.GetSecret(t.Context(), "db", "app", "")
	if err != nil {
		t.Fatalf("GetSecret(db, app-level): %v", err)
	}
	if got.TenantID != "" || got.Version != 2 || string(got.EncryptedValue) != "sealed-v2" ||
		got.Metadata["env"] != "prod" || got.ExpiresAt == nil {
		t.Errorf("db after migration = %+v", got)
	}
	vs, err := l.store.ListSecretVersions(t.Context(), "db", "app", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 2 || vs[0].EncryptionAlg != nil || vs[1].EncryptionAlg == nil || vs[0].TenantID != "" {
		t.Errorf("db versions after migration = %d rows, v1 alg %v", len(vs), vs[0].EncryptionAlg)
	}
}

// putT1 writes t1's own "db" and fails unless it lands beside the app's.
func (l *pgLegacy) putT1(t *testing.T) {
	t.Helper()
	sec := &secret.Secret{
		Entity: core.NewEntity(), ID: id.NewSecretID(),
		Key: "db", AppID: "app", TenantID: "t1", EncryptedValue: []byte("t1-value"),
	}
	if err := l.store.SetSecret(t.Context(), sec); err != nil {
		t.Fatalf("SetSecret(db, t1): %v", err)
	}
	if sec.Version != 1 {
		t.Errorf("t1's db got version %d, want 1", sec.Version)
	}
	l.wantAppLevel(t)
}

// constraints returns the unique constraints on the secret tables, by name.
func (l *pgLegacy) constraints(t *testing.T) map[string]bool {
	t.Helper()
	rows, err := l.pgdb.Query(t.Context(), `SELECT conname FROM pg_constraint
		WHERE contype = 'u' AND conrelid IN ('vault_secrets'::regclass, 'vault_secret_versions'::regclass)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		out[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// wantConstraints fails unless the unique constraints are exactly want.
func (l *pgLegacy) wantConstraints(t *testing.T, want ...string) {
	t.Helper()
	got := l.constraints(t)
	if len(got) != len(want) {
		t.Errorf("unique constraints = %v, want %v", got, want)
		return
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("unique constraints = %v, want %v", got, want)
			return
		}
	}
}

var (
	scopedConstraints = []string{
		"vault_secrets_key_app_id_tenant_id_key",
		"vault_secret_versions_secret_key_app_id_tenant_id_version_key",
	}
	legacyConstraints = []string{
		"vault_secrets_key_app_id_key",
		"vault_secret_versions_secret_key_app_id_version_key",
	}
)

func TestPGScopeSecretsByTenant_MigrationGroup(t *testing.T) {
	l := newPGLegacy(t)
	ctx := t.Context()
	l.wantConstraints(t, legacyConstraints...)

	if _, err := migrate.NewOrchestrator(l.exec, pgstore.Migrations).Migrate(ctx); err != nil {
		t.Fatalf("migrate group: %v", err)
	}
	l.wantConstraints(t, scopedConstraints...)
	l.wantAppLevel(t)

	// Running the Up again, as a run that stopped before it was recorded
	// would, changes nothing.
	up := tenantMigration(t)
	for range 2 {
		if err := up.Up(ctx, l.exec); err != nil {
			t.Fatalf("Up again: %v", err)
		}
	}
	l.wantConstraints(t, scopedConstraints...)
	l.putT1(t)

	// Down refuses while t1 and the app share "db", and changes nothing.
	if err := up.Down(ctx, l.exec); err == nil {
		t.Fatal("Down merged t1's db and the app's into one")
	}
	l.wantConstraints(t, scopedConstraints...)
	got, err := l.store.GetSecret(ctx, "db", "app", "t1")
	if err != nil || string(got.EncryptedValue) != "t1-value" {
		t.Fatalf("t1's db after the refused Down: %v %v", got, err)
	}

	// With the tenant rows gone, Down puts the old shape back, and Up
	// brings the new one again.
	if err := l.store.DeleteSecret(ctx, "db", "app", "t1"); err != nil {
		t.Fatal(err)
	}
	if err := up.Down(ctx, l.exec); err != nil {
		t.Fatalf("Down: %v", err)
	}
	l.wantConstraints(t, legacyConstraints...)
	if err := up.Up(ctx, l.exec); err != nil {
		t.Fatalf("Up after Down: %v", err)
	}
	l.wantConstraints(t, scopedConstraints...)
	l.wantAppLevel(t)
}

func TestPGScopeSecretsByTenant_StoreMigrate(t *testing.T) {
	l := newPGLegacy(t)
	for i := range 2 {
		if err := l.store.Migrate(t.Context()); err != nil {
			t.Fatalf("Migrate run %d: %v", i+1, err)
		}
	}
	l.wantConstraints(t, scopedConstraints...)
	l.wantAppLevel(t)
	l.putT1(t)
}

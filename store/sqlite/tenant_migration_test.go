package sqlite

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"
	"github.com/xraph/grove/migrate"

	// Registers the "sqlite" migration executor, as the store's other tests
	// do. Vault leaves this to the consumer.
	_ "github.com/xraph/grove/drivers/sqlitedriver/sqlitemigrate"

	"github.com/xraph/vault/core"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/secret"
)

// tenantMigrationVersion is the version of "scope_secrets_by_tenant".
const tenantMigrationVersion = "20240101120013"

// legacyDB is a database migrated the way the release before tenants left
// it, holding rows that release wrote.
type legacyDB struct {
	store *Store
	sdb   *sqlitedriver.SqliteDB
	exec  migrate.Executor
	// secretID is the id of the "db" secret.
	secretID string
}

// newLegacyDB runs every migration older than scope_secrets_by_tenant on a
// fresh database and writes rows into the old shape: "db" at version 2 with
// metadata and an expiry, its two versions (one recorded as encrypted, one
// never recorded), and "plain", stored without encryption.
func newLegacyDB(t *testing.T) *legacyDB {
	t.Helper()
	ctx := t.Context()

	sdb := sqlitedriver.New()
	if err := sdb.Open(ctx, filepath.Join(t.TempDir(), "vault.db")); err != nil {
		t.Fatalf("sqlitedriver open: %v", err)
	}
	db, err := grove.Open(sdb)
	if err != nil {
		t.Fatalf("grove open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	exec, err := migrate.NewExecutorFor(sdb)
	if err != nil {
		t.Fatalf("executor: %v", err)
	}
	before := migrate.NewGroup("vault")
	for _, m := range Migrations.Migrations() {
		if m.Version < tenantMigrationVersion {
			cp := *m
			before.MustRegister(&cp)
		}
	}
	if _, err := migrate.NewOrchestrator(exec, before).Migrate(ctx); err != nil {
		t.Fatalf("migrate to the release before tenants: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(30 * 24 * time.Hour)
	l := &legacyDB{store: New(db), sdb: sdb, exec: exec, secretID: id.NewSecretID().String()}
	l.mustExec(t, `INSERT INTO vault_secrets
		(id, key, app_id, encrypted_value, encryption_alg, encryption_key_id, version, metadata, expires_at, created_at, updated_at)
		VALUES (?, 'db', 'app', ?, ?, 'k1', 2, '{"env":"prod"}', ?, ?, ?)`,
		l.secretID, []byte("sealed-v2"), secret.EncryptionAlgorithm, expires, now, now)
	l.mustExec(t, `INSERT INTO vault_secrets
		(id, key, app_id, encrypted_value, encryption_alg, version, created_at, updated_at)
		VALUES (?, 'plain', 'app', ?, '', 1, ?, ?)`,
		id.NewSecretID().String(), []byte("clear"), now, now)
	l.mustExec(t, `INSERT INTO vault_secret_versions
		(id, secret_key, app_id, version, encrypted_value, created_at, encryption_alg)
		VALUES (?, 'db', 'app', 1, ?, ?, NULL)`,
		id.NewVersionID().String(), []byte("sealed-v1"), now)
	l.mustExec(t, `INSERT INTO vault_secret_versions
		(id, secret_key, app_id, version, encrypted_value, created_at, encryption_alg)
		VALUES (?, 'db', 'app', 2, ?, ?, ?)`,
		id.NewVersionID().String(), []byte("sealed-v2"), now, secret.EncryptionAlgorithm)
	l.mustExec(t, `INSERT INTO vault_secret_versions
		(id, secret_key, app_id, version, encrypted_value, created_at, encryption_alg)
		VALUES (?, 'plain', 'app', 1, ?, ?, '')`,
		id.NewVersionID().String(), []byte("clear"), now)
	return l
}

func (l *legacyDB) mustExec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := l.sdb.Exec(t.Context(), query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

func (l *legacyDB) count(t *testing.T, query string, args ...any) int64 {
	t.Helper()
	n, err := count(t.Context(), l.exec, query, args...)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// wantLegacyRowsAppLevel fails unless every row newLegacyDB wrote reads back
// unchanged as an app-level secret.
func (l *legacyDB) wantLegacyRowsAppLevel(t *testing.T) {
	t.Helper()
	ctx := t.Context()

	got, err := l.store.GetSecret(ctx, "db", "app", "")
	if err != nil {
		t.Fatalf("GetSecret(db, app-level): %v", err)
	}
	if got.ID.String() != l.secretID || got.TenantID != "" || got.Version != 2 ||
		string(got.EncryptedValue) != "sealed-v2" || got.EncryptionAlg != secret.EncryptionAlgorithm ||
		got.EncryptionKeyID != "k1" || got.Metadata["env"] != "prod" || got.ExpiresAt == nil {
		t.Errorf("db after migration = %+v", got)
	}

	vs, err := l.store.ListSecretVersions(ctx, "db", "app", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 2 {
		t.Fatalf("db versions = %d, want 2", len(vs))
	}
	if vs[0].TenantID != "" || string(vs[0].EncryptedValue) != "sealed-v1" || vs[0].EncryptionAlg != nil {
		t.Errorf("db v1 = %+v, want sealed-v1 with no recorded algorithm", vs[0])
	}
	if vs[1].EncryptionAlg == nil || *vs[1].EncryptionAlg != secret.EncryptionAlgorithm {
		t.Errorf("db v2 lost its recorded algorithm: %+v", vs[1])
	}
	plainVersions, err := l.store.ListSecretVersions(ctx, "plain", "app", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(plainVersions) != 1 || plainVersions[0].EncryptionAlg == nil || *plainVersions[0].EncryptionAlg != "" {
		t.Errorf("plain versions = %+v, want one recorded as stored without encryption", plainVersions)
	}

	metas, err := l.store.ListSecrets(ctx, "app", secret.ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(metas))
	for _, m := range metas {
		keys = append(keys, m.Key)
	}
	if !slices.Equal(keys, []string{"db", "plain"}) {
		t.Errorf("app-level keys = %v, want [db plain]", keys)
	}

	// Nothing is left behind from the rebuild, and every index is back.
	for _, tmp := range []string{secretsTenantRebuild.tmp, secretVersionsTenantRebuild.tmp} {
		if l.count(t, `SELECT COUNT(*) FROM sqlite_master WHERE name = ?`, tmp) != 0 {
			t.Errorf("%s is left behind", tmp)
		}
	}
	for _, idx := range []string{
		"idx_secrets_app_expires", "idx_secrets_app_tenant",
		"idx_secret_versions_key", "idx_secret_versions_app_alg",
	} {
		if l.count(t, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?`, idx) != 1 {
			t.Errorf("index %s is missing", idx)
		}
	}
}

// wantTenantsShareKeys fails unless a tenant can now hold its own secret
// under a key the app already has, without touching the app's.
func (l *legacyDB) wantTenantsShareKeys(t *testing.T) {
	t.Helper()
	sec := &secret.Secret{
		Entity: core.NewEntity(), ID: id.NewSecretID(),
		Key: "db", AppID: "app", TenantID: "t1", EncryptedValue: []byte("t1-value"),
	}
	if err := l.store.SetSecret(t.Context(), sec); err != nil {
		t.Fatalf("SetSecret(db, t1) after migration: %v", err)
	}
	if sec.Version != 1 {
		t.Errorf("t1's db got version %d, want 1", sec.Version)
	}
	app, err := l.store.GetSecret(t.Context(), "db", "app", "")
	if err != nil {
		t.Fatal(err)
	}
	if app.Version != 2 || string(app.EncryptedValue) != "sealed-v2" {
		t.Errorf("app-level db after t1's write = v%d %q", app.Version, app.EncryptedValue)
	}
}

func TestScopeSecretsByTenant_KeepsEveryRowAsAppLevel(t *testing.T) {
	l := newLegacyDB(t)
	if err := l.store.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	l.wantLegacyRowsAppLevel(t)
	l.wantTenantsShareKeys(t)
}

func TestScopeSecretsByTenant_RunsAgainSafely(t *testing.T) {
	l := newLegacyDB(t)
	for i := range 3 {
		if err := scopeSecretsByTenant(t.Context(), l.exec); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}
	l.wantLegacyRowsAppLevel(t)
	l.wantTenantsShareKeys(t)
}

func TestScopeSecretsByTenant_PicksUpAStoppedRun(t *testing.T) {
	stages := []struct {
		name string
		// stop runs the rebuild of r up to where an earlier run stopped.
		stop func(t *testing.T, l *legacyDB, r tableRebuild)
	}{
		{"new table built, nothing copied", func(t *testing.T, l *legacyDB, r tableRebuild) {
			l.mustExec(t, r.create)
		}},
		{"rows copied, old table not dropped", func(t *testing.T, l *legacyDB, r tableRebuild) {
			l.mustExec(t, r.create)
			l.mustExec(t, "INSERT INTO "+r.tmp+" ("+r.columns+") SELECT "+r.columns+" FROM "+r.table)
		}},
		{"old table dropped, new one not renamed", func(t *testing.T, l *legacyDB, r tableRebuild) {
			l.mustExec(t, r.create)
			l.mustExec(t, "INSERT INTO "+r.tmp+" ("+r.columns+") SELECT "+r.columns+" FROM "+r.table)
			l.mustExec(t, "DROP TABLE "+r.table)
		}},
	}
	for _, stage := range stages {
		for _, r := range []tableRebuild{secretsTenantRebuild, secretVersionsTenantRebuild} {
			t.Run(r.table+"/"+stage.name, func(t *testing.T) {
				l := newLegacyDB(t)
				if r.table == secretVersionsTenantRebuild.table {
					// The secrets table goes first, so a run that stopped on
					// the versions table had finished it.
					if err := rebuildUnlessColumn(t.Context(), l.exec, secretsTenantRebuild, "tenant_id"); err != nil {
						t.Fatal(err)
					}
				}
				stage.stop(t, l, r)
				if err := l.store.Migrate(t.Context()); err != nil {
					t.Fatalf("Migrate after a stopped run: %v", err)
				}
				l.wantLegacyRowsAppLevel(t)
				l.wantTenantsShareKeys(t)
			})
		}
	}
}

func TestUnscopeSecretsByTenant(t *testing.T) {
	t.Run("app-level rows only", func(t *testing.T) {
		l := newLegacyDB(t)
		if err := l.store.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := unscopeSecretsByTenant(t.Context(), l.exec); err != nil {
			t.Fatalf("Down: %v", err)
		}
		for _, table := range []string{"vault_secrets", "vault_secret_versions"} {
			if l.count(t, `SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = 'tenant_id'`, table) != 0 {
				t.Errorf("%s still has tenant_id after Down", table)
			}
		}
		if n := l.count(t, `SELECT COUNT(*) FROM vault_secret_versions`); n != 3 {
			t.Errorf("versions after Down = %d, want 3", n)
		}
		// The old uniqueness is back: one secret per key and app.
		_, err := l.sdb.Exec(t.Context(), `INSERT INTO vault_secrets (id, key, app_id) VALUES ('dup', 'db', 'app')`)
		if err == nil {
			t.Error("a second app-level db was accepted after Down")
		}

		// And Up again brings it all back.
		if err := scopeSecretsByTenant(t.Context(), l.exec); err != nil {
			t.Fatalf("Up after Down: %v", err)
		}
		l.wantLegacyRowsAppLevel(t)
	})

	t.Run("a key two tenants share refuses to roll back", func(t *testing.T) {
		l := newLegacyDB(t)
		if err := l.store.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
		l.wantTenantsShareKeys(t)

		err := unscopeSecretsByTenant(t.Context(), l.exec)
		if err == nil {
			t.Fatal("Down merged two tenants' db secrets into one")
		}
		// The table is left as it was: still scoped, every row there.
		got, getErr := l.store.GetSecret(t.Context(), "db", "app", "t1")
		if getErr != nil || string(got.EncryptedValue) != "t1-value" {
			t.Errorf("t1's db after the refused Down: %v %v", got, getErr)
		}
		l.wantLegacyRowsAppLevel(t)
	})
}

// TestScopeSecretsByTenant_NeitherTableIsAnError covers a database whose
// secrets table is gone with no rebuild in flight: there is nothing to
// recover from, and the migration says so rather than creating an empty
// table.
func TestScopeSecretsByTenant_NeitherTableIsAnError(t *testing.T) {
	l := newLegacyDB(t)
	l.mustExec(t, "DROP TABLE vault_secrets")
	if err := scopeSecretsByTenant(t.Context(), l.exec); err == nil {
		t.Fatal("got nil, want an error naming the missing table")
	}
}

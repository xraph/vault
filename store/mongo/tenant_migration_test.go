package mongo_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/mongodriver"
	"github.com/xraph/grove/drivers/mongodriver/mongomigrate"
	"github.com/xraph/grove/migrate"

	"github.com/xraph/vault/core"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/secret"
	mongostore "github.com/xraph/vault/store/mongo"
)

// tenantMigrationVersion is the version of "scope_secrets_by_tenant".
const tenantMigrationVersion = "20240101000014"

// mongoLegacy is a database migrated the way the release before tenants left
// it, holding documents that release wrote: no tenant_id field anywhere.
type mongoLegacy struct {
	db    *grove.DB
	mdb   *mongodriver.MongoDB
	exec  migrate.Executor
	store *mongostore.Store
}

func newMongoLegacy(t *testing.T) *mongoLegacy {
	t.Helper()
	ctx := t.Context()
	db := testDB(t)
	mdb := mongodriver.Unwrap(db)
	exec := mongomigrate.New(mdb)

	before := migrate.NewGroup("vault")
	for _, m := range mongostore.Migrations.Migrations() {
		if m.Version < tenantMigrationVersion {
			cp := *m
			before.MustRegister(&cp)
		}
	}
	if _, err := migrate.NewOrchestrator(exec, before).Migrate(ctx); err != nil {
		t.Fatalf("migrate to the release before tenants: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	if _, err := mdb.Collection("vault_secrets").InsertOne(ctx, bson.M{
		"_id": id.NewSecretID().String(), "key": "db", "app_id": "app",
		"encrypted_value": []byte("sealed-v2"), "encryption_alg": secret.EncryptionAlgorithm,
		"encryption_key_id": "k1", "version": int64(2), "metadata": bson.M{"env": "prod"},
		"created_at": now, "updated_at": now,
	}); err != nil {
		t.Fatalf("seed secret: %v", err)
	}
	for v, value := range []string{"sealed-v1", "sealed-v2"} {
		if _, err := mdb.Collection("vault_secret_versions").InsertOne(ctx, bson.M{
			"_id": id.NewVersionID().String(), "secret_key": "db", "app_id": "app",
			"version": int64(v + 1), "encrypted_value": []byte(value),
			"encryption_alg": secret.EncryptionAlgorithm, "created_by": "", "created_at": now,
		}); err != nil {
			t.Fatalf("seed version: %v", err)
		}
	}
	return &mongoLegacy{db: db, mdb: mdb, exec: exec, store: mongostore.New(db)}
}

// uniqueIndexes returns the key patterns of col's unique indexes, each
// written as its field names joined by commas.
func (l *mongoLegacy) uniqueIndexes(t *testing.T, col string) []string {
	t.Helper()
	specs, err := l.mdb.Collection(col).Indexes().ListSpecifications(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, s := range specs {
		if s.Unique == nil || !*s.Unique {
			continue
		}
		elems, err := s.KeysDocument.Elements()
		if err != nil {
			t.Fatal(err)
		}
		names := make([]string, len(elems))
		for i, e := range elems {
			names[i] = e.Key()
		}
		out = append(out, strings.Join(names, ","))
	}
	slices.Sort(out)
	return out
}

func (l *mongoLegacy) wantUnique(t *testing.T, secrets, versions string) {
	t.Helper()
	if got := l.uniqueIndexes(t, "vault_secrets"); !slices.Equal(got, []string{secrets}) {
		t.Errorf("vault_secrets unique indexes = %v, want [%s]", got, secrets)
	}
	if got := l.uniqueIndexes(t, "vault_secret_versions"); !slices.Equal(got, []string{versions}) {
		t.Errorf("vault_secret_versions unique indexes = %v, want [%s]", got, versions)
	}
}

func (l *mongoLegacy) wantAppLevel(t *testing.T) {
	t.Helper()
	got, err := l.store.GetSecret(t.Context(), "db", "app", "")
	if err != nil {
		t.Fatalf("GetSecret(db, app-level): %v", err)
	}
	if got.TenantID != "" || got.Version != 2 || string(got.EncryptedValue) != "sealed-v2" || got.Metadata["env"] != "prod" {
		t.Errorf("db after migration = %+v", got)
	}
	vs, err := l.store.ListSecretVersions(t.Context(), "db", "app", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 2 {
		t.Errorf("db versions after migration = %d, want 2", len(vs))
	}
}

func (l *mongoLegacy) putT1(t *testing.T) {
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

const (
	legacySecretsUnique  = "key,app_id"
	legacyVersionsUnique = "secret_key,app_id,version"
	scopedSecretsUnique  = "key,app_id,tenant_id"
	scopedVersionsUnique = "secret_key,app_id,tenant_id,version"
)

func TestMongoScopeSecretsByTenant_MigrationGroup(t *testing.T) {
	l := newMongoLegacy(t)
	ctx := t.Context()
	l.wantUnique(t, legacySecretsUnique, legacyVersionsUnique)

	if _, err := migrate.NewOrchestrator(l.exec, mongostore.Migrations).Migrate(ctx); err != nil {
		t.Fatalf("migrate group: %v", err)
	}
	l.wantUnique(t, scopedSecretsUnique, scopedVersionsUnique)
	l.wantAppLevel(t)

	// Every old document now carries tenant_id "".
	for _, col := range []string{"vault_secrets", "vault_secret_versions"} {
		n, err := l.mdb.Collection(col).CountDocuments(ctx, bson.M{"tenant_id": bson.M{"$exists": false}})
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s: %d documents without tenant_id after the migration", col, n)
		}
	}

	var up *migrate.Migration
	for _, m := range mongostore.Migrations.Migrations() {
		if m.Version == tenantMigrationVersion {
			up = m
		}
	}
	if up == nil {
		t.Fatal("scope_secrets_by_tenant is not in the migration group")
	}
	if err := up.Up(ctx, l.exec); err != nil {
		t.Fatalf("Up again: %v", err)
	}
	l.wantUnique(t, scopedSecretsUnique, scopedVersionsUnique)
	l.putT1(t)

	// Down refuses while t1 and the app share "db".
	if err := up.Down(ctx, l.exec); err == nil {
		t.Fatal("Down restored a per-app unique index over two tenants' db")
	}
	l.wantUnique(t, scopedSecretsUnique, scopedVersionsUnique)

	if err := l.store.DeleteSecret(ctx, "db", "app", "t1"); err != nil {
		t.Fatal(err)
	}
	if err := up.Down(ctx, l.exec); err != nil {
		t.Fatalf("Down: %v", err)
	}
	l.wantUnique(t, legacySecretsUnique, legacyVersionsUnique)
	if err := up.Up(ctx, l.exec); err != nil {
		t.Fatalf("Up after Down: %v", err)
	}
	l.wantUnique(t, scopedSecretsUnique, scopedVersionsUnique)
	l.wantAppLevel(t)
}

func TestMongoScopeSecretsByTenant_StoreMigrate(t *testing.T) {
	l := newMongoLegacy(t)
	for i := range 2 {
		if err := l.store.Migrate(t.Context()); err != nil {
			t.Fatalf("Migrate run %d: %v", i+1, err)
		}
	}
	l.wantUnique(t, scopedSecretsUnique, scopedVersionsUnique)
	l.wantAppLevel(t)
	l.putT1(t)
}

// TestMongoAppLevelReadsADocumentWithNoTenant covers a document a replica of
// the previous release writes after the migration ran: it has no tenant_id
// field. It must read as app-level, never as a tenant's, and the next write
// through this release gives it tenant_id "".
func TestMongoAppLevelReadsADocumentWithNoTenant(t *testing.T) {
	s := testStore(t)
	ctx := t.Context()
	coll := mongodriver.Unwrap(s.DB()).Collection("vault_secrets")
	now := time.Now().UTC()
	if _, err := coll.InsertOne(ctx, bson.M{
		"_id": id.NewSecretID().String(), "key": "old", "app_id": "app",
		"encrypted_value": []byte("v1"), "encryption_alg": "", "version": int64(1),
		"created_at": now, "updated_at": now,
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := s.GetSecret(ctx, "old", "app", ""); err != nil {
		t.Fatalf("app-level read of a document with no tenant_id: %v", err)
	}
	if _, err := s.GetSecret(ctx, "old", "app", "t1"); err == nil {
		t.Fatal("t1 read an app-level document")
	}

	sec := &secret.Secret{
		Entity: core.NewEntity(), ID: id.NewSecretID(),
		Key: "old", AppID: "app", EncryptedValue: []byte("v2"),
	}
	if err := s.SetSecret(ctx, sec); err != nil {
		t.Fatal(err)
	}
	if sec.Version != 2 {
		t.Errorf("app-level write over the old document got version %d, want 2", sec.Version)
	}
	n, err := coll.CountDocuments(ctx, bson.M{"key": "old", "app_id": "app"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("%d documents for old, want 1: the write must update the old document, not add one", n)
	}
	n, err = coll.CountDocuments(ctx, bson.M{"key": "old", "tenant_id": ""})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Error("the write did not give the old document tenant_id \"\"")
	}
}

package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"

	// Registers the "sqlite" migration executor. Vault leaves this to the
	// consumer rather than importing it from the store package.
	_ "github.com/xraph/grove/drivers/sqlitedriver/sqlitemigrate"

	"github.com/xraph/vault/config"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/secret"
	sqlitestore "github.com/xraph/vault/store/sqlite"
)

// testStore returns a migrated SQLite store backed by a temp-file database.
//
// SQLite is pure Go here (modernc.org/sqlite), so unlike the Postgres suite
// this needs no external service and runs under a plain `go test ./...`.
func testStore(t *testing.T) *sqlitestore.Store {
	t.Helper()

	sdb := sqlitedriver.New()
	dsn := filepath.Join(t.TempDir(), "vault_test.db")
	if err := sdb.Open(context.Background(), dsn); err != nil {
		t.Fatalf("sqlitedriver open: %v", err)
	}

	db, err := grove.Open(sdb)
	if err != nil {
		t.Fatalf("grove open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	s := sqlitestore.New(db)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s
}

// TestSetSecretFreshKey is the regression test for the scalar-scan bug: the
// version lookup in SetSecret read the `version` column into an *int64, which
// grove's scanner rejects outright ("dest must be a pointer to a struct"). That
// failed before any row was written, so storing a secret under a brand-new key
// never worked at all.
func TestSetSecretFreshKey(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	sec := &secret.Secret{
		ID:              id.NewSecretID(),
		Key:             "slack-bot-token",
		AppID:           "app1",
		EncryptedValue:  []byte("ciphertext-v1"),
		EncryptionAlg:   "aes-256-gcm",
		EncryptionKeyID: "key-1",
		Metadata:        map[string]string{"env": "prod"},
	}

	if err := s.SetSecret(ctx, sec); err != nil {
		t.Fatalf("SetSecret on a fresh key: %v", err)
	}
	if sec.Version != 1 {
		t.Errorf("version: got %d, want 1", sec.Version)
	}

	got, err := s.GetSecret(ctx, "slack-bot-token", "app1")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(got.EncryptedValue) != "ciphertext-v1" {
		t.Errorf("value: got %q, want %q", got.EncryptedValue, "ciphertext-v1")
	}
}

// TestSetSecretIncrementsVersion covers the other side of the same lookup: an
// existing key must read the stored version back and increment it, rather than
// resetting to 1 and losing version history.
func TestSetSecretIncrementsVersion(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	sec := &secret.Secret{
		ID:              id.NewSecretID(),
		Key:             "db-password",
		AppID:           "app1",
		EncryptedValue:  []byte("ciphertext-v1"),
		EncryptionAlg:   "aes-256-gcm",
		EncryptionKeyID: "key-1",
	}
	if err := s.SetSecret(ctx, sec); err != nil {
		t.Fatalf("SetSecret v1: %v", err)
	}

	sec.EncryptedValue = []byte("ciphertext-v2")
	if err := s.SetSecret(ctx, sec); err != nil {
		t.Fatalf("SetSecret v2: %v", err)
	}
	if sec.Version != 2 {
		t.Errorf("version: got %d, want 2", sec.Version)
	}

	versions, err := s.ListSecretVersions(ctx, "db-password", "app1")
	if err != nil {
		t.Fatalf("ListSecretVersions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("versions: got %d, want 2", len(versions))
	}

	v1, err := s.GetSecretVersion(ctx, "db-password", "app1", 1)
	if err != nil {
		t.Fatalf("GetSecretVersion: %v", err)
	}
	if string(v1.EncryptedValue) != "ciphertext-v1" {
		t.Errorf("v1 value: got %q, want %q", v1.EncryptedValue, "ciphertext-v1")
	}
}

// TestSetConfigVersioning covers the identical scalar scan that SetConfig used
// for its own version lookup.
func TestSetConfigVersioning(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	entry := &config.Entry{
		ID:        id.NewConfigID(),
		Key:       "pool.size",
		Value:     10,
		ValueType: "int",
		AppID:     "app1",
	}
	if err := s.SetConfig(ctx, entry); err != nil {
		t.Fatalf("SetConfig on a fresh key: %v", err)
	}
	if entry.Version != 1 {
		t.Errorf("version: got %d, want 1", entry.Version)
	}

	entry.Value = 20
	if err := s.SetConfig(ctx, entry); err != nil {
		t.Fatalf("SetConfig v2: %v", err)
	}
	if entry.Version != 2 {
		t.Errorf("version: got %d, want 2", entry.Version)
	}

	got, err := s.GetConfig(ctx, "pool.size", "app1")
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if got.Version != 2 {
		t.Errorf("stored version: got %d, want 2", got.Version)
	}
}

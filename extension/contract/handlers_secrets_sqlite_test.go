package contract

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"

	// Registers the "sqlite" migration executor. Vault leaves this to the
	// consumer rather than importing it from the store package.
	_ "github.com/xraph/grove/drivers/sqlitedriver/sqlitemigrate"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/vault"
	"github.com/xraph/vault/secret"
	sqlitestore "github.com/xraph/vault/store/sqlite"
)

// testSQLiteStore returns a migrated SQLite store backed by a temp-file
// database. Copied from store/sqlite/store_test.go's testStore, imports and
// all: test helpers cannot be imported across packages, and this suite
// exists specifically to prove the expiry/metadata carry-forward fix
// against a real backend. The erasure bug lived in the SQL upsert
// (SetSecret writes expires_at and metadata straight from whatever row
// Secrets().Set built), and a memory store's SetSecret never had that bug
// in the first place, so it cannot prove the fix either way.
//
// SQLite is pure Go here (modernc.org/sqlite), so this needs no external
// service and runs under a plain `go test ./...`.
func testSQLiteStore(t *testing.T) *sqlitestore.Store {
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

// newSQLiteTestVault builds a Vault over a fresh sqlite store, keyed and
// scoped to testAppID, the same shape newTestVault gives the memory suite.
func newSQLiteTestVault(t *testing.T) *vault.Vault {
	t.Helper()
	st := testSQLiteStore(t)
	v, err := vault.New(
		vault.WithStore(st),
		vault.WithAppID(testAppID),
		vault.WithEncryptionKey(testEncryptionKey),
	)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	return v
}

// TestSecretsUpdate_SQLite_NoExpiryFieldKeepsExpiryAndMetadata is the
// regression test for the erasure bug against a real backend. It was
// confirmed to fail against the handler with the carry-forward options
// removed (secretsUpdateHandler calling Set with no WithExpiresAt/
// WithMetadata options when the request omits both fields), and to pass
// once they were restored, per the task's instructions; see the commit
// report for the record of that run.
func TestSecretsUpdate_SQLite_NoExpiryFieldKeepsExpiryAndMetadata(t *testing.T) {
	v := newSQLiteTestVault(t)
	ctx := context.Background()
	// Round(0) strips the monotonic clock reading time.Now() carries. A
	// real request never has one (expiresAt always arrives as an RFC3339
	// string and goes through time.Parse), and seeding directly with a
	// monotonic-tainted time.Time here would round-trip through sqlite as
	// an unparseable string, failing on the unrelated ground that a real
	// caller can never hit.
	future := time.Now().Add(24 * time.Hour).Round(0)
	if _, err := v.Secrets().Set(ctx, "keep-me", []byte("v1"), testAppID,
		secret.WithExpiresAt(future), secret.WithMetadata(map[string]string{"env": "prod"})); err != nil {
		t.Fatalf("seed: %v", err)
	}

	out, err := secretsUpdateHandler(Deps{Vault: v})(ctx, secretsUpdateRequest{Key: "keep-me", Value: "v2"}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if out.Secret.ExpiresAt == nil {
		t.Fatal("expiresAt = nil after an update with no expiresAt field, want it kept (sqlite)")
	}
	got, err := time.Parse(time.RFC3339, *out.Secret.ExpiresAt)
	if err != nil {
		t.Fatalf("parse expiresAt: %v", err)
	}
	if !got.Equal(future.UTC().Truncate(time.Second)) {
		t.Errorf("expiresAt = %v, want %v (sqlite)", got, future)
	}
	if out.Secret.Metadata["env"] != "prod" {
		t.Errorf("metadata = %+v, want env=prod kept (sqlite)", out.Secret.Metadata)
	}

	// Confirm against a fresh read too, not just the Set call's own return
	// value, so a handler that fabricated the response without actually
	// persisting the carried-forward fields would still be caught.
	fresh, err := v.Secrets().GetMeta(ctx, "keep-me", testAppID)
	if err != nil {
		t.Fatalf("GetMeta after update: %v", err)
	}
	if fresh.ExpiresAt == nil {
		t.Fatal("a fresh GetMeta shows expiresAt = nil after update, want it kept (sqlite)")
	}
	if fresh.Metadata["env"] != "prod" {
		t.Errorf("a fresh GetMeta shows metadata = %+v, want env=prod kept (sqlite)", fresh.Metadata)
	}
}

func TestSecretsUpdate_SQLite_EmptyExpiryClears(t *testing.T) {
	v := newSQLiteTestVault(t)
	ctx := context.Background()
	// See the Round(0) comment in the test above: strips the monotonic
	// reading a raw time.Now() carries, which this backend cannot
	// round-trip and no real caller ever produces.
	future := time.Now().Add(24 * time.Hour).Round(0)
	if _, err := v.Secrets().Set(ctx, "clear-me", []byte("v1"), testAppID, secret.WithExpiresAt(future)); err != nil {
		t.Fatalf("seed: %v", err)
	}

	empty := ""
	if _, err := secretsUpdateHandler(Deps{Vault: v})(ctx, secretsUpdateRequest{Key: "clear-me", Value: "v2", ExpiresAt: &empty}, dashcontract.Principal{}); err != nil {
		t.Fatalf("update: %v", err)
	}

	fresh, err := v.Secrets().GetMeta(ctx, "clear-me", testAppID)
	if err != nil {
		t.Fatalf("GetMeta after update: %v", err)
	}
	if fresh.ExpiresAt != nil {
		t.Errorf("expiresAt = %v after clearing, want nil (sqlite)", *fresh.ExpiresAt)
	}
}

func TestSecretsUpdate_SQLite_NewTimestampChangesExpiry(t *testing.T) {
	v := newSQLiteTestVault(t)
	ctx := context.Background()
	if _, err := v.Secrets().Set(ctx, "reset-me", []byte("v1"), testAppID); err != nil {
		t.Fatalf("seed: %v", err)
	}

	next := time.Now().Add(48 * time.Hour)
	nextStr := next.Format(time.RFC3339)
	if _, err := secretsUpdateHandler(Deps{Vault: v})(ctx, secretsUpdateRequest{Key: "reset-me", Value: "v2", ExpiresAt: &nextStr}, dashcontract.Principal{}); err != nil {
		t.Fatalf("update: %v", err)
	}

	fresh, err := v.Secrets().GetMeta(ctx, "reset-me", testAppID)
	if err != nil {
		t.Fatalf("GetMeta after update: %v", err)
	}
	if fresh.ExpiresAt == nil {
		t.Fatal("expiresAt = nil, want the new timestamp (sqlite)")
	}
	if !fresh.ExpiresAt.Equal(next.UTC().Truncate(time.Second)) {
		t.Errorf("expiresAt = %v, want %v (sqlite)", *fresh.ExpiresAt, next)
	}
}

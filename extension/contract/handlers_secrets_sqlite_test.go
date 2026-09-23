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

// TestSecretsCreateAndUpdate_SQLite_NonUTCOffsetExpiryIsReadable is the
// regression test for the "keeps the caller's UTC offset" bug:
// parseFutureExpiry used to return the parsed time.Time exactly as given,
// offset and all, and that value went straight into Secrets().Set. The
// sqlite store's own read path cannot parse its own Go-formatted time
// string back when it carries a non-UTC offset (e.g. "+02:00" round-trips
// as "... +0200 +0200"), and the failure isn't confined to the one row:
// GetSecret/GetMeta's scan fails for that row, which then fails
// secrets.list too, because list scans every row for the app in a single
// query and one bad row poisons the whole result set.
//
// This was confirmed to FAIL, for both the create flow and the update
// flow below, with parseFutureExpiry returning the parsed time as-is
// instead of t.UTC(), and to pass once .UTC() was restored; see the fix
// report for the record of that run.
func TestSecretsCreateAndUpdate_SQLite_NonUTCOffsetExpiryIsReadable(t *testing.T) {
	v := newSQLiteTestVault(t)
	ctx := context.Background()
	const key = "offset-expiry"

	// +02:00: deliberately not UTC, and not whatever offset the test host
	// itself happens to run in.
	createZone := time.FixedZone("+0200", 2*60*60)
	createExpiry := time.Now().In(createZone).Add(24 * time.Hour).Truncate(time.Second)
	createOut, err := secretsCreateHandler(Deps{Vault: v})(ctx, secretsCreateRequest{
		Key: key, Value: "v1", ExpiresAt: createExpiry.Format(time.RFC3339),
	}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("create with a +02:00 expiresAt: %v", err)
	}
	if createOut.Secret.ExpiresAt == nil {
		t.Fatal("create response expiresAt = nil, want the parsed instant")
	}
	if gotCreate, perr := time.Parse(time.RFC3339, *createOut.Secret.ExpiresAt); perr != nil {
		t.Fatalf("parse create response expiresAt: %v", perr)
	} else if !gotCreate.Equal(createExpiry) {
		t.Errorf("create response expiresAt = %v, want the same instant as %v", gotCreate, createExpiry)
	}

	// The row must still be readable afterward: not just GetMeta for this
	// one key, but secrets.list, which scans every row for the app in one
	// query and fails outright if even one row's expires_at can't be
	// parsed back.
	listOut, err := secretsListHandler(Deps{Vault: v})(ctx, secretsListRequest{}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("secrets.list after a +02:00 create: %v", err)
	}
	found := false
	for _, s := range listOut.Secrets {
		if s.Key == key {
			found = true
		}
	}
	if !found {
		t.Fatalf("secrets.list did not include %q: %+v", key, listOut.Secrets)
	}

	detailOut, err := secretsDetailHandler(Deps{Vault: v})(ctx, secretsDetailRequest{Key: key}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("secrets.detail after a +02:00 create: %v", err)
	}
	if detailOut.Secret.ExpiresAt == nil {
		t.Fatal("detail expiresAt = nil, want the stored instant")
	}
	if gotDetail, perr := time.Parse(time.RFC3339, *detailOut.Secret.ExpiresAt); perr != nil {
		t.Fatalf("parse detail expiresAt: %v", perr)
	} else if !gotDetail.Equal(createExpiry) {
		t.Errorf("detail expiresAt = %v, want the same instant as %v", gotDetail, createExpiry)
	}

	// Now update with a DIFFERENT non-UTC offset, -05:00, and prove the
	// same thing holds for the update path, not just create.
	updateZone := time.FixedZone("-0500", -5*60*60)
	updateExpiry := time.Now().In(updateZone).Add(48 * time.Hour).Truncate(time.Second)
	updateExpiryStr := updateExpiry.Format(time.RFC3339)
	updateOut, err := secretsUpdateHandler(Deps{Vault: v})(ctx, secretsUpdateRequest{
		Key: key, Value: "v2", ExpiresAt: &updateExpiryStr,
	}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("update with a -05:00 expiresAt: %v", err)
	}
	if updateOut.Secret.ExpiresAt == nil {
		t.Fatal("update response expiresAt = nil, want the parsed instant")
	}
	if gotUpdate, perr := time.Parse(time.RFC3339, *updateOut.Secret.ExpiresAt); perr != nil {
		t.Fatalf("parse update response expiresAt: %v", perr)
	} else if !gotUpdate.Equal(updateExpiry) {
		t.Errorf("update response expiresAt = %v, want the same instant as %v", gotUpdate, updateExpiry)
	}

	listOut2, err := secretsListHandler(Deps{Vault: v})(ctx, secretsListRequest{}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("secrets.list after a -05:00 update: %v", err)
	}
	found2 := false
	for _, s := range listOut2.Secrets {
		if s.Key == key {
			found2 = true
		}
	}
	if !found2 {
		t.Fatalf("secrets.list did not include %q after update: %+v", key, listOut2.Secrets)
	}

	detailOut2, err := secretsDetailHandler(Deps{Vault: v})(ctx, secretsDetailRequest{Key: key}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("secrets.detail after a -05:00 update: %v", err)
	}
	if detailOut2.Secret.ExpiresAt == nil {
		t.Fatal("detail expiresAt = nil after update, want the stored instant")
	}
	if gotDetail2, perr := time.Parse(time.RFC3339, *detailOut2.Secret.ExpiresAt); perr != nil {
		t.Fatalf("parse detail expiresAt after update: %v", perr)
	} else if !gotDetail2.Equal(updateExpiry) {
		t.Errorf("detail expiresAt after update = %v, want the same instant as %v", gotDetail2, updateExpiry)
	}
}

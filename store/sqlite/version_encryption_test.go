package sqlite_test

import (
	"testing"

	"github.com/xraph/grove/drivers/sqlitedriver"

	"github.com/xraph/vault/internal/storetest"
	"github.com/xraph/vault/secret"
	sqlitestore "github.com/xraph/vault/store/sqlite"
)

func TestVersionEncryption(t *testing.T) {
	storetest.RunVersionEncryption(t, func(t *testing.T) (secret.Store, func(key, appID string, version int64)) {
		s := testStore(t)
		return s, legacyVersionRow(t, s)
	})
}

// legacyVersionRow returns a function that resets one version row to how a row
// from before the encryption_alg column looks: NULL.
func legacyVersionRow(t *testing.T, s *sqlitestore.Store) func(key, appID string, version int64) {
	t.Helper()
	sdb := sqlitedriver.Unwrap(s.DB())
	return func(key, appID string, version int64) {
		t.Helper()
		if _, err := sdb.Exec(t.Context(),
			`UPDATE vault_secret_versions SET encryption_alg = NULL WHERE secret_key = ? AND app_id = ? AND version = ?`,
			key, appID, version); err != nil {
			t.Fatalf("legacy row: %v", err)
		}
	}
}

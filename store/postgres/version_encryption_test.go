//go:build integration

package postgres_test

import (
	"context"
	"os"
	"testing"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/pgdriver"

	"github.com/xraph/vault/internal/storetest"
	"github.com/xraph/vault/secret"
	pgstore "github.com/xraph/vault/store/postgres"
)

// versionStore returns a migrated store with empty secret tables plus the
// driver, which the legacy-row helper needs for raw SQL. Set VAULT_TEST_PG_URL
// to a Postgres connection string.
func versionStore(t *testing.T) (*pgstore.Store, *pgdriver.PgDB) {
	t.Helper()

	connStr := os.Getenv("VAULT_TEST_PG_URL")
	if connStr == "" {
		t.Skip("VAULT_TEST_PG_URL not set; skipping integration test")
	}

	pgdb := pgdriver.New()
	if err := pgdb.Open(context.Background(), connStr); err != nil {
		t.Fatalf("pgdriver open: %v", err)
	}
	db, err := grove.Open(pgdb)
	if err != nil {
		t.Fatalf("grove open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	s := pgstore.New(db)
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, tbl := range []string{"vault_secret_versions", "vault_secrets"} {
		if _, err := pgdb.Exec(t.Context(), "DELETE FROM "+tbl); err != nil {
			t.Fatalf("clean %s: %v", tbl, err)
		}
	}
	return s, pgdb
}

func TestVersionEncryption(t *testing.T) {
	storetest.RunVersionEncryption(t, func(t *testing.T) (secret.Store, func(key, appID string, version int64)) {
		s, pgdb := versionStore(t)
		return s, func(key, appID string, version int64) {
			t.Helper()
			if _, err := pgdb.Exec(t.Context(),
				`UPDATE vault_secret_versions SET encryption_alg = NULL WHERE secret_key = $1 AND app_id = $2 AND version = $3`,
				key, appID, version); err != nil {
				t.Fatalf("legacy row: %v", err)
			}
		}
	})
}

package mongo_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/mongodriver"

	"github.com/xraph/vault/internal/storetest"
	"github.com/xraph/vault/secret"
	mongostore "github.com/xraph/vault/store/mongo"
)

// testStore returns a migrated MongoDB store on a database named for the test,
// dropped when the test ends. Set VAULT_TEST_MONGO_URL to a server URI such as
// mongodb://localhost:27017; any database name in it is ignored.
func testStore(t *testing.T) *mongostore.Store {
	t.Helper()

	s := mongostore.New(testDB(t))
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s
}

// testDB opens an empty database named for the test and drops it when the
// test ends. Nothing is migrated.
func testDB(t *testing.T) *grove.DB {
	t.Helper()

	uri := os.Getenv("VAULT_TEST_MONGO_URL")
	if uri == "" {
		t.Skip("VAULT_TEST_MONGO_URL not set; skipping integration test")
	}

	// Database names allow neither '/' nor spaces, and subtests have both.
	name := "vault_test_" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()) +
		fmt.Sprintf("_%d", time.Now().UnixNano())
	if len(name) > 63 {
		name = name[:40] + fmt.Sprintf("_%d", time.Now().UnixNano())
	}

	mdb := mongodriver.New()
	if err := mdb.Open(t.Context(), uri, mongodriver.WithDatabase(name)); err != nil {
		t.Fatalf("mongodriver open: %v", err)
	}
	db, err := grove.Open(mdb)
	if err != nil {
		t.Fatalf("grove open: %v", err)
	}
	t.Cleanup(func() {
		// t.Context() is already cancelled here.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := mdb.Database().Drop(ctx); err != nil {
			t.Errorf("drop %s: %v", name, err)
		}
		db.Close()
	})
	return db
}

// legacyVersionRow resets a version row to how one from before the column
// looks. unset removes the field, as a row written by the old code never had
// it; otherwise the field is stored as an explicit null.
func legacyVersionRow(t *testing.T, s *mongostore.Store, unset bool) func(key, appID string, version int64) {
	t.Helper()
	coll := mongodriver.Unwrap(s.DB()).Collection("vault_secret_versions")
	return func(key, appID string, version int64) {
		t.Helper()
		update := bson.M{"$set": bson.M{"encryption_alg": nil}}
		if unset {
			update = bson.M{"$unset": bson.M{"encryption_alg": ""}}
		}
		res, err := coll.UpdateOne(t.Context(),
			bson.M{"secret_key": key, "app_id": appID, "version": version}, update)
		if err != nil {
			t.Fatalf("legacy row: %v", err)
		}
		if res.MatchedCount != 1 {
			t.Fatalf("legacy row: matched %d documents, want 1", res.MatchedCount)
		}
	}
}

func TestVersionEncryption(t *testing.T) {
	for name, unset := range map[string]bool{"field absent": true, "field null": false} {
		t.Run(name, func(t *testing.T) {
			storetest.RunVersionEncryption(t, func(t *testing.T) (secret.Store, func(key, appID string, version int64)) {
				s := testStore(t)
				return s, legacyVersionRow(t, s, unset)
			})
		})
	}
}

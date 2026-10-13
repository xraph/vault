package mongo

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/xraph/grove/drivers/mongodriver"
)

// legacyUniqueIndexes lists, per secret collection, the key pattern of the
// unique index it had before secrets were scoped by tenant: one secret per key
// and app, and one version number per key and app.
var legacyUniqueIndexes = map[string][]string{
	colSecrets:        {"key", "app_id"},
	colSecretVersions: {"secret_key", "app_id", "version"},
}

// scopeSecretsByTenant moves the secret collections from one secret per key
// and app to one per key, app and tenant. It is safe to run again: every step
// is a no-op on a database it has already moved.
//
//  1. Every document without a tenant_id gets "", the app-level tenant, which
//     is what each of them was.
//  2. The tenant-scoped unique indexes are created before the old ones go, so
//     the collections are never without a uniqueness guarantee.
//  3. The old unique indexes are dropped, found by their key pattern rather
//     than by name, so one created under a name of its own goes too.
func scopeSecretsByTenant(ctx context.Context, mdb *mongodriver.MongoDB) error {
	for _, col := range []string{colSecrets, colSecretVersions} {
		_, err := mdb.Collection(col).UpdateMany(ctx,
			bson.M{"tenant_id": nil},
			bson.M{"$set": bson.M{"tenant_id": ""}})
		if err != nil {
			return fmt.Errorf("vault/mongo: backfill %s tenant_id: %w", col, err)
		}
	}

	if _, err := mdb.Collection(colSecrets).Indexes().CreateMany(ctx,
		[]mongo.IndexModel{secretsTenantUniqueIndex, secretsTenantListIndex}); err != nil {
		return fmt.Errorf("vault/mongo: create %s tenant indexes: %w", colSecrets, err)
	}
	if _, err := mdb.Collection(colSecretVersions).Indexes().CreateMany(ctx,
		[]mongo.IndexModel{secretVersionsTenantUniqueIndex}); err != nil {
		return fmt.Errorf("vault/mongo: create %s tenant indexes: %w", colSecretVersions, err)
	}

	for col, keys := range legacyUniqueIndexes {
		if err := dropIndexOn(ctx, mdb.Collection(col), keys, true); err != nil {
			return err
		}
	}
	return nil
}

// unscopeSecretsByTenant is the way back. It restores the per-app unique
// indexes before it drops the tenant ones, so a database where two tenants
// (or a tenant and the app) share a key fails to roll back and is left as it
// is, rather than losing which secret was whose. The tenant_id fields stay:
// the previous release never reads them.
func unscopeSecretsByTenant(ctx context.Context, mdb *mongodriver.MongoDB) error {
	for col, keys := range legacyUniqueIndexes {
		pattern := make(bson.D, 0, len(keys))
		for _, k := range keys {
			pattern = append(pattern, bson.E{Key: k, Value: 1})
		}
		if _, err := mdb.Collection(col).Indexes().CreateOne(ctx, mongo.IndexModel{
			Keys: pattern, Options: options.Index().SetUnique(true),
		}); err != nil {
			return fmt.Errorf("vault/mongo: restore %s unique index: %w", col, err)
		}
	}
	tenantIndexes := map[string][][]string{
		colSecrets: {
			{"key", "app_id", "tenant_id"},
			{"app_id", "tenant_id", "key"},
		},
		colSecretVersions: {{"secret_key", "app_id", "tenant_id", "version"}},
	}
	for col, patterns := range tenantIndexes {
		for _, keys := range patterns {
			if err := dropIndexOn(ctx, mdb.Collection(col), keys, false); err != nil {
				return err
			}
		}
	}
	return nil
}

// dropIndexOn drops every index on coll whose key pattern is exactly keys,
// each ascending, and that is unique when uniqueOnly is set. Finding none is
// not an error.
func dropIndexOn(ctx context.Context, coll *mongo.Collection, keys []string, uniqueOnly bool) error {
	specs, err := coll.Indexes().ListSpecifications(ctx)
	if err != nil {
		return fmt.Errorf("vault/mongo: list %s indexes: %w", coll.Name(), err)
	}
	for _, spec := range specs {
		if uniqueOnly && (spec.Unique == nil || !*spec.Unique) {
			continue
		}
		match, err := ascendingKeysAre(spec.KeysDocument, keys)
		if err != nil {
			return fmt.Errorf("vault/mongo: read %s index %s: %w", coll.Name(), spec.Name, err)
		}
		if !match {
			continue
		}
		if err := coll.Indexes().DropOne(ctx, spec.Name); err != nil {
			return fmt.Errorf("vault/mongo: drop %s index %s: %w", coll.Name(), spec.Name, err)
		}
	}
	return nil
}

// ascendingKeysAre reports whether the index key document doc names exactly
// keys, in order, each ascending.
func ascendingKeysAre(doc bson.Raw, keys []string) (bool, error) {
	elems, err := doc.Elements()
	if err != nil {
		return false, err
	}
	if len(elems) != len(keys) {
		return false, nil
	}
	for i, e := range elems {
		if e.Key() != keys[i] {
			return false, nil
		}
		// The server may hand an index direction back as an int32, an
		// int64 or a double.
		if dir, ok := e.Value().AsInt64OK(); !ok || dir != 1 {
			return false, nil
		}
	}
	return true, nil
}

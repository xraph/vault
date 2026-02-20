package source

import (
	"context"
	"errors"
	"strconv"

	"github.com/xraph/vault"
	"github.com/xraph/vault/config"
)

// Database reads configuration from a config.Store backend.
type Database struct {
	store config.Store
	appID string
}

// NewDatabase creates a Database source backed by the given config store.
func NewDatabase(store config.Store, appID string) *Database {
	return &Database{store: store, appID: appID}
}

// Name returns "database".
func (d *Database) Name() string { return "database" }

// Get retrieves a config entry and wraps it as a Value.
func (d *Database) Get(ctx context.Context, key string) (*Value, error) {
	entry, err := d.store.GetConfig(ctx, key, d.appID)
	if err != nil {
		return nil, convertError(err)
	}
	return entryToValue(entry), nil
}

// List returns all config entries for the app matching the prefix.
func (d *Database) List(ctx context.Context, prefix string) ([]*Value, error) {
	entries, err := d.store.ListConfig(ctx, d.appID, config.ListOpts{})
	if err != nil {
		return nil, err
	}

	var result []*Value
	for _, e := range entries {
		if prefix == "" || len(e.Key) >= len(prefix) && e.Key[:len(prefix)] == prefix {
			result = append(result, entryToValue(e))
		}
	}
	return result, nil
}

// Watch is not yet supported for the database source; returns nil.
func (d *Database) Watch(_ context.Context, _ string, _ WatchFunc) error {
	return nil
}

// Close is a no-op.
func (d *Database) Close() error { return nil }

func entryToValue(e *config.Entry) *Value {
	return &Value{
		Key:     e.Key,
		Raw:     valueToString(e.Value),
		Source:  "database",
		Version: e.Version,
	}
}

func valueToString(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case int:
		return strconv.Itoa(val)
	case int64:
		return strconv.FormatInt(val, 10)
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(val)
	default:
		return ""
	}
}

func convertError(err error) error {
	if errors.Is(err, vault.ErrConfigNotFound) {
		return ErrKeyNotFound
	}
	return err
}

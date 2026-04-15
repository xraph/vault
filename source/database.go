package source

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/xraph/vault"
	"github.com/xraph/vault/config"
)

// DatabaseOption configures a Database source.
type DatabaseOption func(*Database)

// WithPollInterval sets the polling interval for watch. Default is 30 seconds.
func WithPollInterval(d time.Duration) DatabaseOption {
	return func(db *Database) { db.pollInterval = d }
}

// Database reads configuration from a config.Store backend.
type Database struct {
	store        config.Store
	appID        string
	pollInterval time.Duration

	mu           sync.RWMutex
	watchers     map[string][]WatchFunc
	lastVersions map[string]int64
	polling      bool
	stopCh       chan struct{}
	done         chan struct{}
}

// NewDatabase creates a Database source backed by the given config store.
func NewDatabase(store config.Store, appID string, opts ...DatabaseOption) *Database {
	d := &Database{
		store:        store,
		appID:        appID,
		pollInterval: 30 * time.Second,
		watchers:     make(map[string][]WatchFunc),
		lastVersions: make(map[string]int64),
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
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

// Watch registers a callback for changes to a key. The database source uses
// polling to detect changes, starting a background goroutine on the first
// registration. Watch is non-blocking and returns immediately.
func (d *Database) Watch(ctx context.Context, key string, fn WatchFunc) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.watchers[key] = append(d.watchers[key], fn)

	// Seed last known version to avoid false-positive on first poll tick.
	if _, seeded := d.lastVersions[key]; !seeded {
		entry, err := d.store.GetConfig(ctx, key, d.appID)
		if err == nil {
			d.lastVersions[key] = entry.Version
		} else {
			d.lastVersions[key] = 0
		}
	}

	// Start the poll goroutine on first watcher registration.
	if !d.polling {
		d.stopCh = make(chan struct{})
		d.done = make(chan struct{})
		d.polling = true
		go d.pollLoop(ctx)
	}

	return nil
}

// Close stops the poll goroutine and releases resources.
func (d *Database) Close() error {
	d.mu.Lock()
	if !d.polling {
		d.mu.Unlock()
		return nil
	}
	close(d.stopCh)
	d.polling = false
	d.mu.Unlock()

	<-d.done
	return nil
}

// pollLoop runs in a goroutine and polls watched keys on a timer.
func (d *Database) pollLoop(ctx context.Context) {
	defer close(d.done)

	ticker := time.NewTicker(d.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.pollOnce(ctx)
		}
	}
}

// pollOnce checks all watched keys for version changes.
func (d *Database) pollOnce(ctx context.Context) {
	// Snapshot the watched keys.
	d.mu.RLock()
	keys := make([]string, 0, len(d.watchers))
	for k := range d.watchers {
		keys = append(keys, k)
	}
	d.mu.RUnlock()

	for _, key := range keys {
		entry, err := d.store.GetConfig(ctx, key, d.appID)

		d.mu.RLock()
		prevVersion := d.lastVersions[key]
		fns := make([]WatchFunc, len(d.watchers[key]))
		copy(fns, d.watchers[key])
		d.mu.RUnlock()

		if err != nil {
			if errors.Is(err, vault.ErrConfigNotFound) && prevVersion > 0 {
				// Key was deleted.
				d.mu.Lock()
				d.lastVersions[key] = 0
				d.mu.Unlock()

				for _, fn := range fns {
					fn(ctx, key, nil)
				}
			}
			// Other errors: skip this tick.
			continue
		}

		if entry.Version == prevVersion {
			continue // No change.
		}

		// Version changed — update tracker and fire callbacks.
		d.mu.Lock()
		d.lastVersions[key] = entry.Version
		d.mu.Unlock()

		val := entryToValue(entry)
		for _, fn := range fns {
			fn(ctx, key, val)
		}
	}
}

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

// Package source provides a composable configuration source system.
// Sources are checked in priority order; the first hit wins.
package source

import (
	"context"
	"errors"
	"time"
)

// ErrKeyNotFound is returned when no source contains the requested key.
var ErrKeyNotFound = errors.New("source: key not found")

// Value represents a configuration value from a source.
type Value struct {
	Key       string            `json:"key"`
	Raw       string            `json:"raw"`
	Source    string            `json:"source"`
	Version   int64             `json:"version,omitempty"`
	ExpiresAt *time.Time        `json:"expires_at,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// WatchFunc is called when a source value changes.
type WatchFunc func(ctx context.Context, key string, val *Value)

// Source is a configuration value provider.
type Source interface {
	// Name returns a human-readable name for this source.
	Name() string

	// Get retrieves a value by key.
	Get(ctx context.Context, key string) (*Value, error)

	// List returns all values matching a prefix (empty prefix = all).
	List(ctx context.Context, prefix string) ([]*Value, error)

	// Watch registers a callback for changes to a key. It blocks until ctx is done.
	// Sources that don't support watching should return nil immediately.
	Watch(ctx context.Context, key string, fn WatchFunc) error

	// Close releases any resources held by the source.
	Close() error
}

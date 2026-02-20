package config

import "context"

// Store defines the persistence interface for runtime configuration.
type Store interface {
	// GetConfig retrieves a config entry by key and app ID.
	GetConfig(ctx context.Context, key, appID string) (*Entry, error)

	// SetConfig creates or updates a config entry. A new version is created on update.
	SetConfig(ctx context.Context, e *Entry) error

	// DeleteConfig removes a config entry.
	DeleteConfig(ctx context.Context, key, appID string) error

	// ListConfig returns config entries for an app.
	ListConfig(ctx context.Context, appID string, opts ListOpts) ([]*Entry, error)

	// GetConfigVersion retrieves a specific version of a config entry.
	GetConfigVersion(ctx context.Context, key, appID string, version int64) (*Entry, error)

	// ListConfigVersions returns all versions of a config entry.
	ListConfigVersions(ctx context.Context, key, appID string) ([]*EntryVersion, error)
}

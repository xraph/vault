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

	// ListConfig returns the config entries for an app in key order, filtered
	// by opts.KeyPrefix and then paged. An empty result is an empty slice,
	// never nil.
	ListConfig(ctx context.Context, appID string, opts ListOpts) ([]*Entry, error)

	// GetConfigVersion retrieves a specific version of a config entry.
	GetConfigVersion(ctx context.Context, key, appID string, version int64) (*Entry, error)

	// ListConfigVersions returns all versions of a config entry.
	ListConfigVersions(ctx context.Context, key, appID string) ([]*EntryVersion, error)

	// CountConfig returns the total number of config entries for an app,
	// independent of any paging.
	CountConfig(ctx context.Context, appID string) (int64, error)

	// CountConfigMatching returns the number of config entries for an app
	// that match opts.KeyPrefix. Limit and Offset are ignored, so it is the
	// total behind a page returned by ListConfig with the same opts.
	CountConfigMatching(ctx context.Context, appID string, opts ListOpts) (int64, error)
}

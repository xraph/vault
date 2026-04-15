// Package confy provides confy ConfigSource and SecretProvider adapters
// backed by vault's config and secret stores. This allows forge applications
// to use vault-managed configuration and secrets via the confy config system.
package confy

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	confypkg "github.com/xraph/confy"

	"github.com/xraph/vault/config"
	"github.com/xraph/vault/secret"
)

// Compile-time interface check.
var _ confypkg.ConfigSource = (*VaultConfigSource)(nil)

// VaultSourceOption configures a VaultConfigSource.
type VaultSourceOption func(*VaultConfigSource)

// WithSourceName sets the source name. Default is "vault".
func WithSourceName(name string) VaultSourceOption {
	return func(s *VaultConfigSource) { s.name = name }
}

// WithSourcePriority sets the source priority. Default is 100.
func WithSourcePriority(p int) VaultSourceOption {
	return func(s *VaultConfigSource) { s.priority = p }
}

// WithSourcePollInterval sets the watch poll interval. Default is 30s.
func WithSourcePollInterval(d time.Duration) VaultSourceOption {
	return func(s *VaultConfigSource) { s.pollInterval = d }
}

// WithKeyPrefix sets a prefix that is prepended to all vault keys when
// exposed through confy. For example, WithKeyPrefix("vault.") causes
// a vault key "db.host" to appear as "vault.db.host" in confy.
func WithKeyPrefix(prefix string) VaultSourceOption {
	return func(s *VaultConfigSource) { s.keyPrefix = prefix }
}

// WithKeys restricts which vault keys are mounted into confy.
// Only the listed keys will be included; all others are filtered out.
// When empty (the default), all keys are included.
func WithKeys(keys ...string) VaultSourceOption {
	return func(s *VaultConfigSource) {
		s.allowedKeys = make(map[string]struct{}, len(keys))
		for _, k := range keys {
			s.allowedKeys[k] = struct{}{}
		}
	}
}

// WithKeyPatterns restricts which vault keys are mounted into confy
// using glob patterns (e.g. "db.*", "auth.**", "feature.flags.*").
// Uses filepath.Match semantics. Multiple patterns are OR-ed together.
// When empty (the default), all keys are included.
func WithKeyPatterns(patterns ...string) VaultSourceOption {
	return func(s *VaultConfigSource) {
		s.keyPatterns = patterns
	}
}

// VaultConfigSource is a confy ConfigSource backed by vault's config and secret stores.
type VaultConfigSource struct {
	name         string
	priority     int
	appID        string
	configStore  config.Store
	secretStore  secret.Store
	pollInterval time.Duration

	// Mounting / filtering options.
	keyPrefix   string              // prepended to vault keys in confy
	allowedKeys map[string]struct{} // nil = all keys; non-nil = whitelist
	keyPatterns []string            // glob patterns; nil = no pattern filter

	mu           sync.RWMutex
	watching     bool
	watchStop    chan struct{}
	lastSnapshot map[string]int64 // vault key -> version for change detection
}

// NewVaultConfigSource creates a new VaultConfigSource.
func NewVaultConfigSource(configStore config.Store, secretStore secret.Store, appID string, opts ...VaultSourceOption) *VaultConfigSource {
	s := &VaultConfigSource{
		name:         "vault",
		priority:     100,
		appID:        appID,
		configStore:  configStore,
		secretStore:  secretStore,
		pollInterval: 30 * time.Second,
		lastSnapshot: make(map[string]int64),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Name returns the source name.
func (s *VaultConfigSource) Name() string { return s.name }

// GetName returns the source name (alias for Name).
func (s *VaultConfigSource) GetName() string { return s.name }

// GetType returns the source type.
func (s *VaultConfigSource) GetType() string { return "vault" }

// Priority returns the source priority.
func (s *VaultConfigSource) Priority() int { return s.priority }

// IsWatchable returns true — vault config source supports polling-based watch.
func (s *VaultConfigSource) IsWatchable() bool { return true }

// SupportsSecrets returns true if a secret store is configured.
func (s *VaultConfigSource) SupportsSecrets() bool { return s.secretStore != nil }

// IsAvailable checks if the vault config store is reachable.
func (s *VaultConfigSource) IsAvailable(ctx context.Context) bool {
	_, err := s.configStore.ListConfig(ctx, s.appID, config.ListOpts{Limit: 1})
	return err == nil
}

// Load returns config entries for the app as a flat map, filtered and
// prefixed according to the configured mount options.
func (s *VaultConfigSource) Load(ctx context.Context) (map[string]any, error) {
	entries, err := s.configStore.ListConfig(ctx, s.appID, config.ListOpts{})
	if err != nil {
		return nil, fmt.Errorf("vault config source: load: %w", err)
	}

	result := make(map[string]any, len(entries))

	s.mu.Lock()
	for _, e := range entries {
		if !s.matchesFilter(e.Key) {
			continue
		}
		confyKey := s.keyPrefix + e.Key
		result[confyKey] = e.Value
		s.lastSnapshot[e.Key] = e.Version
	}
	s.mu.Unlock()

	return result, nil
}

// Watch starts polling for config changes and calls callback when any value changes.
func (s *VaultConfigSource) Watch(ctx context.Context, callback func(map[string]any)) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.watching {
		return fmt.Errorf("vault config source: already watching")
	}

	s.watchStop = make(chan struct{})
	s.watching = true

	go s.watchLoop(ctx, callback)

	return nil
}

// StopWatch stops the watch goroutine.
func (s *VaultConfigSource) StopWatch() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.watching {
		return nil
	}

	close(s.watchStop)
	s.watching = false
	return nil
}

// Reload re-fetches all config from the store.
func (s *VaultConfigSource) Reload(ctx context.Context) error {
	_, err := s.Load(ctx)
	return err
}

// GetSecret retrieves a secret from the vault secret store.
func (s *VaultConfigSource) GetSecret(ctx context.Context, key string) (string, error) {
	if s.secretStore == nil {
		return "", fmt.Errorf("vault config source: secret store not configured")
	}

	sec, err := s.secretStore.GetSecret(ctx, key, s.appID)
	if err != nil {
		return "", fmt.Errorf("vault config source: get secret: %w", err)
	}

	return string(sec.Value), nil
}

// matchesFilter returns true if the vault key passes the configured filters.
// When no filters are set, all keys pass. Whitelist and patterns are OR-ed:
// a key passes if it is in the whitelist OR matches any pattern.
func (s *VaultConfigSource) matchesFilter(key string) bool {
	// No filters = allow all.
	if s.allowedKeys == nil && len(s.keyPatterns) == 0 {
		return true
	}

	// Check whitelist.
	if s.allowedKeys != nil {
		if _, ok := s.allowedKeys[key]; ok {
			return true
		}
	}

	// Check glob patterns.
	for _, pattern := range s.keyPatterns {
		matched, err := filepath.Match(pattern, key)
		if err != nil {
			continue // Invalid pattern, skip.
		}
		if matched {
			return true
		}
	}

	// If any filter was configured but nothing matched, reject.
	return false
}

// watchLoop polls for config changes on a timer.
func (s *VaultConfigSource) watchLoop(ctx context.Context, callback func(map[string]any)) {
	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.watchStop:
			return
		case <-ticker.C:
			s.pollAndNotify(ctx, callback)
		}
	}
}

// pollAndNotify loads current config and fires callback if any version changed.
func (s *VaultConfigSource) pollAndNotify(ctx context.Context, callback func(map[string]any)) {
	entries, err := s.configStore.ListConfig(ctx, s.appID, config.ListOpts{})
	if err != nil {
		return // Skip on error.
	}

	s.mu.Lock()
	changed := false
	newSnapshot := make(map[string]int64, len(entries))
	result := make(map[string]any, len(entries))

	for _, e := range entries {
		if !s.matchesFilter(e.Key) {
			continue
		}
		confyKey := s.keyPrefix + e.Key
		result[confyKey] = e.Value
		newSnapshot[e.Key] = e.Version

		if prev, ok := s.lastSnapshot[e.Key]; !ok || prev != e.Version {
			changed = true
		}
	}

	// Detect deletions of previously tracked keys.
	for k := range s.lastSnapshot {
		if _, ok := newSnapshot[k]; !ok {
			changed = true
		}
	}

	s.lastSnapshot = newSnapshot
	s.mu.Unlock()

	if changed {
		callback(result)
	}
}

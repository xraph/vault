package config

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/xraph/vault"
	"github.com/xraph/vault/id"
)

// ValueResolver resolves config values with tenant-aware override support.
// The override.Resolver type satisfies this interface.
type ValueResolver interface {
	Resolve(ctx context.Context, key, appID string) (any, error)
	Invalidate(key, appID string)
}

// WatchCallback is invoked when a config entry is updated.
type WatchCallback func(ctx context.Context, key string, oldValue, newValue any)

// ServiceOption configures the Service.
type ServiceOption func(*Service)

// WithAppID sets the default app ID for the config service.
func WithAppID(appID string) ServiceOption {
	return func(s *Service) { s.appID = appID }
}

// WithResolver sets the override resolver for tenant-aware config resolution.
func WithResolver(r ValueResolver) ServiceOption {
	return func(s *Service) { s.resolver = r }
}

// Service provides type-safe config reading, writing, and watch support.
type Service struct {
	store    Store
	resolver ValueResolver
	appID    string
	mu       sync.RWMutex
	watchers map[string][]WatchCallback
}

// NewService creates a config service.
func NewService(store Store, opts ...ServiceOption) *Service {
	s := &Service{
		store:    store,
		watchers: make(map[string][]WatchCallback),
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// resolveAppID returns appID from argument or service default.
func (s *Service) resolveAppID(appID string) string {
	if appID != "" {
		return appID
	}
	return s.appID
}

// ──────────────────────────────────────────────────
// Type-safe accessors
// ──────────────────────────────────────────────────

// String returns a string config value. Returns defaultVal on error or type mismatch.
func (s *Service) String(ctx context.Context, key, defaultVal string) string {
	val, err := s.resolve(ctx, key)
	if err != nil {
		return defaultVal
	}
	str, ok := val.(string)
	if !ok {
		return defaultVal
	}
	return str
}

// Bool returns a boolean config value. Returns defaultVal on error or type mismatch.
func (s *Service) Bool(ctx context.Context, key string, defaultVal bool) bool {
	val, err := s.resolve(ctx, key)
	if err != nil {
		return defaultVal
	}
	b, ok := val.(bool)
	if !ok {
		return defaultVal
	}
	return b
}

// Int returns an integer config value. Returns defaultVal on error or type mismatch.
// Handles int, float64 (from JSON), and int64.
func (s *Service) Int(ctx context.Context, key string, defaultVal int) int {
	val, err := s.resolve(ctx, key)
	if err != nil {
		return defaultVal
	}
	switch v := val.(type) {
	case int:
		return v
	case float64:
		return int(v)
	case int64:
		return int(v)
	default:
		return defaultVal
	}
}

// Float returns a float64 config value. Returns defaultVal on error or type mismatch.
// Handles float64, int, and int64.
func (s *Service) Float(ctx context.Context, key string, defaultVal float64) float64 {
	val, err := s.resolve(ctx, key)
	if err != nil {
		return defaultVal
	}
	switch v := val.(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	default:
		return defaultVal
	}
}

// Duration returns a time.Duration config value. Returns defaultVal on error or type mismatch.
// Parses from a string using time.ParseDuration (e.g. "5s", "1m30s").
func (s *Service) Duration(ctx context.Context, key string, defaultVal time.Duration) time.Duration {
	val, err := s.resolve(ctx, key)
	if err != nil {
		return defaultVal
	}

	switch v := val.(type) {
	case string:
		d, pErr := time.ParseDuration(v)
		if pErr != nil {
			return defaultVal
		}
		return d
	case float64:
		// Interpret as nanoseconds (JSON number).
		return time.Duration(int64(v))
	case int64:
		return time.Duration(v)
	case int:
		return time.Duration(int64(v))
	default:
		return defaultVal
	}
}

// JSON reads a config value and unmarshals it into target.
// target must be a pointer. Returns an error if the config is not found
// or the value cannot be converted to JSON and unmarshaled into target.
func (s *Service) JSON(ctx context.Context, key string, target any) error {
	val, err := s.resolve(ctx, key)
	if err != nil {
		return fmt.Errorf("config %q: %w", key, err)
	}

	switch v := val.(type) {
	case []byte:
		return json.Unmarshal(v, target)
	case string:
		return json.Unmarshal([]byte(v), target)
	default:
		data, mErr := json.Marshal(val)
		if mErr != nil {
			return fmt.Errorf("config %q: marshal: %w", key, mErr)
		}
		return json.Unmarshal(data, target)
	}
}

// ──────────────────────────────────────────────────
// CRUD
// ──────────────────────────────────────────────────

// Get retrieves a config entry by key.
func (s *Service) Get(ctx context.Context, key, appID string) (*Entry, error) {
	appID = s.resolveAppID(appID)
	return s.store.GetConfig(ctx, key, appID)
}

// SetOption configures a Set operation.
type SetOption func(*setConfig)

type setConfig struct {
	description string
	valueType   string
	metadata    map[string]string
}

// WithDescription sets the description on the config entry.
func WithDescription(desc string) SetOption {
	return func(c *setConfig) { c.description = desc }
}

// WithValueType sets an explicit value type label (e.g. "string", "int", "json").
func WithValueType(vt string) SetOption {
	return func(c *setConfig) { c.valueType = vt }
}

// WithMetadata sets metadata on the config entry.
func WithMetadata(m map[string]string) SetOption {
	return func(c *setConfig) { c.metadata = m }
}

// Set creates or updates a config entry, auto-versioning on update.
func (s *Service) Set(ctx context.Context, key string, value any, appID string, opts ...SetOption) error {
	appID = s.resolveAppID(appID)

	var cfg setConfig
	for _, o := range opts {
		o(&cfg)
	}

	// Determine old value for watchers.
	var oldValue any
	existing, err := s.store.GetConfig(ctx, key, appID)
	if err == nil {
		oldValue = existing.Value
	}

	entry := &Entry{
		Entity:      vault.NewEntity(),
		ID:          id.NewConfigID(),
		Key:         key,
		Value:       value,
		ValueType:   cfg.valueType,
		Description: cfg.description,
		AppID:       appID,
		Metadata:    cfg.metadata,
	}

	if cfg.valueType == "" {
		entry.ValueType = inferValueType(value)
	}

	if err := s.store.SetConfig(ctx, entry); err != nil {
		return err
	}

	// Invalidate resolver cache for this key.
	if s.resolver != nil {
		s.resolver.Invalidate(key, appID)
	}

	// Notify watchers.
	s.notifyWatchers(ctx, key, oldValue, value)

	return nil
}

// Delete removes a config entry and all its versions.
func (s *Service) Delete(ctx context.Context, key, appID string) error {
	appID = s.resolveAppID(appID)

	if err := s.store.DeleteConfig(ctx, key, appID); err != nil {
		return err
	}

	// Invalidate resolver cache.
	if s.resolver != nil {
		s.resolver.Invalidate(key, appID)
	}

	return nil
}

// List returns config entries for an app.
func (s *Service) List(ctx context.Context, appID string, opts ListOpts) ([]*Entry, error) {
	appID = s.resolveAppID(appID)
	return s.store.ListConfig(ctx, appID, opts)
}

// ──────────────────────────────────────────────────
// Watch
// ──────────────────────────────────────────────────

// Watch registers a callback that fires when the given config key is updated via Set.
func (s *Service) Watch(key string, cb WatchCallback) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.watchers[key] = append(s.watchers[key], cb)
}

func (s *Service) notifyWatchers(ctx context.Context, key string, oldValue, newValue any) {
	s.mu.RLock()
	cbs := s.watchers[key]
	s.mu.RUnlock()

	for _, cb := range cbs {
		cb(ctx, key, oldValue, newValue)
	}
}

// ──────────────────────────────────────────────────
// Internal resolution
// ──────────────────────────────────────────────────

// resolve returns the effective value for a config key.
// If a resolver is set, it handles tenant override resolution.
// Otherwise, it reads directly from the config store.
func (s *Service) resolve(ctx context.Context, key string) (any, error) {
	appID := s.resolveAppID("")

	if s.resolver != nil {
		return s.resolver.Resolve(ctx, key, appID)
	}

	entry, err := s.store.GetConfig(ctx, key, appID)
	if err != nil {
		return nil, err
	}
	return entry.Value, nil
}

// inferValueType returns a type label for common Go types.
func inferValueType(v any) string {
	switch v.(type) {
	case string:
		return "string"
	case bool:
		return "bool"
	case int, int64:
		return "int"
	case float64:
		return "float"
	default:
		return "json"
	}
}

// ──────────────────────────────────────────────────
// Parsing helpers for numeric strings
// ──────────────────────────────────────────────────

// ParseInt tries to parse a string as an integer.
func ParseInt(s string) (int, error) {
	return strconv.Atoi(s)
}

// ParseFloat tries to parse a string as a float64.
func ParseFloat(s string) (float64, error) {
	return strconv.ParseFloat(s, 64)
}

// ParseBool tries to parse a string as a boolean.
func ParseBool(s string) (bool, error) {
	return strconv.ParseBool(s)
}

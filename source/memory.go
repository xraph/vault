package source

import (
	"context"
	"strings"
	"sync"
)

// Memory is an in-memory source useful for testing and dynamic overrides.
type Memory struct {
	mu       sync.RWMutex
	data     map[string]*Value
	watchers map[string][]WatchFunc
}

// NewMemory creates a new empty Memory source.
func NewMemory() *Memory {
	return &Memory{
		data:     make(map[string]*Value),
		watchers: make(map[string][]WatchFunc),
	}
}

// Name returns "memory".
func (m *Memory) Name() string { return "memory" }

// Set sets a value and notifies watchers.
func (m *Memory) Set(ctx context.Context, key, raw string) {
	m.mu.Lock()
	v := &Value{Key: key, Raw: raw, Source: "memory"}
	m.data[key] = v
	fns := m.watchers[key]
	m.mu.Unlock()

	for _, fn := range fns {
		fn(ctx, key, v)
	}
}

// Get retrieves a value by key.
func (m *Memory) Get(_ context.Context, key string) (*Value, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	v, ok := m.data[key]
	if !ok {
		return nil, ErrKeyNotFound
	}
	cp := *v
	return &cp, nil
}

// List returns all values whose keys have the given prefix.
func (m *Memory) List(_ context.Context, prefix string) ([]*Value, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*Value
	for k, v := range m.data {
		if prefix == "" || strings.HasPrefix(k, prefix) {
			cp := *v
			result = append(result, &cp)
		}
	}
	return result, nil
}

// Watch registers a callback for the given key. Non-blocking — returns immediately.
func (m *Memory) Watch(_ context.Context, key string, fn WatchFunc) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.watchers[key] = append(m.watchers[key], fn)
	return nil
}

// Close is a no-op.
func (m *Memory) Close() error { return nil }

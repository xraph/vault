package flag

import (
	"sync"
	"time"
)

// cacheEntry holds a cached evaluation result with expiry.
type cacheEntry struct {
	value     any
	expiresAt time.Time
}

// evaluationCache is a simple TTL-based cache for flag evaluation results.
// Keys are composed of flagKey + tenantID.
type evaluationCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	ttl     time.Duration
}

// newEvaluationCache creates a cache with the given TTL.
func newEvaluationCache(ttl time.Duration) *evaluationCache {
	return &evaluationCache{
		entries: make(map[string]cacheEntry),
		ttl:     ttl,
	}
}

// cacheKey builds a composite cache key from flag key and tenant ID.
func cacheKey(flagKey, tenantID string) string {
	return flagKey + "\x00" + tenantID
}

// get retrieves a cached value. Returns (value, true) on hit, (nil, false) on miss or expired.
func (c *evaluationCache) get(flagKey, tenantID string) (any, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[cacheKey(flagKey, tenantID)]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.value, true
}

// set stores a value in the cache with the configured TTL.
func (c *evaluationCache) set(flagKey, tenantID string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[cacheKey(flagKey, tenantID)] = cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// invalidate removes all entries for a specific flag key.
func (c *evaluationCache) invalidate(flagKey string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	prefix := flagKey + "\x00"
	for k := range c.entries {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(c.entries, k)
		}
	}
}

// invalidateAll removes all cached entries.
func (c *evaluationCache) invalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]cacheEntry)
}

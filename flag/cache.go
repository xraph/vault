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
// Keys are composed of flagKey, appID, tenantID and userID. Every input that
// can change a result must be in the key: without appID the same flag key in
// two apps shared results, and without userID a user-targeted rule's result
// was served to every other user of the tenant until the TTL expired.
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

// cacheKey builds a composite cache key. flagKey comes first so that
// invalidate can drop every entry for a flag with a prefix match.
func cacheKey(flagKey, appID, tenantID, userID string) string {
	return flagKey + "\x00" + appID + "\x00" + tenantID + "\x00" + userID
}

// get retrieves a cached value. Returns (value, true) on hit, (nil, false) on miss or expired.
func (c *evaluationCache) get(flagKey, appID, tenantID, userID string) (any, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[cacheKey(flagKey, appID, tenantID, userID)]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.value, true
}

// set stores a value in the cache with the configured TTL.
func (c *evaluationCache) set(flagKey, appID, tenantID, userID string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[cacheKey(flagKey, appID, tenantID, userID)] = cacheEntry{
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

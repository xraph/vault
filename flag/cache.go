package flag

import (
	"sync"
	"time"
)

// defaultMaxEntries bounds the cache when the caller does not set one. Since
// the key includes the user, an unbounded cache grows by one entry per flag,
// app, tenant and user forever.
const defaultMaxEntries = 10000

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
//
// gen is a cache-wide generation counter. invalidate and invalidateAll bump
// it under the write lock. Evaluate reads it before it reads the store and
// writes its result through setIfGen, which stores nothing if the counter
// moved in between. Without it, an evaluation that read a flag just before a
// writer changed it and called Invalidate would cache the old value after
// the Invalidate, and that value would outlive the change for a full TTL.
// The counter is shared by every flag, so an Invalidate on one flag also
// stops in-flight evaluations of other flags from caching. That costs a few
// cache misses, never a wrong answer.
type evaluationCache struct {
	mu         sync.RWMutex
	entries    map[string]cacheEntry
	ttl        time.Duration
	maxEntries int
	gen        uint64
}

// newEvaluationCache creates a cache with the given TTL and entry cap.
// maxEntries <= 0 falls back to defaultMaxEntries.
func newEvaluationCache(ttl time.Duration, maxEntries int) *evaluationCache {
	if maxEntries <= 0 {
		maxEntries = defaultMaxEntries
	}
	return &evaluationCache{
		entries:    make(map[string]cacheEntry),
		ttl:        ttl,
		maxEntries: maxEntries,
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

// set stores a value in the cache with the configured TTL. When the cache is
// at or over its cap, it first sweeps every expired entry; if that was not
// enough, it clears the map entirely rather than picking entries to evict.
// The cache is an optimisation, so dropping entries only changes the hit
// rate, never an answer.
func (c *evaluationCache) set(flagKey, appID, tenantID, userID string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.putLocked(flagKey, appID, tenantID, userID, value)
}

// generation returns the current generation. Read it before reading the
// store, and pass it to setIfGen with the result.
func (c *evaluationCache) generation() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.gen
}

// setIfGen stores value like set, but only if no invalidate or
// invalidateAll ran since gen was read. A result computed from a store read
// that an Invalidate has since overtaken is dropped, not cached.
func (c *evaluationCache) setIfGen(flagKey, appID, tenantID, userID string, value any, gen uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.gen != gen {
		return
	}
	c.putLocked(flagKey, appID, tenantID, userID, value)
}

// putLocked does the work of set and setIfGen. The caller holds c.mu for
// writing.
func (c *evaluationCache) putLocked(flagKey, appID, tenantID, userID string, value any) {
	if len(c.entries) >= c.maxEntries {
		now := time.Now()
		for k, e := range c.entries {
			if now.After(e.expiresAt) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= c.maxEntries {
			c.entries = make(map[string]cacheEntry)
		}
	}

	c.entries[cacheKey(flagKey, appID, tenantID, userID)] = cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// invalidate removes all entries for a specific flag key.
func (c *evaluationCache) invalidate(flagKey string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.gen++

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

	c.gen++

	c.entries = make(map[string]cacheEntry)
}

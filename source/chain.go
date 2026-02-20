package source

import (
	"context"
	"errors"
)

// Chain is a priority-ordered list of Sources. Get returns the first hit.
type Chain struct {
	sources []Source
}

// NewChain creates a new priority chain from sources (first = highest priority).
func NewChain(sources ...Source) *Chain {
	return &Chain{sources: sources}
}

// Get returns the value from the first source that contains the key.
func (c *Chain) Get(ctx context.Context, key string) (*Value, error) {
	for _, src := range c.sources {
		val, err := src.Get(ctx, key)
		if err == nil {
			return val, nil
		}
		if !errors.Is(err, ErrKeyNotFound) {
			return nil, err
		}
	}
	return nil, ErrKeyNotFound
}

// List merges values from all sources. Higher-priority sources override lower ones.
func (c *Chain) List(ctx context.Context, prefix string) ([]*Value, error) {
	seen := make(map[string]*Value)
	var order []string

	for _, src := range c.sources {
		vals, err := src.List(ctx, prefix)
		if err != nil {
			return nil, err
		}
		for _, v := range vals {
			if _, exists := seen[v.Key]; !exists {
				seen[v.Key] = v
				order = append(order, v.Key)
			}
		}
	}

	result := make([]*Value, 0, len(order))
	for _, k := range order {
		result = append(result, seen[k])
	}
	return result, nil
}

// Watch registers watchers on all sources for the given key.
func (c *Chain) Watch(ctx context.Context, key string, fn WatchFunc) error {
	for _, src := range c.sources {
		if err := src.Watch(ctx, key, fn); err != nil {
			return err
		}
	}
	return nil
}

// Close closes all sources.
func (c *Chain) Close() error {
	var errs []error
	for _, src := range c.sources {
		if err := src.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

package flag_test

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/vault"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/store/memory"
)

// raceStore plays a writer that changes a flag and calls Invalidate in the
// window between Evaluate's store read and its cache write. The first
// GetFlagDefinition returns the old definition, then updates the flag and
// invalidates before returning, which is the exact interleaving that used to
// leave the old value cached for the whole TTL. No goroutines, no sleeps:
// the interleaving is forced, so the test is deterministic.
type raceStore struct {
	*memory.Store
	engine *flag.Engine
	fired  bool
}

func (s *raceStore) GetFlagDefinition(ctx context.Context, key, appID string) (*flag.Definition, error) {
	def, err := s.Store.GetFlagDefinition(ctx, key, appID)
	if err != nil || s.fired {
		return def, err
	}
	s.fired = true

	old := *def
	updated := *def
	updated.DefaultValue = "new"
	if err := s.DefineFlag(ctx, &updated); err != nil {
		return nil, err
	}
	s.engine.Invalidate(key)
	return &old, nil
}

func TestEvaluateDoesNotRecacheOverAConcurrentInvalidate(t *testing.T) {
	inner := memory.New()
	if err := inner.DefineFlag(bg(), &flag.Definition{
		Entity:       vault.NewEntity(),
		ID:           id.NewFlagID(),
		Key:          "feat-race",
		Type:         flag.TypeString,
		DefaultValue: "old",
		Enabled:      true,
		AppID:        testApp,
	}); err != nil {
		t.Fatalf("DefineFlag: %v", err)
	}

	s := &raceStore{Store: inner}
	engine := flag.NewEngine(s, flag.WithCacheTTL(time.Hour))
	s.engine = engine

	// This evaluation started before the change, so "old" is a fair answer
	// for it to return. It must not cache that answer over the Invalidate.
	first, err := engine.Evaluate(bg(), "feat-race", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if first != "old" {
		t.Fatalf("first Evaluate = %v, want %q (it read the store before the change)", first, "old")
	}
	if !s.fired {
		t.Fatal("the store hook never ran, so the interleaving was not exercised")
	}

	second, err := engine.Evaluate(bg(), "feat-race", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if second != "new" {
		t.Errorf("second Evaluate = %v, want %q: the in-flight evaluation re-cached the old value over Invalidate", second, "new")
	}
}

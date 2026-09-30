//go:build integration

package postgres_test

import (
	"context"
	"testing"

	"github.com/xraph/vault/config"
	"github.com/xraph/vault/id"
)

// seedPrefixedConfig writes five keys into app1 (out of key order) and one
// db.-prefixed key into app2.
func seedPrefixedConfig(t *testing.T, s config.Store) {
	t.Helper()
	keys := []struct{ key, app string }{
		{"db.port", "app1"},
		{"dbx", "app1"},
		{"db.host", "app1"},
		{"cache.ttl", "app1"},
		{"db_x", "app1"},
		{"db.other", "app2"},
	}
	for _, k := range keys {
		if err := s.SetConfig(t.Context(), &config.Entry{
			ID: id.NewConfigID(), Key: k.key, Value: k.key, AppID: k.app,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func configKeys(es []*config.Entry) []string {
	keys := make([]string, len(es))
	for i, e := range es {
		keys[i] = e.Key
	}
	return keys
}

func TestListConfigFiltersByKeyPrefix(t *testing.T) {
	s := testStore(t)
	ctx := t.Context()
	seedPrefixedConfig(t, s)

	got, err := s.ListConfig(ctx, "app1", config.ListOpts{KeyPrefix: "db."})
	if err != nil {
		t.Fatal(err)
	}
	if k := configKeys(got); len(k) != 2 || k[0] != "db.host" || k[1] != "db.port" {
		t.Errorf("prefix db.: got %v, want [db.host db.port]", k)
	}
	if n := countMatching(ctx, t, s, "app1", config.ListOpts{KeyPrefix: "db."}); n != 2 {
		t.Errorf("count prefix db.: got %d, want 2", n)
	}

	// The underscore is a literal, so db_ matches db_x and not dbx or db.host.
	got, err = s.ListConfig(ctx, "app1", config.ListOpts{KeyPrefix: "db_"})
	if err != nil {
		t.Fatal(err)
	}
	if k := configKeys(got); len(k) != 1 || k[0] != "db_x" {
		t.Errorf("prefix db_: got %v, want [db_x]", k)
	}
	if n := countMatching(ctx, t, s, "app1", config.ListOpts{KeyPrefix: "db_"}); n != 1 {
		t.Errorf("count prefix db_: got %d, want 1", n)
	}

	// A percent sign and a backslash are literals too.
	for _, p := range []string{"%", "db%", "\\", "db\\"} {
		got, err = s.ListConfig(ctx, "app1", config.ListOpts{KeyPrefix: p})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("prefix %q: got %v, want none", p, configKeys(got))
		}
		if n := countMatching(ctx, t, s, "app1", config.ListOpts{KeyPrefix: p}); n != 0 {
			t.Errorf("count prefix %q: got %d, want 0", p, n)
		}
	}

	// Empty prefix means every key of the app.
	got, err = s.ListConfig(ctx, "app1", config.ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Errorf("no prefix: got %d entries, want 5", len(got))
	}
	if n := countMatching(ctx, t, s, "app1", config.ListOpts{}); n != 5 {
		t.Errorf("count no prefix: got %d, want 5", n)
	}
}

func TestListConfigPagesWithinKeyPrefix(t *testing.T) {
	s := testStore(t)
	ctx := t.Context()
	seedPrefixedConfig(t, s)

	opts := config.ListOpts{KeyPrefix: "db.", Limit: 1}
	page, err := s.ListConfig(ctx, "app1", opts)
	if err != nil {
		t.Fatal(err)
	}
	if k := configKeys(page); len(k) != 1 || k[0] != "db.host" {
		t.Errorf("first page: got %v, want [db.host]", k)
	}

	opts.Offset = 1
	page, err = s.ListConfig(ctx, "app1", opts)
	if err != nil {
		t.Fatal(err)
	}
	if k := configKeys(page); len(k) != 1 || k[0] != "db.port" {
		t.Errorf("second page: got %v, want [db.port]", k)
	}

	opts.Offset = 10
	page, err = s.ListConfig(ctx, "app1", opts)
	if err != nil {
		t.Fatal(err)
	}
	if page == nil || len(page) != 0 {
		t.Errorf("page past the end: got %#v, want a non-nil empty slice", page)
	}

	// Paging is ignored by the count, so the total survives an empty page.
	if n := countMatching(ctx, t, s, "app1", opts); n != 2 {
		t.Errorf("count past the end: got %d, want 2", n)
	}

	// Another app's keys never leak in.
	if n := countMatching(ctx, t, s, "app2", config.ListOpts{KeyPrefix: "db."}); n != 1 {
		t.Errorf("app2 count: got %d, want 1", n)
	}
}

func countMatching(ctx context.Context, t *testing.T, s config.Store, app string, opts config.ListOpts) int64 {
	t.Helper()
	n, err := s.CountConfigMatching(ctx, app, opts)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

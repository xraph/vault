//go:build integration

package postgres_test

import (
	"testing"

	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/id"
)

func TestFlagTypeFilter(t *testing.T) {
	s := testStore(t)
	ctx := t.Context()
	defs := []struct {
		key, app string
		typ      flag.Type
	}{
		{"d-bool", "app1", flag.TypeBool},
		{"a-bool", "app1", flag.TypeBool},
		{"c-string", "app1", flag.TypeString},
		{"e-bool", "app1", flag.TypeBool},
		{"b-int", "app1", flag.TypeInt},
		{"z-bool", "app2", flag.TypeBool},
	}
	for _, d := range defs {
		if err := s.DefineFlag(ctx, &flag.Definition{
			ID: id.NewFlagID(), Key: d.key, Type: d.typ, AppID: d.app, Enabled: true,
		}); err != nil {
			t.Fatal(err)
		}
	}

	keys := func(ds []*flag.Definition) []string {
		out := make([]string, len(ds))
		for i, d := range ds {
			out[i] = d.Key
		}
		return out
	}

	page, err := s.ListFlagDefinitions(ctx, "app1", flag.ListOpts{Type: flag.TypeBool, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if k := keys(page); len(k) != 2 || k[0] != "a-bool" || k[1] != "d-bool" {
		t.Errorf("first bool page: got %v, want [a-bool d-bool]", k)
	}

	page, err = s.ListFlagDefinitions(ctx, "app1", flag.ListOpts{Type: flag.TypeBool, Limit: 2, Offset: 2})
	if err != nil {
		t.Fatal(err)
	}
	if k := keys(page); len(k) != 1 || k[0] != "e-bool" {
		t.Errorf("second bool page: got %v, want [e-bool]", k)
	}

	past, err := s.ListFlagDefinitions(ctx, "app1", flag.ListOpts{Type: flag.TypeBool, Limit: 2, Offset: 10})
	if err != nil {
		t.Fatal(err)
	}
	if past == nil || len(past) != 0 {
		t.Errorf("page past the end: got %#v, want a non-nil empty slice", past)
	}

	all, err := s.ListFlagDefinitions(ctx, "app1", flag.ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 5 {
		t.Errorf("no type: got %d flags, want 5", len(all))
	}

	cases := []struct {
		name string
		app  string
		opts flag.ListOpts
		want int64
	}{
		{"bool", "app1", flag.ListOpts{Type: flag.TypeBool}, 3},
		{"bool ignores paging", "app1", flag.ListOpts{Type: flag.TypeBool, Limit: 2, Offset: 10}, 3},
		{"string", "app1", flag.ListOpts{Type: flag.TypeString}, 1},
		{"json has none", "app1", flag.ListOpts{Type: flag.TypeJSON}, 0},
		{"no type", "app1", flag.ListOpts{}, 5},
		{"other app", "app2", flag.ListOpts{Type: flag.TypeBool}, 1},
	}
	for _, c := range cases {
		n, err := s.CountFlagDefinitionsMatching(ctx, c.app, c.opts)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if n != c.want {
			t.Errorf("%s: got %d, want %d", c.name, n, c.want)
		}
	}
}

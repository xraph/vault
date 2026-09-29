package sqlite_test

import (
	"testing"

	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/id"
	sqlitestore "github.com/xraph/vault/store/sqlite"
)

// seedTypedFlags defines five flags in app "app1" (keys a..e, defined out of
// key order) and one bool flag in another app.
func seedTypedFlags(t *testing.T, s *sqlitestore.Store) {
	t.Helper()
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
		if err := s.DefineFlag(bg(), &flag.Definition{
			ID: id.NewFlagID(), Key: d.key, Type: d.typ, AppID: d.app, Enabled: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func flagKeys(defs []*flag.Definition) []string {
	keys := make([]string, len(defs))
	for i, d := range defs {
		keys[i] = d.Key
	}
	return keys
}

func TestListFlagDefinitionsFiltersByType(t *testing.T) {
	s := testStore(t)
	seedTypedFlags(t, s)

	got, err := s.ListFlagDefinitions(bg(), "app1", flag.ListOpts{Type: flag.TypeBool, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if k := flagKeys(got); len(k) != 2 || k[0] != "a-bool" || k[1] != "d-bool" {
		t.Errorf("first bool page: got %v, want [a-bool d-bool]", k)
	}

	got, err = s.ListFlagDefinitions(bg(), "app1", flag.ListOpts{Type: flag.TypeBool, Limit: 2, Offset: 2})
	if err != nil {
		t.Fatal(err)
	}
	if k := flagKeys(got); len(k) != 1 || k[0] != "e-bool" {
		t.Errorf("second bool page: got %v, want [e-bool]", k)
	}

	all, err := s.ListFlagDefinitions(bg(), "app1", flag.ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 5 {
		t.Errorf("no type: got %d flags, want 5", len(all))
	}
}

func TestListFlagDefinitionsPastEndIsEmptyNotNil(t *testing.T) {
	s := testStore(t)
	seedTypedFlags(t, s)

	got, err := s.ListFlagDefinitions(bg(), "app1", flag.ListOpts{Type: flag.TypeBool, Limit: 2, Offset: 10})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || len(got) != 0 {
		t.Errorf("page past the end: got %#v, want a non-nil empty slice", got)
	}

	none, err := s.ListFlagDefinitions(bg(), "nobody", flag.ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if none == nil || len(none) != 0 {
		t.Errorf("empty app: got %#v, want a non-nil empty slice", none)
	}
}

func TestCountFlagDefinitionsMatching(t *testing.T) {
	s := testStore(t)
	seedTypedFlags(t, s)

	cases := []struct {
		name string
		app  string
		opts flag.ListOpts
		want int64
	}{
		{"bool", "app1", flag.ListOpts{Type: flag.TypeBool}, 3},
		{"bool ignores paging", "app1", flag.ListOpts{Type: flag.TypeBool, Limit: 2, Offset: 0}, 3},
		{"bool past the end", "app1", flag.ListOpts{Type: flag.TypeBool, Limit: 2, Offset: 10}, 3},
		{"string", "app1", flag.ListOpts{Type: flag.TypeString}, 1},
		{"json has none", "app1", flag.ListOpts{Type: flag.TypeJSON}, 0},
		{"no type", "app1", flag.ListOpts{}, 5},
		{"other app", "app2", flag.ListOpts{Type: flag.TypeBool}, 1},
		{"unknown app", "nobody", flag.ListOpts{}, 0},
	}
	for _, c := range cases {
		got, err := s.CountFlagDefinitionsMatching(bg(), c.app, c.opts)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

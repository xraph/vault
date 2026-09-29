package sqlite_test

import (
	"testing"
	"time"

	"github.com/xraph/vault/audit"
	"github.com/xraph/vault/id"
	sqlitestore "github.com/xraph/vault/store/sqlite"
)

// seedAuditRows records three rows for key "k" (two secret, one flag) and one
// row for another key, all in app "app1", newest last.
func seedAuditRows(t *testing.T, s *sqlitestore.Store) {
	t.Helper()
	base := time.Now().UTC()
	rows := []struct{ resource, key string }{
		{"secret", "k"},
		{"flag", "k"},
		{"secret", "k"},
		{"secret", "other"},
	}
	for i, r := range rows {
		if err := s.RecordAudit(bg(), &audit.Entry{
			ID:        id.NewAuditID(),
			Action:    "test",
			Resource:  r.resource,
			Key:       r.key,
			AppID:     "app1",
			Outcome:   "success",
			CreatedAt: base.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestListAuditByKeyFiltersByResource(t *testing.T) {
	s := testStore(t)
	seedAuditRows(t, s)

	got, err := s.ListAuditByKey(bg(), "k", "app1", audit.ListOpts{Resource: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("resource=secret: got %d rows, want 2", len(got))
	}
	for _, e := range got {
		if e.Resource != "secret" {
			t.Errorf("row has resource %q, want secret", e.Resource)
		}
	}

	all, err := s.ListAuditByKey(bg(), "k", "app1", audit.ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Errorf("no resource: got %d rows, want 3", len(all))
	}
}

func TestListAuditFiltersByResource(t *testing.T) {
	s := testStore(t)
	seedAuditRows(t, s)

	got, err := s.ListAudit(bg(), "app1", audit.ListOpts{Resource: "flag"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Resource != "flag" {
		t.Fatalf("resource=flag: got %d rows, want the one flag row", len(got))
	}

	all, err := s.ListAudit(bg(), "app1", audit.ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 4 {
		t.Errorf("no resource: got %d rows, want 4", len(all))
	}
}

// The resource filter runs before paging, so a page is a page of matches.
func TestListAuditResourceFilterComposesWithPaging(t *testing.T) {
	s := testStore(t)
	seedAuditRows(t, s)

	page, err := s.ListAudit(bg(), "app1", audit.ListOpts{Resource: "secret", Limit: 2, Offset: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 2 {
		t.Fatalf("got %d rows, want 2 (three secret rows, offset 1)", len(page))
	}
	for _, e := range page {
		if e.Resource != "secret" {
			t.Errorf("row has resource %q, want secret", e.Resource)
		}
	}
}

func TestCountAuditMatching(t *testing.T) {
	s := testStore(t)
	seedAuditRows(t, s)

	cases := []struct {
		name string
		app  string
		opts audit.ListOpts
		want int64
	}{
		{"flag", "app1", audit.ListOpts{Resource: "flag"}, 1},
		{"secret", "app1", audit.ListOpts{Resource: "secret"}, 3},
		{"every resource", "app1", audit.ListOpts{}, 4},
		{"paging is ignored", "app1", audit.ListOpts{Resource: "secret", Limit: 1, Offset: 2}, 3},
		{"another app", "app2", audit.ListOpts{Resource: "secret"}, 0},
	}
	for _, c := range cases {
		got, err := s.CountAuditMatching(bg(), c.app, c.opts)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

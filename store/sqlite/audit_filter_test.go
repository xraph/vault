package sqlite_test

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
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

// filterRow is one seeded row for the filter tests. off is seconds after the
// base time.
type filterRow struct {
	off                            int
	app, key, action, outcome, res string
}

// seedFilterRows records rows for app1 in shuffled insert order and returns
// them keyed by the label the tests use, plus the base time. Offsets 0..5 are
// distinct so "newest first" is unambiguous.
//
//	r0 k    secret.set    success  secret
//	r1 k    secret.get    success  secret
//	r2 k    secret.get    failure  secret
//	r3 j    flag.created  success  flag
//	r4 k    secret.set    failure  secret
//	r5 (app2, k, secret.set, failure) never counts for app1
func seedFilterRows(t *testing.T, s *sqlitestore.Store) (map[string]id.ID, time.Time) {
	t.Helper()
	base := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	rows := []filterRow{
		{0, "app1", "k", "secret.set", "success", "secret"},
		{1, "app1", "k", "secret.get", "success", "secret"},
		{2, "app1", "k", "secret.get", "failure", "secret"},
		{3, "app1", "j", "flag.created", "success", "flag"},
		{4, "app1", "k", "secret.set", "failure", "secret"},
		{5, "app2", "k", "secret.set", "failure", "secret"},
	}
	ids := map[string]id.ID{}
	// Insert in a scrambled order so a passing test cannot lean on insertion
	// order.
	for _, i := range []int{3, 0, 5, 4, 1, 2} {
		r := rows[i]
		e := &audit.Entry{
			ID: id.NewAuditID(), Action: r.action, Resource: r.res, Key: r.key,
			AppID: r.app, Outcome: r.outcome,
			CreatedAt: base.Add(time.Duration(r.off) * time.Second),
		}
		if err := s.RecordAudit(bg(), e); err != nil {
			t.Fatal(err)
		}
		ids[fmt.Sprintf("r%d", i)] = e.ID
	}
	return ids, base
}

// Every filter, alone and combined, must change the page and the total the
// same way: the total is exactly the rows the pages show.
func TestAuditFiltersChangePageAndTotalTogether(t *testing.T) {
	s := testStore(t)
	ids, base := seedFilterRows(t, s)

	cases := []struct {
		name string
		opts audit.ListOpts
		want []string // labels, newest first
	}{
		{"no filter", audit.ListOpts{}, []string{"r4", "r3", "r2", "r1", "r0"}},
		{"key", audit.ListOpts{Key: "k"}, []string{"r4", "r2", "r1", "r0"}},
		{"key with no rows", audit.ListOpts{Key: "nope"}, nil},
		{"action", audit.ListOpts{Action: "secret.set"}, []string{"r4", "r0"}},
		{"outcome", audit.ListOpts{Outcome: "failure"}, []string{"r4", "r2"}},
		{"since is inclusive", audit.ListOpts{Since: base.Add(2 * time.Second)}, []string{"r4", "r3", "r2"}},
		{"since after everything", audit.ListOpts{Since: base.Add(time.Hour)}, nil},
		{"exclude one action", audit.ListOpts{ExcludeActions: []string{"secret.get"}}, []string{"r4", "r3", "r0"}},
		{"exclude two actions", audit.ListOpts{ExcludeActions: []string{"secret.get", "flag.created"}}, []string{"r4", "r0"}},
		{"key and outcome", audit.ListOpts{Key: "k", Outcome: "failure"}, []string{"r4", "r2"}},
		{"key, action and outcome", audit.ListOpts{Key: "k", Action: "secret.set", Outcome: "failure"}, []string{"r4"}},
		{"resource and exclude", audit.ListOpts{Resource: "secret", ExcludeActions: []string{"secret.get"}}, []string{"r4", "r0"}},
		{"since and exclude", audit.ListOpts{Since: base.Add(1 * time.Second), ExcludeActions: []string{"secret.get"}}, []string{"r4", "r3"}},
		{"action wins over exclude", audit.ListOpts{Action: "secret.get", ExcludeActions: []string{"secret.get"}}, nil},
	}
	for _, c := range cases {
		opts := c.opts
		opts.Limit = 100
		got, err := s.ListAudit(bg(), "app1", opts)
		if err != nil {
			t.Fatalf("%s: list: %v", c.name, err)
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: page has %d rows, want %d", c.name, len(got), len(c.want))
			continue
		}
		for i, label := range c.want {
			if got[i].ID != ids[label] {
				t.Errorf("%s: row %d is not %s", c.name, i, label)
			}
		}
		n, err := s.CountAuditMatching(bg(), "app1", c.opts)
		if err != nil {
			t.Fatalf("%s: count: %v", c.name, err)
		}
		if n != int64(len(c.want)) {
			t.Errorf("%s: total %d, page %d: they must agree", c.name, n, len(c.want))
		}
	}
}

// ListAuditByKey keeps working and honours the new fields.
func TestListAuditByKeyHonoursTheNewFilters(t *testing.T) {
	s := testStore(t)
	ids, base := seedFilterRows(t, s)

	got, err := s.ListAuditByKey(bg(), "k", "app1", audit.ListOpts{
		Outcome: "failure", ExcludeActions: []string{"secret.get"}, Since: base, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != ids["r4"] {
		t.Fatalf("got %d rows, want only r4", len(got))
	}

	got, err = s.ListAuditByKey(bg(), "k", "app1", audit.ListOpts{Action: "secret.get", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != ids["r2"] || got[1].ID != ids["r1"] {
		t.Fatalf("action=secret.get by key: got %d rows, want r2 then r1", len(got))
	}
}

// Rows that share a created_at must page without repeats or gaps, in id
// descending order, whatever order they went in.
func TestAuditPagingIsStableAcrossTiedTimestamps(t *testing.T) {
	s := testStore(t)
	at := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	all := make([]string, 0, 30)
	entries := make([]*audit.Entry, 0, 30)
	for range 30 {
		e := &audit.Entry{
			ID: id.NewAuditID(), Action: "secret.set", Resource: "secret", Key: "k",
			AppID: "app1", Outcome: "success", CreatedAt: at,
		}
		all = append(all, e.ID.String())
		entries = append(entries, e)
	}
	// Ids are minted in increasing order, so insert them scrambled: a store
	// that leans on insertion order for ties then comes out wrong.
	rand.New(rand.NewPCG(1, 2)).Shuffle(len(entries), func(i, j int) { entries[i], entries[j] = entries[j], entries[i] })
	for _, e := range entries {
		if err := s.RecordAudit(bg(), e); err != nil {
			t.Fatal(err)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(all)))

	var got []string
	for off := 0; ; off += 7 {
		page, err := s.ListAudit(bg(), "app1", audit.ListOpts{Limit: 7, Offset: off})
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		for _, e := range page {
			got = append(got, e.ID.String())
		}
	}
	if !slices.Equal(got, all) {
		t.Fatalf("paged ids differ from id-descending order\n got: %v\nwant: %v", got, all)
	}

	// The same holds when a key is asked for.
	byKey, err := s.ListAuditByKey(bg(), "k", "app1", audit.ListOpts{Limit: 7, Offset: 7})
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range byKey {
		if e.ID.String() != all[7+i] {
			t.Fatalf("ListAuditByKey page 2 row %d out of order", i)
		}
	}
}

// Empty-string filters mean "no filter", including an empty exclusion list.
func TestAuditEmptyFiltersMeanNoFilter(t *testing.T) {
	s := testStore(t)
	seedFilterRows(t, s)
	n, err := s.CountAuditMatching(bg(), "app1", audit.ListOpts{ExcludeActions: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Errorf("got %d, want 5", n)
	}
}

// Since compares instants, not whole seconds: a bound with a fraction keeps
// the rows at or after that instant and drops the ones just before it, and a
// bound in another zone means the same instant.
func TestAuditSinceHandlesSubSecondAndZones(t *testing.T) {
	s := testStore(t)
	base := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	offsets := []time.Duration{0, 400 * time.Millisecond, 500 * time.Millisecond, 600 * time.Millisecond, time.Second}
	for _, d := range offsets {
		if err := s.RecordAudit(bg(), &audit.Entry{
			ID: id.NewAuditID(), Action: "a", Resource: "secret", Key: "k",
			AppID: "app1", Outcome: "success", CreatedAt: base.Add(d),
		}); err != nil {
			t.Fatal(err)
		}
	}
	zone := time.FixedZone("plus2", 2*60*60)
	cases := []struct {
		since time.Time
		want  int64
	}{
		{base.Add(500 * time.Millisecond), 3},
		{base.Add(500*time.Millisecond + time.Microsecond), 2},
		{base.Add(500 * time.Millisecond).In(zone), 3},
		{base, 5},
		{base.Add(time.Second), 1},
	}
	for _, c := range cases {
		n, err := s.CountAuditMatching(bg(), "app1", audit.ListOpts{Since: c.since})
		if err != nil {
			t.Fatal(err)
		}
		rows, err := s.ListAudit(bg(), "app1", audit.ListOpts{Since: c.since, Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if n != c.want || int64(len(rows)) != c.want {
			t.Errorf("since %s: count %d, page %d, want %d", c.since.Format(time.RFC3339Nano), n, len(rows), c.want)
		}
	}
}

// ListAuditByKey takes its key from the argument; opts.Key does not narrow it
// further or contradict it.
func TestListAuditByKeyIgnoresOptsKey(t *testing.T) {
	s := testStore(t)
	seedFilterRows(t, s)
	got, err := s.ListAuditByKey(bg(), "k", "app1", audit.ListOpts{Key: "j", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d rows, want the 4 rows for key k", len(got))
	}
}

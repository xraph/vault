//go:build integration

package postgres_test

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/xraph/vault/audit"
	"github.com/xraph/vault/id"
	pgstore "github.com/xraph/vault/store/postgres"
)

func TestAuditResourceFilter(t *testing.T) {
	s := testStore(t)
	ctx := t.Context()
	base := time.Now().UTC()
	rows := []struct{ resource, key string }{
		{"secret", "k"},
		{"flag", "k"},
		{"secret", "k"},
		{"secret", "other"},
	}
	for i, r := range rows {
		if err := s.RecordAudit(ctx, &audit.Entry{
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

	byKey, err := s.ListAuditByKey(ctx, "k", "app1", audit.ListOpts{Resource: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if len(byKey) != 2 {
		t.Errorf("ListAuditByKey resource=secret: got %d, want 2", len(byKey))
	}
	all, err := s.ListAuditByKey(ctx, "k", "app1", audit.ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Errorf("ListAuditByKey no resource: got %d, want 3", len(all))
	}
	flags, err := s.ListAudit(ctx, "app1", audit.ListOpts{Resource: "flag"})
	if err != nil {
		t.Fatal(err)
	}
	if len(flags) != 1 {
		t.Errorf("ListAudit resource=flag: got %d, want 1", len(flags))
	}
	n, err := s.CountAuditMatching(ctx, "app1", audit.ListOpts{Resource: "secret", Limit: 1, Offset: 1})
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("CountAuditMatching resource=secret: got %d, want 3", n)
	}
	n, err = s.CountAuditMatching(ctx, "app1", audit.ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Errorf("CountAuditMatching no resource: got %d, want 4", n)
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
func seedFilterRows(t *testing.T, s *pgstore.Store) (map[string]id.ID, time.Time) {
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
		if err := s.RecordAudit(t.Context(), e); err != nil {
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
		got, err := s.ListAudit(t.Context(), "app1", opts)
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
		n, err := s.CountAuditMatching(t.Context(), "app1", c.opts)
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

	got, err := s.ListAuditByKey(t.Context(), "k", "app1", audit.ListOpts{
		Outcome: "failure", ExcludeActions: []string{"secret.get"}, Since: base, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != ids["r4"] {
		t.Fatalf("got %d rows, want only r4", len(got))
	}

	got, err = s.ListAuditByKey(t.Context(), "k", "app1", audit.ListOpts{Action: "secret.get", Limit: 10})
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
		if err := s.RecordAudit(t.Context(), e); err != nil {
			t.Fatal(err)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(all)))

	var got []string
	for off := 0; ; off += 7 {
		page, err := s.ListAudit(t.Context(), "app1", audit.ListOpts{Limit: 7, Offset: off})
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
	byKey, err := s.ListAuditByKey(t.Context(), "k", "app1", audit.ListOpts{Limit: 7, Offset: 7})
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
	n, err := s.CountAuditMatching(t.Context(), "app1", audit.ListOpts{ExcludeActions: []string{}})
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
		if err := s.RecordAudit(t.Context(), &audit.Entry{
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
		n, err := s.CountAuditMatching(t.Context(), "app1", audit.ListOpts{Since: c.since})
		if err != nil {
			t.Fatal(err)
		}
		rows, err := s.ListAudit(t.Context(), "app1", audit.ListOpts{Since: c.since, Limit: 10})
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
	got, err := s.ListAuditByKey(t.Context(), "k", "app1", audit.ListOpts{Key: "j", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d rows, want the 4 rows for key k", len(got))
	}
}

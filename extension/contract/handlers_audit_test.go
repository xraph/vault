package contract

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/vault"
	"github.com/xraph/vault/audit"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/store/memory"
)

// auditSeed is one audit row to write straight to the store, so a test
// controls its time, user and metadata.
type auditSeed struct {
	action   string
	resource string
	key      string
	outcome  string
	tenant   string
	user     string
	errText  string
	age      time.Duration // how long before the seed's base time
}

var auditBase = time.Now().UTC().Truncate(time.Second)

func seedAuditRows(t *testing.T, v *vault.Vault, rows []auditSeed) {
	t.Helper()
	for _, r := range rows {
		if r.outcome == "" {
			r.outcome = "success"
		}
		e := &audit.Entry{
			ID: id.NewAuditID(), Action: r.action, Resource: r.resource, Key: r.key,
			AppID: testAppID, TenantID: r.tenant, UserID: r.user, Outcome: r.outcome,
			CreatedAt: auditBase.Add(-r.age),
		}
		if r.errText != "" {
			e.Metadata = map[string]any{"error": r.errText}
		}
		if err := v.Store().RecordAudit(context.Background(), e); err != nil {
			t.Fatalf("seed audit %s/%s: %v", r.action, r.key, err)
		}
	}
}

// label names a projected row by its action and key.
func label(e AuditSummary) string { return e.Action + "/" + e.Key }

func labels(es []AuditSummary) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, label(e))
	}
	return out
}

// seedMixedAudit writes rows newest first by age:
//
//	secret.get      s1  success   1m   (a read)
//	secret.set      s1  success   2m   user u1
//	secret.rotated  s1  failure   3m   error text, no user
//	secret.set      s2  success   4m   tenant t1
//	flag.created    f1  success   5m
//	config.set      c1  success   48h
func seedMixedAudit(t *testing.T, v *vault.Vault) {
	t.Helper()
	seedAuditRows(t, v, []auditSeed{
		{action: "secret.get", resource: "secret", key: "s1", age: time.Minute},
		{action: "secret.set", resource: "secret", key: "s1", user: "u1", age: 2 * time.Minute},
		{action: "secret.rotated", resource: "secret", key: "s1", outcome: "failure", errText: "rotator exploded", age: 3 * time.Minute},
		{action: "secret.set", resource: "secret", key: "s2", tenant: "t1", age: 4 * time.Minute},
		{action: "flag.created", resource: "flag", key: "f1", age: 5 * time.Minute},
		{action: "config.set", resource: "config", key: "c1", age: 48 * time.Hour},
	})
}

// Every filter changes both the page and the total, and the total counts
// exactly the rows the pages show.
func TestAuditList_FiltersReachTheStoreAndTheTotalMatches(t *testing.T) {
	v, _ := newTestVault(t)
	seedMixedAudit(t, v)
	handler := auditListHandler(Deps{Vault: v})
	ctx := context.Background()
	since := auditBase.Add(-time.Hour).Format(time.RFC3339)

	tests := []struct {
		name string
		in   auditListRequest
		want []string
	}{
		{"default hides reads", auditListRequest{},
			[]string{"secret.set/s1", "secret.rotated/s1", "secret.set/s2", "flag.created/f1", "config.set/c1"}},
		{"includeReads shows them", auditListRequest{IncludeReads: true},
			[]string{"secret.get/s1", "secret.set/s1", "secret.rotated/s1", "secret.set/s2", "flag.created/f1", "config.set/c1"}},
		{"resource", auditListRequest{Resource: "secret"},
			[]string{"secret.set/s1", "secret.rotated/s1", "secret.set/s2"}},
		{"resource with reads", auditListRequest{Resource: "secret", IncludeReads: true},
			[]string{"secret.get/s1", "secret.set/s1", "secret.rotated/s1", "secret.set/s2"}},
		{"key", auditListRequest{Key: "s1"}, []string{"secret.set/s1", "secret.rotated/s1"}},
		{"key with reads", auditListRequest{Key: "s1", IncludeReads: true},
			[]string{"secret.get/s1", "secret.set/s1", "secret.rotated/s1"}},
		{"action", auditListRequest{Action: "secret.set"}, []string{"secret.set/s1", "secret.set/s2"}},
		{"action secret.get without includeReads is empty", auditListRequest{Action: "secret.get"}, nil},
		{"action secret.get with includeReads", auditListRequest{Action: "secret.get", IncludeReads: true}, []string{"secret.get/s1"}},
		{"outcome failure", auditListRequest{Outcome: "failure"}, []string{"secret.rotated/s1"}},
		{"outcome success", auditListRequest{Outcome: "success"},
			[]string{"secret.set/s1", "secret.set/s2", "flag.created/f1", "config.set/c1"}},
		{"since", auditListRequest{Since: since},
			[]string{"secret.set/s1", "secret.rotated/s1", "secret.set/s2", "flag.created/f1"}},
		{"since as a non-UTC RFC3339", auditListRequest{Since: auditBase.Add(-time.Hour).In(time.FixedZone("x", 5*3600)).Format(time.RFC3339)},
			[]string{"secret.set/s1", "secret.rotated/s1", "secret.set/s2", "flag.created/f1"}},
		{"combined", auditListRequest{Resource: "secret", Outcome: "success", Since: since}, []string{"secret.set/s1", "secret.set/s2"}},
		{"no match", auditListRequest{Key: "nope"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := handler(ctx, tt.in, dashcontract.Principal{})
			if err != nil {
				t.Fatal(err)
			}
			got := labels(out.Entries)
			if !reflect.DeepEqual(got, append([]string{}, tt.want...)) {
				t.Errorf("entries = %v, want %v", got, tt.want)
			}
			if out.Total != int64(len(tt.want)) {
				t.Errorf("total = %d, want %d", out.Total, len(tt.want))
			}
			if out.Entries == nil {
				t.Error("entries is nil, want an empty slice")
			}
		})
	}
}

// A page is a slice of the filtered list and the total does not move.
func TestAuditList_PagingKeepsTheFilteredTotal(t *testing.T) {
	v, _ := newTestVault(t)
	seedMixedAudit(t, v)
	handler := auditListHandler(Deps{Vault: v})
	ctx := context.Background()

	p1, err := handler(ctx, auditListRequest{Limit: 2, Offset: 0}, dashcontract.Principal{})
	if err != nil {
		t.Fatal(err)
	}
	p2, err := handler(ctx, auditListRequest{Limit: 2, Offset: 2}, dashcontract.Principal{})
	if err != nil {
		t.Fatal(err)
	}
	p3, err := handler(ctx, auditListRequest{Limit: 2, Offset: 4}, dashcontract.Principal{})
	if err != nil {
		t.Fatal(err)
	}
	all := make([]string, 0, 5)
	for _, p := range []auditListResponse{p1, p2, p3} {
		if p.Total != 5 {
			t.Errorf("total = %d, want 5 on every page", p.Total)
		}
		all = append(all, labels(p.Entries)...)
	}
	want := []string{"secret.set/s1", "secret.rotated/s1", "secret.set/s2", "flag.created/f1", "config.set/c1"}
	if !reflect.DeepEqual(all, want) {
		t.Errorf("pages joined = %v, want %v", all, want)
	}
	if len(p3.Entries) != 1 {
		t.Errorf("last page len = %d, want 1", len(p3.Entries))
	}
}

func TestAuditList_LimitDefaultsAndCaps(t *testing.T) {
	v, _ := newTestVault(t)
	var rows []auditSeed
	for i := 0; i < 130; i++ {
		rows = append(rows, auditSeed{action: "config.set", resource: "config", key: fmt.Sprintf("c%03d", i), age: time.Duration(i) * time.Second})
	}
	seedAuditRows(t, v, rows)
	handler := auditListHandler(Deps{Vault: v})
	ctx := context.Background()

	for _, tt := range []struct{ limit, want int }{{0, 25}, {-3, 25}, {7, 7}, {100, 100}, {1000, 100}} {
		out, err := handler(ctx, auditListRequest{Limit: tt.limit}, dashcontract.Principal{})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Entries) != tt.want || out.Total != 130 {
			t.Errorf("limit %d: %d entries, total %d; want %d entries, total 130", tt.limit, len(out.Entries), out.Total, tt.want)
		}
	}
	out, err := handler(ctx, auditListRequest{Offset: -5}, dashcontract.Principal{})
	if err != nil || len(out.Entries) != 25 || out.Entries[0].Key != "c000" {
		t.Errorf("negative offset: %d entries, first %v, err %v", len(out.Entries), out.Entries, err)
	}
}

func TestAuditList_RefusesABadOutcomeOrSince(t *testing.T) {
	v, _ := newTestVault(t)
	handler := auditListHandler(Deps{Vault: v})
	ctx := context.Background()
	for name, in := range map[string]auditListRequest{
		"unknown outcome": {Outcome: "denied"},
		"wrong case":      {Outcome: "Failure"},
		"bad since":       {Since: "yesterday"},
		"date only":       {Since: "2026-09-30"},
	} {
		_, err := handler(ctx, in, dashcontract.Principal{})
		if codeOf(err) != dashcontract.CodeBadRequest {
			t.Errorf("%s: code = %q (%v), want BAD_REQUEST", name, codeOf(err), err)
		}
	}
	// Blank filters mean no filter.
	if _, err := handler(ctx, auditListRequest{Outcome: " ", Since: " ", Resource: " ", Key: " ", Action: " "}, dashcontract.Principal{}); err != nil {
		t.Errorf("blank filters: %v", err)
	}
}

// Rows of another app never appear, in the page or the total.
func TestAuditList_OtherAppsRowsAreInvisible(t *testing.T) {
	v, _ := newTestVault(t)
	seedMixedAudit(t, v)
	other := &audit.Entry{ID: id.NewAuditID(), Action: "secret.set", Resource: "secret", Key: "foreign", AppID: "other-app", Outcome: "success", CreatedAt: auditBase}
	if err := v.Store().RecordAudit(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	out, err := auditListHandler(Deps{Vault: v})(context.Background(), auditListRequest{IncludeReads: true}, dashcontract.Principal{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Total != 6 || len(out.Entries) != 6 {
		t.Errorf("total %d entries %d, want 6 and 6", out.Total, len(out.Entries))
	}
}

// The wire row carries the tenant, the user and the failure's error, and
// omits each when there is none.
func TestAuditList_ProjectsTenantUserAndError(t *testing.T) {
	v, _ := newTestVault(t)
	seedMixedAudit(t, v)
	out, err := auditListHandler(Deps{Vault: v})(context.Background(), auditListRequest{}, dashcontract.Principal{})
	if err != nil {
		t.Fatal(err)
	}
	byLabel := map[string]AuditSummary{}
	for _, e := range out.Entries {
		byLabel[label(e)] = e
	}
	if e := byLabel["secret.set/s1"]; e.UserID != "u1" || e.TenantID != "" || e.Error != "" || e.Resource != "secret" || e.Key != "s1" {
		t.Errorf("secret.set/s1 = %+v", e)
	}
	if e := byLabel["secret.rotated/s1"]; e.Outcome != "failure" || e.Error != "rotator exploded" || e.UserID != "" {
		t.Errorf("secret.rotated/s1 = %+v", e)
	}
	if e := byLabel["secret.set/s2"]; e.TenantID != "t1" {
		t.Errorf("secret.set/s2 = %+v", e)
	}

	raw, err := json.Marshal(byLabel["flag.created/f1"])
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tenantId", "userId", "error"} {
		if strings.Contains(string(raw), `"`+name+`"`) {
			t.Errorf("a row with no %s still carries it on the wire: %s", name, raw)
		}
	}
	raw, _ = json.Marshal(byLabel["secret.rotated/s1"])
	if !strings.Contains(string(raw), `"error":"rotator exploded"`) {
		t.Errorf("failure row wire = %s", raw)
	}
}

// Only a failure row shows an error, even if a success row carries an
// "error" key in its metadata.
func TestProjectAuditSummary_ErrorOnlyOnFailure(t *testing.T) {
	e := &audit.Entry{ID: id.NewAuditID(), Outcome: "success", Metadata: map[string]any{"error": "stale"}, CreatedAt: auditBase}
	if got := projectAuditSummary(e).Error; got != "" {
		t.Errorf("success row error = %q, want none", got)
	}
	e.Outcome = "failure"
	e.Metadata = map[string]any{"error": 42}
	if got := projectAuditSummary(e).Error; got != "" {
		t.Errorf("non-string error = %q, want none", got)
	}
	e.Metadata = nil
	if got := projectAuditSummary(e).Error; got != "" {
		t.Errorf("no metadata error = %q, want none", got)
	}
}

var errStoreBoom = errors.New("store exploded")

func TestAuditList_AStoreErrorIsAnError(t *testing.T) {
	for _, fail := range []string{"ListAudit", "CountAuditMatching"} {
		v, err := vault.New(vault.WithStore(failingStore{Store: memory.New(), fail: fail}), vault.WithAppID(testAppID), vault.WithEncryptionKey(testEncryptionKey))
		if err != nil {
			t.Fatal(err)
		}
		_, err = auditListHandler(Deps{Vault: v})(context.Background(), auditListRequest{}, dashcontract.Principal{})
		if codeOf(err) != dashcontract.CodeInternal {
			t.Errorf("%s failing: code = %q (%v), want INTERNAL", fail, codeOf(err), err)
		}
	}
}

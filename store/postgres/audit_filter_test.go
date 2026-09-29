//go:build integration

package postgres_test

import (
	"testing"
	"time"

	"github.com/xraph/vault/audit"
	"github.com/xraph/vault/id"
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

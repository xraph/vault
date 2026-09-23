package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/vault/audit"
	"github.com/xraph/vault/config"
	"github.com/xraph/vault/core"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/override"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/secret"
)

func bg() context.Context { return context.Background() }

// An app with nothing in it counts zero and does not error. Every list
// handler calls these for its caption, so an error here would break a page
// that is merely empty.
func TestCountsAreZeroForAnEmptyApp(t *testing.T) {
	s := testStore(t)
	checks := map[string]func() (int64, error){
		"secrets":   func() (int64, error) { return s.CountSecrets(bg(), "nobody") },
		"flags":     func() (int64, error) { return s.CountFlagDefinitions(bg(), "nobody") },
		"config":    func() (int64, error) { return s.CountConfig(bg(), "nobody") },
		"overrides": func() (int64, error) { return s.CountOverrides(bg(), "nobody") },
		"rotation":  func() (int64, error) { return s.CountRotationPolicies(bg(), "nobody") },
		"audit":     func() (int64, error) { return s.CountAudit(bg(), "nobody") },
	}
	for name, fn := range checks {
		got, err := fn()
		if err != nil {
			t.Errorf("%s: unexpected error %v", name, err)
		}
		if got != 0 {
			t.Errorf("%s: got %d, want 0", name, got)
		}
	}
}

// Counts are per app and must not leak rows from another one.
func TestCountsAreScopedToTheApp(t *testing.T) {
	s := testStore(t)
	for _, app := range []string{"a", "a", "b"} {
		if err := s.SetSecret(bg(), &secret.Secret{
			Entity: core.NewEntity(), ID: id.NewSecretID(),
			Key: app + "-" + id.NewSecretID().String(), AppID: app,
			EncryptedValue: []byte("x"),
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.CountSecrets(bg(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if got != 2 {
		t.Errorf("app a: got %d, want 2", got)
	}
	got, err = s.CountSecrets(bg(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Errorf("app b: got %d, want 1", got)
	}
}

// Per-app scoping with identity assertion: list the rows and verify every
// returned row's AppID matches the app we queried.
func TestCountSecretsPerAppWithIdentityAssertion(t *testing.T) {
	s := testStore(t)
	for _, app := range []string{"a", "a", "b"} {
		if err := s.SetSecret(bg(), &secret.Secret{
			Entity: core.NewEntity(), ID: id.NewSecretID(),
			Key: app + "-" + id.NewSecretID().String(), AppID: app,
			EncryptedValue: []byte("x"),
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Assert count for app "a".
	count, err := s.CountSecrets(bg(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("count for app a: got %d, want 2", count)
	}
	// Assert identity: every listed row has AppID="a".
	list, err := s.ListSecrets(bg(), "a", secret.ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != int(count) {
		t.Errorf("list length %d does not match count %d", len(list), count)
	}
	for _, m := range list {
		if m.AppID != "a" {
			t.Errorf("listed row has AppID %q, want %q", m.AppID, "a")
		}
	}
}

// Per-app scoping for flags with identity assertion.
func TestCountFlagsPerAppWithIdentityAssertion(t *testing.T) {
	s := testStore(t)
	for _, app := range []string{"a", "a", "b"} {
		if err := s.DefineFlag(bg(), &flag.Definition{
			Entity: core.NewEntity(), ID: id.NewFlagID(),
			Key: app + "-" + id.NewFlagID().String(), Type: flag.TypeBool, AppID: app,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Assert count for app "a".
	count, err := s.CountFlagDefinitions(bg(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("count for app a: got %d, want 2", count)
	}
	// Assert identity: every listed row has AppID="a".
	list, err := s.ListFlagDefinitions(bg(), "a", flag.ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != int(count) {
		t.Errorf("list length %d does not match count %d", len(list), count)
	}
	for _, m := range list {
		if m.AppID != "a" {
			t.Errorf("listed row has AppID %q, want %q", m.AppID, "a")
		}
	}
}

// An empty appID must match only rows whose app_id is literally empty, never
// every row. This is pinned rather than assumed: if a backend ever answers a
// blank scope with the whole table, a list handler that fails to resolve a
// tenant would hand one caller every tenant's secrets. Assert on identity,
// because a count assertion passes when the wrong rows arrive in the right
// quantity.
func TestEmptyAppIDMatchesOnlyEmptyScopedRows(t *testing.T) {
	s := testStore(t)
	for _, app := range []string{"a", "b"} {
		if err := s.SetSecret(bg(), &secret.Secret{
			Entity: core.NewEntity(), ID: id.NewSecretID(),
			Key: "k-" + app, AppID: app, EncryptedValue: []byte("x"),
		}); err != nil {
			t.Fatal(err)
		}
	}

	n, err := s.CountSecrets(bg(), "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("empty appID counted %d rows, want 0; a blank scope must not match every row", n)
	}

	list, err := s.ListSecrets(bg(), "", secret.ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range list {
		if m.AppID != "" {
			t.Errorf("empty appID returned a row scoped to %q", m.AppID)
		}
	}
}

// A count is the whole set, not one page. Paging must not change it, or the
// caption would report the page size forever.
func TestCountIgnoresPagingSecrets(t *testing.T) {
	s := testStore(t)
	for i := 0; i < 5; i++ {
		if err := s.SetSecret(bg(), &secret.Secret{
			Entity: core.NewEntity(), ID: id.NewSecretID(),
			Key: id.NewSecretID().String(), AppID: "a",
			EncryptedValue: []byte("x"),
		}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.ListSecrets(bg(), "a", secret.ListOpts{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 2 {
		t.Fatalf("page: got %d, want 2", len(page))
	}
	count, err := s.CountSecrets(bg(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if count != 5 {
		t.Errorf("count: got %d, want 5", count)
	}
}

// Count ignores paging for flags.
func TestCountIgnoresPagingFlags(t *testing.T) {
	s := testStore(t)
	for i := 0; i < 5; i++ {
		if err := s.DefineFlag(bg(), &flag.Definition{
			Entity: core.NewEntity(), ID: id.NewFlagID(),
			Key: id.NewFlagID().String(), Type: flag.TypeBool, AppID: "a",
		}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.ListFlagDefinitions(bg(), "a", flag.ListOpts{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 2 {
		t.Fatalf("page: got %d, want 2", len(page))
	}
	count, err := s.CountFlagDefinitions(bg(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if count != 5 {
		t.Errorf("count: got %d, want 5", count)
	}
}

// Config counts are scoped per app.
func TestCountConfigPerApp(t *testing.T) {
	s := testStore(t)
	for _, app := range []string{"a", "a", "b"} {
		if err := s.SetConfig(bg(), &config.Entry{
			Entity: core.NewEntity(), ID: id.NewConfigID(),
			Key: app + "-" + id.NewConfigID().String(), Value: 1,
			AppID: app,
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.CountConfig(bg(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if got != 2 {
		t.Errorf("app a: got %d, want 2", got)
	}
	got, err = s.CountConfig(bg(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Errorf("app b: got %d, want 1", got)
	}
}

// Override counts are scoped per app.
func TestCountOverridesPerApp(t *testing.T) {
	s := testStore(t)
	for _, app := range []string{"a", "a", "b"} {
		if err := s.SetOverride(bg(), &override.Override{
			Entity: core.NewEntity(), ID: id.NewOverrideID(),
			Key: app + "-" + id.NewOverrideID().String(), Value: 1,
			AppID: app, TenantID: "t1",
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.CountOverrides(bg(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if got != 2 {
		t.Errorf("app a: got %d, want 2", got)
	}
	got, err = s.CountOverrides(bg(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Errorf("app b: got %d, want 1", got)
	}
}

// Rotation policy counts are scoped per app.
func TestCountRotationPoliciesPerApp(t *testing.T) {
	s := testStore(t)
	for _, app := range []string{"a", "a", "b"} {
		if err := s.SaveRotationPolicy(bg(), &rotation.Policy{
			Entity: core.NewEntity(), ID: id.NewRotationID(),
			SecretKey: app + "-" + id.NewRotationID().String(),
			AppID:     app, Interval: time.Hour,
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.CountRotationPolicies(bg(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if got != 2 {
		t.Errorf("app a: got %d, want 2", got)
	}
	got, err = s.CountRotationPolicies(bg(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Errorf("app b: got %d, want 1", got)
	}
}

// Audit counts are scoped per app.
func TestCountAuditPerApp(t *testing.T) {
	s := testStore(t)
	now := time.Now().UTC()
	for i, app := range []string{"a", "a", "b"} {
		if err := s.RecordAudit(bg(), &audit.Entry{
			ID:        id.NewAuditID(),
			Action:    "test",
			Resource:  "test",
			Key:       app + "-key",
			AppID:     app,
			Outcome:   "success",
			CreatedAt: now.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.CountAudit(bg(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if got != 2 {
		t.Errorf("app a: got %d, want 2", got)
	}
	got, err = s.CountAudit(bg(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Errorf("app b: got %d, want 1", got)
	}
}

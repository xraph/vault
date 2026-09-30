package memory_test

import (
	"testing"

	"github.com/xraph/vault/core"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/secret"
	"github.com/xraph/vault/store/memory"
)

// store_test.go in this package already declares bg(); reuse it rather than
// adding a second context helper to the same package.

// An app with nothing in it counts zero and does not error. Every list
// handler calls these for its caption, so an error here would break a page
// that is merely empty.
func TestCountsAreZeroForAnEmptyApp(t *testing.T) {
	s := memory.New()
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
	s := memory.New()
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

// An empty appID must match only rows whose app_id is literally empty, never
// every row. This is pinned rather than assumed: if a backend ever answers a
// blank scope with the whole table, a list handler that fails to resolve a
// tenant would hand one caller every tenant's secrets. Assert on identity,
// because a count assertion passes when the wrong rows arrive in the right
// quantity.
func TestEmptyAppIDMatchesOnlyEmptyScopedRows(t *testing.T) {
	s := memory.New()
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
func TestCountIgnoresPaging(t *testing.T) {
	s := memory.New()
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

// CountSecretsUnencrypted counts the rows stored without an encryption
// algorithm, per app, and follows a secret when it is rewritten encrypted.
func TestCountSecretsUnencrypted(t *testing.T) {
	s := memory.New()
	put := func(app, key, alg string) {
		t.Helper()
		if err := s.SetSecret(bg(), &secret.Secret{
			Entity: core.NewEntity(), ID: id.NewSecretID(),
			Key: key, AppID: app, EncryptedValue: []byte("x"), EncryptionAlg: alg,
		}); err != nil {
			t.Fatal(err)
		}
	}
	count := func(app string, want int64) {
		t.Helper()
		got, err := s.CountSecretsUnencrypted(bg(), app)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("app %s: got %d, want %d", app, got, want)
		}
	}

	count("a", 0)
	put("a", "plain-1", "")
	put("a", "plain-2", "")
	put("a", "sealed", "AES-256-GCM")
	put("b", "other-plain", "")
	count("a", 2)
	count("b", 1)
	count("nobody", 0)

	// Rewriting a plain secret with an algorithm takes it out of the count.
	put("a", "plain-1", "AES-256-GCM")
	count("a", 1)
}

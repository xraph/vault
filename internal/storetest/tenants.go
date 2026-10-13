package storetest

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/xraph/vault/core"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/secret"
)

// TenantFactory returns a fresh, empty secret store.
type TenantFactory func(t *testing.T) secret.Store

// tenantApp is the app every tenant isolation case writes under.
const tenantApp = "app"

// tenantKey is the key the app and both tenants each hold a secret under.
const tenantKey = "db-password"

// tenants are the scopes the isolation cases write under: the app itself
// ("") and two tenants.
var tenants = []string{"", "t1", "t2"}

// tenantName names a tenant for a failure message.
func tenantName(tenantID string) string {
	if tenantID == "" {
		return "app-level"
	}
	return "tenant " + tenantID
}

// putTenant stores value under key for tenantID and returns the version the
// store gave it.
func putTenant(t *testing.T, s secret.Store, tenantID, key, value string, at *time.Time) int64 {
	t.Helper()
	sec := &secret.Secret{
		Entity: core.NewEntity(), ID: id.NewSecretID(),
		Key: key, AppID: tenantApp, TenantID: tenantID,
		EncryptedValue: []byte(value), ExpiresAt: at,
	}
	if err := s.SetSecret(t.Context(), sec); err != nil {
		t.Fatalf("SetSecret(%s, %s): %v", key, tenantName(tenantID), err)
	}
	return sec.Version
}

// wantSecret fails unless tenantID's secret under key holds value at version.
func wantSecret(t *testing.T, s secret.Store, tenantID, key, value string, version int64) {
	t.Helper()
	got, err := s.GetSecret(t.Context(), key, tenantApp, tenantID)
	if err != nil {
		t.Fatalf("GetSecret(%s, %s): %v", key, tenantName(tenantID), err)
	}
	if string(got.EncryptedValue) != value || got.Version != version || got.TenantID != tenantID {
		t.Errorf("GetSecret(%s, %s) = %q v%d tenant %q, want %q v%d tenant %q",
			key, tenantName(tenantID), got.EncryptedValue, got.Version, got.TenantID, value, version, tenantID)
	}
}

// wantNotFound fails unless err is core.ErrSecretNotFound.
func wantNotFound(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, core.ErrSecretNotFound) {
		t.Errorf("%s: got %v, want ErrSecretNotFound", what, err)
	}
}

// versionValues returns tenantID's version values for tenantKey, oldest
// first, and fails if any version row names another tenant.
func versionValues(t *testing.T, s secret.Store, tenantID string) []string {
	t.Helper()
	vs, err := s.ListSecretVersions(t.Context(), tenantKey, tenantApp, tenantID)
	if err != nil {
		t.Fatalf("ListSecretVersions(%s, %s): %v", tenantKey, tenantName(tenantID), err)
	}
	out := make([]string, len(vs))
	for i, v := range vs {
		if v.TenantID != tenantID || v.SecretKey != tenantKey || v.AppID != tenantApp {
			t.Errorf("ListSecretVersions(%s, %s) returned a row of key %q app %q tenant %q",
				tenantKey, tenantName(tenantID), v.SecretKey, v.AppID, v.TenantID)
		}
		out[i] = string(v.EncryptedValue)
	}
	return out
}

// listKeys returns the keys ListSecrets returns for tenantID, and fails if
// any of them names another tenant.
func listKeys(t *testing.T, s secret.Store, tenantID string, opts secret.ListOpts) []string {
	t.Helper()
	opts.TenantID = tenantID
	ms, err := s.ListSecrets(t.Context(), tenantApp, opts)
	if err != nil {
		t.Fatalf("ListSecrets(%s): %v", tenantName(tenantID), err)
	}
	for _, m := range ms {
		if m.TenantID != tenantID {
			t.Errorf("ListSecrets(%s) returned %s of tenant %q", tenantName(tenantID), m.Key, m.TenantID)
		}
	}
	return metaKeys(ms)
}

// RunTenantIsolation runs the cross-tenant isolation conformance tests
// against the store newStore builds. The app and two tenants each hold a
// secret under one key, and no read, write or delete under one of them may
// reach another's.
func RunTenantIsolation(t *testing.T, newStore TenantFactory) {
	t.Helper()

	t.Run("SameKeyHoldsIndependentValues", func(t *testing.T) {
		s := newStore(t)
		for _, tenantID := range tenants {
			if v := putTenant(t, s, tenantID, tenantKey, "v1-"+tenantName(tenantID), nil); v != 1 {
				t.Errorf("first SetSecret for %s got version %d, want 1: versions must count per tenant", tenantName(tenantID), v)
			}
		}
		for _, tenantID := range tenants {
			wantSecret(t, s, tenantID, tenantKey, "v1-"+tenantName(tenantID), 1)
		}

		_, err := s.GetSecret(t.Context(), tenantKey, tenantApp, "t3")
		wantNotFound(t, "GetSecret for a tenant with no secret", err)
		_, err = s.GetSecret(t.Context(), tenantKey, "other-app", "t1")
		wantNotFound(t, "GetSecret for t1 in another app", err)
	})

	t.Run("WritesVersionPerTenant", func(t *testing.T) {
		s := newStore(t)
		for _, tenantID := range tenants {
			putTenant(t, s, tenantID, tenantKey, "v1-"+tenantName(tenantID), nil)
		}
		// A second and third write for t1 alone must not touch the app's
		// secret or t2's, nor take their version numbers.
		if v := putTenant(t, s, "t1", tenantKey, "v2-t1", nil); v != 2 {
			t.Errorf("t1 second SetSecret got version %d, want 2", v)
		}
		if v := putTenant(t, s, "t1", tenantKey, "v3-t1", nil); v != 3 {
			t.Errorf("t1 third SetSecret got version %d, want 3", v)
		}
		wantSecret(t, s, "", tenantKey, "v1-app-level", 1)
		wantSecret(t, s, "t1", tenantKey, "v3-t1", 3)
		wantSecret(t, s, "t2", tenantKey, "v1-tenant t2", 1)

		if got, want := versionValues(t, s, ""), []string{"v1-app-level"}; !slices.Equal(got, want) {
			t.Errorf("app-level versions = %q, want %q", got, want)
		}
		if got, want := versionValues(t, s, "t1"), []string{"v1-tenant t1", "v2-t1", "v3-t1"}; !slices.Equal(got, want) {
			t.Errorf("t1 versions = %q, want %q", got, want)
		}
		if got, want := versionValues(t, s, "t2"), []string{"v1-tenant t2"}; !slices.Equal(got, want) {
			t.Errorf("t2 versions = %q, want %q", got, want)
		}
		if got := versionValues(t, s, "t3"); len(got) != 0 {
			t.Errorf("t3 versions = %q, want none", got)
		}
	})

	t.Run("GetSecretVersionStaysInTheTenant", func(t *testing.T) {
		s := newStore(t)
		for _, tenantID := range tenants {
			putTenant(t, s, tenantID, tenantKey, "v1-"+tenantName(tenantID), nil)
		}
		putTenant(t, s, "t1", tenantKey, "v2-t1", nil)

		for _, c := range []struct {
			tenantID string
			version  int64
			want     string
		}{
			{"", 1, "v1-app-level"},
			{"t1", 1, "v1-tenant t1"},
			{"t1", 2, "v2-t1"},
			{"t2", 1, "v1-tenant t2"},
		} {
			got, err := s.GetSecretVersion(t.Context(), tenantKey, tenantApp, c.tenantID, c.version)
			if err != nil {
				t.Fatalf("GetSecretVersion(%s, v%d): %v", tenantName(c.tenantID), c.version, err)
			}
			if string(got.EncryptedValue) != c.want || got.TenantID != c.tenantID {
				t.Errorf("GetSecretVersion(%s, v%d) = %q tenant %q, want %q",
					tenantName(c.tenantID), c.version, got.EncryptedValue, got.TenantID, c.want)
			}
		}

		// Only t1 has a version 2. The app and t2 must not read it.
		for _, tenantID := range []string{"", "t2", "t3"} {
			_, err := s.GetSecretVersion(t.Context(), tenantKey, tenantApp, tenantID, 2)
			wantNotFound(t, "GetSecretVersion(v2) for "+tenantName(tenantID), err)
		}
	})

	t.Run("ListSecretsMatchesTheTenantExactly", func(t *testing.T) {
		s := newStore(t)
		soon := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
		for _, tenantID := range tenants {
			putTenant(t, s, tenantID, tenantKey, "v1-"+tenantName(tenantID), nil)
		}
		putTenant(t, s, "t1", "only-t1", "x", &soon)
		putTenant(t, s, "", "only-app", "x", nil)

		for _, c := range []struct {
			tenantID string
			want     []string
		}{
			{"", []string{tenantKey, "only-app"}},
			{"t1", []string{tenantKey, "only-t1"}},
			{"t2", []string{tenantKey}},
			{"t3", []string{}},
		} {
			if got := listKeys(t, s, c.tenantID, secret.ListOpts{}); !slices.Equal(got, c.want) {
				t.Errorf("ListSecrets(%s) = %v, want %v", tenantName(c.tenantID), got, c.want)
			}
		}

		// An expiry bound narrows within the tenant; it never widens past it.
		later := soon.Add(time.Hour)
		bounded := secret.ListOpts{ExpiresBefore: &later}
		if got, want := listKeys(t, s, "t1", bounded), []string{"only-t1"}; !slices.Equal(got, want) {
			t.Errorf("ListSecrets(t1, expiring) = %v, want %v", got, want)
		}
		for _, tenantID := range []string{"", "t2"} {
			if got := listKeys(t, s, tenantID, bounded); len(got) != 0 {
				t.Errorf("ListSecrets(%s, expiring) = %v, want none: only t1 has an expiring secret", tenantName(tenantID), got)
			}
		}
	})

	t.Run("DeleteRemovesOneTenantOnly", func(t *testing.T) {
		s := newStore(t)
		for _, tenantID := range tenants {
			putTenant(t, s, tenantID, tenantKey, "v1-"+tenantName(tenantID), nil)
		}
		putTenant(t, s, "t1", tenantKey, "v2-t1", nil)
		putTenant(t, s, "t2", tenantKey, "v2-t2", nil)

		err := s.DeleteSecret(t.Context(), tenantKey, tenantApp, "t3")
		wantNotFound(t, "DeleteSecret for a tenant with no secret", err)

		if delErr := s.DeleteSecret(t.Context(), tenantKey, tenantApp, "t1"); delErr != nil {
			t.Fatalf("DeleteSecret(t1): %v", delErr)
		}
		_, err = s.GetSecret(t.Context(), tenantKey, tenantApp, "t1")
		wantNotFound(t, "GetSecret(t1) after its delete", err)
		_, err = s.GetSecretVersion(t.Context(), tenantKey, tenantApp, "t1", 1)
		wantNotFound(t, "GetSecretVersion(t1) after its delete", err)
		if got := versionValues(t, s, "t1"); len(got) != 0 {
			t.Errorf("t1 versions after its delete = %q, want none", got)
		}
		err = s.DeleteSecret(t.Context(), tenantKey, tenantApp, "t1")
		wantNotFound(t, "second DeleteSecret(t1)", err)

		// The app's secret and t2's, with every version, are untouched.
		wantSecret(t, s, "", tenantKey, "v1-app-level", 1)
		wantSecret(t, s, "t2", tenantKey, "v2-t2", 2)
		if got, want := versionValues(t, s, "t2"), []string{"v1-tenant t2", "v2-t2"}; !slices.Equal(got, want) {
			t.Errorf("t2 versions after t1's delete = %q, want %q", got, want)
		}

		// Deleting the app-level secret leaves the tenant's alone, and the
		// other way round.
		if delErr := s.DeleteSecret(t.Context(), tenantKey, tenantApp, ""); delErr != nil {
			t.Fatalf("DeleteSecret(app-level): %v", delErr)
		}
		_, err = s.GetSecret(t.Context(), tenantKey, tenantApp, "")
		wantNotFound(t, "GetSecret(app-level) after its delete", err)
		wantSecret(t, s, "t2", tenantKey, "v2-t2", 2)

		// A deleted tenant can write the key again and starts over at 1.
		if v := putTenant(t, s, "t1", tenantKey, "again", nil); v != 1 {
			t.Errorf("t1 SetSecret after its delete got version %d, want 1", v)
		}
		wantSecret(t, s, "t2", tenantKey, "v2-t2", 2)
	})

	t.Run("KeysAndTenantsDoNotRunTogether", func(t *testing.T) {
		// A store that joined key and tenant into one string would see these
		// two as one secret.
		s := newStore(t)
		putTenant(t, s, "c", "a:b", "first", nil)
		putTenant(t, s, "b:c", "a", "second", nil)
		wantSecret(t, s, "c", "a:b", "first", 1)
		wantSecret(t, s, "b:c", "a", "second", 1)
		_, err := s.GetSecret(t.Context(), "a", tenantApp, "c")
		wantNotFound(t, "GetSecret(a, c)", err)
	})

	t.Run("OperatorCountsSpanEveryTenant", func(t *testing.T) {
		s := newStore(t)
		past := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
		for _, tenantID := range tenants {
			putTenant(t, s, tenantID, tenantKey, "v1-"+tenantName(tenantID), &past)
		}

		n, err := s.CountSecrets(t.Context(), tenantApp)
		if err != nil {
			t.Fatal(err)
		}
		if n != 3 {
			t.Errorf("CountSecrets = %d, want 3 (the app and both tenants)", n)
		}
		now := time.Now().UTC()
		for _, tenantID := range []string{"", "t1"} {
			n, err = s.CountSecretsMatching(t.Context(), tenantApp, secret.ListOpts{ExpiresBefore: &now, TenantID: tenantID})
			if err != nil {
				t.Fatal(err)
			}
			if n != 3 {
				t.Errorf("CountSecretsMatching(TenantID %q) = %d, want 3: it is app-wide and ignores TenantID", tenantID, n)
			}
		}
		n, err = s.CountSecretsUnencrypted(t.Context(), tenantApp)
		if err != nil {
			t.Fatal(err)
		}
		if n != 3 {
			t.Errorf("CountSecretsUnencrypted = %d, want 3", n)
		}
	})

	t.Run("CountVersionEncryptionJoinsOnTheTenant", func(t *testing.T) {
		s := newStore(t)
		// The app's v1 is plaintext history under an encrypted v2. t1's only
		// version is its current v1. A count that matched a version row to
		// its secret by key and app alone would take t1's current v1 as the
		// app's, and leave the app's plaintext v1 out.
		putAlg(t, s, "", "")
		putAlg(t, s, "", Alg)
		putAlg(t, s, "t1", Alg)
		// t2's v1 is plaintext history as well, which t1's current v1 would
		// hide the same way.
		putAlg(t, s, "t2", "")
		putAlg(t, s, "t2", Alg)

		got, err := s.CountVersionEncryption(t.Context(), tenantApp)
		if err != nil {
			t.Fatal(err)
		}
		if want := (secret.VersionEncryptionCounts{Plaintext: 2}); got != want {
			t.Errorf("CountVersionEncryption = %+v, want %+v", got, want)
		}
	})
}

// putAlg stores a secret for tenantID under tenantKey, recorded with alg.
func putAlg(t *testing.T, s secret.Store, tenantID, alg string) {
	t.Helper()
	sec := &secret.Secret{
		Entity: core.NewEntity(), ID: id.NewSecretID(),
		Key: tenantKey, AppID: tenantApp, TenantID: tenantID,
		EncryptedValue: []byte("bytes"), EncryptionAlg: alg,
	}
	if err := s.SetSecret(t.Context(), sec); err != nil {
		t.Fatalf("SetSecret(%s, %s, %q): %v", tenantKey, tenantName(tenantID), alg, err)
	}
}

package vault_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/vault"
	"github.com/xraph/vault/audit"
	"github.com/xraph/vault/config"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/override"
	"github.com/xraph/vault/scope"
	"github.com/xraph/vault/store/memory"
)

const testKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func TestNewRequiresAStore(t *testing.T) {
	_, err := vault.New()
	if err == nil {
		t.Fatal("expected an error with no store configured")
	}
	if !strings.Contains(err.Error(), "store") {
		t.Errorf("error should name the missing store, got %q", err)
	}
}

func TestNewWiresEverySubsystem(t *testing.T) {
	key, _ := hex.DecodeString(testKeyHex)
	v, err := vault.New(
		vault.WithStore(memory.New()),
		vault.WithAppID("app1"),
		vault.WithEncryptionKey(key),
	)
	if err != nil {
		t.Fatal(err)
	}
	if v.Secrets() == nil {
		t.Error("Secrets() is nil")
	}
	if v.Flags() == nil {
		t.Error("Flags() is nil")
	}
	if v.FlagEngine() == nil {
		t.Error("FlagEngine() is nil")
	}
	if v.Config() == nil {
		t.Error("Config() is nil")
	}
	if v.Overrides() == nil {
		t.Error("Overrides() is nil")
	}
	if v.Rotation() == nil {
		t.Error("Rotation() is nil")
	}
	if v.Audit() == nil {
		t.Error("Audit() is nil")
	}
	if v.Store() == nil {
		t.Error("Store() is nil")
	}
	if !v.EncryptionEnabled() {
		t.Error("EncryptionEnabled() is false with a valid key")
	}
}

// EncryptionAlgorithm names what a stored secret carries in EncryptionAlg,
// and is empty when no key is configured.
func TestEncryptionAlgorithmMatchesWhatIsStored(t *testing.T) {
	key, _ := hex.DecodeString(testKeyHex)
	for name, opts := range map[string][]vault.Option{
		"key":    {vault.WithEncryptionKey(key)},
		"no key": nil,
	} {
		t.Run(name, func(t *testing.T) {
			v, err := vault.New(append([]vault.Option{vault.WithStore(memory.New()), vault.WithAppID("app1")}, opts...)...)
			if err != nil {
				t.Fatal(err)
			}
			if _, setErr := v.Secrets().Set(context.Background(), "k", []byte("v"), "app1"); setErr != nil {
				t.Fatal(setErr)
			}
			meta, err := v.Secrets().GetMeta(context.Background(), "k", "app1")
			if err != nil {
				t.Fatal(err)
			}
			if got := v.EncryptionAlgorithm(); got != meta.EncryptionAlg {
				t.Errorf("EncryptionAlgorithm() = %q, stored EncryptionAlg = %q", got, meta.EncryptionAlg)
			}
			if name == "key" && v.EncryptionAlgorithm() != "AES-256-GCM" {
				t.Errorf("EncryptionAlgorithm() = %q, want AES-256-GCM", v.EncryptionAlgorithm())
			}
		})
	}
}

// Review Focus 1: no key at all is the documented fallback, not a panic.
func TestNewWithNoKeyStoresPlaintextAndDoesNotPanic(t *testing.T) {
	v, err := vault.New(vault.WithStore(memory.New()), vault.WithAppID("app1"))
	if err != nil {
		t.Fatalf("no key should not be an error: %v", err)
	}
	if v.EncryptionEnabled() {
		t.Error("EncryptionEnabled() is true with no key configured")
	}
	// The real risk is a nil encryptor dereference on the first write.
	if _, err := v.Secrets().Set(context.Background(), "k", []byte("v"), "app1"); err != nil {
		t.Fatalf("Set with no encryptor: %v", err)
	}
}

// Review Focus 2: a broken key must fail loudly. Falling back to plaintext
// here would store secrets in the clear while the operator believes
// otherwise, which is worse than refusing to start.
func TestNewWithAMalformedKeyIsAnError(t *testing.T) {
	cases := map[string][]byte{
		"too short": []byte("short"),
		"too long":  make([]byte, 64),
	}
	for name, key := range cases {
		if _, err := vault.New(vault.WithStore(memory.New()), vault.WithEncryptionKey(key)); err == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
}

func TestNewWithAnUndecodableKeyEnvIsAnError(t *testing.T) {
	t.Setenv("VAULT_TEST_KEY", "not-a-key")
	if _, err := vault.New(
		vault.WithStore(memory.New()),
		vault.WithEncryptionKeyEnv("VAULT_TEST_KEY"),
	); err == nil {
		t.Error("expected an error for an undecodable key env, got nil")
	}
}

// Naming an env var is a statement of intent, so a variable that is named
// but never set must refuse to start rather than fall back to plaintext.
func TestNewWithANamedButUnsetKeyEnvIsAnError(t *testing.T) {
	if _, err := vault.New(
		vault.WithStore(memory.New()),
		vault.WithEncryptionKeyEnv("VAULT_TEST_KEY_DEFINITELY_UNSET"),
	); err == nil {
		t.Error("expected an error for a named but unset key env, got nil")
	} else if !strings.Contains(err.Error(), "VAULT_TEST_KEY_DEFINITELY_UNSET") {
		t.Errorf("error does not name the variable: %v", err)
	}
}

// An env var that is named but set to the empty string is the same
// deployment mistake as leaving it unset: it must also error.
func TestNewWithANamedButEmptyKeyEnvIsAnError(t *testing.T) {
	t.Setenv("VAULT_TEST_KEY_EMPTY", "")
	if _, err := vault.New(
		vault.WithStore(memory.New()),
		vault.WithEncryptionKeyEnv("VAULT_TEST_KEY_EMPTY"),
	); err == nil {
		t.Error("expected an error for a named but empty key env, got nil")
	} else if !strings.Contains(err.Error(), "VAULT_TEST_KEY_EMPTY") {
		t.Errorf("error does not name the variable: %v", err)
	}
}

// A secret written through the service round-trips, which is the thing the
// templ dashboard got wrong by writing Value and never EncryptedValue.
func TestSecretsRoundTripThroughTheService(t *testing.T) {
	key, _ := hex.DecodeString(testKeyHex)
	v, err := vault.New(
		vault.WithStore(memory.New()),
		vault.WithAppID("app1"),
		vault.WithEncryptionKey(key),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	meta, err := v.Secrets().Set(ctx, "api_key", []byte("s3cret"), "app1")
	if err != nil {
		t.Fatal(err)
	}
	if meta.ID.String() == "" {
		t.Error("Set returned a meta with an empty ID")
	}
	got, err := v.Secrets().Get(ctx, "api_key", "app1")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Value) != "s3cret" {
		t.Errorf("round trip: got %q, want %q", got.Value, "s3cret")
	}
}

// The audit hooks exist for this and nothing has ever passed them, which is
// why every audit surface in the templ dashboard read an empty table.
func TestSecretMutationsWriteAnAuditEntry(t *testing.T) {
	key, _ := hex.DecodeString(testKeyHex)
	s := memory.New()
	v, err := vault.New(
		vault.WithStore(s),
		vault.WithAppID("app1"),
		vault.WithEncryptionKey(key),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, setErr := v.Secrets().Set(ctx, "api_key", []byte("s3cret"), "app1"); setErr != nil {
		t.Fatal(setErr)
	}
	n, err := s.CountAudit(ctx, "app1")
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Error("no audit entry was written for a secret mutation")
	}
}

// WithConfig must overlay, not replace: a later WithConfig with unrelated
// fields set must not silently drop a key configured by an earlier option.
// Before the fix, this combination reported EncryptionEnabled() == false
// and stored every secret in plaintext without any error.
func TestWithConfigDoesNotDropAnEarlierEncryptionKey(t *testing.T) {
	key, _ := hex.DecodeString(testKeyHex)
	v, err := vault.New(
		vault.WithStore(memory.New()),
		vault.WithEncryptionKey(key),
		vault.WithConfig(vault.Config{FlagCacheTTL: time.Minute}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !v.EncryptionEnabled() {
		t.Error("EncryptionEnabled() is false: WithConfig dropped the earlier WithEncryptionKey")
	}
}

// WithConfig must not drop an earlier AppID either. Before the fix, a
// WithConfig call after WithAppID zeroed AppID and every write landed under
// the empty app scope instead of the configured one.
func TestWithConfigDoesNotDropAnEarlierAppID(t *testing.T) {
	s := memory.New()
	v, err := vault.New(
		vault.WithStore(s),
		vault.WithAppID("a"),
		vault.WithConfig(vault.Config{FlagCacheTTL: time.Minute}),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// Empty appID argument: the service must fall back to its configured
	// default, which must still be "a".
	if _, setErr := v.Secrets().Set(ctx, "k", []byte("v"), ""); setErr != nil {
		t.Fatal(setErr)
	}
	gotA, err := s.CountSecrets(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	if gotA != 1 {
		t.Errorf("CountSecrets(%q) = %d, want 1: the write should have landed under the configured AppID", "a", gotA)
	}
	gotEmpty, err := s.CountSecrets(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if gotEmpty != 0 {
		t.Errorf("CountSecrets(\"\") = %d, want 0: WithConfig dropped the earlier AppID and the write landed under the empty scope", gotEmpty)
	}
}

// The overlay must still override when the incoming Config field is
// non-zero, so this pins that WithConfig did not become a no-op.
func TestWithConfigStillOverridesWithNonZeroValues(t *testing.T) {
	s := memory.New()
	v, err := vault.New(
		vault.WithStore(s),
		vault.WithAppID("a"),
		vault.WithConfig(vault.Config{AppID: "b"}),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, setErr := v.Secrets().Set(ctx, "k", []byte("v"), ""); setErr != nil {
		t.Fatal(setErr)
	}
	gotB, err := s.CountSecrets(ctx, "b")
	if err != nil {
		t.Fatal(err)
	}
	if gotB != 1 {
		t.Errorf("CountSecrets(%q) = %d, want 1: WithConfig should still override AppID with a non-zero value", "b", gotB)
	}
}

// AppID must reflect WithConfig's overlay semantics: a later WithConfig
// call with unrelated fields set must not silently drop the app id an
// earlier WithAppID configured.
func TestAppIDReturnsTheConfiguredValueAfterWithConfigOverlays(t *testing.T) {
	v, err := vault.New(
		vault.WithStore(memory.New()),
		vault.WithAppID("a"),
		vault.WithConfig(vault.Config{FlagCacheTTL: time.Minute}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := v.AppID(); got != "a" {
		t.Errorf("AppID() = %q, want %q", got, "a")
	}
}

func TestKeylessRoundTripReturnsThePlaintext(t *testing.T) {
	v, err := vault.New(vault.WithStore(memory.New()), vault.WithAppID("app1"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, setErr := v.Secrets().Set(ctx, "k", []byte("v"), "app1"); setErr != nil {
		t.Fatal(setErr)
	}
	got, err := v.Secrets().Get(ctx, "k", "app1")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Value) != "v" {
		t.Errorf("keyless round trip: got %q, want %q", got.Value, "v")
	}
}

func TestAKeyAddedLaterStillReadsOlderPlaintextRows(t *testing.T) {
	key, _ := hex.DecodeString(testKeyHex)
	s := memory.New()
	ctx := context.Background()

	keyless, err := vault.New(vault.WithStore(s), vault.WithAppID("app1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, setErr := keyless.Secrets().Set(ctx, "first", []byte("old"), "app1"); setErr != nil {
		t.Fatal(setErr)
	}

	keyed, err := vault.New(vault.WithStore(s), vault.WithAppID("app1"), vault.WithEncryptionKey(key))
	if err != nil {
		t.Fatal(err)
	}
	if _, setErr := keyed.Secrets().Set(ctx, "second", []byte("new"), "app1"); setErr != nil {
		t.Fatal(setErr)
	}

	first, err := keyed.Secrets().Get(ctx, "first", "app1")
	if err != nil {
		t.Fatalf("reading a row written before the key existed: %v", err)
	}
	if string(first.Value) != "old" {
		t.Errorf("first: got %q, want %q", first.Value, "old")
	}
	second, err := keyed.Secrets().Get(ctx, "second", "app1")
	if err != nil {
		t.Fatal(err)
	}
	if string(second.Value) != "new" {
		t.Errorf("second: got %q, want %q", second.Value, "new")
	}
}

func TestAnEncryptedRowWithNoKeyIsAnErrorNotAnEmptyValue(t *testing.T) {
	key, _ := hex.DecodeString(testKeyHex)
	s := memory.New()
	ctx := context.Background()

	keyed, err := vault.New(vault.WithStore(s), vault.WithAppID("app1"), vault.WithEncryptionKey(key))
	if err != nil {
		t.Fatal(err)
	}
	if _, setErr := keyed.Secrets().Set(ctx, "k", []byte("s3cret"), "app1"); setErr != nil {
		t.Fatal(setErr)
	}

	keyless, err := vault.New(vault.WithStore(s), vault.WithAppID("app1"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := keyless.Secrets().Get(ctx, "k", "app1")
	if !errors.Is(err, vault.ErrDecryptionFailed) {
		t.Errorf("err = %v, want one wrapping ErrDecryptionFailed", err)
	}
	if got != nil {
		t.Errorf("got a secret %+v, want nil alongside the error", got)
	}
}

func TestSecretsAreCiphertextAtRest(t *testing.T) {
	key, _ := hex.DecodeString(testKeyHex)
	s := memory.New()
	ctx := context.Background()

	v, err := vault.New(vault.WithStore(s), vault.WithAppID("app1"), vault.WithEncryptionKey(key))
	if err != nil {
		t.Fatal(err)
	}
	if _, setErr := v.Secrets().Set(ctx, "k", []byte("s3cret"), "app1"); setErr != nil {
		t.Fatal(setErr)
	}

	raw, err := s.GetSecret(ctx, "k", "app1")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(raw.EncryptedValue, []byte("s3cret")) {
		t.Error("EncryptedValue at rest is the plaintext")
	}
	if bytes.Contains(raw.EncryptedValue, []byte("s3cret")) {
		t.Error("EncryptedValue at rest contains the plaintext")
	}
	if raw.EncryptionAlg != "AES-256-GCM" {
		t.Errorf("EncryptionAlg = %q, want %q", raw.EncryptionAlg, "AES-256-GCM")
	}
}

// A library caller who passes a logger must hear about the plaintext
// fallback when no key is configured at all.
func TestNewWarnsWhenItFallsBackToPlaintext(t *testing.T) {
	logger, ok := log.NewTestLogger().(*log.TestLogger)
	if !ok {
		t.Fatal("NewTestLogger did not return a *TestLogger")
	}
	if _, err := vault.New(
		vault.WithStore(memory.New()),
		vault.WithLogger(logger),
	); err != nil {
		t.Fatal(err)
	}
	if !logger.AssertHasLog("WARN", "vault: no encryption key configured; secrets will be stored unencrypted") {
		t.Errorf("no plaintext fallback warning was logged; got %+v", logger.GetLogs())
	}
}

func TestNewDoesNotWarnWithAKey(t *testing.T) {
	key, _ := hex.DecodeString(testKeyHex)
	logger, ok := log.NewTestLogger().(*log.TestLogger)
	if !ok {
		t.Fatal("NewTestLogger did not return a *TestLogger")
	}
	if _, err := vault.New(
		vault.WithStore(memory.New()),
		vault.WithLogger(logger),
		vault.WithEncryptionKey(key),
	); err != nil {
		t.Fatal(err)
	}
	if n := logger.CountLogs("WARN"); n != 0 {
		t.Errorf("got %d warnings with a valid key, want 0: %+v", n, logger.GetLogs())
	}
}

// Config reads must go through the override resolver, which is what
// config.WithResolver wires. Without it the app-level value comes back and
// the tenant override is silently ignored.
//
// The tenant goes on the context under override.ContextKeyTenantID rather
// than through scope.WithTenantID: the two keys share a string but not a
// type, so the resolver cannot see a tenant set through scope.
func TestConfigReadsHonourTenantOverrides(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	if err := s.SetConfig(ctx, &config.Entry{
		Entity:    vault.NewEntity(),
		ID:        id.NewConfigID(),
		Key:       "rate_limit",
		Value:     100,
		ValueType: "int",
		AppID:     "app1",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetOverride(ctx, &override.Override{
		Entity:   vault.NewEntity(),
		ID:       id.NewOverrideID(),
		Key:      "rate_limit",
		Value:    500,
		AppID:    "app1",
		TenantID: "t-1",
	}); err != nil {
		t.Fatal(err)
	}

	v, err := vault.New(vault.WithStore(s), vault.WithAppID("app1"))
	if err != nil {
		t.Fatal(err)
	}

	if got := v.Config().Int(ctx, "rate_limit", 0); got != 100 {
		t.Fatalf("no tenant: got %d, want the app-level 100", got)
	}
	tctx := context.WithValue(ctx, override.ContextKeyTenantID, "t-1")
	if got := v.Config().Int(tctx, "rate_limit", 0); got != 500 {
		t.Errorf("tenant t-1: got %d, want the override 500", got)
	}
}

// Reading a secret must write an audit entry attributed to its app. That
// is the OnAccess hook; without it only mutations are audited.
func TestSecretReadsWriteAnAttributedAuditEntry(t *testing.T) {
	key, _ := hex.DecodeString(testKeyHex)
	s := memory.New()
	v, err := vault.New(vault.WithStore(s), vault.WithAppID("app1"), vault.WithEncryptionKey(key))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, setErr := v.Secrets().Set(ctx, "api_key", []byte("s3cret"), "app1"); setErr != nil {
		t.Fatal(setErr)
	}
	if _, getErr := v.Secrets().Get(ctx, "api_key", "app1"); getErr != nil {
		t.Fatal(getErr)
	}

	entries, err := s.ListAudit(ctx, "app1", audit.ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Action == "secret.get" && e.AppID == "app1" {
			return
		}
	}
	t.Errorf("no secret.get audit entry for app1 among %d entries", len(entries))
}

// A flag override row names the tenant that was overridden, so the audit log
// can say which tenant an override touched. Rows for the flag itself, which
// belong to no tenant, carry none.
func TestFlagOverrideAuditRowsCarryTheTenant(t *testing.T) {
	ctx := context.Background()
	v, err := vault.New(vault.WithStore(memory.New()), vault.WithAppID("app1"))
	if err != nil {
		t.Fatal(err)
	}
	fm := v.FlagManager()
	if _, err := fm.Create(ctx, flag.CreateInput{Key: "f", Type: flag.TypeBool, DefaultValue: true, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := fm.SetTenantOverride(ctx, "f", "tenant-a", false); err != nil {
		t.Fatal(err)
	}
	if err := fm.DeleteTenantOverride(ctx, "f", "tenant-a"); err != nil {
		t.Fatal(err)
	}

	for action, wantTenant := range map[string]string{
		"flag.override_set":     "tenant-a",
		"flag.override_deleted": "tenant-a",
		"flag.created":          "",
	} {
		rows, err := v.Store().ListAudit(ctx, "app1", audit.ListOpts{Limit: 10, Action: action})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("%s rows = %d, want 1", action, len(rows))
		}
		if rows[0].TenantID != wantTenant {
			t.Errorf("%s tenant = %q, want %q", action, rows[0].TenantID, wantTenant)
		}
	}
}

// refusingCancelled is a memory store that, like a real database driver,
// refuses an audit write made under a cancelled context.
type refusingCancelled struct {
	*memory.Store
}

func (r refusingCancelled) RecordAudit(ctx context.Context, e *audit.Entry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return r.Store.RecordAudit(ctx, e)
}

// A dashboard client that disconnects mid-rotation cancels the request
// context. The attempt's audit row must survive that, failed or not, and
// still name the user the context carried.
func TestRotationAuditRowSurvivesACancelledContext(t *testing.T) {
	cases := []struct {
		name        string
		rotatorErr  error
		wantOutcome string
	}{
		{"success", nil, "success"},
		{"failure", errors.New("rotator exploded"), "failure"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := refusingCancelled{memory.New()}
			v, err := vault.New(vault.WithStore(s), vault.WithAppID("app1"))
			if err != nil {
				t.Fatal(err)
			}
			base := context.Background()
			if _, err := v.Secrets().Set(base, "rk", []byte("v1"), "app1"); err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithCancel(scope.WithUserID(base, "user_operator_1"))
			defer cancel()
			v.Rotation().RegisterRotator("rk", func(_ context.Context, cur []byte) ([]byte, error) {
				cancel() // the client goes away while the rotator runs
				return cur, tc.rotatorErr
			})
			_ = v.Rotation().RotateNow(ctx, "rk", "app1")

			rows, err := s.ListAudit(base, "app1", audit.ListOpts{Limit: 10, Action: "secret.rotated"})
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 1 {
				t.Fatalf("secret.rotated rows = %d, want 1", len(rows))
			}
			if rows[0].Outcome != tc.wantOutcome {
				t.Errorf("outcome = %q, want %q", rows[0].Outcome, tc.wantOutcome)
			}
			if rows[0].UserID != "user_operator_1" || rows[0].AppID != "app1" {
				t.Errorf("row scope = app %q user %q, want app1 and the operator", rows[0].AppID, rows[0].UserID)
			}
		})
	}
}

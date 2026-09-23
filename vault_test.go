package vault_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xraph/vault"
	"github.com/xraph/vault/secret"
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

// An env var that is not set at all is the same case as no key: fall back.
func TestNewWithAnUnsetKeyEnvFallsBack(t *testing.T) {
	v, err := vault.New(
		vault.WithStore(memory.New()),
		vault.WithEncryptionKeyEnv("VAULT_TEST_KEY_DEFINITELY_UNSET"),
	)
	if err != nil {
		t.Fatalf("an unset env var should fall back, not error: %v", err)
	}
	if v.EncryptionEnabled() {
		t.Error("EncryptionEnabled() is true with an unset env var")
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

// prodLikeStore behaves like postgres, sqlite and mongo: it persists only
// EncryptedValue and never keeps Value. The bare memory store keeps Value,
// which hid a keyless read bug from every test in the repository.
type prodLikeStore struct{ *memory.Store }

func (p prodLikeStore) SetSecret(ctx context.Context, s *secret.Secret) error {
	cp := *s
	cp.Value = nil
	err := p.Store.SetSecret(ctx, &cp)
	// Real backends assign the version on the caller's secret; keep that.
	s.Version = cp.Version
	return err
}

func TestKeylessRoundTripReturnsThePlaintext(t *testing.T) {
	v, err := vault.New(vault.WithStore(prodLikeStore{memory.New()}), vault.WithAppID("app1"))
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
	s := prodLikeStore{memory.New()}
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
	s := prodLikeStore{memory.New()}
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
	s := prodLikeStore{memory.New()}
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

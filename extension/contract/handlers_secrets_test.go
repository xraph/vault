package contract

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/vault"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/secret"
	"github.com/xraph/vault/store/memory"
)

const testAppID = "app1"

// testEncryptionKey is a fixed 32-byte AES-256-GCM key. Its exact bytes
// don't matter, only its length.
var testEncryptionKey = bytes.Repeat([]byte("k"), 32)

// newTestVault builds a Vault over a fresh memory store, with encryption
// enabled and scoped to testAppID, the shape every handler test in this
// file assumes.
func newTestVault(t *testing.T) (*vault.Vault, *memory.Store) {
	t.Helper()
	st := memory.New()
	v, err := vault.New(
		vault.WithStore(st),
		vault.WithAppID(testAppID),
		vault.WithEncryptionKey(testEncryptionKey),
	)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	return v, st
}

func codeOf(err error) dashcontract.ErrorCode {
	var ce *dashcontract.Error
	if errors.As(err, &ce) {
		return ce.Code
	}
	return ""
}

// --- secrets.list ---

func TestSecretsList_PagingAndTotal(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := v.Secrets().Set(ctx, "key-"+string(rune('a'+i)), []byte("value"), testAppID); err != nil {
			t.Fatalf("seed secret %d: %v", i, err)
		}
	}

	handler := secretsListHandler(Deps{Vault: v})

	page1, err := handler(ctx, secretsListRequest{Limit: 2, Offset: 0}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("list page1: %v", err)
	}
	if len(page1.Secrets) != 2 {
		t.Errorf("page1 len = %d, want 2", len(page1.Secrets))
	}
	if page1.Total != 5 {
		t.Errorf("page1 total = %d, want 5", page1.Total)
	}

	page3, err := handler(ctx, secretsListRequest{Limit: 2, Offset: 4}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("list page3: %v", err)
	}
	if len(page3.Secrets) != 1 {
		t.Errorf("page3 len = %d, want 1 (the remainder of 5 with limit 2 offset 4)", len(page3.Secrets))
	}
	if page3.Total != 5 {
		t.Errorf("page3 total = %d, want 5", page3.Total)
	}

	// No limit: defaults to 25, still returns the full 5-row total.
	def, err := handler(ctx, secretsListRequest{}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("list default: %v", err)
	}
	if len(def.Secrets) != 5 {
		t.Errorf("default len = %d, want 5", len(def.Secrets))
	}
}

func TestSecretsList_ExcludesOtherApp(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()

	if _, err := v.Secrets().Set(ctx, "mine", []byte("value"), testAppID); err != nil {
		t.Fatalf("seed app1 secret: %v", err)
	}

	const otherKey = "not-mine"
	if err := st.SetSecret(ctx, &secret.Secret{
		Entity:         vault.NewEntity(),
		ID:             id.NewSecretID(),
		Key:            otherKey,
		EncryptedValue: []byte("whatever bytes are stored for app2"),
		AppID:          "app2",
	}); err != nil {
		t.Fatalf("seed app2 secret: %v", err)
	}

	out, err := secretsListHandler(Deps{Vault: v})(ctx, secretsListRequest{}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, s := range out.Secrets {
		if s.Key == otherKey {
			t.Fatalf("secrets.list for app1 returned app2's secret %q: %+v", otherKey, out.Secrets)
		}
	}
	if len(out.Secrets) != 1 {
		t.Fatalf("secrets.list for app1 returned %d rows, want 1 (app2's row must never appear)", len(out.Secrets))
	}
}

// --- encryptionAlg: "" must survive to the wire, not be dropped ---

func TestSecretsListAndDetail_ReportUnencryptedAlg(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()

	// A second, keyless Vault over the same store writes a row with no
	// encryption, the state every unconfigured Vault produces.
	keyless, err := vault.New(vault.WithStore(st), vault.WithAppID(testAppID))
	if err != nil {
		t.Fatalf("keyless vault.New: %v", err)
	}
	const plainKey = "plaintext-secret"
	if _, setErr := keyless.Secrets().Set(ctx, plainKey, []byte("value"), testAppID); setErr != nil {
		t.Fatalf("seed unencrypted secret: %v", setErr)
	}

	deps := Deps{Vault: v}

	listOut, err := secretsListHandler(deps)(ctx, secretsListRequest{}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var found *SecretSummary
	for i := range listOut.Secrets {
		if listOut.Secrets[i].Key == plainKey {
			found = &listOut.Secrets[i]
		}
	}
	if found == nil {
		t.Fatalf("list did not include %q: %+v", plainKey, listOut.Secrets)
	}
	if found.EncryptionAlg != "" {
		t.Errorf("list encryptionAlg = %q, want \"\" (not encrypted)", found.EncryptionAlg)
	}
	listJSON, err := json.Marshal(listOut)
	if err != nil {
		t.Fatalf("marshal list: %v", err)
	}
	if !strings.Contains(string(listJSON), `"encryptionAlg":""`) {
		t.Errorf("list JSON missing an explicit \"encryptionAlg\":\"\": %s", listJSON)
	}

	detailOut, err := secretsDetailHandler(deps)(ctx, secretsDetailRequest{Key: plainKey}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if detailOut.Secret.EncryptionAlg != "" {
		t.Errorf("detail encryptionAlg = %q, want \"\"", detailOut.Secret.EncryptionAlg)
	}
	detailJSON, err := json.Marshal(detailOut)
	if err != nil {
		t.Fatalf("marshal detail: %v", err)
	}
	if !strings.Contains(string(detailJSON), `"encryptionAlg":""`) {
		t.Errorf("detail JSON missing an explicit \"encryptionAlg\":\"\": %s", detailJSON)
	}
}

// --- secrets.detail ---

func TestSecretsDetail_MissingKeyIsNotFound(t *testing.T) {
	v, _ := newTestVault(t)
	_, err := secretsDetailHandler(Deps{Vault: v})(context.Background(), secretsDetailRequest{Key: "nope"}, dashcontract.Principal{})
	if code := codeOf(err); code != dashcontract.CodeNotFound {
		t.Fatalf("detail of a missing key: code %q, err %v; want NOT_FOUND", code, err)
	}
}

func TestSecretsDetail_RotationNullWithoutPolicy(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	if _, err := v.Secrets().Set(ctx, "no-policy", []byte("value"), testAppID); err != nil {
		t.Fatalf("seed: %v", err)
	}

	out, err := secretsDetailHandler(Deps{Vault: v})(ctx, secretsDetailRequest{Key: "no-policy"}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if out.Rotation != nil {
		t.Errorf("rotation = %+v, want nil for a secret with no policy", out.Rotation)
	}
	// The response must serialize "rotation" as an explicit null, not omit
	// the field.
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"rotation":null`) {
		t.Errorf("JSON missing an explicit \"rotation\":null: %s", raw)
	}
}

func TestSecretsDetail_RotationPresentAndNextRotationAtAbsentWhenDisabled(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()
	const key = "db-password"
	if _, err := v.Secrets().Set(ctx, key, []byte("value"), testAppID); err != nil {
		t.Fatalf("seed secret: %v", err)
	}
	v.Rotation().RegisterRotator(key, func(_ context.Context, current []byte) ([]byte, error) { return current, nil })

	next := time.Now().Add(24 * time.Hour)
	policy := &rotation.Policy{
		Entity:         vault.NewEntity(),
		ID:             id.NewRotationID(),
		SecretKey:      key,
		AppID:          testAppID,
		Interval:       24 * time.Hour,
		Enabled:        true,
		NextRotationAt: &next,
	}
	if err := st.SaveRotationPolicy(ctx, policy); err != nil {
		t.Fatalf("SaveRotationPolicy: %v", err)
	}

	out, err := secretsDetailHandler(Deps{Vault: v})(ctx, secretsDetailRequest{Key: key}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if out.Rotation == nil {
		t.Fatal("rotation = nil, want the saved policy")
	}
	if !out.Rotation.Enabled {
		t.Error("rotation.enabled = false, want true")
	}
	if !out.Rotation.Rotatable {
		t.Error("rotation.rotatable = false, want true: a rotator is registered for this key")
	}
	if out.Rotation.NextRotationAt == nil {
		t.Error("rotation.nextRotationAt = nil, want a value for an enabled policy")
	}

	// Now disable it. NextRotationAt must disappear even though the store
	// still has the old value.
	policy.Enabled = false
	if saveErr := st.SaveRotationPolicy(ctx, policy); saveErr != nil {
		t.Fatalf("SaveRotationPolicy (disable): %v", saveErr)
	}
	out2, err := secretsDetailHandler(Deps{Vault: v})(ctx, secretsDetailRequest{Key: key}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("detail after disable: %v", err)
	}
	if out2.Rotation == nil {
		t.Fatal("rotation = nil after disabling, want the policy still present")
	}
	if out2.Rotation.NextRotationAt != nil {
		t.Errorf("rotation.nextRotationAt = %v, want nil for a disabled policy", *out2.Rotation.NextRotationAt)
	}
	raw, err := json.Marshal(out2)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), `"nextRotationAt"`) {
		t.Errorf("JSON has a nextRotationAt field for a disabled policy (omitempty should drop it): %s", raw)
	}
}

// --- secrets.versions ---

func TestSecretsVersions_NewestFirst(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	const key = "rotating"
	for i := 0; i < 3; i++ {
		if _, err := v.Secrets().Set(ctx, key, []byte("value"), testAppID); err != nil {
			t.Fatalf("set %d: %v", i, err)
		}
	}

	out, err := secretsVersionsHandler(Deps{Vault: v})(ctx, secretsVersionsRequest{Key: key}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("versions: %v", err)
	}
	if len(out.Versions) != 3 {
		t.Fatalf("versions len = %d, want 3", len(out.Versions))
	}
	for i := 0; i < len(out.Versions)-1; i++ {
		if out.Versions[i].Version <= out.Versions[i+1].Version {
			t.Fatalf("versions not newest-first: %+v", out.Versions)
		}
	}
	if out.Versions[0].Version != 3 {
		t.Errorf("newest version = %d, want 3", out.Versions[0].Version)
	}
}

func TestSecretsVersions_MissingKeyIsNotFound(t *testing.T) {
	v, _ := newTestVault(t)
	_, err := secretsVersionsHandler(Deps{Vault: v})(context.Background(), secretsVersionsRequest{Key: "nope"}, dashcontract.Principal{})
	if code := codeOf(err); code != dashcontract.CodeNotFound {
		t.Fatalf("versions of a missing key: code %q, err %v; want NOT_FOUND", code, err)
	}
}

// --- secrets.create ---

func TestSecretsCreate_ConflictOnExistingKey(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	if _, err := v.Secrets().Set(ctx, "exists", []byte("original"), testAppID); err != nil {
		t.Fatalf("seed: %v", err)
	}

	_, err := secretsCreateHandler(Deps{Vault: v})(ctx, secretsCreateRequest{Key: "exists", Value: "new-value"}, dashcontract.Principal{})
	if code := codeOf(err); code != dashcontract.CodeConflict {
		t.Fatalf("create over an existing key: code %q, err %v; want CONFLICT", code, err)
	}
}

func TestSecretsCreate_ThenListShowsIt(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()

	out, err := secretsCreateHandler(Deps{Vault: v})(ctx, secretsCreateRequest{Key: "fresh", Value: "value"}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if out.Secret.Key != "fresh" {
		t.Errorf("created secret key = %q, want fresh", out.Secret.Key)
	}

	list, err := secretsListHandler(Deps{Vault: v})(ctx, secretsListRequest{}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	found := false
	for _, s := range list.Secrets {
		if s.Key == "fresh" {
			found = true
		}
	}
	if !found {
		t.Fatalf("list after create did not include %q: %+v", "fresh", list.Secrets)
	}
}

func TestSecretsCreate_PastExpiryIsRejectedAndCreatesNothing(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	past := time.Now().Add(-time.Hour).Format(time.RFC3339)

	_, err := secretsCreateHandler(Deps{Vault: v})(ctx, secretsCreateRequest{Key: "past", Value: "value", ExpiresAt: past}, dashcontract.Principal{})
	if code := codeOf(err); code != dashcontract.CodeBadRequest {
		t.Fatalf("create with a past expiresAt: code %q, err %v; want BAD_REQUEST", code, err)
	}
	if _, getErr := v.Secrets().GetMeta(ctx, "past", testAppID); !errors.Is(getErr, vault.ErrSecretNotFound) {
		t.Errorf("a rejected create must not create anything; GetMeta err = %v", getErr)
	}
}

func TestSecretsCreate_EmptyValueIsBadRequest(t *testing.T) {
	v, _ := newTestVault(t)
	_, err := secretsCreateHandler(Deps{Vault: v})(context.Background(), secretsCreateRequest{Key: "k"}, dashcontract.Principal{})
	if code := codeOf(err); code != dashcontract.CodeBadRequest {
		t.Fatalf("create with no value: code %q, err %v; want BAD_REQUEST", code, err)
	}
}

// --- secrets.update ---

func TestSecretsUpdate_MissingKeyIsNotFoundAndCreatesNothing(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()

	_, err := secretsUpdateHandler(Deps{Vault: v})(ctx, secretsUpdateRequest{Key: "nope", Value: "value"}, dashcontract.Principal{})
	if code := codeOf(err); code != dashcontract.CodeNotFound {
		t.Fatalf("update of a missing key: code %q, err %v; want NOT_FOUND", code, err)
	}
	if _, getErr := v.Secrets().GetMeta(ctx, "nope", testAppID); !errors.Is(getErr, vault.ErrSecretNotFound) {
		t.Errorf("a NOT_FOUND update must not create the key; GetMeta err = %v", getErr)
	}
}

func TestSecretsUpdate_NoExpiryFieldKeepsExpiryAndMetadata(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	future := time.Now().Add(24 * time.Hour)
	if _, err := v.Secrets().Set(ctx, "keep-me", []byte("v1"), testAppID,
		secret.WithExpiresAt(future), secret.WithMetadata(map[string]string{"env": "prod"})); err != nil {
		t.Fatalf("seed: %v", err)
	}

	out, err := secretsUpdateHandler(Deps{Vault: v})(ctx, secretsUpdateRequest{Key: "keep-me", Value: "v2"}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if out.Secret.ExpiresAt == nil {
		t.Fatal("expiresAt = nil after an update with no expiresAt field, want it kept")
	}
	got, err := time.Parse(time.RFC3339, *out.Secret.ExpiresAt)
	if err != nil {
		t.Fatalf("parse expiresAt: %v", err)
	}
	if !got.Equal(future.UTC().Truncate(time.Second)) {
		t.Errorf("expiresAt = %v, want %v", got, future)
	}
	if out.Secret.Metadata["env"] != "prod" {
		t.Errorf("metadata = %+v, want env=prod kept", out.Secret.Metadata)
	}
}

func TestSecretsUpdate_EmptyExpiryClears(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	future := time.Now().Add(24 * time.Hour)
	if _, err := v.Secrets().Set(ctx, "clear-me", []byte("v1"), testAppID, secret.WithExpiresAt(future)); err != nil {
		t.Fatalf("seed: %v", err)
	}

	empty := ""
	out, err := secretsUpdateHandler(Deps{Vault: v})(ctx, secretsUpdateRequest{Key: "clear-me", Value: "v2", ExpiresAt: &empty}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if out.Secret.ExpiresAt != nil {
		t.Errorf("expiresAt = %v after clearing, want nil", *out.Secret.ExpiresAt)
	}
}

func TestSecretsUpdate_NewTimestampChangesExpiry(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	if _, err := v.Secrets().Set(ctx, "reset-me", []byte("v1"), testAppID); err != nil {
		t.Fatalf("seed: %v", err)
	}

	next := time.Now().Add(48 * time.Hour)
	nextStr := next.Format(time.RFC3339)
	out, err := secretsUpdateHandler(Deps{Vault: v})(ctx, secretsUpdateRequest{Key: "reset-me", Value: "v2", ExpiresAt: &nextStr}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if out.Secret.ExpiresAt == nil {
		t.Fatal("expiresAt = nil, want the new timestamp")
	}
	got, err := time.Parse(time.RFC3339, *out.Secret.ExpiresAt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !got.Equal(next.UTC().Truncate(time.Second)) {
		t.Errorf("expiresAt = %v, want %v", got, next)
	}
}

func TestSecretsUpdate_PastExpiryIsRejected(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	if _, err := v.Secrets().Set(ctx, "reject-me", []byte("v1"), testAppID); err != nil {
		t.Fatalf("seed: %v", err)
	}
	past := time.Now().Add(-time.Hour).Format(time.RFC3339)
	_, err := secretsUpdateHandler(Deps{Vault: v})(ctx, secretsUpdateRequest{Key: "reject-me", Value: "v2", ExpiresAt: &past}, dashcontract.Principal{})
	if code := codeOf(err); code != dashcontract.CodeBadRequest {
		t.Fatalf("update with a past expiresAt: code %q, err %v; want BAD_REQUEST", code, err)
	}
}

func TestSecretsUpdate_MetadataPresentReplaces(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	if _, err := v.Secrets().Set(ctx, "meta-me", []byte("v1"), testAppID, secret.WithMetadata(map[string]string{"env": "prod"})); err != nil {
		t.Fatalf("seed: %v", err)
	}

	newMeta := map[string]string{"env": "staging", "owner": "team-x"}
	out, err := secretsUpdateHandler(Deps{Vault: v})(ctx, secretsUpdateRequest{Key: "meta-me", Value: "v2", Metadata: &newMeta}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if out.Secret.Metadata["env"] != "staging" || out.Secret.Metadata["owner"] != "team-x" {
		t.Errorf("metadata = %+v, want the replacement map", out.Secret.Metadata)
	}
}

func TestSecretsUpdate_EmptyValueIsBadRequest(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	if _, err := v.Secrets().Set(ctx, "novalue", []byte("v1"), testAppID); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, err := secretsUpdateHandler(Deps{Vault: v})(ctx, secretsUpdateRequest{Key: "novalue"}, dashcontract.Principal{})
	if code := codeOf(err); code != dashcontract.CodeBadRequest {
		t.Fatalf("update with no value: code %q, err %v; want BAD_REQUEST", code, err)
	}
}

// --- secrets.delete ---

func TestSecretsDelete_RemovesPolicyToo(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()
	const key = "rotatable"
	if _, err := v.Secrets().Set(ctx, key, []byte("v1"), testAppID); err != nil {
		t.Fatalf("seed secret: %v", err)
	}
	policy := &rotation.Policy{
		Entity: vault.NewEntity(), ID: id.NewRotationID(), SecretKey: key, AppID: testAppID,
		Interval: 24 * time.Hour, Enabled: true,
	}
	if err := st.SaveRotationPolicy(ctx, policy); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	out, err := secretsDeleteHandler(Deps{Vault: v})(ctx, secretsDeleteRequest{Key: key}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !out.OK || out.Key != key {
		t.Errorf("delete response = %+v, want ok=true key=%q", out, key)
	}
	if _, getErr := v.Secrets().GetMeta(ctx, key, testAppID); !errors.Is(getErr, vault.ErrSecretNotFound) {
		t.Errorf("secret still exists after delete: %v", getErr)
	}
	if _, polErr := st.GetRotationPolicy(ctx, key, testAppID); !errors.Is(polErr, vault.ErrRotationNotFound) {
		t.Errorf("rotation policy still exists after delete: %v", polErr)
	}
}

func TestSecretsDelete_NoPolicyIsFine(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	if _, err := v.Secrets().Set(ctx, "no-policy-del", []byte("v1"), testAppID); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := secretsDeleteHandler(Deps{Vault: v})(ctx, secretsDeleteRequest{Key: "no-policy-del"}, dashcontract.Principal{}); err != nil {
		t.Fatalf("delete without a policy: %v", err)
	}
}

func TestSecretsDelete_MissingKeyIsNotFound(t *testing.T) {
	v, _ := newTestVault(t)
	_, err := secretsDeleteHandler(Deps{Vault: v})(context.Background(), secretsDeleteRequest{Key: "nope"}, dashcontract.Principal{})
	if code := codeOf(err); code != dashcontract.CodeNotFound {
		t.Fatalf("delete of a missing key: code %q, err %v; want NOT_FOUND", code, err)
	}
}

// --- value never leaks ---

// TestSecretValueNeverLeaksIntoErrors sends a distinctive value on a
// failing create and a failing update and asserts it appears nowhere in the
// resulting error: not in Error(), not in the message, not in details.
func TestSecretValueNeverLeaksIntoErrors(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	const canary = "hunter2-canary"

	if _, err := v.Secrets().Set(ctx, "already-exists", []byte("orig"), testAppID); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, createErr := secretsCreateHandler(Deps{Vault: v})(ctx, secretsCreateRequest{Key: "already-exists", Value: canary}, dashcontract.Principal{})
	if createErr == nil {
		t.Fatal("expected create over an existing key to fail")
	}
	assertNoCanary(t, createErr, canary)

	_, updateErr := secretsUpdateHandler(Deps{Vault: v})(ctx, secretsUpdateRequest{Key: "does-not-exist", Value: canary}, dashcontract.Principal{})
	if updateErr == nil {
		t.Fatal("expected update of a missing key to fail")
	}
	assertNoCanary(t, updateErr, canary)
}

// assertNoCanary fails t if canary appears anywhere in err's text or in any
// field of a wrapped *contract.Error.
func assertNoCanary(t *testing.T, err error, canary string) {
	t.Helper()
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("err.Error() contains the submitted value: %v", err)
	}
	var ce *dashcontract.Error
	if errors.As(err, &ce) {
		if strings.Contains(ce.Message, canary) {
			t.Fatalf("contract.Error.Message contains the submitted value: %q", ce.Message)
		}
		for k, v := range ce.Details {
			if s, ok := v.(string); ok && strings.Contains(s, canary) {
				t.Fatalf("contract.Error.Details[%q] contains the submitted value: %q", k, s)
			}
		}
	}
}

// --- secrets.create / secrets.update / secrets.detail report the real alg ---

// TestSecretsListAndDetail_ReportAES256GCMForKeyedVault checks the other
// half of the encryptionAlg contract: newTestVault is configured with an
// encryption key, so a secret written through it must report the real
// algorithm, not just an empty string the way an unkeyed vault's rows do
// (covered by TestSecretsListAndDetail_ReportUnencryptedAlg above).
func TestSecretsListAndDetail_ReportAES256GCMForKeyedVault(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	const key = "encrypted-secret"
	if _, err := v.Secrets().Set(ctx, key, []byte("value"), testAppID); err != nil {
		t.Fatalf("seed: %v", err)
	}

	listOut, err := secretsListHandler(Deps{Vault: v})(ctx, secretsListRequest{}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var found *SecretSummary
	for i := range listOut.Secrets {
		if listOut.Secrets[i].Key == key {
			found = &listOut.Secrets[i]
		}
	}
	if found == nil {
		t.Fatalf("list did not include %q: %+v", key, listOut.Secrets)
	}
	if found.EncryptionAlg != "AES-256-GCM" {
		t.Errorf("list encryptionAlg = %q, want AES-256-GCM", found.EncryptionAlg)
	}

	detailOut, err := secretsDetailHandler(Deps{Vault: v})(ctx, secretsDetailRequest{Key: key}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if detailOut.Secret.EncryptionAlg != "AES-256-GCM" {
		t.Errorf("detail encryptionAlg = %q, want AES-256-GCM", detailOut.Secret.EncryptionAlg)
	}
}

// --- no wire TYPE reachable from any response type ever has a field named "value" ---
//
// This walks the response TYPES with reflection rather than inspecting a
// marshalled sample. A sample only shows fields that were actually set: a
// future Value field tagged json:"value,omitempty" left zero-valued on the
// sample would marshal to nothing and pass a JSON-based check anyway.
// Walking the type catches it regardless of what any one instance sets.
func TestNoWireTypeHasAValueField(t *testing.T) {
	responseTypes := []reflect.Type{
		reflect.TypeOf(secretsListResponse{}),
		reflect.TypeOf(secretsDetailResponse{}),
		reflect.TypeOf(secretsVersionsResponse{}),
		reflect.TypeOf(secretsCreateResponse{}),
		reflect.TypeOf(secretsUpdateResponse{}),
		reflect.TypeOf(secretsDeleteResponse{}),
	}
	visited := map[reflect.Type]bool{}
	for _, rt := range responseTypes {
		walkWireType(t, rt, visited)
	}
}

// walkWireType recursively visits typ and every type reachable from it
// through pointers, slices, arrays and maps, failing t if any struct
// field's JSON name is literally "value".
func walkWireType(t *testing.T, typ reflect.Type, visited map[reflect.Type]bool) {
	t.Helper()
	for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
		typ = typ.Elem()
	}
	if typ.Kind() == reflect.Map {
		walkWireType(t, typ.Elem(), visited)
		return
	}
	if typ.Kind() != reflect.Struct {
		return
	}
	if visited[typ] {
		return
	}
	visited[typ] = true

	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := f.Name
		if tag, ok := f.Tag.Lookup("json"); ok {
			if parts := strings.Split(tag, ","); parts[0] != "" {
				name = parts[0]
			}
		}
		if name == "value" {
			t.Errorf("%s.%s has JSON name %q: a wire type must never carry a raw secret value", typ.Name(), f.Name, name)
		}
		walkWireType(t, f.Type, visited)
	}
}

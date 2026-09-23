package contract

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

// --- no response type in this file ever carries a raw value ---

func TestNoResponseTypeCarriesAValueField(t *testing.T) {
	next := "2026-01-01T00:00:00Z"
	samples := map[string]any{
		"secretsListResponse": secretsListResponse{
			Secrets: []SecretSummary{{ID: "id", Key: "k", Version: 1, EncryptionAlg: "AES-256-GCM", AppID: testAppID}},
			Total:   1,
		},
		"secretsDetailResponse": secretsDetailResponse{
			Secret: SecretSummary{ID: "id", Key: "k", Version: 1, AppID: testAppID},
			Rotation: &RotationPolicySummary{
				ID: "rid", SecretKey: "k", Enabled: true, NextRotationAt: &next,
			},
			RecentAudit: []AuditSummary{{ID: "aid", Action: "secret.set", Outcome: "success"}},
		},
		"secretsVersionsResponse": secretsVersionsResponse{
			Versions: []SecretVersionSummary{{ID: "vid", Version: 1, CreatedBy: "tester"}},
		},
	}
	for name, sample := range samples {
		raw, err := json.Marshal(sample)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("%s: unmarshal: %v", name, err)
		}
		if containsValueField(m) {
			t.Errorf("%s JSON contains a field named \"value\": %s", name, raw)
		}
	}
}

// containsValueField walks a decoded JSON document looking for any object
// key literally named "value", at any depth.
func containsValueField(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		if _, ok := t["value"]; ok {
			return true
		}
		for _, child := range t {
			if containsValueField(child) {
				return true
			}
		}
	case []any:
		for _, child := range t {
			if containsValueField(child) {
				return true
			}
		}
	}
	return false
}

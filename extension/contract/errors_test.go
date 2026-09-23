package contract

import (
	"errors"
	"testing"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/vault"
)

func TestMapError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want dashcontract.ErrorCode
	}{
		{"secret not found", vault.ErrSecretNotFound, dashcontract.CodeNotFound},
		{"wrapped secret not found", errors.New("store: " + vault.ErrSecretNotFound.Error()), dashcontract.CodeInternal},
		{"rotation not found", vault.ErrRotationNotFound, dashcontract.CodeNotFound},
		{"decryption failed", vault.ErrDecryptionFailed, dashcontract.CodeUnavailable},
		{"anything else", errors.New("boom"), dashcontract.CodeInternal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapError(tc.err)
			var ce *dashcontract.Error
			if !errors.As(got, &ce) {
				t.Fatalf("mapError(%v) = %T, want *contract.Error", tc.err, got)
			}
			if ce.Code != tc.want {
				t.Errorf("mapError(%v) code = %q, want %q", tc.err, ce.Code, tc.want)
			}
		})
	}
	if mapError(nil) != nil {
		t.Errorf("mapError(nil) = %v, want nil", mapError(nil))
	}
}

// mapError must never let an internal error's own text reach the client:
// only the two fixed messages below are acceptable for CodeInternal and
// CodeUnavailable, whatever the underlying error says.
func TestMapError_NeverEchoesInternalErrorText(t *testing.T) {
	err := mapError(errors.New("dial tcp 10.0.0.1:5432: connection refused (password=hunter2)"))
	var ce *dashcontract.Error
	if !errors.As(err, &ce) {
		t.Fatalf("mapError = %T, want *contract.Error", err)
	}
	if ce.Message != "an internal error occurred" {
		t.Errorf("message = %q, leaked the underlying error text", ce.Message)
	}
}

func TestBadRequest(t *testing.T) {
	err := badRequest("key is required")
	var ce *dashcontract.Error
	if !errors.As(err, &ce) {
		t.Fatalf("badRequest = %T, want *contract.Error", err)
	}
	if ce.Code != dashcontract.CodeBadRequest || ce.Message != "key is required" {
		t.Errorf("badRequest = %+v", ce)
	}
}

func TestConflict(t *testing.T) {
	err := conflict("a secret with this key already exists")
	var ce *dashcontract.Error
	if !errors.As(err, &ce) {
		t.Fatalf("conflict = %T, want *contract.Error", err)
	}
	if ce.Code != dashcontract.CodeConflict || ce.Message != "a secret with this key already exists" {
		t.Errorf("conflict = %+v", ce)
	}
}

func TestRequireKey(t *testing.T) {
	if got, err := requireKey("  db-password  "); err != nil || got != "db-password" {
		t.Errorf("requireKey(padded) = %q, %v; want \"db-password\", nil", got, err)
	}
	if _, err := requireKey("   "); codeOf(err) != dashcontract.CodeBadRequest {
		t.Errorf("requireKey(blank) code = %q, want BAD_REQUEST", codeOf(err))
	}
	if _, err := requireKey(""); codeOf(err) != dashcontract.CodeBadRequest {
		t.Errorf("requireKey(empty) code = %q, want BAD_REQUEST", codeOf(err))
	}
}

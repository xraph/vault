package contract

import (
	"errors"
	"fmt"
	"testing"

	"github.com/xraph/forge"
	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/vault"
)

// recordingLogger is a forge.Logger that records Error calls and drops
// everything else.
type recordingLogger struct {
	forge.Logger
	errors []recordedLog
}

type recordedLog struct {
	msg    string
	fields map[string]any
}

func (l *recordingLogger) Error(msg string, fields ...forge.Field) {
	rec := recordedLog{msg: msg, fields: map[string]any{}}
	for _, f := range fields {
		rec.fields[f.Key()] = f.Value()
	}
	l.errors = append(l.errors, rec)
}

func newRecordingLogger() *recordingLogger {
	return &recordingLogger{Logger: forge.NewNoopLogger()}
}

func TestDepsMapError_LogsInternalErrorsOnly(t *testing.T) {
	logger := newRecordingLogger()
	deps := Deps{Logger: logger}

	cause := errors.New("dial tcp 10.0.0.1:5432: connection refused")
	got := deps.mapError("secrets.list", cause)

	var ce *dashcontract.Error
	if !errors.As(got, &ce) {
		t.Fatalf("mapError = %T, want *contract.Error", got)
	}
	if ce.Code != dashcontract.CodeInternal {
		t.Errorf("code = %q, want %q", ce.Code, dashcontract.CodeInternal)
	}
	if ce.Message != "an internal error occurred" {
		t.Errorf("message = %q, want the generic internal message", ce.Message)
	}

	if len(logger.errors) != 1 {
		t.Fatalf("Error calls = %d, want 1", len(logger.errors))
	}
	rec := logger.errors[0]
	if rec.fields["intent"] != "secrets.list" {
		t.Errorf("intent field = %v, want secrets.list", rec.fields["intent"])
	}
	if logged := fmt.Sprint(rec.fields["error"]); logged != cause.Error() {
		t.Errorf("error field = %q, want %q", logged, cause.Error())
	}

	// A domain error the client can act on is not an operator problem,
	// so it is mapped and not logged.
	for _, domainErr := range []error{vault.ErrSecretNotFound, vault.ErrRotationNotFound, vault.ErrDecryptionFailed} {
		if deps.mapError("secrets.detail", domainErr) == nil {
			t.Fatalf("mapError(%v) = nil", domainErr)
		}
	}
	if len(logger.errors) != 1 {
		t.Errorf("Error calls after domain errors = %d, want still 1", len(logger.errors))
	}

	if deps.mapError("secrets.list", nil) != nil {
		t.Error("mapError(nil) != nil")
	}
	if len(logger.errors) != 1 {
		t.Errorf("Error calls after nil = %d, want still 1", len(logger.errors))
	}
}

func TestDepsMapError_NilLoggerDoesNotLog(t *testing.T) {
	got := Deps{}.mapError("secrets.list", errors.New("boom"))
	var ce *dashcontract.Error
	if !errors.As(got, &ce) || ce.Code != dashcontract.CodeInternal {
		t.Fatalf("mapError = %v, want CodeInternal", got)
	}
}

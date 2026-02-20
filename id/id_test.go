package id

import (
	"database/sql/driver"
	"encoding/json"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name   string
		prefix Prefix
	}{
		{"secret", PrefixSecret},
		{"flag", PrefixFlag},
		{"rule", PrefixRule},
		{"config", PrefixConfig},
		{"override", PrefixOverride},
		{"rotation", PrefixRotation},
		{"version", PrefixVersion},
		{"audit", PrefixAudit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := New(tt.prefix)
			if id.IsNil() {
				t.Fatal("expected non-nil ID")
			}
			if id.IDPrefix() != tt.prefix {
				t.Fatalf("expected prefix %q, got %q", tt.prefix, id.IDPrefix())
			}
			s := id.String()
			if s == "" {
				t.Fatal("expected non-empty string")
			}
			if !strings.HasPrefix(s, string(tt.prefix)+"_") {
				t.Fatalf("expected string to start with %q_, got %q", tt.prefix, s)
			}
		})
	}
}

func TestNewUniqueness(t *testing.T) {
	a := NewSecretID()
	b := NewSecretID()
	if a.String() == b.String() {
		t.Fatal("expected unique IDs")
	}
}

func TestParse(t *testing.T) {
	original := NewSecretID()
	parsed, err := Parse(original.String())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.String() != original.String() {
		t.Fatalf("expected %q, got %q", original.String(), parsed.String())
	}
	if parsed.IDPrefix() != PrefixSecret {
		t.Fatalf("expected prefix %q, got %q", PrefixSecret, parsed.IDPrefix())
	}
}

func TestParseEmpty(t *testing.T) {
	parsed, err := Parse("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !parsed.IsNil() {
		t.Fatal("expected nil ID for empty string")
	}
	if parsed.String() != "" {
		t.Fatalf("expected empty string, got %q", parsed.String())
	}
}

func TestParseInvalid(t *testing.T) {
	tests := []string{
		"not-a-typeid",
		"missing_underscore",
		"_no_prefix",
	}
	for _, s := range tests {
		_, err := Parse(s)
		if err == nil {
			t.Fatalf("expected error for %q", s)
		}
	}
}

func TestParseWithPrefix(t *testing.T) {
	original := NewFlagID()
	parsed, err := ParseWithPrefix(original.String(), PrefixFlag)
	if err != nil {
		t.Fatalf("parse with prefix: %v", err)
	}
	if parsed.String() != original.String() {
		t.Fatalf("expected %q, got %q", original.String(), parsed.String())
	}
}

func TestParseWithPrefixMismatch(t *testing.T) {
	secretID := NewSecretID()
	_, err := ParseWithPrefix(secretID.String(), PrefixFlag)
	if err == nil {
		t.Fatal("expected error for prefix mismatch")
	}
	if !strings.Contains(err.Error(), "expected prefix") {
		t.Fatalf("expected prefix mismatch error, got: %v", err)
	}
}

func TestParseWithPrefixEmpty(t *testing.T) {
	_, err := ParseWithPrefix("", PrefixSecret)
	if err == nil {
		t.Fatal("expected error for empty string with prefix")
	}
}

func TestIDNilBehavior(t *testing.T) {
	var id ID
	if !id.IsNil() {
		t.Fatal("zero value should be nil")
	}
	if id.String() != "" {
		t.Fatalf("nil ID string should be empty, got %q", id.String())
	}
	if id.IDPrefix() != "" {
		t.Fatalf("nil ID prefix should be empty, got %q", id.IDPrefix())
	}
}

func TestMarshalText(t *testing.T) {
	original := NewConfigID()
	data, err := original.MarshalText()
	if err != nil {
		t.Fatalf("marshal text: %v", err)
	}
	if string(data) != original.String() {
		t.Fatalf("expected %q, got %q", original.String(), string(data))
	}
}

func TestUnmarshalText(t *testing.T) {
	original := NewConfigID()
	data, _ := original.MarshalText()

	var parsed ID
	if err := parsed.UnmarshalText(data); err != nil {
		t.Fatalf("unmarshal text: %v", err)
	}
	if parsed.String() != original.String() {
		t.Fatalf("expected %q, got %q", original.String(), parsed.String())
	}
}

func TestUnmarshalTextEmpty(t *testing.T) {
	var id ID
	if err := id.UnmarshalText([]byte("")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !id.IsNil() {
		t.Fatal("expected nil ID for empty text")
	}
}

func TestMarshalJSON(t *testing.T) {
	original := NewRuleID()
	data, err := original.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	expected := `"` + original.String() + `"`
	if string(data) != expected {
		t.Fatalf("expected %q, got %q", expected, string(data))
	}
}

func TestMarshalJSONNil(t *testing.T) {
	var id ID
	data, err := id.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal json nil: %v", err)
	}
	if string(data) != `""` {
		t.Fatalf("expected empty string JSON, got %q", string(data))
	}
}

func TestUnmarshalJSON(t *testing.T) {
	original := NewOverrideID()
	data, _ := original.MarshalJSON()

	var parsed ID
	if err := parsed.UnmarshalJSON(data); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}
	if parsed.String() != original.String() {
		t.Fatalf("expected %q, got %q", original.String(), parsed.String())
	}
}

func TestUnmarshalJSONNull(t *testing.T) {
	var id ID
	if err := id.UnmarshalJSON([]byte("null")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !id.IsNil() {
		t.Fatal("expected nil ID for null JSON")
	}
}

func TestUnmarshalJSONEmptyString(t *testing.T) {
	var id ID
	if err := id.UnmarshalJSON([]byte(`""`)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !id.IsNil() {
		t.Fatal("expected nil ID for empty string JSON")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	type wrapper struct {
		ID ID `json:"id"`
	}

	original := wrapper{ID: NewSecretID()}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed wrapper
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.ID.String() != original.ID.String() {
		t.Fatalf("expected %q, got %q", original.ID.String(), parsed.ID.String())
	}
}

func TestValue(t *testing.T) {
	original := NewSecretID()
	val, err := original.Value()
	if err != nil {
		t.Fatalf("value: %v", err)
	}
	s, ok := val.(string)
	if !ok {
		t.Fatalf("expected string, got %T", val)
	}
	if s != original.String() {
		t.Fatalf("expected %q, got %q", original.String(), s)
	}
}

func TestValueNil(t *testing.T) {
	var id ID
	val, err := id.Value()
	if err != nil {
		t.Fatalf("value nil: %v", err)
	}
	if val != nil {
		t.Fatalf("expected nil, got %v", val)
	}
}

func TestScanString(t *testing.T) {
	original := NewFlagID()
	var scanned ID
	if err := scanned.Scan(original.String()); err != nil {
		t.Fatalf("scan string: %v", err)
	}
	if scanned.String() != original.String() {
		t.Fatalf("expected %q, got %q", original.String(), scanned.String())
	}
}

func TestScanBytes(t *testing.T) {
	original := NewFlagID()
	var scanned ID
	if err := scanned.Scan([]byte(original.String())); err != nil {
		t.Fatalf("scan bytes: %v", err)
	}
	if scanned.String() != original.String() {
		t.Fatalf("expected %q, got %q", original.String(), scanned.String())
	}
}

func TestScanNil(t *testing.T) {
	var id ID
	if err := id.Scan(nil); err != nil {
		t.Fatalf("scan nil: %v", err)
	}
	if !id.IsNil() {
		t.Fatal("expected nil ID for nil scan")
	}
}

func TestScanUnsupported(t *testing.T) {
	var id ID
	if err := id.Scan(123); err == nil {
		t.Fatal("expected error for unsupported scan type")
	}
}

func TestDriverValueInterface(t *testing.T) {
	original := NewSecretID()
	var v driver.Valuer = original
	val, err := v.Value()
	if err != nil {
		t.Fatalf("driver value: %v", err)
	}
	if val.(string) != original.String() {
		t.Fatalf("expected %q, got %q", original.String(), val)
	}
}

// ──────────────────────────────────────────────────
// Convenience constructors tests
// ──────────────────────────────────────────────────

func TestConvenienceConstructors(t *testing.T) {
	tests := []struct {
		name string
		fn   func() ID
		pfix Prefix
	}{
		{"NewSecretID", NewSecretID, PrefixSecret},
		{"NewFlagID", NewFlagID, PrefixFlag},
		{"NewRuleID", NewRuleID, PrefixRule},
		{"NewConfigID", NewConfigID, PrefixConfig},
		{"NewOverrideID", NewOverrideID, PrefixOverride},
		{"NewRotationID", NewRotationID, PrefixRotation},
		{"NewVersionID", NewVersionID, PrefixVersion},
		{"NewAuditID", NewAuditID, PrefixAudit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := tt.fn()
			if id.IsNil() {
				t.Fatal("expected non-nil ID")
			}
			if id.IDPrefix() != tt.pfix {
				t.Fatalf("expected prefix %q, got %q", tt.pfix, id.IDPrefix())
			}
		})
	}
}

// ──────────────────────────────────────────────────
// Convenience parsers tests
// ──────────────────────────────────────────────────

func TestConvenienceParsers(t *testing.T) {
	tests := []struct {
		name    string
		newFn   func() ID
		parseFn func(string) (ID, error)
	}{
		{"ParseSecretID", NewSecretID, ParseSecretID},
		{"ParseFlagID", NewFlagID, ParseFlagID},
		{"ParseRuleID", NewRuleID, ParseRuleID},
		{"ParseConfigID", NewConfigID, ParseConfigID},
		{"ParseOverrideID", NewOverrideID, ParseOverrideID},
		{"ParseRotationID", NewRotationID, ParseRotationID},
		{"ParseVersionID", NewVersionID, ParseVersionID},
		{"ParseAuditID", NewAuditID, ParseAuditID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := tt.newFn()
			parsed, err := tt.parseFn(original.String())
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if parsed.String() != original.String() {
				t.Fatalf("expected %q, got %q", original.String(), parsed.String())
			}
		})
	}
}

func TestConvenienceParsersPrefixMismatch(t *testing.T) {
	secretID := NewSecretID()
	parsers := []struct {
		name    string
		parseFn func(string) (ID, error)
	}{
		{"ParseFlagID", ParseFlagID},
		{"ParseRuleID", ParseRuleID},
		{"ParseConfigID", ParseConfigID},
		{"ParseOverrideID", ParseOverrideID},
		{"ParseRotationID", ParseRotationID},
		{"ParseVersionID", ParseVersionID},
		{"ParseAuditID", ParseAuditID},
	}

	for _, tt := range parsers {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.parseFn(secretID.String())
			if err == nil {
				t.Fatalf("expected error parsing secret ID as %s", tt.name)
			}
		})
	}
}

func TestParseAny(t *testing.T) {
	tests := []func() ID{
		NewSecretID, NewFlagID, NewRuleID, NewConfigID,
		NewOverrideID, NewRotationID, NewVersionID, NewAuditID,
	}
	for _, fn := range tests {
		original := fn()
		parsed, err := ParseAny(original.String())
		if err != nil {
			t.Fatalf("parse any: %v", err)
		}
		if parsed.String() != original.String() {
			t.Fatalf("expected %q, got %q", original.String(), parsed.String())
		}
	}
}

package id_test

import (
	"strings"
	"testing"

	"github.com/xraph/vault/id"
)

func TestConstructors(t *testing.T) {
	tests := []struct {
		name   string
		newFn  func() id.ID
		prefix string
	}{
		{"SecretID", id.NewSecretID, "sec_"},
		{"FlagID", id.NewFlagID, "flag_"},
		{"RuleID", id.NewRuleID, "rule_"},
		{"ConfigID", id.NewConfigID, "cfg_"},
		{"OverrideID", id.NewOverrideID, "ovr_"},
		{"RotationID", id.NewRotationID, "rot_"},
		{"VersionID", id.NewVersionID, "ver_"},
		{"AuditID", id.NewAuditID, "vaudit_"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.newFn().String()
			if !strings.HasPrefix(got, tt.prefix) {
				t.Errorf("expected prefix %q, got %q", tt.prefix, got)
			}
		})
	}
}

func TestNew(t *testing.T) {
	i := id.New(id.PrefixSecret)
	if i.IsNil() {
		t.Fatal("expected non-nil ID")
	}
	if i.Prefix() != id.PrefixSecret {
		t.Errorf("expected prefix %q, got %q", id.PrefixSecret, i.Prefix())
	}
}

func TestParseRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		newFn   func() id.ID
		parseFn func(string) (id.ID, error)
	}{
		{"SecretID", id.NewSecretID, id.ParseSecretID},
		{"FlagID", id.NewFlagID, id.ParseFlagID},
		{"RuleID", id.NewRuleID, id.ParseRuleID},
		{"ConfigID", id.NewConfigID, id.ParseConfigID},
		{"OverrideID", id.NewOverrideID, id.ParseOverrideID},
		{"RotationID", id.NewRotationID, id.ParseRotationID},
		{"VersionID", id.NewVersionID, id.ParseVersionID},
		{"AuditID", id.NewAuditID, id.ParseAuditID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := tt.newFn()
			parsed, err := tt.parseFn(original.String())
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}
			if parsed.String() != original.String() {
				t.Errorf("round-trip mismatch: %q != %q", parsed.String(), original.String())
			}
		})
	}
}

func TestCrossTypeRejection(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		parseFn func(string) (id.ID, error)
	}{
		{"ParseSecretID rejects flag_", id.NewFlagID().String(), id.ParseSecretID},
		{"ParseFlagID rejects rule_", id.NewRuleID().String(), id.ParseFlagID},
		{"ParseRuleID rejects cfg_", id.NewConfigID().String(), id.ParseRuleID},
		{"ParseConfigID rejects ovr_", id.NewOverrideID().String(), id.ParseConfigID},
		{"ParseOverrideID rejects rot_", id.NewRotationID().String(), id.ParseOverrideID},
		{"ParseRotationID rejects ver_", id.NewVersionID().String(), id.ParseRotationID},
		{"ParseVersionID rejects sec_", id.NewSecretID().String(), id.ParseVersionID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.parseFn(tt.input)
			if err == nil {
				t.Errorf("expected error for cross-type parse of %q, got nil", tt.input)
			}
		})
	}
}

func TestParseAny(t *testing.T) {
	ids := []id.ID{
		id.NewSecretID(),
		id.NewFlagID(),
		id.NewRuleID(),
		id.NewConfigID(),
		id.NewOverrideID(),
		id.NewRotationID(),
		id.NewVersionID(),
		id.NewAuditID(),
	}

	for _, i := range ids {
		t.Run(i.String(), func(t *testing.T) {
			parsed, err := id.ParseAny(i.String())
			if err != nil {
				t.Fatalf("ParseAny(%q) failed: %v", i.String(), err)
			}
			if parsed.String() != i.String() {
				t.Errorf("round-trip mismatch: %q != %q", parsed.String(), i.String())
			}
		})
	}
}

func TestParseWithPrefix(t *testing.T) {
	i := id.NewSecretID()
	parsed, err := id.ParseWithPrefix(i.String(), id.PrefixSecret)
	if err != nil {
		t.Fatalf("ParseWithPrefix failed: %v", err)
	}
	if parsed.String() != i.String() {
		t.Errorf("mismatch: %q != %q", parsed.String(), i.String())
	}

	_, err = id.ParseWithPrefix(i.String(), id.PrefixFlag)
	if err == nil {
		t.Error("expected error for wrong prefix")
	}
}

func TestParseEmpty(t *testing.T) {
	_, err := id.Parse("")
	if err == nil {
		t.Error("expected error for empty string")
	}
}

func TestNilID(t *testing.T) {
	var i id.ID
	if !i.IsNil() {
		t.Error("zero-value ID should be nil")
	}
	if i.String() != "" {
		t.Errorf("expected empty string, got %q", i.String())
	}
	if i.Prefix() != "" {
		t.Errorf("expected empty prefix, got %q", i.Prefix())
	}
}

func TestMarshalUnmarshalText(t *testing.T) {
	original := id.NewSecretID()
	data, err := original.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText failed: %v", err)
	}

	var restored id.ID
	if unmarshalErr := restored.UnmarshalText(data); unmarshalErr != nil {
		t.Fatalf("UnmarshalText failed: %v", unmarshalErr)
	}
	if restored.String() != original.String() {
		t.Errorf("mismatch: %q != %q", restored.String(), original.String())
	}

	// Nil round-trip.
	var nilID id.ID
	data, err = nilID.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText(nil) failed: %v", err)
	}
	var restored2 id.ID
	if err := restored2.UnmarshalText(data); err != nil {
		t.Fatalf("UnmarshalText(nil) failed: %v", err)
	}
	if !restored2.IsNil() {
		t.Error("expected nil after round-trip of nil ID")
	}
}

func TestValueScan(t *testing.T) {
	original := id.NewFlagID()
	val, err := original.Value()
	if err != nil {
		t.Fatalf("Value failed: %v", err)
	}

	var scanned id.ID
	if scanErr := scanned.Scan(val); scanErr != nil {
		t.Fatalf("Scan failed: %v", scanErr)
	}
	if scanned.String() != original.String() {
		t.Errorf("mismatch: %q != %q", scanned.String(), original.String())
	}

	// Nil round-trip.
	var nilID id.ID
	val, err = nilID.Value()
	if err != nil {
		t.Fatalf("Value(nil) failed: %v", err)
	}
	if val != nil {
		t.Errorf("expected nil value for nil ID, got %v", val)
	}

	var scanned2 id.ID
	if err := scanned2.Scan(nil); err != nil {
		t.Fatalf("Scan(nil) failed: %v", err)
	}
	if !scanned2.IsNil() {
		t.Error("expected nil after scan of nil")
	}
}

func TestUniqueness(t *testing.T) {
	a := id.NewSecretID()
	b := id.NewSecretID()
	if a.String() == b.String() {
		t.Errorf("two consecutive NewSecretID() calls returned the same ID: %q", a.String())
	}
}

func TestBSONRoundTrip(t *testing.T) {
	original := id.NewSecretID()

	bsonType, data, err := original.MarshalBSONValue()
	if err != nil {
		t.Fatalf("MarshalBSONValue failed: %v", err)
	}
	if bsonType != 0x02 {
		t.Fatalf("expected BSON string type 0x02, got 0x%02x", bsonType)
	}

	var restored id.ID
	if unmarshalErr := restored.UnmarshalBSONValue(bsonType, data); unmarshalErr != nil {
		t.Fatalf("UnmarshalBSONValue failed: %v", unmarshalErr)
	}
	if restored.String() != original.String() {
		t.Errorf("BSON round-trip mismatch: %q != %q", restored.String(), original.String())
	}

	var nilID id.ID
	bsonType, data, err = nilID.MarshalBSONValue()
	if err != nil {
		t.Fatalf("MarshalBSONValue(nil) failed: %v", err)
	}
	if bsonType != 0x0A {
		t.Fatalf("expected BSON null type 0x0A, got 0x%02x", bsonType)
	}

	var restored2 id.ID
	if unmarshalErr := restored2.UnmarshalBSONValue(bsonType, data); unmarshalErr != nil {
		t.Fatalf("UnmarshalBSONValue(nil) failed: %v", unmarshalErr)
	}
	if !restored2.IsNil() {
		t.Error("expected nil after BSON round-trip of nil ID")
	}
}

func TestBSONUnmarshalInvalidType(t *testing.T) {
	var restored id.ID
	err := restored.UnmarshalBSONValue(0x01, []byte{0x00, 0x00, 0x00, 0x00})
	if err == nil {
		t.Error("expected error for invalid BSON type, got nil")
	}
}

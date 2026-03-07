// Package id defines TypeID-based identity types for all Vault entities.
//
// Every entity in Vault uses a single ID struct with a prefix that identifies
// the entity type. IDs are K-sortable (UUIDv7-based), globally unique,
// and URL-safe in the format "prefix_suffix".
package id

import (
	"database/sql/driver"
	"encoding/binary"
	"fmt"

	"go.jetify.com/typeid/v2"
)

// BSON type constants (avoids importing the mongo-driver bson package).
const (
	bsonTypeString byte = 0x02
	bsonTypeNull   byte = 0x0A
)

// Prefix identifies the entity type encoded in a TypeID.
type Prefix string

// Prefix constants for all Vault entity types.
const (
	PrefixSecret   Prefix = "sec"
	PrefixFlag     Prefix = "flag"
	PrefixRule     Prefix = "rule"
	PrefixConfig   Prefix = "cfg"
	PrefixOverride Prefix = "ovr"
	PrefixRotation Prefix = "rot"
	PrefixVersion  Prefix = "ver"
	PrefixAudit    Prefix = "vaudit"
)

// ID is the primary identifier type for all Vault entities.
// It wraps a TypeID providing a prefix-qualified, globally unique,
// sortable, URL-safe identifier in the format "prefix_suffix".
//
//nolint:recvcheck // Value receivers for read-only methods, pointer receivers for UnmarshalText/Scan.
type ID struct {
	inner typeid.TypeID
	valid bool
}

// Nil is the zero-value ID.
var Nil ID

// New generates a new globally unique ID with the given prefix.
// It panics if prefix is not a valid TypeID prefix (programming error).
func New(prefix Prefix) ID {
	tid, err := typeid.Generate(string(prefix))
	if err != nil {
		panic(fmt.Sprintf("id: invalid prefix %q: %v", prefix, err))
	}

	return ID{inner: tid, valid: true}
}

// Parse parses a TypeID string (e.g., "sec_01h2xcejqtf2nbrexx3vqjhp41")
// into an ID. Returns an error if the string is not valid.
func Parse(s string) (ID, error) {
	if s == "" {
		return Nil, fmt.Errorf("id: parse %q: empty string", s)
	}

	tid, err := typeid.Parse(s)
	if err != nil {
		return Nil, fmt.Errorf("id: parse %q: %w", s, err)
	}

	return ID{inner: tid, valid: true}, nil
}

// ParseWithPrefix parses a TypeID string and validates that its prefix
// matches the expected value.
func ParseWithPrefix(s string, expected Prefix) (ID, error) {
	parsed, err := Parse(s)
	if err != nil {
		return Nil, err
	}

	if parsed.Prefix() != expected {
		return Nil, fmt.Errorf("id: expected prefix %q, got %q", expected, parsed.Prefix())
	}

	return parsed, nil
}

// MustParse is like Parse but panics on error. Use for hardcoded ID values.
func MustParse(s string) ID {
	parsed, err := Parse(s)
	if err != nil {
		panic(fmt.Sprintf("id: must parse %q: %v", s, err))
	}

	return parsed
}

// MustParseWithPrefix is like ParseWithPrefix but panics on error.
func MustParseWithPrefix(s string, expected Prefix) ID {
	parsed, err := ParseWithPrefix(s, expected)
	if err != nil {
		panic(fmt.Sprintf("id: must parse with prefix %q: %v", expected, err))
	}

	return parsed
}

// ──────────────────────────────────────────────────
// Type aliases for backward compatibility
// ──────────────────────────────────────────────────

// SecretID is a type-safe identifier for secrets (prefix: "sec").
type SecretID = ID

// FlagID is a type-safe identifier for flags (prefix: "flag").
type FlagID = ID

// RuleID is a type-safe identifier for rules (prefix: "rule").
type RuleID = ID

// ConfigID is a type-safe identifier for configs (prefix: "cfg").
type ConfigID = ID

// OverrideID is a type-safe identifier for overrides (prefix: "ovr").
type OverrideID = ID

// RotationID is a type-safe identifier for rotations (prefix: "rot").
type RotationID = ID

// VersionID is a type-safe identifier for versions (prefix: "ver").
type VersionID = ID

// AuditID is a type-safe identifier for audit entries (prefix: "vaudit").
type AuditID = ID

// AnyID is a type alias that accepts any valid prefix.
type AnyID = ID

// ──────────────────────────────────────────────────
// Convenience constructors
// ──────────────────────────────────────────────────

// NewSecretID generates a new unique secret ID.
func NewSecretID() ID { return New(PrefixSecret) }

// NewFlagID generates a new unique flag ID.
func NewFlagID() ID { return New(PrefixFlag) }

// NewRuleID generates a new unique rule ID.
func NewRuleID() ID { return New(PrefixRule) }

// NewConfigID generates a new unique config ID.
func NewConfigID() ID { return New(PrefixConfig) }

// NewOverrideID generates a new unique override ID.
func NewOverrideID() ID { return New(PrefixOverride) }

// NewRotationID generates a new unique rotation ID.
func NewRotationID() ID { return New(PrefixRotation) }

// NewVersionID generates a new unique version ID.
func NewVersionID() ID { return New(PrefixVersion) }

// NewAuditID generates a new unique audit ID.
func NewAuditID() ID { return New(PrefixAudit) }

// ──────────────────────────────────────────────────
// Convenience parsers
// ──────────────────────────────────────────────────

// ParseSecretID parses a string and validates the "sec" prefix.
func ParseSecretID(s string) (ID, error) { return ParseWithPrefix(s, PrefixSecret) }

// ParseFlagID parses a string and validates the "flag" prefix.
func ParseFlagID(s string) (ID, error) { return ParseWithPrefix(s, PrefixFlag) }

// ParseRuleID parses a string and validates the "rule" prefix.
func ParseRuleID(s string) (ID, error) { return ParseWithPrefix(s, PrefixRule) }

// ParseConfigID parses a string and validates the "cfg" prefix.
func ParseConfigID(s string) (ID, error) { return ParseWithPrefix(s, PrefixConfig) }

// ParseOverrideID parses a string and validates the "ovr" prefix.
func ParseOverrideID(s string) (ID, error) { return ParseWithPrefix(s, PrefixOverride) }

// ParseRotationID parses a string and validates the "rot" prefix.
func ParseRotationID(s string) (ID, error) { return ParseWithPrefix(s, PrefixRotation) }

// ParseVersionID parses a string and validates the "ver" prefix.
func ParseVersionID(s string) (ID, error) { return ParseWithPrefix(s, PrefixVersion) }

// ParseAuditID parses a string and validates the "vaudit" prefix.
func ParseAuditID(s string) (ID, error) { return ParseWithPrefix(s, PrefixAudit) }

// ParseAny parses a string into an ID without type checking the prefix.
func ParseAny(s string) (ID, error) { return Parse(s) }

// ──────────────────────────────────────────────────
// ID methods
// ──────────────────────────────────────────────────

// String returns the full TypeID string representation (prefix_suffix).
// Returns an empty string for the Nil ID.
func (i ID) String() string {
	if !i.valid {
		return ""
	}

	return i.inner.String()
}

// Prefix returns the prefix component of this ID.
func (i ID) Prefix() Prefix {
	if !i.valid {
		return ""
	}

	return Prefix(i.inner.Prefix())
}

// IsNil reports whether this ID is the zero value.
func (i ID) IsNil() bool {
	return !i.valid
}

// MarshalText implements encoding.TextMarshaler.
func (i ID) MarshalText() ([]byte, error) {
	if !i.valid {
		return []byte{}, nil
	}

	return []byte(i.inner.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (i *ID) UnmarshalText(data []byte) error {
	if len(data) == 0 {
		*i = Nil

		return nil
	}

	parsed, err := Parse(string(data))
	if err != nil {
		return err
	}

	*i = parsed

	return nil
}

// MarshalBSONValue satisfies bson.ValueMarshaler (mongo-driver v2) so the ID
// is stored as a BSON string instead of an opaque struct. No bson import needed
// because Go uses structural typing for interface satisfaction.
func (i ID) MarshalBSONValue() (bsonType byte, data []byte, err error) {
	if !i.valid {
		return bsonTypeNull, nil, nil
	}

	s := i.inner.String()
	l := len(s) + 1 // length includes null terminator

	buf := make([]byte, 4+len(s)+1)
	binary.LittleEndian.PutUint32(buf, uint32(l)) //nolint:gosec // TypeID strings are <64 bytes; no overflow
	copy(buf[4:], s)
	// trailing 0x00 is already zero from make

	return bsonTypeString, buf, nil
}

// UnmarshalBSONValue satisfies bson.ValueUnmarshaler (mongo-driver v2).
func (i *ID) UnmarshalBSONValue(t byte, data []byte) error {
	if t == bsonTypeNull {
		*i = Nil

		return nil
	}

	if t != bsonTypeString {
		return fmt.Errorf("id: cannot unmarshal BSON type 0x%02x into ID", t)
	}

	if len(data) < 5 { //nolint:mnd // 4-byte length + at least 1 null terminator
		*i = Nil

		return nil
	}

	l := binary.LittleEndian.Uint32(data[:4])
	if l <= 1 { // empty string (just null terminator)
		*i = Nil

		return nil
	}

	s := string(data[4 : 4+l-1]) // exclude null terminator

	return i.UnmarshalText([]byte(s))
}

// Value implements driver.Valuer for database storage.
// Returns nil for the Nil ID so that optional foreign key columns store NULL.
func (i ID) Value() (driver.Value, error) {
	if !i.valid {
		return nil, nil //nolint:nilnil // nil is the canonical NULL for driver.Valuer
	}

	return i.inner.String(), nil
}

// Scan implements sql.Scanner for database retrieval.
func (i *ID) Scan(src any) error {
	if src == nil {
		*i = Nil

		return nil
	}

	switch v := src.(type) {
	case string:
		if v == "" {
			*i = Nil

			return nil
		}

		return i.UnmarshalText([]byte(v))
	case []byte:
		if len(v) == 0 {
			*i = Nil

			return nil
		}

		return i.UnmarshalText(v)
	default:
		return fmt.Errorf("id: cannot scan %T into ID", src)
	}
}

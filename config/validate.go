package config

import (
	"encoding/json"
	"fmt"
	"math"
	"time"
)

// The value types a config entry can carry and the write service accepts.
// Entry.ValueType is a free-form label in the store, so an entry stored with
// any other label is read-only to the write service.
const (
	TypeString   = "string"
	TypeInt      = "int"
	TypeFloat    = "float"
	TypeBool     = "bool"
	TypeJSON     = "json"
	TypeDuration = "duration"
)

// ValidationError is a refusal of caller input. Field names the part of the
// request at fault in the wire's own spelling, so a handler can hand it
// straight to the client.
type ValidationError struct {
	Field   string
	Message string
}

// Error returns "config: <field>: <message>".
func (e *ValidationError) Error() string {
	return "config: " + e.Field + ": " + e.Message
}

// KnownType reports whether t is one of the value types the write service
// supports.
func KnownType(t string) bool {
	switch t {
	case TypeString, TypeInt, TypeFloat, TypeBool, TypeJSON, TypeDuration:
		return true
	default:
		return false
	}
}

// maxSafeInt is the largest integer a float64 (and so a JSON number) holds
// exactly: 2^53.
const maxSafeInt = 1 << 53

// ValidateValue reports whether v is an acceptable value for an entry of
// type valueType. No backend checks: an int entry holding "abc" is stored
// happily, and every typed read then silently answers the caller's fallback.
//
// A value that arrives through JSON is a float64, so int accepts a float64
// with no fractional part, up to 2^53 in magnitude, as well as any Go
// integer. duration is a string time.ParseDuration accepts. nil is refused
// for every type except json, where it is the JSON null.
//
// An unknown valueType returns a *ValidationError naming "valueType". Any
// other refusal is a plain error describing the value; the caller knows
// which field it came from and wraps it.
func ValidateValue(valueType string, v any) error {
	switch valueType {
	case TypeString:
		if _, ok := v.(string); !ok {
			return fmt.Errorf("must be a string, got %s", DescribeValue(v))
		}
	case TypeInt:
		return validateInt(v)
	case TypeFloat:
		return validateFloat(v)
	case TypeBool:
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("must be a boolean, got %s", DescribeValue(v))
		}
	case TypeJSON:
		if v == nil {
			return nil
		}
		if _, err := json.Marshal(v); err != nil {
			return fmt.Errorf("must be JSON-encodable: %w", err)
		}
	case TypeDuration:
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("must be a duration string such as \"30s\", got %s", DescribeValue(v))
		}
		if _, err := time.ParseDuration(s); err != nil {
			return fmt.Errorf("must be a duration such as \"30s\" or \"1h30m\": %w", err)
		}
	default:
		return &ValidationError{Field: "valueType", Message: fmt.Sprintf("unknown type %q", valueType)}
	}
	return nil
}

func validateInt(v any) error {
	switch n := v.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return nil
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) || n != math.Trunc(n) {
			return fmt.Errorf("must be a whole number, got %v", n)
		}
		if math.Abs(n) > maxSafeInt {
			return fmt.Errorf("must not exceed 2^53 in magnitude, got %v", n)
		}
		return nil
	default:
		return fmt.Errorf("must be a whole number, got %s", DescribeValue(v))
	}
}

func validateFloat(v any) error {
	switch n := v.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return nil
	case float32:
		return finite(float64(n))
	case float64:
		return finite(n)
	default:
		return fmt.Errorf("must be a number, got %s", DescribeValue(v))
	}
}

func finite(n float64) error {
	if math.IsNaN(n) || math.IsInf(n, 0) {
		return fmt.Errorf("must be a finite number, got %v", n)
	}
	return nil
}

// DescribeValue names v's kind ("a string", "an object", "null") without
// echoing its value, which for a bad value could be anything the caller
// sent. It is what the write service uses to word a refusal.
func DescribeValue(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "a boolean"
	case string:
		return "a string"
	case float32, float64, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return "a number"
	case []any:
		return "an array"
	case map[string]any:
		return "an object"
	default:
		return fmt.Sprintf("%T", v)
	}
}

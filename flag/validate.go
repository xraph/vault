package flag

import (
	"encoding/json"
	"fmt"
	"math"
)

// ValidationError is a refusal of caller input. Field names the part of the
// request at fault in the wire's own spelling (for example
// "rules[0].returnValue"), so a handler can hand it straight to the client.
type ValidationError struct {
	Field   string
	Message string
}

// Error returns "flag: <field>: <message>".
func (e *ValidationError) Error() string {
	return "flag: " + e.Field + ": " + e.Message
}

// maxSafeInt is the largest integer a float64 (and so a JSON number) holds
// exactly: 2^53.
const maxSafeInt = 1 << 53

// ValidateValue reports whether v is an acceptable value for a flag of type
// t. It exists because no backend checks: a bool flag whose default is the
// string "true" is stored happily, and every typed read then silently
// answers the caller's fallback.
//
// A value that arrives through JSON is a float64, so int accepts a float64
// with no fractional part, up to 2^53 in magnitude, as well as any Go
// integer. nil is refused for every type except json, where it is the JSON
// null.
func ValidateValue(t Type, v any) error {
	switch t {
	case TypeBool:
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("must be a boolean, got %s", describe(v))
		}
	case TypeString:
		if _, ok := v.(string); !ok {
			return fmt.Errorf("must be a string, got %s", describe(v))
		}
	case TypeInt:
		return validateInt(v)
	case TypeFloat:
		return validateFloat(v)
	case TypeJSON:
		if v == nil {
			return nil
		}
		if _, err := json.Marshal(v); err != nil {
			return fmt.Errorf("must be JSON-encodable: %w", err)
		}
	default:
		return fmt.Errorf("unknown flag type %q", t)
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
		return fmt.Errorf("must be a whole number, got %s", describe(v))
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
		return fmt.Errorf("must be a number, got %s", describe(v))
	}
}

func finite(n float64) error {
	if math.IsNaN(n) || math.IsInf(n, 0) {
		return fmt.Errorf("must be a finite number, got %v", n)
	}
	return nil
}

// describe names v's kind without echoing its value, which for a bad
// default could be anything the caller sent.
func describe(v any) string {
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

package flag_test

import (
	"errors"
	"math"
	"testing"

	"github.com/xraph/vault/flag"
)

func TestValidateValue(t *testing.T) {
	type custom struct{ A int }
	cases := []struct {
		name string
		typ  flag.Type
		v    any
		ok   bool
	}{
		{"bool true", flag.TypeBool, true, true},
		{"bool string", flag.TypeBool, "true", false},
		{"bool nil", flag.TypeBool, nil, false},
		{"bool number", flag.TypeBool, 1.0, false},

		{"string", flag.TypeString, "x", true},
		{"string empty", flag.TypeString, "", true},
		{"string number", flag.TypeString, 1.0, false},
		{"string nil", flag.TypeString, nil, false},

		{"int 2.0", flag.TypeInt, 2.0, true},
		{"int 1.5", flag.TypeInt, 1.5, false},
		{"int go int", flag.TypeInt, 5, true},
		{"int int32", flag.TypeInt, int32(5), true},
		{"int int64", flag.TypeInt, int64(-5), true},
		{"int uint8", flag.TypeInt, uint8(5), true},
		{"int 2^53", flag.TypeInt, 9007199254740992.0, true},
		{"int over 2^53", flag.TypeInt, 9007199254740994.0, false},
		{"int -2^53", flag.TypeInt, -9007199254740992.0, true},
		{"int NaN", flag.TypeInt, math.NaN(), false},
		{"int Inf", flag.TypeInt, math.Inf(1), false},
		{"int string", flag.TypeInt, "5", false},
		{"int nil", flag.TypeInt, nil, false},
		{"int bool", flag.TypeInt, true, false},

		{"float 1.5", flag.TypeFloat, 1.5, true},
		{"float int", flag.TypeFloat, 3, true},
		{"float float32", flag.TypeFloat, float32(1.5), true},
		{"float string", flag.TypeFloat, "1.5", false},
		{"float NaN", flag.TypeFloat, math.NaN(), false},
		{"float Inf", flag.TypeFloat, math.Inf(-1), false},
		{"float nil", flag.TypeFloat, nil, false},

		{"json nil", flag.TypeJSON, nil, true},
		{"json map", flag.TypeJSON, map[string]any{"a": []any{1.0}}, true},
		{"json string", flag.TypeJSON, "text", true},
		{"json struct", flag.TypeJSON, custom{A: 1}, true},
		{"json chan", flag.TypeJSON, make(chan int), false},
		{"json func", flag.TypeJSON, func() {}, false},
		{"json NaN", flag.TypeJSON, math.NaN(), false},

		{"unknown type", "yaml", "x", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := flag.ValidateValue(tc.typ, tc.v)
			if (err == nil) != tc.ok {
				t.Errorf("ValidateValue(%s, %v) = %v, want ok=%v", tc.typ, tc.v, err, tc.ok)
			}
		})
	}
}

func TestValidationErrorText(t *testing.T) {
	err := error(&flag.ValidationError{Field: "key", Message: "is required"})
	if got := err.Error(); got != "flag: key: is required" {
		t.Errorf("Error() = %q", got)
	}
	var ve *flag.ValidationError
	if !errors.As(err, &ve) || ve.Field != "key" {
		t.Errorf("errors.As failed: %v", ve)
	}
}

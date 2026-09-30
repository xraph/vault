package config_test

import (
	"errors"
	"math"
	"testing"

	cfgpkg "github.com/xraph/vault/config"
)

func TestValidateValue(t *testing.T) {
	type custom struct{ A int }
	cases := []struct {
		name string
		typ  string
		v    any
		ok   bool
	}{
		{"string", cfgpkg.TypeString, "x", true},
		{"string empty", cfgpkg.TypeString, "", true},
		{"string number", cfgpkg.TypeString, 1.0, false},
		{"string nil", cfgpkg.TypeString, nil, false},

		{"int 2.0", cfgpkg.TypeInt, 2.0, true},
		{"int 1.5", cfgpkg.TypeInt, 1.5, false},
		{"int abc", cfgpkg.TypeInt, "abc", false},
		{"int go int", cfgpkg.TypeInt, 5, true},
		{"int int64", cfgpkg.TypeInt, int64(-5), true},
		{"int 2^53", cfgpkg.TypeInt, 9007199254740992.0, true},
		{"int over 2^53", cfgpkg.TypeInt, 9007199254740994.0, false},
		{"int NaN", cfgpkg.TypeInt, math.NaN(), false},
		{"int Inf", cfgpkg.TypeInt, math.Inf(-1), false},
		{"int nil", cfgpkg.TypeInt, nil, false},

		{"float 1.5", cfgpkg.TypeFloat, 1.5, true},
		{"float int", cfgpkg.TypeFloat, 3, true},
		{"float string", cfgpkg.TypeFloat, "1.5", false},
		{"float NaN", cfgpkg.TypeFloat, math.NaN(), false},
		{"float nil", cfgpkg.TypeFloat, nil, false},

		{"bool", cfgpkg.TypeBool, false, true},
		{"bool string", cfgpkg.TypeBool, "true", false},
		{"bool nil", cfgpkg.TypeBool, nil, false},

		{"json nil", cfgpkg.TypeJSON, nil, true},
		{"json map", cfgpkg.TypeJSON, map[string]any{"a": 1.0}, true},
		{"json struct", cfgpkg.TypeJSON, custom{A: 1}, true},
		{"json chan", cfgpkg.TypeJSON, make(chan int), false},
		{"json NaN", cfgpkg.TypeJSON, math.NaN(), false},

		{"duration", cfgpkg.TypeDuration, "1h30m", true},
		{"duration soon", cfgpkg.TypeDuration, "soon", false},
		{"duration number", cfgpkg.TypeDuration, 5.0, false},
		{"duration nil", cfgpkg.TypeDuration, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := cfgpkg.ValidateValue(tc.typ, tc.v)
			if (err == nil) != tc.ok {
				t.Errorf("ValidateValue(%q, %v) = %v, want ok=%v", tc.typ, tc.v, err, tc.ok)
			}
		})
	}
}

func TestValidateValueUnknownTypeNamesValueType(t *testing.T) {
	err := cfgpkg.ValidateValue("yaml", "a: 1")
	var ve *cfgpkg.ValidationError
	if !errors.As(err, &ve) || ve.Field != "valueType" {
		t.Fatalf("err = %v, want *ValidationError for valueType", err)
	}
	if got, want := ve.Error(), "config: valueType: "+ve.Message; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestKnownType(t *testing.T) {
	for _, ok := range []string{"string", "int", "float", "bool", "json", "duration"} {
		if !cfgpkg.KnownType(ok) {
			t.Errorf("KnownType(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", "yaml", "Int", "bogus"} {
		if cfgpkg.KnownType(bad) {
			t.Errorf("KnownType(%q) = true", bad)
		}
	}
}

package flag_test

import (
	"testing"

	"github.com/xraph/vault"
	vflag "github.com/xraph/vault/flag"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/store/memory"
)

func newServiceWithFlag(t *testing.T, key string, defaultVal any, flagType vflag.Type) *vflag.Service {
	t.Helper()
	s := memory.New()
	err := s.DefineFlag(bg(), &vflag.Definition{
		Entity:       vault.NewEntity(),
		ID:           id.NewFlagID(),
		Key:          key,
		Type:         flagType,
		DefaultValue: defaultVal,
		Enabled:      true,
		AppID:        testApp,
	})
	if err != nil {
		t.Fatal(err)
	}
	engine := vflag.NewEngine(s)
	return vflag.NewService(engine, vflag.WithAppID(testApp))
}

func TestServiceBool(t *testing.T) {
	svc := newServiceWithFlag(t, "bool-flag", true, vflag.TypeBool)

	val := svc.Bool(bg(), "bool-flag", false)
	if val != true {
		t.Errorf("Bool = %v, want true", val)
	}
}

func TestServiceBoolDefault(t *testing.T) {
	s := memory.New()
	engine := vflag.NewEngine(s)
	svc := vflag.NewService(engine, vflag.WithAppID(testApp))

	// Flag doesn't exist -> returns default.
	val := svc.Bool(bg(), "nonexistent", true)
	if val != true {
		t.Errorf("Bool = %v, want true (default)", val)
	}
}

func TestServiceBoolTypeMismatch(t *testing.T) {
	svc := newServiceWithFlag(t, "string-flag", "not-a-bool", vflag.TypeString)

	val := svc.Bool(bg(), "string-flag", true)
	if val != true {
		t.Errorf("Bool = %v, want true (type mismatch default)", val)
	}
}

func TestServiceString(t *testing.T) {
	svc := newServiceWithFlag(t, "str-flag", "hello", vflag.TypeString)

	val := svc.String(bg(), "str-flag", "default")
	if val != "hello" {
		t.Errorf("String = %q, want %q", val, "hello")
	}
}

func TestServiceStringTypeMismatch(t *testing.T) {
	svc := newServiceWithFlag(t, "int-flag", 42, vflag.TypeInt)

	val := svc.String(bg(), "int-flag", "fallback")
	if val != "fallback" {
		t.Errorf("String = %q, want %q (type mismatch default)", val, "fallback")
	}
}

func TestServiceInt(t *testing.T) {
	svc := newServiceWithFlag(t, "int-flag", 42, vflag.TypeInt)

	val := svc.Int(bg(), "int-flag", 0)
	if val != 42 {
		t.Errorf("Int = %d, want 42", val)
	}
}

func TestServiceIntFromFloat(t *testing.T) {
	svc := newServiceWithFlag(t, "float-as-int", float64(99), vflag.TypeFloat)

	val := svc.Int(bg(), "float-as-int", 0)
	if val != 99 {
		t.Errorf("Int = %d, want 99 (from float64)", val)
	}
}

func TestServiceIntTypeMismatch(t *testing.T) {
	svc := newServiceWithFlag(t, "bool-flag2", true, vflag.TypeBool)

	val := svc.Int(bg(), "bool-flag2", 7)
	if val != 7 {
		t.Errorf("Int = %d, want 7 (type mismatch default)", val)
	}
}

func TestServiceFloat(t *testing.T) {
	svc := newServiceWithFlag(t, "float-flag", 3.14, vflag.TypeFloat)

	val := svc.Float(bg(), "float-flag", 0.0)
	if val != 3.14 {
		t.Errorf("Float = %f, want 3.14", val)
	}
}

func TestServiceFloatFromInt(t *testing.T) {
	svc := newServiceWithFlag(t, "int-as-float", 10, vflag.TypeInt)

	val := svc.Float(bg(), "int-as-float", 0.0)
	if val != 10.0 {
		t.Errorf("Float = %f, want 10.0 (from int)", val)
	}
}

func TestServiceJSON(t *testing.T) {
	cfg := map[string]any{
		"max_retries": float64(3),
		"timeout":     "30s",
	}
	svc := newServiceWithFlag(t, "json-flag", cfg, vflag.TypeJSON)

	var target map[string]any
	err := svc.JSON(bg(), "json-flag", &target)
	if err != nil {
		t.Fatal(err)
	}
	if target["timeout"] != "30s" {
		t.Errorf("timeout = %v, want %q", target["timeout"], "30s")
	}
	if target["max_retries"] != float64(3) {
		t.Errorf("max_retries = %v, want 3", target["max_retries"])
	}
}

func TestServiceJSONFromString(t *testing.T) {
	svc := newServiceWithFlag(t, "json-str", `{"key":"val"}`, vflag.TypeJSON)

	var target map[string]string
	err := svc.JSON(bg(), "json-str", &target)
	if err != nil {
		t.Fatal(err)
	}
	if target["key"] != "val" {
		t.Errorf("key = %q, want %q", target["key"], "val")
	}
}

func TestServiceJSONNotFound(t *testing.T) {
	s := memory.New()
	engine := vflag.NewEngine(s)
	svc := vflag.NewService(engine, vflag.WithAppID(testApp))

	var target map[string]any
	err := svc.JSON(bg(), "nonexistent", &target)
	if err == nil {
		t.Fatal("expected error for nonexistent JSON flag")
	}
}

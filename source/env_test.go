package source_test

import (
	"errors"
	"testing"

	"github.com/xraph/vault/source"
)

func TestEnvGet(t *testing.T) {
	t.Setenv("MYAPP_DB_HOST", "localhost")

	env := source.NewEnv("MYAPP")
	val, err := env.Get(bg(), "db-host")
	if err != nil {
		t.Fatal(err)
	}
	if val.Raw != "localhost" {
		t.Errorf("Raw = %q, want %q", val.Raw, "localhost")
	}
	if val.Source != "env" {
		t.Errorf("Source = %q, want %q", val.Source, "env")
	}
}

func TestEnvGetNoPrefix(t *testing.T) {
	t.Setenv("LOG_LEVEL", "debug")

	env := source.NewEnv("")
	val, err := env.Get(bg(), "log-level")
	if err != nil {
		t.Fatal(err)
	}
	if val.Raw != "debug" {
		t.Errorf("Raw = %q", val.Raw)
	}
}

func TestEnvGetMissing(t *testing.T) {
	env := source.NewEnv("")
	_, err := env.Get(bg(), "definitely-not-set-xyz")
	if !errors.Is(err, source.ErrKeyNotFound) {
		t.Errorf("got %v, want ErrKeyNotFound", err)
	}
}

func TestEnvName(t *testing.T) {
	env := source.NewEnv("")
	if env.Name() != "env" {
		t.Errorf("Name = %q", env.Name())
	}
}

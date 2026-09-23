package contract

import (
	"strings"
	"testing"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/forge/extensions/dashboard/contract/loader"
)

func TestManifest_Loads(t *testing.T) {
	m, err := loader.Load(strings.NewReader(string(manifestYAML)), "vault/contract/manifest.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if m.Contributor.Name != "vault" {
		t.Errorf("contributor name = %q, want vault", m.Contributor.Name)
	}
	// secrets.list, secrets.detail, secrets.versions, secrets.create,
	// secrets.update, secrets.delete. A later task appends rotation
	// intents; bump this count when it does.
	if got := len(m.Intents); got != 6 {
		t.Errorf("intents = %d, want 6", got)
	}
}

func TestManifest_Validates(t *testing.T) {
	m, err := loader.Load(strings.NewReader(string(manifestYAML)), "vault/contract/manifest.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := loader.Validate(m, dashcontract.NewWardenRegistry()); err != nil {
		t.Errorf("validate: %v", err)
	}
}

func TestManifest_RegistersWithRegistry(t *testing.T) {
	reg := dashcontract.NewRegistry()
	m, err := loader.Load(strings.NewReader(string(manifestYAML)), "vault/contract/manifest.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := reg.Register(m); err != nil {
		t.Fatalf("register: %v", err)
	}
	queries := []string{"secrets.list", "secrets.detail", "secrets.versions"}
	commands := []string{"secrets.create", "secrets.update", "secrets.delete"}
	for _, name := range queries {
		intent, ok := reg.Intent("vault", name, 1)
		if !ok {
			t.Fatalf("expected %s to be registered", name)
		}
		if intent.Kind != "query" {
			t.Errorf("%s kind = %q, want query", name, intent.Kind)
		}
	}
	for _, name := range commands {
		intent, ok := reg.Intent("vault", name, 1)
		if !ok {
			t.Fatalf("expected %s to be registered", name)
		}
		if intent.Kind != "command" {
			t.Errorf("%s kind = %q, want command", name, intent.Kind)
		}
	}
}

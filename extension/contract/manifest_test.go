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
	// secrets.update, secrets.delete, rotation.policies, rotation.detail,
	// rotation.savePolicy, rotation.deletePolicy, rotation.rotateNow, flags.list,
	// flags.detail, flags.evaluate, flags.create, flags.update, flags.delete,
	// flags.setEnabled, flags.setRules, flags.setTenantOverride,
	// flags.deleteTenantOverride.
	if got := len(m.Intents); got != 21 {
		t.Errorf("intents = %d, want 21", got)
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
	queries := []string{"secrets.list", "secrets.detail", "secrets.versions", "rotation.policies", "rotation.detail", "flags.list", "flags.detail", "flags.evaluate"}
	commands := []string{"secrets.create", "secrets.update", "secrets.delete", "rotation.savePolicy", "rotation.deletePolicy", "rotation.rotateNow",
		"flags.create", "flags.update", "flags.delete", "flags.setEnabled", "flags.setRules", "flags.setTenantOverride", "flags.deleteTenantOverride"}
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

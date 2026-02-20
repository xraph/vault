package plugin_test

import (
	"context"
	"sync"
	"testing"

	"github.com/xraph/vault/crypto"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/plugin"
	"github.com/xraph/vault/source"
)

// ──────────────────────────────────────────────────
// Test plugin implementations
// ──────────────────────────────────────────────────

// basicPlugin only implements Plugin.
type basicPlugin struct{ name string }

func (p *basicPlugin) Name() string { return p.name }

// sourcePlugin implements Plugin + SourceProvider.
type sourcePlugin struct {
	name     string
	src      source.Source
	priority int
}

func (p *sourcePlugin) Name() string          { return p.name }
func (p *sourcePlugin) Source() source.Source { return p.src }
func (p *sourcePlugin) Priority() int         { return p.priority }

// evalPlugin implements Plugin + FlagEvaluator.
type evalPlugin struct {
	name     string
	evalName string
	result   bool
}

func (p *evalPlugin) Name() string          { return p.name }
func (p *evalPlugin) EvaluatorName() string { return p.evalName }
func (p *evalPlugin) Evaluate(_ context.Context, _ *flag.Rule, _, _ string) (bool, error) {
	return p.result, nil
}

// lifecyclePlugin implements Plugin + OnInit + OnShutdown.
type lifecyclePlugin struct {
	name     string
	initDone bool
	shutdown bool
}

func (p *lifecyclePlugin) Name() string                       { return p.name }
func (p *lifecyclePlugin) OnInit(_ context.Context) error     { p.initDone = true; return nil }
func (p *lifecyclePlugin) OnShutdown(_ context.Context) error { p.shutdown = true; return nil }

// multiPlugin implements many interfaces.
type multiPlugin struct {
	name       string
	accessKeys []string
	configKeys []string
}

func (p *multiPlugin) Name() string                       { return p.name }
func (p *multiPlugin) OnInit(_ context.Context) error     { return nil }
func (p *multiPlugin) OnShutdown(_ context.Context) error { return nil }
func (p *multiPlugin) OnSecretAccess(_ context.Context, key, _ string) error {
	p.accessKeys = append(p.accessKeys, key)
	return nil
}
func (p *multiPlugin) OnConfigChange(_ context.Context, key string, _, _ any) error {
	p.configKeys = append(p.configKeys, key)
	return nil
}
func (p *multiPlugin) EncryptionKeyProvider() crypto.EncryptionKeyProvider { return nil }
func (p *multiPlugin) RotationName() string                                { return "multi-rotation" }
func (p *multiPlugin) Rotate(_ context.Context, _ string, current []byte) ([]byte, error) {
	return append(current, '-', 'r'), nil
}

// dummySource is a minimal Source for testing.
type dummySource struct{}

func (dummySource) Name() string                                                { return "dummy" }
func (dummySource) Get(_ context.Context, _ string) (*source.Value, error)      { return nil, nil }
func (dummySource) List(_ context.Context, _ string) ([]*source.Value, error)   { return nil, nil }
func (dummySource) Watch(_ context.Context, _ string, _ source.WatchFunc) error { return nil }
func (dummySource) Close() error                                                { return nil }

// ──────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────

func TestRegisterBasicPlugin(t *testing.T) {
	r := plugin.NewRegistry()
	r.Register(&basicPlugin{name: "basic"})

	plugins := r.Plugins()
	if len(plugins) != 1 {
		t.Fatalf("plugins: got %d, want 1", len(plugins))
	}
	if plugins[0].Name() != "basic" {
		t.Errorf("name: got %q", plugins[0].Name())
	}
}

func TestRegisterSourceProvider(t *testing.T) {
	r := plugin.NewRegistry()
	r.Register(&sourcePlugin{name: "my-src", src: dummySource{}, priority: 10})

	providers := r.SourceProviders()
	if len(providers) != 1 {
		t.Fatalf("source providers: got %d, want 1", len(providers))
	}
	if providers[0].Priority() != 10 {
		t.Errorf("priority: got %d", providers[0].Priority())
	}
}

func TestRegisterFlagEvaluator(t *testing.T) {
	r := plugin.NewRegistry()
	r.Register(&evalPlugin{name: "custom-eval", evalName: "geo-check", result: true})

	ev := r.FlagEvaluatorByName("geo-check")
	if ev == nil {
		t.Fatal("evaluator not found")
	}

	result, err := ev.Evaluate(context.Background(), &flag.Rule{}, "t1", "u1")
	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Error("expected true from evaluator")
	}
}

func TestFlagEvaluatorNotFound(t *testing.T) {
	r := plugin.NewRegistry()
	if ev := r.FlagEvaluatorByName("nonexistent"); ev != nil {
		t.Error("expected nil for nonexistent evaluator")
	}
}

func TestLifecycleHooks(t *testing.T) {
	r := plugin.NewRegistry()
	lc := &lifecyclePlugin{name: "lifecycle"}
	r.Register(lc)

	initHooks := r.InitHooks()
	if len(initHooks) != 1 {
		t.Fatalf("init hooks: got %d, want 1", len(initHooks))
	}

	shutdownHooks := r.ShutdownHooks()
	if len(shutdownHooks) != 1 {
		t.Fatalf("shutdown hooks: got %d, want 1", len(shutdownHooks))
	}

	_ = initHooks[0].OnInit(context.Background())
	if !lc.initDone {
		t.Error("OnInit was not called")
	}

	_ = shutdownHooks[0].OnShutdown(context.Background())
	if !lc.shutdown {
		t.Error("OnShutdown was not called")
	}
}

func TestMultiCapabilityPlugin(t *testing.T) {
	r := plugin.NewRegistry()
	mp := &multiPlugin{name: "multi"}
	r.Register(mp)

	if len(r.Plugins()) != 1 {
		t.Errorf("plugins: got %d", len(r.Plugins()))
	}
	if len(r.InitHooks()) != 1 {
		t.Errorf("init hooks: got %d", len(r.InitHooks()))
	}
	if len(r.ShutdownHooks()) != 1 {
		t.Errorf("shutdown hooks: got %d", len(r.ShutdownHooks()))
	}
	if len(r.SecretAccessHooks()) != 1 {
		t.Errorf("secret access hooks: got %d", len(r.SecretAccessHooks()))
	}
	if len(r.ConfigChangeHooks()) != 1 {
		t.Errorf("config change hooks: got %d", len(r.ConfigChangeHooks()))
	}
	if len(r.EncryptionProviders()) != 1 {
		t.Errorf("encryption providers: got %d", len(r.EncryptionProviders()))
	}
	if r.RotationStrategyByName("multi-rotation") == nil {
		t.Error("rotation strategy not found")
	}
}

func TestConcurrentRegister(t *testing.T) {
	r := plugin.NewRegistry()

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			r.Register(&basicPlugin{name: "p"})
			_ = n
		}(i)
	}
	wg.Wait()

	if len(r.Plugins()) != 50 {
		t.Errorf("plugins: got %d, want 50", len(r.Plugins()))
	}
}

func TestRotationStrategyNotFound(t *testing.T) {
	r := plugin.NewRegistry()
	if s := r.RotationStrategyByName("missing"); s != nil {
		t.Error("expected nil for missing strategy")
	}
}

func TestSecretAccessHookExecution(t *testing.T) {
	r := plugin.NewRegistry()
	mp := &multiPlugin{name: "hook-test"}
	r.Register(mp)

	hooks := r.SecretAccessHooks()
	_ = hooks[0].OnSecretAccess(context.Background(), "my-secret", "access")

	if len(mp.accessKeys) != 1 || mp.accessKeys[0] != "my-secret" {
		t.Errorf("access keys: got %v", mp.accessKeys)
	}
}

func TestConfigChangeHookExecution(t *testing.T) {
	r := plugin.NewRegistry()
	mp := &multiPlugin{name: "cfg-hook"}
	r.Register(mp)

	hooks := r.ConfigChangeHooks()
	_ = hooks[0].OnConfigChange(context.Background(), "pool.size", 10, 50)

	if len(mp.configKeys) != 1 || mp.configKeys[0] != "pool.size" {
		t.Errorf("config keys: got %v", mp.configKeys)
	}
}

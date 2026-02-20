package plugin

import (
	"log/slog"
	"sync"
)

// RegistryOption configures the Registry.
type RegistryOption func(*Registry)

// WithLogger sets the logger for the registry.
func WithLogger(l *slog.Logger) RegistryOption {
	return func(r *Registry) { r.logger = l }
}

// Registry manages plugin registration and discovery.
// It uses type-switch discovery to categorize plugins by capability at registration time.
type Registry struct {
	mu sync.RWMutex

	plugins         []Plugin
	onInit          []OnInit
	onShutdown      []OnShutdown
	sourceProviders []SourceProvider
	encProviders    []EncryptionProvider
	flagEvaluators  map[string]FlagEvaluator // evaluatorName → evaluator
	secretHooks     []OnSecretAccess
	configHooks     []OnConfigChange
	rotationStrats  map[string]RotationStrategy // rotationName → strategy

	logger *slog.Logger
}

// NewRegistry creates a plugin registry.
func NewRegistry(opts ...RegistryOption) *Registry {
	r := &Registry{
		flagEvaluators: make(map[string]FlagEvaluator),
		rotationStrats: make(map[string]RotationStrategy),
		logger:         slog.Default(),
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Register adds a plugin to the registry. It discovers all implemented
// capability interfaces via type assertion and registers the plugin in
// the appropriate internal collections.
func (r *Registry) Register(p Plugin) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.plugins = append(r.plugins, p)

	if v, ok := p.(OnInit); ok {
		r.onInit = append(r.onInit, v)
	}
	if v, ok := p.(OnShutdown); ok {
		r.onShutdown = append(r.onShutdown, v)
	}
	if v, ok := p.(SourceProvider); ok {
		r.sourceProviders = append(r.sourceProviders, v)
	}
	if v, ok := p.(EncryptionProvider); ok {
		r.encProviders = append(r.encProviders, v)
	}
	if v, ok := p.(FlagEvaluator); ok {
		r.flagEvaluators[v.EvaluatorName()] = v
	}
	if v, ok := p.(OnSecretAccess); ok {
		r.secretHooks = append(r.secretHooks, v)
	}
	if v, ok := p.(OnConfigChange); ok {
		r.configHooks = append(r.configHooks, v)
	}
	if v, ok := p.(RotationStrategy); ok {
		r.rotationStrats[v.RotationName()] = v
	}

	r.logger.Info("plugin: registered", "name", p.Name())
}

// ──────────────────────────────────────────────────
// Accessors
// ──────────────────────────────────────────────────

// Plugins returns all registered plugins.
func (r *Registry) Plugins() []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]Plugin{}, r.plugins...)
}

// InitHooks returns all plugins that implement OnInit.
func (r *Registry) InitHooks() []OnInit {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]OnInit{}, r.onInit...)
}

// ShutdownHooks returns all plugins that implement OnShutdown.
func (r *Registry) ShutdownHooks() []OnShutdown {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]OnShutdown{}, r.onShutdown...)
}

// SourceProviders returns all source-providing plugins.
func (r *Registry) SourceProviders() []SourceProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]SourceProvider{}, r.sourceProviders...)
}

// EncryptionProviders returns all encryption key providers.
func (r *Registry) EncryptionProviders() []EncryptionProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]EncryptionProvider{}, r.encProviders...)
}

// FlagEvaluatorByName returns the flag evaluator with the given name, or nil.
func (r *Registry) FlagEvaluatorByName(name string) FlagEvaluator {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.flagEvaluators[name]
}

// SecretAccessHooks returns all plugins that implement OnSecretAccess.
func (r *Registry) SecretAccessHooks() []OnSecretAccess {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]OnSecretAccess{}, r.secretHooks...)
}

// ConfigChangeHooks returns all plugins that implement OnConfigChange.
func (r *Registry) ConfigChangeHooks() []OnConfigChange {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]OnConfigChange{}, r.configHooks...)
}

// RotationStrategyByName returns the rotation strategy with the given name, or nil.
func (r *Registry) RotationStrategyByName(name string) RotationStrategy {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.rotationStrats[name]
}

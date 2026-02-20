package source

import (
	"context"
	"os"
	"strings"
)

// Env reads configuration from environment variables.
type Env struct {
	prefix string // optional prefix to strip
}

// NewEnv creates an Env source. If prefix is non-empty, keys are looked up
// as PREFIX_KEY (uppercased, dashes replaced with underscores).
func NewEnv(prefix string) *Env {
	return &Env{prefix: prefix}
}

// Name returns "env".
func (e *Env) Name() string { return "env" }

// Get reads the key from os.Getenv. Keys are normalized: uppercased, dashes → underscores.
func (e *Env) Get(_ context.Context, key string) (*Value, error) {
	envKey := e.envKey(key)
	raw := os.Getenv(envKey)
	if raw == "" {
		return nil, ErrKeyNotFound
	}
	return &Value{Key: key, Raw: raw, Source: "env"}, nil
}

// List is not supported for environment variables; returns nil.
func (e *Env) List(_ context.Context, _ string) ([]*Value, error) {
	return nil, nil
}

// Watch is not supported for environment variables; returns nil immediately.
func (e *Env) Watch(_ context.Context, _ string, _ WatchFunc) error {
	return nil
}

// Close is a no-op.
func (e *Env) Close() error { return nil }

func (e *Env) envKey(key string) string {
	k := strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
	if e.prefix != "" {
		return strings.ToUpper(e.prefix) + "_" + k
	}
	return k
}

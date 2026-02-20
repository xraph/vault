package crypto

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// EnvKeyProvider reads the encryption key from an environment variable.
// The key can be hex-encoded or base64-encoded (auto-detected).
type EnvKeyProvider struct {
	envVar string
}

// NewEnvKeyProvider creates a provider that reads the key from the given env var.
func NewEnvKeyProvider(envVar string) *EnvKeyProvider {
	return &EnvKeyProvider{envVar: envVar}
}

// GetKey reads and decodes the encryption key from the environment variable.
func (p *EnvKeyProvider) GetKey(_ context.Context) ([]byte, error) {
	raw := os.Getenv(p.envVar)
	if raw == "" {
		return nil, fmt.Errorf("crypto: env var %q is empty or not set", p.envVar)
	}
	return decodeKey(raw)
}

// RotateKey is not supported by the environment provider.
func (p *EnvKeyProvider) RotateKey(_ context.Context) ([]byte, error) {
	return nil, errors.New("crypto: env provider does not support key rotation")
}

// decodeKey auto-detects hex or base64 encoding and decodes to raw bytes.
func decodeKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)

	// Try hex first (64 hex chars = 32 bytes).
	if len(raw) == 64 {
		key, err := hex.DecodeString(raw)
		if err == nil && len(key) == 32 {
			return key, nil
		}
	}

	// Try base64 (44 base64 chars = 32 bytes).
	key, err := base64.StdEncoding.DecodeString(raw)
	if err == nil && len(key) == 32 {
		return key, nil
	}

	// Try base64 URL encoding.
	key, err = base64.URLEncoding.DecodeString(raw)
	if err == nil && len(key) == 32 {
		return key, nil
	}

	// Try raw base64 (no padding).
	key, err = base64.RawStdEncoding.DecodeString(raw)
	if err == nil && len(key) == 32 {
		return key, nil
	}

	return nil, fmt.Errorf("crypto: unable to decode key from %q (expected 32-byte hex or base64)", raw[:min(len(raw), 10)]+"...")
}

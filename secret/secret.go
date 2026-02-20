// Package secret provides the secret entity types and store interface.
package secret

import (
	"time"

	"github.com/xraph/vault"
	"github.com/xraph/vault/id"
)

// Secret represents a stored secret with its encrypted value.
type Secret struct {
	vault.Entity
	ID              id.ID             `json:"id"`
	Key             string            `json:"key"`
	Value           []byte            `json:"-"` // decrypted value — never serialized
	EncryptedValue  []byte            `json:"-"` // encrypted at rest
	Version         int64             `json:"version"`
	EncryptionAlg   string            `json:"encryption_alg"`
	EncryptionKeyID string            `json:"encryption_key_id"`
	ExpiresAt       *time.Time        `json:"expires_at,omitempty"`
	AppID           string            `json:"app_id"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// Meta is the public metadata for a secret (never includes the value).
type Meta struct {
	ID        id.ID             `json:"id"`
	Key       string            `json:"key"`
	Version   int64             `json:"version"`
	ExpiresAt *time.Time        `json:"expires_at,omitempty"`
	AppID     string            `json:"app_id"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// Version represents a historical version of a secret.
type Version struct {
	ID             id.ID     `json:"id"`
	SecretKey      string    `json:"secret_key"`
	AppID          string    `json:"app_id"`
	Version        int64     `json:"version"`
	EncryptedValue []byte    `json:"-"`
	CreatedBy      string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
}

// ListOpts configures list queries for secrets.
type ListOpts struct {
	Limit  int
	Offset int
	AppID  string
}

// ToMeta creates a Meta from a Secret.
func (s *Secret) ToMeta() *Meta {
	return &Meta{
		ID:        s.ID,
		Key:       s.Key,
		Version:   s.Version,
		ExpiresAt: s.ExpiresAt,
		AppID:     s.AppID,
		Metadata:  s.Metadata,
		CreatedAt: s.CreatedAt,
		UpdatedAt: s.UpdatedAt,
	}
}

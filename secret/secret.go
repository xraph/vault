// Package secret provides the secret entity types and store interface.
package secret

import (
	"time"

	"github.com/xraph/vault/core"
	"github.com/xraph/vault/id"
)

// Secret represents a stored secret with its encrypted value.
type Secret struct {
	core.Entity
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
	ID      id.ID  `json:"id"`
	Key     string `json:"key"`
	Version int64  `json:"version"`
	// EncryptionAlg names the algorithm the stored value was encrypted with.
	// Empty means the value is NOT encrypted: it was written while no
	// encryption key was configured and is stored as given. A caller that
	// displays secrets must treat empty as "not encrypted" rather than as
	// "unknown", because it is the state every unconfigured Vault produces.
	EncryptionAlg string            `json:"encryption_alg,omitempty"`
	ExpiresAt     *time.Time        `json:"expires_at,omitempty"`
	AppID         string            `json:"app_id"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

// Version represents a historical version of a secret.
type Version struct {
	ID             id.ID  `json:"id"`
	SecretKey      string `json:"secret_key"`
	AppID          string `json:"app_id"`
	Version        int64  `json:"version"`
	EncryptedValue []byte `json:"-"`
	// EncryptionAlg is the algorithm this version's bytes were written with.
	// nil means the row predates the column and nobody has classified it yet:
	// readers fall back to the secret's current algorithm. A non-nil empty
	// string means the version was recorded as stored without encryption.
	EncryptionAlg *string   `json:"-"`
	CreatedBy     string    `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
}

// VersionEncryptionCounts tallies the version rows of one app by what is
// known about their encryption.
type VersionEncryptionCounts struct {
	// Plaintext is the number of versions recorded as stored without
	// encryption (algorithm recorded as empty).
	Plaintext int64
	// Unrecorded is the number of versions whose algorithm was never recorded.
	Unrecorded int64
}

// ListOpts configures list queries for secrets.
//
// The expiry bounds are half-open so the two views of "expired" and "expiring"
// never overlap: ExpiresAfter is exclusive (expires_at > t) and ExpiresBefore
// is inclusive (expires_at <= t). Expired secrets are ExpiresBefore = now. The
// ones expiring within 30 days are ExpiresAfter = now, ExpiresBefore =
// now+30d. Setting either bound also excludes secrets with no expiry, and
// orders the result by expiry, then key.
type ListOpts struct {
	Limit         int
	Offset        int
	AppID         string
	ExpiresAfter  *time.Time
	ExpiresBefore *time.Time
}

// HasExpiryBound reports whether either expiry bound is set.
func (o ListOpts) HasExpiryBound() bool {
	return o.ExpiresAfter != nil || o.ExpiresBefore != nil
}

// ToMeta creates a Meta from a Secret.
func (s *Secret) ToMeta() *Meta {
	return &Meta{
		ID:            s.ID,
		Key:           s.Key,
		Version:       s.Version,
		EncryptionAlg: s.EncryptionAlg,
		ExpiresAt:     s.ExpiresAt,
		AppID:         s.AppID,
		Metadata:      s.Metadata,
		CreatedAt:     s.CreatedAt,
		UpdatedAt:     s.UpdatedAt,
	}
}

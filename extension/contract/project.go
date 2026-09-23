package contract

import (
	"time"

	"github.com/xraph/vault/audit"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/secret"
)

// SecretSummary is the wire projection of a secret's metadata. It never
// carries a value: only secrets.create and secrets.update ever put one on
// the wire, and only in their request, never a response.
type SecretSummary struct {
	ID      string `json:"id"`
	Key     string `json:"key"`
	Version int64  `json:"version"`
	// EncryptionAlg names the algorithm the stored value was encrypted
	// with. It has no omitempty: an empty string must reach the client as
	// "", because absence and "not encrypted" must not be confusable, and
	// "" is what every row written by an unconfigured Vault produces.
	EncryptionAlg string            `json:"encryptionAlg"`
	ExpiresAt     *string           `json:"expiresAt,omitempty"` // RFC3339
	AppID         string            `json:"appId"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	CreatedAt     string            `json:"createdAt"`
	UpdatedAt     string            `json:"updatedAt"`
}

// SecretVersionSummary is the wire projection of one historical version's
// metadata. Like SecretSummary, it never carries a value.
type SecretVersionSummary struct {
	ID        string `json:"id"`
	Version   int64  `json:"version"`
	CreatedBy string `json:"createdBy,omitempty"`
	CreatedAt string `json:"createdAt"`
}

// RotationPolicySummary is the wire projection of a rotation policy.
type RotationPolicySummary struct {
	ID              string `json:"id"`
	SecretKey       string `json:"secretKey"`
	IntervalSeconds int64  `json:"intervalSeconds"`
	Enabled         bool   `json:"enabled"`
	// Rotatable reports whether an application has registered a rotator
	// for this key. A policy without one will never rotate, however due it
	// gets: the loop logs an error every minute and changes nothing.
	Rotatable      bool    `json:"rotatable"`
	LastRotatedAt  *string `json:"lastRotatedAt,omitempty"`
	NextRotationAt *string `json:"nextRotationAt,omitempty"` // omitted when disabled
	CreatedAt      string  `json:"createdAt"`
	UpdatedAt      string  `json:"updatedAt"`
}

// RotationRecordSummary is the wire projection of one completed rotation
// event.
type RotationRecordSummary struct {
	ID         string `json:"id"`
	OldVersion int64  `json:"oldVersion"`
	NewVersion int64  `json:"newVersion"`
	RotatedBy  string `json:"rotatedBy,omitempty"`
	RotatedAt  string `json:"rotatedAt"`
}

// AuditSummary is the wire projection of one audit log entry, trimmed to
// what a secret or rotation detail page shows.
type AuditSummary struct {
	ID        string `json:"id"`
	Action    string `json:"action"`
	Outcome   string `json:"outcome"`
	UserID    string `json:"userId,omitempty"`
	CreatedAt string `json:"createdAt"`
}

// formatTime renders t as UTC RFC3339, the wire format every timestamp in
// this package uses.
func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// formatTimePtr is formatTime for an optional timestamp: nil in, nil out.
func formatTimePtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := formatTime(*t)
	return &s
}

// projectSecretSummary projects a secret.Meta onto its wire type.
func projectSecretSummary(m *secret.Meta) SecretSummary {
	return SecretSummary{
		ID:            m.ID.String(),
		Key:           m.Key,
		Version:       m.Version,
		EncryptionAlg: m.EncryptionAlg,
		ExpiresAt:     formatTimePtr(m.ExpiresAt),
		AppID:         m.AppID,
		Metadata:      m.Metadata,
		CreatedAt:     formatTime(m.CreatedAt),
		UpdatedAt:     formatTime(m.UpdatedAt),
	}
}

// projectSecretVersionSummary projects a secret.Version onto its wire type.
func projectSecretVersionSummary(v *secret.Version) SecretVersionSummary {
	return SecretVersionSummary{
		ID:        v.ID.String(),
		Version:   v.Version,
		CreatedBy: v.CreatedBy,
		CreatedAt: formatTime(v.CreatedAt),
	}
}

// projectRotationPolicy projects a rotation.Policy onto its wire type.
// rotatable is looked up by the caller (rotation.Manager.RotatorKeys),
// because Policy itself has no notion of which keys have a registered
// rotator. NextRotationAt is projected as nil whenever the policy is
// disabled, whatever the stored value says: a disabled policy has no next
// rotation.
func projectRotationPolicy(p *rotation.Policy, rotatable bool) RotationPolicySummary {
	var next *string
	if p.Enabled {
		next = formatTimePtr(p.NextRotationAt)
	}
	return RotationPolicySummary{
		ID:              p.ID.String(),
		SecretKey:       p.SecretKey,
		IntervalSeconds: int64(p.Interval / time.Second),
		Enabled:         p.Enabled,
		Rotatable:       rotatable,
		LastRotatedAt:   formatTimePtr(p.LastRotatedAt),
		NextRotationAt:  next,
		CreatedAt:       formatTime(p.CreatedAt),
		UpdatedAt:       formatTime(p.UpdatedAt),
	}
}

// projectRotationRecord projects a rotation.Record onto its wire type.
func projectRotationRecord(r *rotation.Record) RotationRecordSummary {
	return RotationRecordSummary{
		ID:         r.ID.String(),
		OldVersion: r.OldVersion,
		NewVersion: r.NewVersion,
		RotatedBy:  r.RotatedBy,
		RotatedAt:  formatTime(r.RotatedAt),
	}
}

// projectAuditSummary projects an audit.Entry onto its wire type.
func projectAuditSummary(e *audit.Entry) AuditSummary {
	return AuditSummary{
		ID:        e.ID.String(),
		Action:    e.Action,
		Outcome:   e.Outcome,
		UserID:    e.UserID,
		CreatedAt: formatTime(e.CreatedAt),
	}
}

// isRotatable reports whether key appears in the sorted list a
// rotation.Manager's RotatorKeys returns.
func isRotatable(keys []string, key string) bool {
	for _, k := range keys {
		if k == key {
			return true
		}
	}
	return false
}

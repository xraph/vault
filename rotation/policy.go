// Package rotation provides secret rotation policy entities and store interface.
package rotation

import (
	"time"

	"github.com/xraph/vault"
	"github.com/xraph/vault/id"
)

// Policy represents a secret rotation policy.
type Policy struct {
	vault.Entity
	ID             id.ID         `json:"id"`
	SecretKey      string        `json:"secret_key"`
	AppID          string        `json:"app_id"`
	Interval       time.Duration `json:"interval"`
	Enabled        bool          `json:"enabled"`
	LastRotatedAt  *time.Time    `json:"last_rotated_at,omitempty"`
	NextRotationAt *time.Time    `json:"next_rotation_at,omitempty"`
}

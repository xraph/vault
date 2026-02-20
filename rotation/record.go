package rotation

import (
	"time"

	"github.com/xraph/vault/id"
)

// Record records a completed rotation event.
type Record struct {
	ID         id.ID     `json:"id"`
	SecretKey  string    `json:"secret_key"`
	AppID      string    `json:"app_id"`
	OldVersion int64     `json:"old_version"`
	NewVersion int64     `json:"new_version"`
	RotatedBy  string    `json:"rotated_by"`
	RotatedAt  time.Time `json:"rotated_at"`
}

// ListOpts configures list queries for rotation records.
type ListOpts struct {
	Limit  int
	Offset int
}

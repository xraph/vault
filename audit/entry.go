// Package audit provides audit log entries and store interface.
package audit

import (
	"time"

	"github.com/xraph/vault/id"
)

// Entry represents a single audit log entry.
type Entry struct {
	ID        id.ID          `json:"id"`
	Action    string         `json:"action"`
	Resource  string         `json:"resource"`
	Key       string         `json:"key"`
	AppID     string         `json:"app_id"`
	TenantID  string         `json:"tenant_id,omitempty"`
	UserID    string         `json:"user_id,omitempty"`
	IP        string         `json:"ip,omitempty"`
	Outcome   string         `json:"outcome"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

// ListOpts configures list queries for audit entries.
type ListOpts struct {
	Limit  int
	Offset int
}

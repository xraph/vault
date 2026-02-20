// Package override provides per-tenant config override entities and store interface.
package override

import (
	"github.com/xraph/vault"
	"github.com/xraph/vault/id"
)

// Override represents a per-tenant override for a config entry.
type Override struct {
	vault.Entity
	ID       id.ID             `json:"id"`
	Key      string            `json:"key"`
	Value    any               `json:"value"`
	AppID    string            `json:"app_id"`
	TenantID string            `json:"tenant_id"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ListOpts configures list queries for overrides.
type ListOpts struct {
	Limit  int
	Offset int
}

// Package config provides runtime configuration entries and store interface.
package config

import (
	"time"

	"github.com/xraph/vault"
	"github.com/xraph/vault/id"
)

// Entry represents a runtime configuration entry.
type Entry struct {
	vault.Entity
	ID          id.ID             `json:"id"`
	Key         string            `json:"key"`
	Value       any               `json:"value"`
	ValueType   string            `json:"value_type"`
	Version     int64             `json:"version"`
	Description string            `json:"description"`
	AppID       string            `json:"app_id"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// EntryVersion represents a historical version of a config entry.
type EntryVersion struct {
	ID        id.ID     `json:"id"`
	ConfigKey string    `json:"config_key"`
	AppID     string    `json:"app_id"`
	Version   int64     `json:"version"`
	Value     any       `json:"value"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// ListOpts configures list queries for config entries.
type ListOpts struct {
	Limit  int
	Offset int
	AppID  string
}

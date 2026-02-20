// Package flag provides feature flag definitions, targeting rules, and evaluation.
package flag

import (
	"github.com/xraph/vault"
	"github.com/xraph/vault/id"
)

// Type represents the value type of a feature flag.
type Type string

// Flag value types.
const (
	TypeBool   Type = "bool"
	TypeString Type = "string"
	TypeInt    Type = "int"
	TypeFloat  Type = "float"
	TypeJSON   Type = "json"
)

// Definition represents a feature flag definition.
type Definition struct {
	vault.Entity
	ID           id.ID             `json:"id"`
	Key          string            `json:"key"`
	Type         Type              `json:"type"`
	DefaultValue any               `json:"default_value"`
	Description  string            `json:"description"`
	Tags         []string          `json:"tags,omitempty"`
	Variants     []Variant         `json:"variants,omitempty"`
	Enabled      bool              `json:"enabled"`
	AppID        string            `json:"app_id"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// Variant represents a named flag variant.
type Variant struct {
	Value       any    `json:"value"`
	Description string `json:"description"`
}

// ListOpts configures list queries for flag definitions.
type ListOpts struct {
	Limit  int
	Offset int
	AppID  string
}

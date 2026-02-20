package vault

import "time"

// Entity is the base type embedded by all Vault entities.
// It provides standard timestamp fields.
type Entity struct {
	CreatedAt time.Time `json:"created_at" bun:"created_at,notnull,default:current_timestamp"`
	UpdatedAt time.Time `json:"updated_at" bun:"updated_at,notnull,default:current_timestamp"`
}

// NewEntity creates a new Entity with both timestamps set to now (UTC).
func NewEntity() Entity {
	now := time.Now().UTC()
	return Entity{CreatedAt: now, UpdatedAt: now}
}

// Touch updates the UpdatedAt timestamp to now (UTC).
func (e *Entity) Touch() {
	e.UpdatedAt = time.Now().UTC()
}

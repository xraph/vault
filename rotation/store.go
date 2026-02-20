package rotation

import "context"

// Store defines the persistence interface for rotation policies.
type Store interface {
	// SaveRotationPolicy creates or updates a rotation policy.
	SaveRotationPolicy(ctx context.Context, p *Policy) error

	// GetRotationPolicy retrieves a rotation policy by secret key and app ID.
	GetRotationPolicy(ctx context.Context, key, appID string) (*Policy, error)

	// ListRotationPolicies returns all rotation policies for an app.
	ListRotationPolicies(ctx context.Context, appID string) ([]*Policy, error)

	// DeleteRotationPolicy removes a rotation policy.
	DeleteRotationPolicy(ctx context.Context, key, appID string) error

	// RecordRotation records a completed rotation event.
	RecordRotation(ctx context.Context, r *Record) error

	// ListRotationRecords returns rotation history for a secret.
	ListRotationRecords(ctx context.Context, key, appID string, opts ListOpts) ([]*Record, error)
}

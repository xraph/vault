package rotation

import (
	"context"
	"time"
)

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

	// CountRotationPolicies returns the total number of rotation policies for
	// an app, independent of any paging.
	CountRotationPolicies(ctx context.Context, appID string) (int64, error)

	// ClaimDueRotation atomically claims a due policy for one rotation run.
	// If the policy for key and appID exists, is enabled, and its
	// NextRotationAt is set and before now, it sets NextRotationAt to until
	// and returns true. Otherwise it changes nothing and returns false.
	// Exactly one of several concurrent callers can win a given due time.
	//
	// "Before now" is the scheduled loop's own test, now.After(next), so a
	// policy due at exactly now is not yet due. A missing policy is not an
	// error: it returns false and a nil error, like any other policy that is
	// not due. Implementations compare and store now and until in UTC.
	ClaimDueRotation(ctx context.Context, key, appID string, now, until time.Time) (bool, error)
}

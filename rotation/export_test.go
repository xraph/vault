package rotation

import "context"

// CheckDuePoliciesForTest runs one pass of the scheduled loop's body, so the
// external test package can drive it without waiting on a ticker.
func (m *Manager) CheckDuePoliciesForTest(ctx context.Context) { m.checkDuePolicies(ctx) }

package confy

import "context"

// PollForTest runs one watch poll, so the external test package can drive
// it without waiting on a ticker.
func (s *VaultConfigSource) PollForTest(ctx context.Context, callback func(map[string]any)) {
	s.pollAndNotify(ctx, callback)
}

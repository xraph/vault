package source

import "context"

// PollOnceForTest runs one watch poll, so the external test package can
// drive it without waiting on a ticker.
func (d *Database) PollOnceForTest(ctx context.Context) { d.pollOnce(ctx) }

package rotation

import (
	"context"
	"testing"
	"time"
)

// A second Start while the loop is already running must not replace it.
// Before this test's fix, Start unconditionally created a new context,
// cancel func and done channel and started a second goroutine, so the
// first loop's goroutine was orphaned: nothing held its cancel func any
// more, and it ran forever on its own ticker. This test is internal
// (package rotation) because the only reliable way to observe the leak is
// to check that the done channel Start hands out does not change on a
// second call while already running.
func TestStartTwiceRunsOneLoop(t *testing.T) {
	m := NewManager(nil, nil, WithCheckInterval(10*time.Millisecond))

	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	firstDone := m.done

	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("second Start: %v", err)
	}
	if m.done != firstDone {
		t.Error("a second Start replaced the running loop's done channel; the first loop's goroutine is now orphaned with nothing left to cancel it")
	}

	// Stop must return promptly: nothing should be left waiting on an
	// orphaned first loop that nobody can cancel any more.
	mustReturnPromptly(t, "Stop", func() error { return m.Stop(context.Background()) })

	// A further Stop, with nothing running, must also return promptly.
	mustReturnPromptly(t, "second Stop", func() error { return m.Stop(context.Background()) })

	// Start after Stop must actually restart the loop, not silently no-op
	// because some stale state still says it's running.
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start after Stop: %v", err)
	}
	if m.done == firstDone {
		t.Error("Start after Stop reused the earlier done channel; the loop was not actually restarted")
	}

	mustReturnPromptly(t, "final Stop", func() error { return m.Stop(context.Background()) })
}

func mustReturnPromptly(t *testing.T, name string, fn func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("%s returned an error: %v", name, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("%s did not return within 2s", name)
	}
}

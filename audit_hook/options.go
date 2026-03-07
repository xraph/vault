package audithook

import log "github.com/xraph/go-utils/log"

// Option configures the Extension.
type Option func(*Extension)

// WithActions limits the extension to only record the specified actions.
// If not set, all actions are recorded.
func WithActions(actions ...string) Option {
	return func(e *Extension) {
		e.enabled = make(map[string]bool, len(actions))
		for _, a := range actions {
			e.enabled[a] = true
		}
	}
}

// WithLogger sets the logger for the extension.
func WithLogger(l log.Logger) Option {
	return func(e *Extension) { e.logger = l }
}

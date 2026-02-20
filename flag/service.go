package flag

import (
	"context"
	"encoding/json"
	"fmt"
)

// ServiceOption configures the flag Service.
type ServiceOption func(*Service)

// WithAppID sets the default app ID for the flag service.
func WithAppID(appID string) ServiceOption {
	return func(s *Service) { s.appID = appID }
}

// Service provides type-safe feature flag evaluation.
type Service struct {
	engine *Engine
	appID  string
}

// NewService creates a type-safe flag evaluation service.
func NewService(engine *Engine, opts ...ServiceOption) *Service {
	s := &Service{engine: engine}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Bool evaluates a boolean flag. Returns defaultVal on error or type mismatch.
func (s *Service) Bool(ctx context.Context, key string, defaultVal bool) bool {
	val, err := s.engine.Evaluate(ctx, key, s.appID)
	if err != nil {
		return defaultVal
	}
	b, ok := val.(bool)
	if !ok {
		return defaultVal
	}
	return b
}

// String evaluates a string flag. Returns defaultVal on error or type mismatch.
func (s *Service) String(ctx context.Context, key, defaultVal string) string {
	val, err := s.engine.Evaluate(ctx, key, s.appID)
	if err != nil {
		return defaultVal
	}
	str, ok := val.(string)
	if !ok {
		return defaultVal
	}
	return str
}

// Int evaluates an integer flag. Returns defaultVal on error or type mismatch.
// Handles both int and float64 (from JSON unmarshaling).
func (s *Service) Int(ctx context.Context, key string, defaultVal int) int {
	val, err := s.engine.Evaluate(ctx, key, s.appID)
	if err != nil {
		return defaultVal
	}
	switch v := val.(type) {
	case int:
		return v
	case float64:
		return int(v)
	case int64:
		return int(v)
	default:
		return defaultVal
	}
}

// Float evaluates a float flag. Returns defaultVal on error or type mismatch.
// Handles both float64 and int (promoted to float64).
func (s *Service) Float(ctx context.Context, key string, defaultVal float64) float64 {
	val, err := s.engine.Evaluate(ctx, key, s.appID)
	if err != nil {
		return defaultVal
	}
	switch v := val.(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	default:
		return defaultVal
	}
}

// JSON evaluates a JSON flag and unmarshals it into target.
// target must be a pointer. Returns an error if evaluation fails or
// the value cannot be marshaled to JSON and unmarshaled into target.
func (s *Service) JSON(ctx context.Context, key string, target any) error {
	val, err := s.engine.Evaluate(ctx, key, s.appID)
	if err != nil {
		return fmt.Errorf("flag %q: %w", key, err)
	}

	// If the value is already a []byte or string, try direct unmarshal.
	switch v := val.(type) {
	case []byte:
		return json.Unmarshal(v, target)
	case string:
		return json.Unmarshal([]byte(v), target)
	default:
		// Marshal → unmarshal round-trip for map/struct values.
		data, mErr := json.Marshal(val)
		if mErr != nil {
			return fmt.Errorf("flag %q: marshal: %w", key, mErr)
		}
		return json.Unmarshal(data, target)
	}
}

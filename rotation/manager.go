package rotation

import (
	"context"
	"fmt"
	"sync"
	"time"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/vault/id"
	"github.com/xraph/vault/secret"
)

// Rotator produces a new secret value from the current one.
type Rotator func(ctx context.Context, currentValue []byte) ([]byte, error)

// ManagerOption configures the Manager.
type ManagerOption func(*Manager)

// WithCheckInterval sets how often the manager checks for due rotations.
func WithCheckInterval(d time.Duration) ManagerOption {
	return func(m *Manager) { m.checkInterval = d }
}

// WithLogger sets the logger for the manager.
func WithLogger(l log.Logger) ManagerOption {
	return func(m *Manager) { m.logger = l }
}

// WithAppID sets the default app ID for the manager.
func WithAppID(appID string) ManagerOption {
	return func(m *Manager) { m.appID = appID }
}

// Manager handles scheduled secret rotation with registered rotator functions.
type Manager struct {
	store         Store
	secretService *secret.Service
	appID         string
	logger        log.Logger
	checkInterval time.Duration

	mu       sync.RWMutex
	rotators map[string]Rotator // secretKey → rotator

	cancel context.CancelFunc
	done   chan struct{}
}

// NewManager creates a rotation manager.
func NewManager(store Store, secretSvc *secret.Service, opts ...ManagerOption) *Manager {
	m := &Manager{
		store:         store,
		secretService: secretSvc,
		logger:        log.NewNoopLogger(),
		checkInterval: 1 * time.Minute,
		rotators:      make(map[string]Rotator),
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// RegisterRotator registers a rotator function for the given secret key.
func (m *Manager) RegisterRotator(secretKey string, r Rotator) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.rotators[secretKey] = r
}

// Start begins the background rotation check loop.
// The loop runs until Stop is called or the context is cancelled.
func (m *Manager) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.done = make(chan struct{})

	go m.loop(ctx)
	return nil
}

// Stop cancels the background loop and waits for it to finish.
func (m *Manager) Stop(_ context.Context) error {
	if m.cancel != nil {
		m.cancel()
	}
	if m.done != nil {
		<-m.done
	}
	return nil
}

// RotateNow performs an immediate rotation for the given secret key.
func (m *Manager) RotateNow(ctx context.Context, secretKey, appID string) error {
	if appID == "" {
		appID = m.appID
	}

	// Look up registered rotator.
	m.mu.RLock()
	rotator, ok := m.rotators[secretKey]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("rotation: no rotator registered for %q", secretKey)
	}

	// Get current secret.
	currentSecret, err := m.secretService.Get(ctx, secretKey, appID)
	if err != nil {
		return fmt.Errorf("rotation: get current secret %q: %w", secretKey, err)
	}

	oldVersion := currentSecret.Version

	// Invoke the rotator.
	newValue, err := rotator(ctx, currentSecret.Value)
	if err != nil {
		return fmt.Errorf("rotation: rotator failed for %q: %w", secretKey, err)
	}

	// Set the new value (auto-versions).
	meta, err := m.secretService.Set(ctx, secretKey, newValue, appID)
	if err != nil {
		return fmt.Errorf("rotation: set new secret %q: %w", secretKey, err)
	}

	// Record the rotation.
	now := time.Now().UTC()
	record := &Record{
		ID:         id.NewRotationID(),
		SecretKey:  secretKey,
		AppID:      appID,
		OldVersion: oldVersion,
		NewVersion: meta.Version,
		RotatedBy:  "rotation-manager",
		RotatedAt:  now,
	}
	if rErr := m.store.RecordRotation(ctx, record); rErr != nil {
		m.logger.Error("rotation: record failed", log.String("key", secretKey), log.Any("error", rErr))
	}

	// Update policy timestamps.
	m.updatePolicyTimestamps(ctx, secretKey, appID, now)

	m.logger.Info("rotation: completed", log.String("key", secretKey), log.Int64("old_version", oldVersion), log.Int64("new_version", meta.Version))
	return nil
}

// loop periodically checks for due rotations.
func (m *Manager) loop(ctx context.Context) {
	defer close(m.done)

	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkDuePolicies(ctx)
		}
	}
}

// checkDuePolicies lists all enabled policies and rotates any that are due.
func (m *Manager) checkDuePolicies(ctx context.Context) {
	appID := m.appID
	if appID == "" {
		return
	}

	policies, err := m.store.ListRotationPolicies(ctx, appID)
	if err != nil {
		m.logger.Error("rotation: list policies failed", log.Any("error", err))
		return
	}

	now := time.Now().UTC()
	for _, p := range policies {
		if !p.Enabled {
			continue
		}
		if p.NextRotationAt == nil || !now.After(*p.NextRotationAt) {
			continue
		}

		if err := m.RotateNow(ctx, p.SecretKey, p.AppID); err != nil {
			m.logger.Error("rotation: scheduled rotation failed",
				log.String("key", p.SecretKey), log.Any("error", err))
		}
	}
}

// updatePolicyTimestamps updates LastRotatedAt and NextRotationAt on the policy.
func (m *Manager) updatePolicyTimestamps(ctx context.Context, secretKey, appID string, now time.Time) {
	policy, err := m.store.GetRotationPolicy(ctx, secretKey, appID)
	if err != nil {
		m.logger.Error("rotation: get policy for timestamp update failed",
			log.String("key", secretKey), log.Any("error", err))
		return
	}

	policy.LastRotatedAt = &now
	next := now.Add(policy.Interval)
	policy.NextRotationAt = &next
	policy.Touch()

	if err := m.store.SaveRotationPolicy(ctx, policy); err != nil {
		m.logger.Error("rotation: save policy timestamps failed",
			log.String("key", secretKey), log.Any("error", err))
	}
}

package rotation

import (
	"context"
	"fmt"
	"sort"
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

	// lifecycleMu guards running, cancel and done. It is separate from mu,
	// which only ever guards the rotators map, so a Start or Stop call
	// never contends with a RegisterRotator or RotateNow lookup.
	lifecycleMu sync.Mutex
	running     bool
	cancel      context.CancelFunc
	done        chan struct{}
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

// RotatorKeys returns the secret keys that have a registered rotator, sorted.
//
// RotateNow fails for any key not in this list, because a rotator is Go code
// an application registers and nothing outside the process can supply one. A
// caller that offers rotation as an action should gate on this rather than
// offering a button that always fails.
func (m *Manager) RotatorKeys() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]string, 0, len(m.rotators))
	for k := range m.rotators {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Start begins the background rotation check loop. The loop runs until
// Stop is called or the context is cancelled.
//
// Start is idempotent: calling it while a loop is already running is a
// no-op, because starting a second loop would overwrite the cancel func
// and done channel that reach the first one, orphaning its goroutine with
// nothing left able to cancel it. Call Stop first to restart the loop.
func (m *Manager) Start(ctx context.Context) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()

	if m.running {
		return nil
	}

	loopCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	m.cancel = cancel
	m.done = done
	m.running = true

	go m.loop(loopCtx, done)
	return nil
}

// Stop cancels the background loop and waits for it to finish. It is safe
// to call without a prior Start, and safe to call more than once: the
// second call sees running already false and returns immediately.
func (m *Manager) Stop(_ context.Context) error {
	m.lifecycleMu.Lock()
	if !m.running {
		m.lifecycleMu.Unlock()
		return nil
	}
	cancel := m.cancel
	done := m.done
	m.running = false
	m.cancel = nil
	m.done = nil
	m.lifecycleMu.Unlock()

	cancel()
	<-done
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

	// secret.Service.Set builds a fresh row, so a rotation that doesn't
	// carry expiry and metadata forward silently erases both. Read them
	// from the current secret before the rotator runs.
	currentMeta, err := m.secretService.GetMeta(ctx, secretKey, appID)
	if err != nil {
		return fmt.Errorf("rotation: get current secret meta %q: %w", secretKey, err)
	}

	// Invoke the rotator.
	newValue, err := rotator(ctx, currentSecret.Value)
	if err != nil {
		return fmt.Errorf("rotation: rotator failed for %q: %w", secretKey, err)
	}

	var setOpts []secret.SetOption
	if currentMeta.ExpiresAt != nil {
		setOpts = append(setOpts, secret.WithExpiresAt(*currentMeta.ExpiresAt))
	}
	if len(currentMeta.Metadata) > 0 {
		setOpts = append(setOpts, secret.WithMetadata(currentMeta.Metadata))
	}

	// Set the new value (auto-versions), carrying expiry and metadata forward.
	meta, err := m.secretService.Set(ctx, secretKey, newValue, appID, setOpts...)
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

// loop periodically checks for due rotations. done is the channel Start
// created for this run; it is passed in rather than read from the Manager
// field so that closing it can never race with a later Start or Stop
// reassigning that field.
func (m *Manager) loop(ctx context.Context, done chan struct{}) {
	defer close(done)

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

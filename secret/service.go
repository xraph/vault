package secret

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	gometrics "github.com/xraph/go-utils/metrics"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/xraph/vault/core"
	"github.com/xraph/vault/crypto"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/internal/telemetry"
	"github.com/xraph/vault/scope"
)

// EncryptionAlgorithm is the value recorded in Meta.EncryptionAlg for a
// secret stored encrypted. An unencrypted secret records "".
const EncryptionAlgorithm = "AES-256-GCM"

// OnAccessFunc is called after a secret is accessed.
type OnAccessFunc func(ctx context.Context, key, appID string)

// OnMutateFunc is called after a secret is set or deleted.
type OnMutateFunc func(ctx context.Context, action, key, appID string)

// ServiceOption configures the Service.
type ServiceOption func(*Service)

// WithAppID sets the default app ID for the service.
func WithAppID(appID string) ServiceOption {
	return func(s *Service) { s.appID = appID }
}

// WithOnAccess registers a callback invoked after Get/GetVersion.
func WithOnAccess(fn OnAccessFunc) ServiceOption {
	return func(s *Service) { s.onAccess = fn }
}

// WithOnMutate registers a callback invoked after Set/Delete.
func WithOnMutate(fn OnMutateFunc) ServiceOption {
	return func(s *Service) { s.onMutate = fn }
}

// WithMetrics records the service's counters on m: secret operations by op
// and result, and the encrypt and decrypt calls it makes. In a Forge app pass
// app.Metrics(); vault's Forge extension does this for you. A nil m records
// nothing. No label ever carries a key, a tenant or a value.
func WithMetrics(m gometrics.Metrics) ServiceOption {
	return func(s *Service) { s.metricsSink = m }
}

// Service provides secret CRUD with encryption, auto-versioning, and audit callbacks.
//
// Every method that reads or writes one tenant's secrets takes the tenant
// from the context (scope.WithTenantID), never from an argument. A context
// with no tenant works on the app-level secrets, exactly as it did before
// secrets were scoped by tenant; a context with a tenant sees that tenant's
// secrets and nothing else, not even an app-level secret under the same key.
// The OnAccess and OnMutate callbacks get the same context, so the audit rows
// they write carry the tenant.
type Service struct {
	store     Store
	encryptor *crypto.Encryptor
	appID     string
	onAccess  OnAccessFunc
	onMutate  OnMutateFunc

	metricsSink gometrics.Metrics
	ops         *telemetry.Counter
	cryptoOps   *telemetry.Counter
}

// NewService creates a secret service.
func NewService(store Store, encryptor *crypto.Encryptor, opts ...ServiceOption) *Service {
	svc := &Service{
		store:     store,
		encryptor: encryptor,
	}
	for _, o := range opts {
		o(svc)
	}
	svc.ops = telemetry.NewCounter(svc.metricsSink, telemetry.MetricSecretOperations,
		"Secret service calls by operation and result.", "op", "result")
	svc.cryptoOps = telemetry.NewCounter(svc.metricsSink, telemetry.MetricCryptoOperations,
		"Encrypt and decrypt calls the secret service makes, by result.", "op", "result")
	return svc
}

// Operation label values for MetricSecretOperations.
const (
	opGet        = "get"
	opGetVersion = "get_version"
	opSet        = "set"
	opDelete     = "delete"
)

// Attribute keys on secret spans. None of them carries a key or a value.
const (
	attrFound     = attribute.Key("vault.secret.found")
	attrEncrypted = attribute.Key("vault.secret.encrypted")
)

// classDecrypt is the span status of a read whose row the service could not
// decrypt. The error alone doesn't say so: a wrong key surfaces as the AEAD's
// own error.
const classDecrypt = "decrypt failed"

// finish ends a secret operation's span and counts it. A missing secret is an
// answer, not a failure: the span keeps an unset status and says found=false.
// class names the failed step for the span status; "" lets the error's type
// name it.
func (s *Service) finish(span trace.Span, op, class string, err error) {
	defer span.End()
	switch {
	case err == nil:
		s.ops.Inc(op, telemetry.ResultOK)
	case errors.Is(err, core.ErrSecretNotFound):
		span.SetAttributes(attrFound.Bool(false))
		s.ops.Inc(op, telemetry.ResultNotFound)
	default:
		telemetry.FailAs(span, class, err)
		s.ops.Inc(op, telemetry.ResultError)
	}
}

// countCrypto counts one encrypt or decrypt call.
func (s *Service) countCrypto(op string, err error) {
	if err != nil {
		s.cryptoOps.Inc(op, telemetry.ResultError)
		return
	}
	s.cryptoOps.Inc(op, telemetry.ResultOK)
}

// resolveAppID returns appID from argument or service default.
func (s *Service) resolveAppID(appID string) string {
	if appID != "" {
		return appID
	}
	return s.appID
}

// tenantFrom returns the tenant in ctx, or "" for the app-level secrets.
func tenantFrom(ctx context.Context) string {
	_, tenantID, _, _ := scope.FromContext(ctx)
	return tenantID
}

// Get retrieves and decrypts a secret by key, for the tenant in ctx.
func (s *Service) Get(ctx context.Context, key, appID string) (sec *Secret, err error) {
	ctx, span := telemetry.Start(ctx, "get secret")
	var class string
	defer func() { s.finish(span, opGet, class, err) }()

	appID = s.resolveAppID(appID)

	sec, err = s.store.GetSecret(ctx, key, appID, tenantFrom(ctx))
	if err != nil {
		return nil, err
	}
	span.SetAttributes(attrFound.Bool(true), attrEncrypted.Bool(sec.EncryptionAlg != ""))

	if err = s.reveal(sec, key, 0); err != nil {
		class = classDecrypt
		return nil, err
	}

	if s.onAccess != nil {
		s.onAccess(ctx, key, appID)
	}

	return sec, nil
}

// reveal fills sec.Value from the stored bytes, going by the row's own
// EncryptionAlg rather than by whether this service has a key. No real
// backend persists Value, only EncryptedValue, so this is the only place a
// read gets its plaintext.
//
// An empty EncryptionAlg means the row was written without a key and the
// stored bytes are the plaintext, whatever key this service has now. An
// encrypted row with no key configured is an error, never an empty value.
// version is only used to name the version in a decrypt error; 0 means the
// current one.
func (s *Service) reveal(sec *Secret, key string, version int64) error {
	if sec.EncryptionAlg == "" {
		sec.Value = bytes.Clone(sec.EncryptedValue)
		return nil
	}
	if s.encryptor == nil {
		return fmt.Errorf("secret: %q is encrypted with %s but no encryption key is configured: %w",
			key, sec.EncryptionAlg, core.ErrDecryptionFailed)
	}
	plaintext, err := s.encryptor.Decrypt(sec.EncryptedValue)
	s.countCrypto("decrypt", err)
	if err != nil {
		if version > 0 {
			return fmt.Errorf("secret: decrypt %q v%d: %w", key, version, err)
		}
		return fmt.Errorf("secret: decrypt %q: %w", key, err)
	}
	sec.Value = plaintext
	return nil
}

// GetMeta retrieves secret metadata without the value, for the tenant in ctx.
func (s *Service) GetMeta(ctx context.Context, key, appID string) (*Meta, error) {
	appID = s.resolveAppID(appID)

	sec, err := s.store.GetSecret(ctx, key, appID, tenantFrom(ctx))
	if err != nil {
		return nil, err
	}

	return sec.ToMeta(), nil
}

// SetOption configures a Set operation.
type SetOption func(*setConfig)

type setConfig struct {
	metadata  map[string]string
	expiresAt *time.Time
}

// WithMetadata sets metadata on the secret.
func WithMetadata(m map[string]string) SetOption {
	return func(c *setConfig) { c.metadata = m }
}

// WithExpiresAt sets an expiration time on the secret.
func WithExpiresAt(t time.Time) SetOption {
	return func(c *setConfig) { c.expiresAt = &t }
}

// Set creates or updates a secret, encrypting the value and auto-versioning.
// The secret belongs to the tenant in ctx, or to the app when ctx has none.
func (s *Service) Set(ctx context.Context, key string, value []byte, appID string, opts ...SetOption) (_ *Meta, err error) {
	ctx, span := telemetry.Start(ctx, "set secret", trace.WithAttributes(attrEncrypted.Bool(s.encryptor != nil)))
	defer func() { s.finish(span, opSet, "", err) }()

	appID = s.resolveAppID(appID)

	var cfg setConfig
	for _, o := range opts {
		o(&cfg)
	}

	sec := &Secret{
		Entity:   core.NewEntity(),
		ID:       id.NewSecretID(),
		Key:      key,
		Value:    value,
		AppID:    appID,
		TenantID: tenantFrom(ctx),
	}

	if cfg.metadata != nil {
		sec.Metadata = cfg.metadata
	}
	if cfg.expiresAt != nil {
		sec.ExpiresAt = cfg.expiresAt
	}

	// Encrypt the value.
	if s.encryptor != nil {
		ct, encErr := s.encryptor.Encrypt(value)
		s.countCrypto("encrypt", encErr)
		if encErr != nil {
			return nil, fmt.Errorf("secret: encrypt %q: %w", key, encErr)
		}
		sec.EncryptedValue = ct
		sec.EncryptionAlg = EncryptionAlgorithm
	} else {
		// No encryptor: store plaintext in EncryptedValue as fallback.
		sec.EncryptedValue = value
	}

	if setErr := s.store.SetSecret(ctx, sec); setErr != nil {
		return nil, setErr
	}

	if s.onMutate != nil {
		s.onMutate(ctx, "secret.set", key, appID)
	}

	return sec.ToMeta(), nil
}

// Delete removes a secret and all its versions, for the tenant in ctx. The
// same key under another tenant, or at app level, is left alone.
func (s *Service) Delete(ctx context.Context, key, appID string) (err error) {
	ctx, span := telemetry.Start(ctx, "delete secret")
	defer func() { s.finish(span, opDelete, "", err) }()

	appID = s.resolveAppID(appID)

	if delErr := s.store.DeleteSecret(ctx, key, appID, tenantFrom(ctx)); delErr != nil {
		return delErr
	}
	span.SetAttributes(attrFound.Bool(true))

	if s.onMutate != nil {
		s.onMutate(ctx, "secret.delete", key, appID)
	}

	return nil
}

// List returns secret metadata for an app, for the tenant in ctx only. It
// overwrites opts.TenantID with that tenant, so the caller's value has no
// effect.
func (s *Service) List(ctx context.Context, appID string, opts ListOpts) ([]*Meta, error) {
	appID = s.resolveAppID(appID)
	opts.TenantID = tenantFrom(ctx)
	return s.store.ListSecrets(ctx, appID, opts)
}

// GetVersion retrieves a specific version of a secret and decrypts it, for
// the tenant in ctx.
//
// Each version row records the algorithm its own bytes were written with, and
// the store hands that back, so a version is read the way it was written
// whatever the secret's current algorithm or this service's key is now:
//
//   - A version written without a key reads back as its plaintext once a key
//     is configured.
//   - A version written encrypted is refused with core.ErrDecryptionFailed
//     when no key is configured. Its ciphertext is never returned as a value.
//
// A row from before versions recorded an algorithm falls back to the secret's
// current one, which can be wrong across a change of key configuration.
// BackfillVersionEncryption classifies those rows it can decrypt.
func (s *Service) GetVersion(ctx context.Context, key, appID string, version int64) (sec *Secret, err error) {
	ctx, span := telemetry.Start(ctx, "get secret version")
	var class string
	defer func() { s.finish(span, opGetVersion, class, err) }()

	appID = s.resolveAppID(appID)

	sec, err = s.store.GetSecretVersion(ctx, key, appID, tenantFrom(ctx), version)
	if err != nil {
		return nil, err
	}
	span.SetAttributes(attrFound.Bool(true), attrEncrypted.Bool(sec.EncryptionAlg != ""))

	if err = s.reveal(sec, key, version); err != nil {
		class = classDecrypt
		return nil, err
	}

	if s.onAccess != nil {
		s.onAccess(ctx, key, appID)
	}

	return sec, nil
}

// ListVersions returns all versions of a secret, for the tenant in ctx.
func (s *Service) ListVersions(ctx context.Context, key, appID string) ([]*Version, error) {
	appID = s.resolveAppID(appID)
	return s.store.ListSecretVersions(ctx, key, appID, tenantFrom(ctx))
}

// backfillPageSize is how many unrecorded version rows the backfill reads at
// a time.
const backfillPageSize = 500

// BackfillVersionEncryption records EncryptionAlgorithm on every version row
// of the service's default app whose algorithm was never recorded and that the
// configured key decrypts, and returns how many it marked. It is maintenance,
// not a read: it covers every tenant of the app whatever the tenant in ctx,
// and it never returns a value.
//
// It classifies by trying the key: a row the key cannot decrypt is plaintext,
// or sealed with some other key, and the backfill cannot tell which, so it
// leaves that row alone. With no key configured nothing can be proven, so it
// reads nothing and marks nothing. It pages by version id, so rows it leaves
// unrecorded are not fetched again, and a second run marks nothing new. If the
// store returns a full page that does not move past the cursor, it returns an
// error instead of asking again.
//
// It runs under a "backfill version encryption" span that records how many
// rows it scanned and marked. With no key there is nothing to do and no span.
func (s *Service) BackfillVersionEncryption(ctx context.Context) (marked int, err error) {
	if s.encryptor == nil {
		return 0, nil
	}
	ctx, span := telemetry.Start(ctx, "backfill version encryption")
	scanned := 0
	defer func() {
		span.SetAttributes(
			attribute.Int("vault.backfill.scanned", scanned),
			attribute.Int("vault.backfill.marked", marked),
		)
		if err != nil {
			telemetry.Fail(span, err)
		}
		span.End()
	}()

	appID := s.resolveAppID("")

	cursor := ""
	for {
		page, listErr := s.store.ListUnrecordedVersions(ctx, appID, cursor, backfillPageSize)
		if listErr != nil {
			return marked, fmt.Errorf("secret: list unrecorded versions: %w", listErr)
		}
		scanned += len(page)
		for _, v := range page {
			// A row the key can't open is expected here, not a failure, so
			// these attempts stay out of the crypto counter.
			if _, decErr := s.encryptor.Decrypt(v.EncryptedValue); decErr != nil {
				continue
			}
			if setErr := s.store.SetVersionEncryption(ctx, v.ID, EncryptionAlgorithm); setErr != nil {
				return marked, fmt.Errorf("secret: record version encryption: %w", setErr)
			}
			marked++
		}
		if len(page) < backfillPageSize {
			return marked, nil
		}
		// A store that ignores the cursor would hand back the same page
		// forever. Stop rather than spin.
		last := page[len(page)-1].ID.String()
		if last <= cursor {
			return marked, fmt.Errorf("secret: list unrecorded versions: store returned ids not after the cursor %q", cursor)
		}
		cursor = last
	}
}

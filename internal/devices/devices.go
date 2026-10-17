// Package devices implements device subscriptions: a platform token bound to one app and
// one instance (docs/protocol.md, "Device registration"). The gateway never receives
// device keys, and it stores only a hash of each subscription secret.
package devices

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/parkerbrown98/gotalk-gateway/internal/apps"
	"github.com/parkerbrown98/gotalk-gateway/internal/blocklist"
	"github.com/parkerbrown98/gotalk-gateway/internal/ids"
	"github.com/parkerbrown98/gotalk-gateway/internal/instances"
	"github.com/parkerbrown98/gotalk-gateway/internal/problem"
	"github.com/parkerbrown98/gotalk-gateway/internal/store"
)

const (
	// SecretPrefix starts every subscription secret.
	SecretPrefix = "gtsec_"
	// GoneRetention is how long a subscription the provider reported dead is kept, so the
	// instance can learn about it and a client can reactivate it by registering again.
	GoneRetention = 7 * 24 * time.Hour

	StatusActive = "active"
	StatusGone   = "gone"

	pruneBatch = 1000
)

// AppLister returns the enabled apps; see apps.Registry.
type AppLister interface {
	List(ctx context.Context) ([]apps.App, error)
}

type Options struct {
	// ExpiryDays is how long a subscription lives without a refresh.
	ExpiryDays int
	// WebPushHosts restricts Web Push endpoints to these push services (and their
	// subdomains). Empty allows any public host.
	WebPushHosts []string
	// AllowHTTPOrigins accepts http:// instance origins (development only).
	AllowHTTPOrigins bool
	Logger           *slog.Logger
	Now              func() time.Time
}

type Service struct {
	pool      *pgxpool.Pool
	apps      AppLister
	blocklist *blocklist.Cache
	opts      Options
	log       *slog.Logger
	now       func() time.Time
}

func New(pool *pgxpool.Pool, appList AppLister, bl *blocklist.Cache, opts Options) *Service {
	s := &Service{pool: pool, apps: appList, blocklist: bl, opts: opts, log: opts.Logger, now: opts.Now}
	if s.now == nil {
		s.now = time.Now
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.opts.ExpiryDays <= 0 {
		s.opts.ExpiryDays = 60
	}
	return s
}

func (s *Service) expiry() time.Time {
	return s.now().Add(time.Duration(s.opts.ExpiryDays) * 24 * time.Hour)
}

// HashToken is the stored hash of a normalized token or endpoint. Its hex form keys the
// per-token rate limit.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func hashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

func newSecret() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return SecretPrefix + base64.RawURLEncoding.EncodeToString(b[:])
}

func notFound() *problem.Problem {
	return problem.New(http.StatusNotFound, problem.SubscriptionNotFound, "No such subscription.")
}

func invalidToken(field, message string) *problem.Problem {
	p := problem.New(http.StatusUnprocessableEntity, problem.InvalidToken, message)
	p.Errors = []problem.FieldError{{Field: field, Message: message}}
	return p
}

// tokenField is the request field that carries a platform's token.
func tokenField(platform string) string {
	if platform == Web {
		return "endpoint"
	}
	return "token"
}

type RegisterInput struct {
	AppID          string
	InstanceOrigin string
	Platform       string
	// Token is the APNs or FCM token, or the Web Push endpoint.
	Token string
	// APNsEnvironment applies to iOS only; empty means production.
	APNsEnvironment string
}

type Registration struct {
	SubscriptionID string
	Secret         string
	ExpiresAt      time.Time
}

// Admit is called with the token hash before a token is stored, so the caller can apply
// per-token rate limits. Returning an error aborts the operation.
type Admit func(tokenHash []byte) error

// Register binds a token to an app and an active instance. Registering the same token for
// the same app, instance and platform again returns the same subscription with a new
// secret, which invalidates the old one, and reactivates it if it was gone.
func (s *Service) Register(ctx context.Context, in RegisterInput, admit Admit) (*Registration, error) {
	if err := s.checkApp(ctx, in.AppID, in.Platform); err != nil {
		return nil, err
	}
	token, err := NormalizeToken(in.Platform, in.Token, s.opts.WebPushHosts)
	if err != nil {
		return nil, invalidToken(tokenField(in.Platform), err.Error())
	}
	var env *string
	if in.Platform == IOS {
		env = &in.APNsEnvironment
		if *env == "" {
			*env = APNsProduction
		}
	}
	origin, err := instances.NormalizeOrigin(in.InstanceOrigin, s.opts.AllowHTTPOrigins)
	if err != nil {
		return nil, problem.Invalid("instance_origin", err.Error())
	}
	inst, err := s.activeInstance(ctx, origin)
	if err != nil {
		return nil, err
	}
	tokenHash := HashToken(token)
	if admit != nil {
		if err := admit(tokenHash); err != nil {
			return nil, err
		}
	}

	secret := newSecret()
	reg := &Registration{Secret: secret, ExpiresAt: s.expiry()}
	reg.SubscriptionID, err = store.New(s.pool).UpsertDevice(ctx, store.UpsertDeviceParams{
		ID: ids.New(ids.Subscription), AppID: in.AppID, InstanceID: inst.ID, Platform: in.Platform,
		Token: token, TokenHash: tokenHash, ApnsEnvironment: env, SecretHash: hashSecret(secret),
		ExpiresAt: reg.ExpiresAt,
	})
	if err != nil {
		return nil, err
	}
	return reg, nil
}

func (s *Service) checkApp(ctx context.Context, appID, platform string) error {
	list, err := s.apps.List(ctx)
	if err != nil {
		return err
	}
	for _, a := range list {
		if a.ID != appID {
			continue
		}
		for _, p := range a.Platforms() {
			if p == platform {
				return nil
			}
		}
		return problem.Newf(http.StatusUnprocessableEntity, problem.UnknownApp,
			"App %q is not served by this gateway on %s.", appID, platform)
	}
	return problem.Newf(http.StatusUnprocessableEntity, problem.UnknownApp, "App %q is not served by this gateway.", appID)
}

// activeInstance returns the verified, active instance of origin.
func (s *Service) activeInstance(ctx context.Context, origin string) (store.Instance, error) {
	if e := s.blocklist.MatchOrigin(origin); e != nil {
		return store.Instance{}, problem.New(http.StatusForbidden, problem.InstanceBlocked, e.Reason)
	}
	q := store.New(s.pool)
	inst, err := q.GetVerifiedInstanceByOrigin(ctx, origin)
	if errors.Is(err, pgx.ErrNoRows) {
		pending, err := q.ListInstancesByOrigin(ctx, origin)
		if err != nil {
			return store.Instance{}, err
		}
		if len(pending) > 0 {
			return store.Instance{}, problem.New(http.StatusForbidden, problem.InstanceNotVerified,
				"The instance has not verified its domain with this gateway yet.")
		}
		return store.Instance{}, problem.Newf(http.StatusNotFound, problem.InstanceNotFound,
			"No instance is registered for %s on this gateway.", origin)
	} else if err != nil {
		return store.Instance{}, err
	}
	switch inst.Status {
	case instances.StatusActive:
		return inst, nil
	case instances.StatusBlocked:
		reason := "This instance is blocked."
		if inst.BlockedReason != nil {
			reason = *inst.BlockedReason
		}
		return store.Instance{}, problem.New(http.StatusForbidden, problem.InstanceBlocked, reason)
	default:
		return store.Instance{}, problem.New(http.StatusForbidden, problem.InstanceNotVerified,
			"The instance's domain verification has lapsed; it cannot accept new devices until it is verified again.")
	}
}

// Authenticate loads a subscription and checks its secret. A missing subscription and a
// wrong secret are indistinguishable.
func (s *Service) Authenticate(ctx context.Context, id, secret string) (store.Device, error) {
	d, err := store.New(s.pool).GetDevice(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Device{}, notFound()
	} else if err != nil {
		return store.Device{}, err
	}
	if subtle.ConstantTimeCompare(hashSecret(secret), d.SecretHash) != 1 {
		return store.Device{}, notFound()
	}
	return d, nil
}

// RefreshInput replaces the token (iOS, Android) or endpoint (web) and, on iOS, the APNs
// environment. Nil fields are unchanged.
type RefreshInput struct {
	Token           *string
	Endpoint        *string
	APNsEnvironment *string
}

type Refreshed struct {
	SubscriptionID string
	ExpiresAt      time.Time
}

// Refresh extends an authenticated subscription's expiry and optionally replaces its
// token. Replacing the token reactivates a gone subscription.
func (s *Service) Refresh(ctx context.Context, d store.Device, in RefreshInput, admit Admit) (*Refreshed, error) {
	id := d.ID
	var err error
	var fieldErrs []problem.FieldError
	newToken := in.Token
	if d.Platform == Web {
		newToken = in.Endpoint
		if in.Token != nil {
			fieldErrs = append(fieldErrs, problem.FieldError{Field: "token", Message: "web subscriptions use endpoint"})
		}
	} else if in.Endpoint != nil {
		fieldErrs = append(fieldErrs, problem.FieldError{Field: "endpoint", Message: "only web subscriptions have an endpoint"})
	}
	if in.APNsEnvironment != nil && d.Platform != IOS {
		fieldErrs = append(fieldErrs, problem.FieldError{Field: "apns_environment", Message: "only iOS subscriptions have an APNs environment"})
	}
	if len(fieldErrs) > 0 {
		p := problem.New(http.StatusUnprocessableEntity, problem.InvalidRequest, "Request validation failed.")
		p.Errors = fieldErrs
		return nil, p
	}

	token, tokenHash, env := d.Token, d.TokenHash, d.ApnsEnvironment
	if newToken != nil {
		if token, err = NormalizeToken(d.Platform, *newToken, s.opts.WebPushHosts); err != nil {
			return nil, invalidToken(tokenField(d.Platform), err.Error())
		}
		tokenHash = HashToken(token)
	}
	if in.APNsEnvironment != nil {
		env = in.APNsEnvironment
	}
	changed := subtle.ConstantTimeCompare(tokenHash, d.TokenHash) != 1 || deref(env) != deref(d.ApnsEnvironment)

	q := store.New(s.pool)
	expires := s.expiry()
	if !changed {
		d, err = q.ExtendDevice(ctx, store.ExtendDeviceParams{ID: id, ExpiresAt: expires})
	} else {
		if admit != nil && newToken != nil {
			if err := admit(tokenHash); err != nil {
				return nil, err
			}
		}
		d, err = q.ReplaceDeviceToken(ctx, store.ReplaceDeviceTokenParams{
			ID: id, Token: token, TokenHash: tokenHash, ApnsEnvironment: env, ExpiresAt: expires,
		})
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, problem.New(http.StatusConflict, problem.Conflict,
				"Another subscription for this app and instance already uses this token; register it instead.")
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound()
	} else if err != nil {
		return nil, err
	}
	return &Refreshed{SubscriptionID: d.ID, ExpiresAt: d.ExpiresAt}, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// DeleteWithSecret deletes a subscription authorized by its secret.
func (s *Service) DeleteWithSecret(ctx context.Context, id, secret string) error {
	if _, err := s.Authenticate(ctx, id, secret); err != nil {
		return err
	}
	return s.delete(ctx, id)
}

// DeleteForInstance deletes a subscription on behalf of the instance it is bound to. A
// subscription of another instance is reported as not found.
func (s *Service) DeleteForInstance(ctx context.Context, id, instanceID string) error {
	d, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if d.InstanceID != instanceID {
		return notFound()
	}
	return s.delete(ctx, id)
}

func (s *Service) delete(ctx context.Context, id string) error {
	n, err := store.New(s.pool).DeleteDevice(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return notFound()
	}
	return nil
}

// Get loads a subscription (for the push path).
func (s *Service) Get(ctx context.Context, id string) (store.Device, error) {
	d, err := store.New(s.pool).GetDevice(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Device{}, notFound()
	}
	return d, err
}

// MarkGone records that a provider reported the subscription's token as dead. tokenHash
// and apnsEnvironment identify what the push was sent to (from the subscription as it was
// read for delivery). A rejection is ignored when the subscription has since moved to
// another token or environment. The bound instance learns about a gone subscription from
// its next push, and it is deleted after GoneRetention unless the client registers again.
// It reports whether the subscription was marked.
func (s *Service) MarkGone(ctx context.Context, id string, tokenHash []byte, apnsEnvironment *string) (bool, error) {
	n, err := store.New(s.pool).MarkDeviceGone(ctx, store.MarkDeviceGoneParams{
		ID: id, TokenHash: tokenHash, ApnsEnvironment: apnsEnvironment,
	})
	if err != nil {
		return false, err
	}
	if n > 0 {
		s.log.Info("subscription marked gone", "subscription_id", id)
	}
	return n > 0, nil
}

// Prune deletes subscriptions that expired without a refresh and gone subscriptions past
// their retention, in batches.
func (s *Service) Prune(ctx context.Context) (int64, error) {
	var total int64
	for {
		n, err := store.New(s.pool).DeleteExpiredDevices(ctx, store.DeleteExpiredDevicesParams{
			GoneRetentionDays: int32(GoneRetention / (24 * time.Hour)), Batch: pruneBatch,
		})
		total += n
		if err != nil || n < pruneBatch {
			if total > 0 {
				s.log.Info("pruned subscriptions", "count", total)
			}
			if err != nil {
				return total, fmt.Errorf("pruning subscriptions: %w", err)
			}
			return total, nil
		}
	}
}

// RunMaintenance prunes subscriptions every ten minutes until ctx ends.
func (s *Service) RunMaintenance(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		if _, err := s.Prune(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("pruning subscriptions", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

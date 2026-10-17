// Package instances implements instance registration, domain verification, key rotation and
// recovery, and deregistration (docs/protocol.md, "Instance registration").
package instances

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/errgroup"

	"github.com/parkerbrown98/gotalk-gateway/internal/blocklist"
	"github.com/parkerbrown98/gotalk-gateway/internal/ids"
	"github.com/parkerbrown98/gotalk-gateway/internal/problem"
	"github.com/parkerbrown98/gotalk-gateway/internal/store"
	"github.com/parkerbrown98/gotalk-gateway/internal/wellknown"
)

// Lifecycle rules from docs/protocol.md.
const (
	PendingTTL       = 24 * time.Hour
	ReverifyInterval = 24 * time.Hour
	MaxFailures      = 3
	MaxLiveKeys      = 3
	MaxRecoveryKeys  = 3
)

// Statuses.
const (
	StatusPending   = "pending"
	StatusActive    = "active"
	StatusSuspended = "suspended"
	StatusBlocked   = "blocked"

	KeyPending = "pending"
	KeyActive  = "active"
	KeyRevoked = "revoked"
)

// KeyFetcher returns the keys an origin advertises; see wellknown.Fetcher.
type KeyFetcher interface {
	Keys(ctx context.Context, origin string) (map[string]bool, error)
	CheckOrigin(u *url.URL) error
}

type Options struct {
	AllowHTTP bool
	Logger    *slog.Logger
	Now       func() time.Time
}

type Service struct {
	pool      *pgxpool.Pool
	fetcher   KeyFetcher
	blocklist *blocklist.Cache
	log       *slog.Logger
	allowHTTP bool
	now       func() time.Time
}

func New(pool *pgxpool.Pool, fetcher KeyFetcher, bl *blocklist.Cache, opts Options) *Service {
	s := &Service{pool: pool, fetcher: fetcher, blocklist: bl, log: opts.Logger, allowHTTP: opts.AllowHTTP, now: opts.Now}
	if s.now == nil {
		s.now = time.Now
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	return s
}

// EncodeKey encodes a public key as unpadded base64url.
func EncodeKey(k []byte) string { return base64.RawURLEncoding.EncodeToString(k) }

func decodeKey(field, s string) ([]byte, error) {
	k, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(k) != ed25519.PublicKeySize {
		return nil, problem.Invalid(field, "must be a 32-byte Ed25519 public key, base64url without padding")
	}
	return k, nil
}

func ptr[T any](v T) *T { return &v }

func notFound(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func instanceNotFound() *problem.Problem {
	return problem.New(http.StatusNotFound, problem.InstanceNotFound, "No such instance.")
}

func blocked(reason string) *problem.Problem {
	return problem.New(http.StatusForbidden, problem.InstanceBlocked, reason)
}

// Normalize validates and normalizes an origin under this gateway's rules.
func (s *Service) Normalize(raw string) (string, error) {
	origin, err := NormalizeOrigin(raw, s.allowHTTP)
	if err != nil {
		return "", err
	}
	u, _ := url.Parse(origin)
	if err := s.fetcher.CheckOrigin(u); err != nil {
		return "", err
	}
	return origin, nil
}

type RegisterInput struct {
	Origin          string
	PublicKey       string
	ContactEmail    string
	Software        string
	SoftwareVersion string
}

type Registration struct {
	InstanceID   string
	KeyID        string
	Status       string
	WellKnownURL string
	ExpiresAt    time.Time
}

// Register records a pending registration for a new origin, or a pending recovery key for
// an origin that is already verified. Repeating a registration with the same key returns
// the existing pending registration.
func (s *Service) Register(ctx context.Context, in RegisterInput) (*Registration, error) {
	origin, err := s.Normalize(in.Origin)
	if err != nil {
		return nil, problem.Invalid("origin", err.Error())
	}
	pub, err := decodeKey("public_key", in.PublicKey)
	if err != nil {
		return nil, err
	}
	if addr, err := mail.ParseAddress(in.ContactEmail); err != nil || addr.Name != "" || addr.Address != in.ContactEmail || len(in.ContactEmail) > 254 {
		return nil, problem.Invalid("contact_email", "must be a plain email address")
	}
	if e := s.blocklist.MatchOrigin(origin); e != nil {
		return nil, blocked(e.Reason)
	}

	now := s.now()
	reg := &Registration{WellKnownURL: wellknown.URL(origin)}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := store.New(tx)
		existing, err := q.GetVerifiedInstanceByOrigin(ctx, origin)
		switch {
		case err == nil:
			return s.registerRecovery(ctx, q, existing.ID, pub, now, reg)
		case !notFound(err):
			return err
		}

		pending, err := q.FindPendingRegistration(ctx, store.FindPendingRegistrationParams{Origin: origin, PublicKey: pub})
		if err == nil {
			reg.InstanceID, reg.KeyID, reg.Status, reg.ExpiresAt = pending.InstanceID, pending.KeyID, StatusPending, *pending.PendingExpiresAt
			return nil
		} else if !notFound(err) {
			return err
		}

		reg.InstanceID, reg.KeyID, reg.Status, reg.ExpiresAt = ids.New(ids.Instance), ids.New(ids.Key), StatusPending, now.Add(PendingTTL)
		if err := q.CreateInstance(ctx, store.CreateInstanceParams{
			ID: reg.InstanceID, Origin: origin, ContactEmail: in.ContactEmail,
			Software: optional(in.Software), SoftwareVersion: optional(in.SoftwareVersion),
			PendingExpiresAt: &reg.ExpiresAt,
		}); err != nil {
			return err
		}
		return q.CreateKey(ctx, store.CreateKeyParams{ID: reg.KeyID, InstanceID: reg.InstanceID, PublicKey: pub})
	})
	if err != nil {
		return nil, err
	}
	return reg, nil
}

func (s *Service) registerRecovery(ctx context.Context, q *store.Queries, instanceID string, pub []byte, now time.Time, reg *Registration) error {
	inst, err := q.LockInstance(ctx, instanceID)
	if err != nil {
		return err
	}
	if inst.Status == StatusBlocked {
		return blocked(deref(inst.BlockedReason))
	}
	reg.InstanceID, reg.Status = inst.ID, inst.Status

	key, err := q.GetKeyByPublicKey(ctx, store.GetKeyByPublicKeyParams{InstanceID: inst.ID, PublicKey: pub})
	switch {
	case err == nil && key.Recovery && key.ExpiresAt != nil && key.ExpiresAt.After(now):
		reg.KeyID, reg.ExpiresAt = key.ID, *key.ExpiresAt
		return nil
	case err == nil && key.Status == KeyActive:
		return problem.New(http.StatusConflict, problem.Conflict, "This key is already active for this origin.")
	case err == nil && key.Status == KeyPending && !key.Recovery:
		return problem.New(http.StatusConflict, problem.Conflict, "This key is pending rotation; publish it and call verify.")
	case err == nil:
		return problem.New(http.StatusConflict, problem.Conflict, "This key was revoked; generate a new key.")
	case !notFound(err):
		return err
	}

	reg.KeyID, reg.ExpiresAt = ids.New(ids.Key), now.Add(PendingTTL)
	if err := q.CreateKey(ctx, store.CreateKeyParams{
		ID: reg.KeyID, InstanceID: inst.ID, PublicKey: pub, Recovery: true, ExpiresAt: &reg.ExpiresAt,
	}); err != nil {
		return err
	}
	return q.TrimRecoveryKeys(ctx, store.TrimRecoveryKeysParams{InstanceID: inst.ID, Keep: MaxRecoveryKeys})
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Principal is an authenticated instance key.
type Principal struct {
	InstanceID     string
	KeyID          string
	Origin         string
	KeyStatus      string
	Recovery       bool
	InstanceStatus string
}

// LookupKey loads a key and its instance for request authentication.
func (s *Service) LookupKey(ctx context.Context, keyID string) (store.GetKeyForAuthRow, error) {
	return store.New(s.pool).GetKeyForAuth(ctx, keyID)
}

// Touch records that a key was used (at most once a minute).
func (s *Service) Touch(ctx context.Context, keyID string) error {
	return store.New(s.pool).TouchKey(ctx, keyID)
}

type View struct {
	Instance store.Instance
	Keys     []store.InstanceKey
	Usage    store.InstanceUsageTodayRow
}

// StatusReason is the operator-visible reason for a blocked or suspended instance.
func (v *View) StatusReason() *string {
	switch v.Instance.Status {
	case StatusBlocked:
		return v.Instance.BlockedReason
	case StatusSuspended:
		return v.Instance.LastVerificationError
	}
	return nil
}

func (s *Service) View(ctx context.Context, id string) (*View, error) {
	q := store.New(s.pool)
	inst, err := q.GetInstance(ctx, id)
	if notFound(err) {
		return nil, instanceNotFound()
	} else if err != nil {
		return nil, err
	}
	keys, err := q.ListKeys(ctx, id)
	if err != nil {
		return nil, err
	}
	usage, err := q.InstanceUsageToday(ctx, id)
	if err != nil {
		return nil, err
	}
	return &View{Instance: inst, Keys: keys, Usage: usage}, nil
}

// Verify fetches the origin's well-known document now and applies the result. It succeeds
// when the signing key ends up active and every active key is advertised. Failures here do
// not count towards suspension; only the scheduled re-verification does, so a caller cannot
// suspend an instance by calling verify during an origin outage.
func (s *Service) Verify(ctx context.Context, p Principal) (*View, error) {
	keys, fetchErr := s.fetcher.Keys(ctx, p.Origin)
	reason, err := s.apply(ctx, p.InstanceID, keys, fetchErr, p.KeyID)
	if err != nil {
		return nil, err
	}
	if reason != "" {
		return nil, problem.New(http.StatusUnprocessableEntity, problem.VerificationFailed, reason)
	}
	return s.View(ctx, p.InstanceID)
}

// apply records a verification result. signingKeyID is the caller's key for an explicit
// verification and empty for a scheduled one. It returns a non-empty reason when
// verification failed; state changes (activated keys, failure counts) are committed either
// way.
func (s *Service) apply(ctx context.Context, id string, advertised map[string]bool, fetchErr error, signingKeyID string) (reason string, err error) {
	scheduled := signingKeyID == ""
	if fetchErr != nil {
		var ve *wellknown.Error
		if !errors.As(fetchErr, &ve) {
			return "", fetchErr
		}
		reason = ve.Reason
	}
	now := s.now()
	next := now.Add(ReverifyInterval)
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := store.New(tx)
		inst, err := q.LockInstance(ctx, id)
		if notFound(err) {
			return instanceNotFound()
		} else if err != nil {
			return err
		}
		wkURL := wellknown.URL(inst.Origin)
		notListed := func(k store.InstanceKey) string {
			return fmt.Sprintf("key %s is not listed in %s", k.ID, wkURL)
		}

		switch inst.Status {
		case StatusBlocked:
			if scheduled {
				return nil
			}
			return blocked(deref(inst.BlockedReason))

		case StatusPending:
			if inst.PendingExpiresAt == nil || !inst.PendingExpiresAt.After(now) {
				return instanceNotFound()
			}
			if reason != "" {
				return nil
			}
			keys, err := q.ListKeys(ctx, id)
			if err != nil {
				return err
			}
			if len(keys) == 0 {
				return instanceNotFound()
			}
			key := keys[0]
			if !advertised[EncodeKey(key.PublicKey)] {
				reason = notListed(key)
				return nil
			}
			if _, err := q.GetVerifiedInstanceByOrigin(ctx, inst.Origin); err == nil {
				return problem.New(http.StatusConflict, problem.Conflict,
					"Another registration verified this origin first; register again to recover it with this key.")
			} else if !notFound(err) {
				return err
			}
			if err := q.ActivateKey(ctx, key.ID); err != nil {
				return err
			}
			err = q.ActivateInstance(ctx, store.ActivateInstanceParams{ID: id, NextVerificationAt: &next})
			if isUniqueViolation(err) {
				// Another pending registration for the origin verified concurrently.
				return problem.New(http.StatusConflict, problem.Conflict,
					"Another registration verified this origin first; register again to recover it with this key.")
			}
			return err

		default: // active, suspended
			if reason == "" {
				reason, err = s.applyKeys(ctx, q, id, advertised, signingKeyID, now, notListed)
				if err != nil {
					return err
				}
			}
			switch {
			case reason == "":
				return q.RecordVerificationSuccess(ctx, store.RecordVerificationSuccessParams{ID: id, NextVerificationAt: &next})
			case scheduled:
				res, err := q.RecordVerificationFailure(ctx, store.RecordVerificationFailureParams{
					ID: id, MaxFailures: MaxFailures, LastVerificationError: &reason, NextVerificationAt: &next,
				})
				if err == nil && res.Status == StatusSuspended && inst.Status == StatusActive {
					s.log.Warn("instance suspended after failed verifications", "instance_id", id, "origin", inst.Origin, "reason", reason)
				}
				return err
			}
			return nil
		}
	})
	return reason, err
}

// applyKeys activates advertised pending keys (a recovery key revokes all others) and
// checks that every active key is still advertised.
func (s *Service) applyKeys(ctx context.Context, q *store.Queries, id string, advertised map[string]bool, signingKeyID string,
	now time.Time, notListed func(store.InstanceKey) string,
) (string, error) {
	keys, err := q.ListKeys(ctx, id)
	if err != nil {
		return "", err
	}
	live := func(k store.InstanceKey) bool {
		return k.Status == KeyPending && (k.ExpiresAt == nil || k.ExpiresAt.After(now)) && advertised[EncodeKey(k.PublicKey)]
	}
	recovered := false
	for _, k := range keys {
		if k.Recovery && live(k) {
			if err := q.ActivateKey(ctx, k.ID); err != nil {
				return "", err
			}
			n, err := q.RevokeOtherKeys(ctx, store.RevokeOtherKeysParams{InstanceID: id, KeepID: k.ID})
			if err != nil {
				return "", err
			}
			s.log.Warn("instance recovered with a new key; all other keys revoked", "instance_id", id, "key_id", k.ID, "revoked", n)
			recovered = true
			break
		}
	}
	if !recovered {
		for _, k := range keys {
			if !k.Recovery && live(k) {
				if err := q.ActivateKey(ctx, k.ID); err != nil {
					return "", err
				}
			}
		}
	}

	keys, err = q.ListKeys(ctx, id)
	if err != nil {
		return "", err
	}
	active := 0
	for _, k := range keys {
		if k.ID == signingKeyID && k.Status != KeyActive {
			return notListed(k), nil
		}
		if k.Status == KeyActive {
			active++
			if !advertised[EncodeKey(k.PublicKey)] {
				return notListed(k), nil
			}
		}
	}
	if active == 0 {
		return "the instance has no active key", nil
	}
	return "", nil
}

// AddKey adds a pending rotation key. It becomes active once the origin advertises it and
// the instance is verified.
func (s *Service) AddKey(ctx context.Context, p Principal, publicKey string) (*store.InstanceKey, error) {
	pub, err := decodeKey("public_key", publicKey)
	if err != nil {
		return nil, err
	}
	var key store.InstanceKey
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := store.New(tx)
		if _, err := q.LockInstance(ctx, p.InstanceID); err != nil {
			return err
		}
		if _, err := q.GetKeyByPublicKey(ctx, store.GetKeyByPublicKeyParams{InstanceID: p.InstanceID, PublicKey: pub}); err == nil {
			return problem.New(http.StatusConflict, problem.Conflict, "This key is already registered for this instance.")
		} else if !notFound(err) {
			return err
		}
		n, err := q.CountLiveKeys(ctx, p.InstanceID)
		if err != nil {
			return err
		}
		if n >= MaxLiveKeys {
			return problem.Newf(http.StatusConflict, problem.Conflict,
				"An instance has at most %d active or pending keys; revoke one first.", MaxLiveKeys)
		}
		id := ids.New(ids.Key)
		if err := q.CreateKey(ctx, store.CreateKeyParams{ID: id, InstanceID: p.InstanceID, PublicKey: pub}); err != nil {
			return err
		}
		key, err = q.GetKeyByPublicKey(ctx, store.GetKeyByPublicKeyParams{InstanceID: p.InstanceID, PublicKey: pub})
		return err
	})
	if err != nil {
		return nil, err
	}
	return &key, nil
}

// RevokeKey revokes a key of the caller's instance. The last active key cannot be revoked.
// Revoking an already revoked key succeeds.
func (s *Service) RevokeKey(ctx context.Context, p Principal, keyID string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := store.New(tx)
		if _, err := q.LockInstance(ctx, p.InstanceID); err != nil {
			return err
		}
		keys, err := q.ListKeys(ctx, p.InstanceID)
		if err != nil {
			return err
		}
		var target *store.InstanceKey
		active := 0
		for i, k := range keys {
			if k.ID == keyID {
				target = &keys[i]
			}
			if k.Status == KeyActive {
				active++
			}
		}
		switch {
		// Pending recovery keys end only by expiring or being verified; otherwise whoever holds
		// a stolen active key could revoke them and block the owner's recovery.
		case target == nil, target.Recovery && target.Status == KeyPending:
			return problem.New(http.StatusNotFound, problem.KeyNotFound, "No such key for this instance.")
		case target.Status == KeyRevoked:
			return nil
		case target.Status == KeyActive && active == 1:
			return problem.New(http.StatusConflict, problem.Conflict,
				"The last active key cannot be revoked; deregister the instance instead.")
		}
		return q.RevokeKey(ctx, keyID)
	})
}

// Delete deregisters an instance. Its keys, subscriptions, usage and delivery log go with it.
func (s *Service) Delete(ctx context.Context, id string) error {
	n, err := store.New(s.pool).DeleteInstance(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return instanceNotFound()
	}
	return nil
}

// ReverifyDue re-verifies instances whose scheduled verification is due. Replicas claim
// disjoint batches, so it is safe to run everywhere.
func (s *Service) ReverifyDue(ctx context.Context, batch int) (int, error) {
	claimed, err := store.New(s.pool).ClaimDueVerifications(ctx, store.ClaimDueVerificationsParams{
		LeaseSeconds: 600, Batch: int32(batch), //nolint:gosec // batch is a small constant
	})
	if err != nil {
		return 0, err
	}
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(4)
	for _, id := range claimed {
		g.Go(func() error {
			inst, err := store.New(s.pool).GetInstance(gctx, id)
			if err != nil {
				if notFound(err) {
					return nil
				}
				return err
			}
			keys, fetchErr := s.fetcher.Keys(gctx, inst.Origin)
			reason, err := s.apply(gctx, id, keys, fetchErr, "")
			if err != nil {
				var p *problem.Problem
				if errors.As(err, &p) {
					return nil
				}
				return err
			}
			if reason != "" {
				s.log.Info("scheduled verification failed", "instance_id", id, "origin", inst.Origin, "reason", reason)
			}
			return nil
		})
	}
	return len(claimed), g.Wait()
}

// Prune deletes expired pending registrations, expired recovery keys and expired
// blocklist entries.
func (s *Service) Prune(ctx context.Context) error {
	q := store.New(s.pool)
	instances, err := q.DeleteExpiredPendingInstances(ctx)
	if err != nil {
		return err
	}
	keys, err := q.DeleteExpiredPendingKeys(ctx)
	if err != nil {
		return err
	}
	entries, err := q.DeleteExpiredBlocklist(ctx)
	if err != nil {
		return err
	}
	if instances+keys+entries > 0 {
		s.log.Info("pruned expired records", "pending_instances", instances, "pending_keys", keys, "blocklist_entries", entries)
	}
	return nil
}

// RunMaintenance re-verifies due instances every minute and prunes every ten minutes
// until ctx ends.
func (s *Service) RunMaintenance(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for tick := 0; ; tick++ {
		if tick%10 == 0 {
			if err := s.Prune(ctx); err != nil && ctx.Err() == nil {
				s.log.Warn("pruning expired records", "error", err.Error())
			}
		}
		for {
			n, err := s.ReverifyDue(ctx, 20)
			if err != nil && ctx.Err() == nil {
				s.log.Warn("scheduled verification", "error", err.Error())
			}
			if err != nil || n < 20 {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Find returns instances by ID or by origin (for the admin CLI).
func (s *Service) Find(ctx context.Context, idOrOrigin string) ([]store.Instance, error) {
	q := store.New(s.pool)
	if strings.HasPrefix(idOrOrigin, ids.Instance+"_") {
		inst, err := q.GetInstance(ctx, idOrOrigin)
		if notFound(err) {
			return nil, nil
		}
		return []store.Instance{inst}, err
	}
	origin, err := NormalizeOrigin(idOrOrigin, true)
	if err != nil {
		return nil, fmt.Errorf("%q is neither an instance ID nor an origin: %w", idOrOrigin, err)
	}
	return q.ListInstancesByOrigin(ctx, origin)
}

// List returns instances, optionally filtered by status (for the admin CLI).
func (s *Service) List(ctx context.Context, status string, limit int) ([]store.Instance, error) {
	return store.New(s.pool).ListInstances(ctx, store.ListInstancesParams{
		Status: optional(status), MaxRows: int32(min(limit, 10000)), //nolint:gosec // bounded above
	})
}

// Block blocks a verified instance. Its requests and pushes fail with instance_blocked and
// the reason.
func (s *Service) Block(ctx context.Context, id, reason string) error {
	if strings.TrimSpace(reason) == "" {
		return errors.New("a reason is required; it is shown to the instance operator")
	}
	n, err := store.New(s.pool).BlockInstance(ctx, store.BlockInstanceParams{ID: id, Reason: ptr(reason)})
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("no verified instance with that ID (pending registrations cannot be blocked; blocklist the origin instead)")
	}
	return nil
}

// Unblock makes a blocked instance active again and schedules an immediate verification.
func (s *Service) Unblock(ctx context.Context, id string) error {
	n, err := store.New(s.pool).UnblockInstance(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("no blocked instance with that ID")
	}
	return nil
}

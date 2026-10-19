// Package push accepts push requests from instances and delivers them (docs/protocol.md,
// "Push requests"). Accepted pushes are written to the delivery log and queued on river in
// one transaction; workers hand them to the APNs, FCM and Web Push providers with retries, backoff
// and dead-lettering. Nothing here stores or reads notification content: the encrypted body
// lives in the queue only until the push is delivered or given up.
package push

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"

	"github.com/parkerbrown98/gotalk-gateway/internal/devices"
	"github.com/parkerbrown98/gotalk-gateway/internal/ids"
	"github.com/parkerbrown98/gotalk-gateway/internal/problem"
	"github.com/parkerbrown98/gotalk-gateway/internal/providers"
	"github.com/parkerbrown98/gotalk-gateway/internal/store"
)

// Delivery-log statuses (docs/protocol.md, "Push status").
const (
	StatusQueued  = "queued"
	StatusSent    = "sent"
	StatusFailed  = "failed"
	StatusExpired = "expired"
	StatusGone    = "gone"
)

const (
	// LogRetention is how long delivery-log entries are kept.
	LogRetention = 72 * time.Hour
	pruneBatch   = 5000
)

// Inserter queues jobs inside a transaction; *river.Client[pgx.Tx] implements it.
type Inserter interface {
	InsertManyFastTx(ctx context.Context, tx pgx.Tx, params []river.InsertManyParams) (int, error)
}

type Service struct {
	pool      *pgxpool.Pool
	queue     Inserter
	providers *providers.Registry
	metrics   *Metrics
	log       *slog.Logger
	now       func() time.Time
}

type Options struct {
	Metrics *Metrics
	Logger  *slog.Logger
	Now     func() time.Time
}

func NewService(pool *pgxpool.Pool, queue Inserter, reg *providers.Registry, o Options) *Service {
	s := &Service{pool: pool, queue: queue, providers: reg, metrics: o.Metrics, log: o.Logger, now: o.Now}
	if s.metrics == nil {
		s.metrics = NewMetrics(nil)
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s
}

// Sender is the authenticated instance.
type Sender struct {
	InstanceID string
	Origin     string
}

// Item is one entry of a push request: a parsed entry, or the reason it could not be parsed.
type Item struct {
	Entry Entry
	Err   *problem.Problem
}

// Result is the outcome of one entry: queued with a push ID, or rejected with an error.
type Result struct {
	PushID         string           `json:"push_id,omitempty"`
	SubscriptionID string           `json:"subscription_id"`
	Error          *problem.Problem `json:"error,omitempty"`
}

// Idempotency is the request's Idempotency-Key, if any.
type Idempotency struct {
	Key string
	// Fingerprint identifies the request (path and body); a key reused for another request
	// is refused.
	Fingerprint []byte
	// AcceptedOnly remembers the response only when a push was queued. A single push that is
	// rejected fails with an HTTP error, and a retry with the same key is evaluated again.
	AcceptedOnly bool
}

type Outcome struct {
	Results []Result
	// Replayed is set when the results are those of an earlier request with the same key.
	Replayed bool
}

func unavailable() *problem.Problem {
	return problem.New(http.StatusServiceUnavailable, problem.ProviderUnavailable,
		"The gateway could not queue the push; retry with backoff.")
}

var errIdempotencyRace = errors.New("idempotency key committed concurrently")

// Accept validates the entries against their subscriptions and queues the valid ones. It
// fails only when nothing could be queued because the database is unavailable, or when an
// Idempotency-Key is reused for a different request.
func (s *Service) Accept(ctx context.Context, from Sender, items []Item, idem Idempotency) (*Outcome, error) {
	if idem.Key != "" {
		if out, err := s.replay(ctx, from, idem); out != nil || err != nil {
			return out, err
		}
	}

	var want []string
	for _, it := range items {
		if it.Err == nil {
			want = append(want, it.Entry.SubscriptionID)
		}
	}
	targets := map[string]store.GetPushTargetsRow{}
	if len(want) > 0 {
		rows, err := store.New(s.pool).GetPushTargets(ctx, want)
		if err != nil {
			s.log.ErrorContext(ctx, "loading push targets", "error", err.Error())
			return nil, unavailable()
		}
		for _, r := range rows {
			targets[r.ID] = r
		}
	}

	now := s.now().UTC()
	results := make([]Result, len(items))
	var logs []store.InsertDeliveryLogParams
	var jobs []river.InsertManyParams
	for i, it := range items {
		res := Result{SubscriptionID: it.Entry.SubscriptionID, Error: it.Err}
		if res.Error == nil {
			t, ok := targets[it.Entry.SubscriptionID]
			res.Error = s.check(it.Entry, t, ok, from)
		}
		if res.Error == nil {
			res.PushID = ids.New(ids.Push)
			e := it.Entry
			logs = append(logs, store.InsertDeliveryLogParams{
				ID: res.PushID, InstanceID: from.InstanceID, SubscriptionID: e.SubscriptionID, NotificationID: e.NotificationID,
			})
			args := DeliveryArgs{
				PushID: res.PushID, InstanceID: from.InstanceID, SubscriptionID: e.SubscriptionID, Mode: e.Mode,
				NotificationID: e.NotificationID, Payload: e.Payload, Urgency: e.Urgency, TTL: e.TTL,
				CollapseKey: e.CollapseKey, AcceptedAt: now,
			}
			if e.Mode == providers.ModeIDOnly {
				args.Instance = from.Origin
			}
			opts := args.InsertOpts()
			opts.Priority = priority(e.Urgency)
			jobs = append(jobs, river.InsertManyParams{Args: args, InsertOpts: &opts})
		} else {
			s.metrics.rejected.WithLabelValues(res.Error.Code).Inc()
		}
		results[i] = res
	}

	rejected := int64(len(items) - len(logs))
	remember := idem.Key != "" && (!idem.AcceptedOnly || len(logs) > 0)
	if len(logs) == 0 && !remember {
		if err := store.New(s.pool).AddUsage(ctx, store.AddUsageParams{InstanceID: from.InstanceID, Rejected: rejected}); err != nil {
			s.log.WarnContext(ctx, "counting rejected pushes", "error", err.Error())
		}
		return &Outcome{Results: results}, nil
	}
	var response []byte
	if remember {
		var err error
		if response, err = json.Marshal(results); err != nil {
			return nil, err
		}
	}

	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := store.New(tx)
		if len(logs) > 0 {
			if _, err := q.InsertDeliveryLog(ctx, logs); err != nil {
				return fmt.Errorf("writing the delivery log: %w", err)
			}
			if _, err := s.queue.InsertManyFastTx(ctx, tx, jobs); err != nil {
				return fmt.Errorf("queueing pushes: %w", err)
			}
		}
		if err := q.AddUsage(ctx, store.AddUsageParams{
			InstanceID: from.InstanceID, Accepted: int64(len(logs)), Rejected: rejected,
		}); err != nil {
			return fmt.Errorf("counting usage: %w", err)
		}
		if remember {
			n, err := q.SaveIdempotentResponse(ctx, store.SaveIdempotentResponseParams{
				InstanceID: from.InstanceID, Key: idem.Key, Fingerprint: idem.Fingerprint, Response: response,
			})
			if err != nil {
				return fmt.Errorf("saving the idempotency key: %w", err)
			}
			if n == 0 {
				return errIdempotencyRace
			}
		}
		return nil
	})
	if errors.Is(err, errIdempotencyRace) {
		// A concurrent request with the same key won; this one's pushes were rolled back.
		if out, err := s.replay(ctx, from, idem); out != nil || err != nil {
			return out, err
		}
		return nil, unavailable()
	}
	if err != nil {
		s.log.ErrorContext(ctx, "accepting pushes", "instance_id", from.InstanceID, "error", err.Error())
		return nil, unavailable()
	}
	s.metrics.accepted.Add(float64(len(logs)))
	return &Outcome{Results: results}, nil
}

// check decides whether an entry can be queued for its subscription.
func (s *Service) check(e Entry, t store.GetPushTargetsRow, found bool, from Sender) *problem.Problem {
	switch {
	case !found || t.InstanceID != from.InstanceID:
		// Foreign subscriptions look exactly like missing ones.
		return problem.New(http.StatusNotFound, problem.SubscriptionNotFound, "No such subscription.")
	case t.Status == devices.StatusGone:
		return problem.New(http.StatusGone, problem.SubscriptionGone,
			"The provider reported the device token as dead. Delete the subscription.")
	case t.Platform == devices.Web && e.Mode == providers.ModeIDOnly:
		return problem.Invalid("mode", "id_only is not supported for web subscriptions; send an encrypted payload")
	case s.providers.Get(t.AppID, t.Platform) == nil:
		return problem.Newf(http.StatusServiceUnavailable, problem.ProviderUnavailable,
			"This gateway cannot deliver to %s devices of app %q.", t.Platform, t.AppID)
	}
	return nil
}

// replay returns the remembered results of a live idempotency key, nil when there is none,
// or an error when the key was used for a different request.
func (s *Service) replay(ctx context.Context, from Sender, idem Idempotency) (*Outcome, error) {
	row, err := store.New(s.pool).GetIdempotentResponse(ctx, store.GetIdempotentResponseParams{InstanceID: from.InstanceID, Key: idem.Key})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		s.log.ErrorContext(ctx, "reading an idempotency key", "error", err.Error())
		return nil, unavailable()
	}
	if string(row.Fingerprint) != string(idem.Fingerprint) {
		return nil, problem.New(http.StatusUnprocessableEntity, problem.InvalidRequest,
			"This Idempotency-Key was already used for a different request in the last 24 hours.")
	}
	var results []Result
	if err := json.Unmarshal(row.Response, &results); err != nil {
		return nil, err
	}
	return &Outcome{Results: results, Replayed: true}, nil
}

// Get returns the delivery-log entry of a push sent by instanceID.
func (s *Service) Get(ctx context.Context, instanceID, pushID string) (store.DeliveryLog, error) {
	l, err := store.New(s.pool).GetPush(ctx, store.GetPushParams{ID: pushID, InstanceID: instanceID})
	if errors.Is(err, pgx.ErrNoRows) {
		return store.DeliveryLog{}, problem.New(http.StatusNotFound, problem.PushNotFound, "No such push.")
	}
	return l, err
}

// ErrorMessage is the human-readable message of a delivery error code.
func ErrorMessage(code string, detail *string) string {
	msg := map[string]string{
		problem.SubscriptionGone:    "The device token is no longer valid; delete the subscription.",
		problem.ProviderRejected:    "The provider permanently refused the push.",
		problem.ProviderUnavailable: "The provider could not be reached or kept failing.",
		problem.InternalError:       "The gateway failed to deliver the push.",
	}[code]
	if msg == "" {
		msg = "Delivery failed."
	}
	if detail != nil && *detail != "" {
		msg = msg[:len(msg)-1] + " (" + *detail + ")."
	}
	return msg
}

// Prune deletes delivery-log entries past LogRetention and idempotency keys past 24 hours.
func (s *Service) Prune(ctx context.Context) (int64, error) {
	q := store.New(s.pool)
	var total int64
	for {
		n, err := q.DeleteOldDeliveryLog(ctx, store.DeleteOldDeliveryLogParams{
			RetentionHours: int32(LogRetention / time.Hour), Batch: pruneBatch,
		})
		total += n
		if err != nil {
			return total, fmt.Errorf("pruning the delivery log: %w", err)
		}
		if n < pruneBatch {
			break
		}
	}
	for {
		n, err := q.DeleteOldIdempotencyKeys(ctx, pruneBatch)
		if err != nil {
			return total, fmt.Errorf("pruning idempotency keys: %w", err)
		}
		if n < pruneBatch {
			break
		}
	}
	if total > 0 {
		s.log.Info("pruned delivery log", "count", total)
	}
	return total, nil
}

// RunMaintenance prunes every ten minutes until ctx ends.
func (s *Service) RunMaintenance(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		if _, err := s.Prune(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("pruning push data", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

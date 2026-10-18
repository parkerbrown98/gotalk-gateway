package push

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"

	"github.com/parkerbrown98/gotalk-gateway/internal/devices"
	"github.com/parkerbrown98/gotalk-gateway/internal/problem"
	"github.com/parkerbrown98/gotalk-gateway/internal/providers"
	"github.com/parkerbrown98/gotalk-gateway/internal/store"
)

const (
	// QueueName is the river queue pushes are delivered from.
	QueueName = "push"
	// MaxAttempts is how many times a push is sent to its provider before it is given up and
	// dead-lettered (docs/protocol.md, "Push status").
	MaxAttempts = 5
	// RetryBase is the first retry delay; each further retry doubles it, with jitter.
	RetryBase = time.Second
	// jobMaxAttempts bounds river's own retries when the worker fails unexpectedly (for
	// example while the database is down). Provider retries are snoozes and do not count.
	jobMaxAttempts = 10
	// maxErrorDetail is the delivery log's limit for error_detail.
	maxErrorDetail = 200
)

// DeliveryArgs is a queued push. The encrypted payload is stored only here, and only until
// the job is finished; the platform token is read from the subscription at each attempt.
type DeliveryArgs struct {
	PushID         string `json:"push_id"`
	InstanceID     string `json:"instance_id"`
	SubscriptionID string `json:"subscription_id"`
	Mode           string `json:"mode"`
	NotificationID string `json:"notification_id"`
	// Instance is the origin, carried in id_only mode only.
	Instance    string    `json:"instance,omitempty"`
	Payload     []byte    `json:"payload,omitempty"`
	Urgency     string    `json:"urgency"`
	TTL         int       `json:"ttl"`
	CollapseKey string    `json:"collapse_key,omitempty"`
	AcceptedAt  time.Time `json:"accepted_at"`
}

func (DeliveryArgs) Kind() string { return "push_delivery" }

func (DeliveryArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueName, MaxAttempts: jobMaxAttempts}
}

// priority maps urgency to river's job priority (1 is worked first).
func priority(urgency string) int {
	switch urgency {
	case providers.UrgencyHigh:
		return 1
	case providers.UrgencyLow:
		return 3
	default:
		return 2
	}
}

// expiresAt is when the push's TTL runs out.
func (a DeliveryArgs) expiresAt() time.Time {
	return a.AcceptedAt.Add(time.Duration(a.TTL) * time.Second)
}

type WorkerOptions struct {
	// ProviderTimeout bounds each provider request.
	ProviderTimeout time.Duration
	// RetryBase overrides RetryBase (tests).
	RetryBase time.Duration
	Metrics   *Metrics
	Logger    *slog.Logger
	Now       func() time.Time
}

// Worker delivers queued pushes.
type Worker struct {
	river.WorkerDefaults[DeliveryArgs]
	pool      *pgxpool.Pool
	devices   *devices.Service
	providers *providers.Registry
	timeout   time.Duration
	retryBase time.Duration
	metrics   *Metrics
	log       *slog.Logger
	now       func() time.Time
}

func NewWorker(pool *pgxpool.Pool, devicesSvc *devices.Service, reg *providers.Registry, o WorkerOptions) *Worker {
	w := &Worker{
		pool: pool, devices: devicesSvc, providers: reg, timeout: o.ProviderTimeout, retryBase: o.RetryBase,
		metrics: o.Metrics, log: o.Logger, now: o.Now,
	}
	if w.timeout <= 0 {
		w.timeout = 10 * time.Second
	}
	if w.retryBase <= 0 {
		w.retryBase = RetryBase
	}
	if w.metrics == nil {
		w.metrics = NewMetrics(nil)
	}
	if w.log == nil {
		w.log = slog.New(slog.DiscardHandler)
	}
	if w.now == nil {
		w.now = time.Now
	}
	return w
}

// Timeout leaves room for the bookkeeping around the provider request.
func (w *Worker) Timeout(*river.Job[DeliveryArgs]) time.Duration { return w.timeout + 20*time.Second }

// NextRetry schedules river's retry of an unexpected failure, such as a database outage.
func (w *Worker) NextRetry(job *river.Job[DeliveryArgs]) time.Time {
	return w.now().Add(min(w.backoff(job.Attempt), time.Minute))
}

// backoff is the delay before retry number attempt (1-based): RetryBase doubled each time,
// with "equal jitter" so it stays between half and all of that.
func (w *Worker) backoff(attempt int) time.Duration {
	d := w.retryBase << min(max(attempt-1, 0), 20)
	return d/2 + rand.N(d/2+1) //nolint:gosec // jitter needs no cryptographic randomness
}

func (w *Worker) Work(ctx context.Context, job *river.Job[DeliveryArgs]) error {
	err := w.work(ctx, job.Args)
	var snooze *river.JobSnoozeError
	var cancel *river.JobCancelError
	if err != nil && !errors.As(err, &snooze) && !errors.As(err, &cancel) && job.Attempt >= job.MaxAttempts {
		// River discards the job after this attempt: record a final status so the instance
		// does not see it queued forever.
		w.log.Error("push dead-lettered after unexpected errors", "push_id", job.Args.PushID, "error", err.Error())
		w.metrics.deadLettered.Inc()
		_ = w.finish(context.WithoutCancel(ctx), job.Args, StatusFailed, problem.InternalError, "")
	}
	return err
}

func (w *Worker) work(ctx context.Context, a DeliveryArgs) error {
	q := store.New(w.pool)
	st, err := q.GetDeliveryState(ctx, a.PushID)
	if errors.Is(err, pgx.ErrNoRows) {
		// The instance was deleted, or the entry outlived the delivery log.
		return nil
	} else if err != nil {
		return err
	}
	if st.Status != StatusQueued {
		return nil
	}
	expires := a.expiresAt()
	// A push with a TTL of 0 gets its one attempt even if the queue was slow to reach it.
	if !w.now().Before(expires) && (a.TTL > 0 || st.Attempts > 0) {
		return w.finish(ctx, a, StatusExpired, deref(st.ErrorCode), deref(st.ErrorDetail))
	}

	d, err := w.devices.Get(ctx, a.SubscriptionID)
	var p *problem.Problem
	if errors.As(err, &p) || (err == nil && d.InstanceID != a.InstanceID) {
		return w.finish(ctx, a, StatusFailed, problem.SubscriptionGone, "The subscription was deleted before delivery")
	} else if err != nil {
		return err
	}
	if d.Status == devices.StatusGone {
		return w.finish(ctx, a, StatusGone, problem.SubscriptionGone, "The subscription was already gone")
	}
	prov := w.providers.Get(d.AppID, d.Platform)
	if prov == nil {
		return w.finish(ctx, a, StatusFailed, problem.ProviderUnavailable, "No "+d.Platform+" credentials are configured for app "+d.AppID)
	}

	attempt, err := q.RecordDeliveryAttempt(ctx, a.PushID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	msg := providers.Message{
		SubscriptionID: a.SubscriptionID, Mode: a.Mode, Body: a.Payload, Instance: a.Instance,
		NotificationID: a.NotificationID, Urgency: a.Urgency, Expiration: expires, CollapseKey: a.CollapseKey,
	}
	sendCtx, cancel := context.WithTimeout(ctx, w.timeout)
	start := time.Now()
	err = prov.Send(sendCtx, providers.Target{Token: d.Token, APNsEnvironment: deref(d.ApnsEnvironment)}, msg)
	cancel()
	elapsed := time.Since(start)

	if err == nil {
		w.metrics.observeRequest(prov.Name(), "ok", elapsed)
		return w.finish(ctx, a, StatusSent, "", "")
	}
	if ctx.Err() != nil {
		// Shutting down: try again as soon as a worker is available.
		return river.JobSnooze(0)
	}
	var perr *providers.Error
	if !errors.As(err, &perr) {
		perr = providers.Transport(prov.Name(), err)
	}
	w.metrics.observeRequest(prov.Name(), perr.Kind.String(), elapsed)
	log := w.log.With("push_id", a.PushID, "subscription_id", a.SubscriptionID, "provider", prov.Name(),
		"attempt", attempt, "reason", perr.Reason)

	switch perr.Kind {
	case providers.Gone:
		marked, err := w.devices.MarkGone(ctx, d.ID, d.TokenHash, d.ApnsEnvironment)
		if err != nil {
			return err
		}
		if marked {
			return w.finish(ctx, a, StatusGone, problem.SubscriptionGone, perr.Reason)
		}
		// The client replaced the token since it was read, so the rejection is stale: try
		// the subscription again as it is now.
		log.Info("ignoring a dead-token report for a replaced token")
		return w.retry(ctx, a, attempt, expires, perr, 0)
	case providers.Rejected:
		log.Warn("provider rejected a push")
		return w.finish(ctx, a, StatusFailed, problem.ProviderRejected, perr.Reason)
	default:
		log.Info("provider failed; retrying", "error", perr.Error())
		return w.retry(ctx, a, attempt, expires, perr, w.backoff(int(attempt)))
	}
}

// retry snoozes the job for delay (or the provider's Retry-After, if longer). A push that
// has used all its attempts is dead-lettered; one whose TTL would run out first expires.
func (w *Worker) retry(ctx context.Context, a DeliveryArgs, attempt int32, expires time.Time, perr *providers.Error, delay time.Duration) error {
	if attempt >= MaxAttempts {
		w.log.Warn("push dead-lettered: retries exhausted", "push_id", a.PushID, "attempts", attempt, "reason", perr.Reason)
		w.metrics.deadLettered.Inc()
		if err := w.finish(ctx, a, StatusFailed, problem.ProviderUnavailable, perr.Reason); err != nil {
			return err
		}
		return river.JobCancel(fmt.Errorf("retries exhausted after %d attempts: %w", attempt, perr))
	}
	delay = max(delay, perr.RetryAfter)
	if !w.now().Add(delay).Before(expires) {
		return w.finish(ctx, a, StatusExpired, problem.ProviderUnavailable, perr.Reason)
	}
	code, detail := problem.ProviderUnavailable, truncate(perr.Reason)
	if err := store.New(w.pool).RecordDeliveryRetry(ctx, store.RecordDeliveryRetryParams{
		ID: a.PushID, ErrorCode: &code, ErrorDetail: &detail,
	}); err != nil {
		return err
	}
	return river.JobSnooze(delay)
}

// finish records a push's final status and counts it in the instance's usage. It does
// nothing if the push was already finished or deleted.
func (w *Worker) finish(ctx context.Context, a DeliveryArgs, status, code, detail string) error {
	params := store.FinishDeliveryParams{ID: a.PushID, Status: status}
	if code != "" {
		params.ErrorCode = &code
	}
	if detail != "" {
		detail = truncate(detail)
		params.ErrorDetail = &detail
	}
	var latency *int32
	done := false
	err := pgx.BeginFunc(ctx, w.pool, func(tx pgx.Tx) error {
		q := store.New(tx)
		row, err := q.FinishDelivery(ctx, params)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		} else if err != nil {
			return err
		}
		done, latency = true, row.LatencyMs
		usage := store.AddUsageParams{InstanceID: row.InstanceID, Failed: 1}
		if status == StatusSent {
			usage = store.AddUsageParams{InstanceID: row.InstanceID, Sent: 1}
			if err := q.TouchDeviceLastPush(ctx, a.SubscriptionID); err != nil {
				return err
			}
		}
		return q.AddUsage(ctx, usage)
	})
	if err != nil {
		return err
	}
	if done {
		w.metrics.finished(status, latency)
		if status == StatusGone {
			w.log.Info("push found a dead token", "push_id", a.PushID, "subscription_id", a.SubscriptionID, "reason", detail)
		}
	}
	return nil
}

func truncate(s string) string {
	if len(s) <= maxErrorDetail {
		return s
	}
	return s[:maxErrorDetail]
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

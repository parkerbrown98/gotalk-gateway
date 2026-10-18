package push

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/parkerbrown98/gotalk-gateway/internal/apps"
	"github.com/parkerbrown98/gotalk-gateway/internal/blocklist"
	"github.com/parkerbrown98/gotalk-gateway/internal/devices"
	"github.com/parkerbrown98/gotalk-gateway/internal/problem"
	"github.com/parkerbrown98/gotalk-gateway/internal/providers"
	"github.com/parkerbrown98/gotalk-gateway/internal/store"
	"github.com/parkerbrown98/gotalk-gateway/internal/testdb"
)

func TestMain(m *testing.M) {
	code := m.Run()
	testdb.Terminate()
	os.Exit(code)
}

const origin = "https://forum.example"

// fakeProvider answers with scripted errors and records what it was asked to send.
type fakeProvider struct {
	mu      sync.Mutex
	errs    []error
	targets []providers.Target
	msgs    []providers.Message
	hook    func()
}

func (f *fakeProvider) Name() string { return "fake" }

func (f *fakeProvider) Send(_ context.Context, t providers.Target, m providers.Message) error {
	f.mu.Lock()
	f.targets = append(f.targets, t)
	f.msgs = append(f.msgs, m)
	var err error
	if len(f.errs) > 0 {
		err, f.errs = f.errs[0], f.errs[1:]
	}
	hook := f.hook
	f.hook = nil
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	return err
}

func (f *fakeProvider) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.targets)
}

// recordingQueue stands in for river and keeps the jobs it was given.
type recordingQueue struct{ jobs []DeliveryArgs }

func (q *recordingQueue) InsertManyFastTx(_ context.Context, _ pgx.Tx, params []river.InsertManyParams) (int, error) {
	for _, p := range params {
		q.jobs = append(q.jobs, p.Args.(DeliveryArgs))
	}
	return len(params), nil
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	t        *testing.T
	pool     *pgxpool.Pool
	devices  *devices.Service
	reg      *providers.Registry
	prov     *fakeProvider
	queue    *recordingQueue
	svc      *Service
	worker   *Worker
	clock    *clock
	instance string
	device   string
	token    string
}

const retryBase = 100 * time.Millisecond

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	pool := testdb.Pool(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	registry := apps.NewRegistry(pool)
	_, err := registry.Sync(ctx, []apps.App{{ID: "gotalk", Name: "Gotalk", IOS: &apps.IOS{BundleID: "app.example.gotalk"}}})
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO instances (id, origin, status, contact_email, verified_at)
		VALUES ('inst_AAAAAAAAAAAA', $1, 'active', 'ops@forum.example', now())`, origin)
	require.NoError(t, err)
	devicesSvc := devices.New(pool, registry, blocklist.NewCache(pool, log), devices.Options{Logger: log})
	e := &env{
		t: t, pool: pool, devices: devicesSvc, reg: providers.NewRegistry(), prov: &fakeProvider{},
		queue: &recordingQueue{}, clock: &clock{t: time.Now()}, instance: "inst_AAAAAAAAAAAA",
		token: strings.Repeat("ab", 32),
	}
	e.reg.Set("gotalk", devices.IOS, e.prov)
	reg, err := devicesSvc.Register(ctx, devices.RegisterInput{AppID: "gotalk", InstanceOrigin: origin, Platform: devices.IOS, Token: e.token}, nil)
	require.NoError(t, err)
	e.device = reg.SubscriptionID
	e.svc = NewService(pool, e.queue, e.reg, Options{Logger: log, Now: e.clock.now})
	e.worker = NewWorker(pool, devicesSvc, e.reg, WorkerOptions{RetryBase: retryBase, Logger: log, Now: e.clock.now})
	return e
}

// accept queues one push and returns its job.
func (e *env) accept(mut ...func(*Entry)) DeliveryArgs {
	e.t.Helper()
	entry := Entry{SubscriptionID: e.device, Mode: providers.ModeEncrypted, NotificationID: "ntf_1",
		Payload: []byte("ciphertext"), Urgency: providers.UrgencyHigh, TTL: 3600, CollapseKey: "c_1"}
	for _, m := range mut {
		m(&entry)
	}
	out, err := e.svc.Accept(context.Background(), Sender{InstanceID: e.instance, Origin: origin}, []Item{{Entry: entry}}, Idempotency{})
	require.NoError(e.t, err)
	require.Nil(e.t, out.Results[0].Error)
	return e.queue.jobs[len(e.queue.jobs)-1]
}

func (e *env) work(a DeliveryArgs) error {
	return e.worker.Work(context.Background(), &river.Job[DeliveryArgs]{
		JobRow: &rivertype.JobRow{ID: 1, Attempt: 1, MaxAttempts: jobMaxAttempts}, Args: a,
	})
}

func (e *env) state(a DeliveryArgs) store.DeliveryLog {
	e.t.Helper()
	l, err := e.svc.Get(context.Background(), e.instance, a.PushID)
	require.NoError(e.t, err)
	return l
}

func (e *env) usage() (accepted, rejected, sent, failed int64) {
	e.t.Helper()
	require.NoError(e.t, e.pool.QueryRow(context.Background(),
		"SELECT accepted, rejected, sent, failed FROM usage_counters WHERE instance_id = $1", e.instance).
		Scan(&accepted, &rejected, &sent, &failed))
	return
}

func snoozed(t *testing.T, err error) time.Duration {
	t.Helper()
	var s *river.JobSnoozeError
	require.ErrorAs(t, err, &s)
	return s.Duration
}

func retryErr(reason string, after time.Duration) error {
	return &providers.Error{Kind: providers.Retry, Reason: reason, Status: 503, RetryAfter: after}
}

func TestDeliverSent(t *testing.T) {
	e := newEnv(t)
	a := e.accept()
	assert.Equal(t, "ciphertext", string(a.Payload))
	assert.Empty(t, a.Instance, "encrypted pushes do not carry the origin")
	assert.Equal(t, StatusQueued, e.state(a).Status)

	require.NoError(t, e.work(a))
	l := e.state(a)
	assert.Equal(t, StatusSent, l.Status)
	assert.Equal(t, int32(1), l.Attempts)
	assert.NotNil(t, l.LatencyMs)
	assert.Nil(t, l.ErrorCode)
	require.Len(t, e.prov.targets, 1)
	assert.Equal(t, providers.Target{Token: e.token, APNsEnvironment: "production"}, e.prov.targets[0])
	assert.Equal(t, providers.Message{
		SubscriptionID: e.device, Mode: "encrypted", Body: []byte("ciphertext"), NotificationID: "ntf_1",
		Urgency: "high", Expiration: a.AcceptedAt.Add(time.Hour), CollapseKey: "c_1",
	}, e.prov.msgs[0])
	accepted, rejected, sent, failed := e.usage()
	assert.Equal(t, []int64{1, 0, 1, 0}, []int64{accepted, rejected, sent, failed})
	var lastPush *time.Time
	require.NoError(t, e.pool.QueryRow(context.Background(), "SELECT last_push_at FROM devices WHERE id = $1", e.device).Scan(&lastPush))
	assert.NotNil(t, lastPush)

	require.NoError(t, e.work(a), "a finished push is not sent again")
	assert.Equal(t, 1, e.prov.calls())
}

func TestDeliverIDOnly(t *testing.T) {
	e := newEnv(t)
	a := e.accept(func(en *Entry) { en.Mode, en.Payload = providers.ModeIDOnly, nil })
	assert.Equal(t, origin, a.Instance)
	require.NoError(t, e.work(a))
	assert.Equal(t, origin, e.prov.msgs[0].Instance)
	assert.Equal(t, "ntf_1", e.prov.msgs[0].NotificationID)
	assert.Nil(t, e.prov.msgs[0].Body)
}

func TestDeliverRetriesWithBackoffThenDeadLetters(t *testing.T) {
	e := newEnv(t)
	for range MaxAttempts {
		e.prov.errs = append(e.prov.errs, retryErr("APNs ServiceUnavailable", 0))
	}
	a := e.accept()
	for attempt := 1; attempt < MaxAttempts; attempt++ {
		d := snoozed(t, e.work(a))
		full := retryBase << (attempt - 1)
		assert.GreaterOrEqual(t, d, full/2, "attempt %d", attempt)
		assert.LessOrEqual(t, d, full, "attempt %d", attempt)
		l := e.state(a)
		assert.Equal(t, StatusQueued, l.Status)
		assert.Equal(t, int32(attempt), l.Attempts)
		assert.Equal(t, problem.ProviderUnavailable, *l.ErrorCode, "the last failure is kept for an eventual expiry")
	}
	err := e.work(a)
	var cancel *river.JobCancelError
	require.ErrorAs(t, err, &cancel, "a push out of attempts is dead-lettered")
	l := e.state(a)
	assert.Equal(t, StatusFailed, l.Status)
	assert.Equal(t, int32(MaxAttempts), l.Attempts)
	assert.Equal(t, problem.ProviderUnavailable, *l.ErrorCode)
	assert.Equal(t, "APNs ServiceUnavailable", *l.ErrorDetail)
	_, _, sent, failed := e.usage()
	assert.Equal(t, []int64{0, 1}, []int64{sent, failed})
}

func TestDeliverHonorsRetryAfter(t *testing.T) {
	e := newEnv(t)
	e.prov.errs = []error{retryErr("FCM QUOTA_EXCEEDED", 30*time.Second)}
	a := e.accept()
	assert.Equal(t, 30*time.Second, snoozed(t, e.work(a)))
	require.NoError(t, e.work(a))
	assert.Equal(t, StatusSent, e.state(a).Status)
	assert.Equal(t, int32(2), e.state(a).Attempts)
}

func TestDeliverExpires(t *testing.T) {
	e := newEnv(t)
	// A retry that would land after the TTL expires the push instead.
	e.prov.errs = []error{retryErr("APNs TooManyRequests", time.Minute)}
	a := e.accept(func(en *Entry) { en.TTL = 30 })
	require.NoError(t, e.work(a))
	l := e.state(a)
	assert.Equal(t, StatusExpired, l.Status)
	assert.Equal(t, problem.ProviderUnavailable, *l.ErrorCode)

	// The queue reaching a push after its TTL expires it without sending.
	b := e.accept(func(en *Entry) { en.TTL = 30 })
	e.clock.add(31 * time.Second)
	require.NoError(t, e.work(b))
	assert.Equal(t, StatusExpired, e.state(b).Status)
	assert.Nil(t, e.state(b).ErrorCode)
	assert.Equal(t, 1, e.prov.calls())
}

func TestDeliverTTLZero(t *testing.T) {
	e := newEnv(t)
	a := e.accept(func(en *Entry) { en.TTL = 0 })
	e.clock.add(5 * time.Second)
	e.prov.errs = []error{retryErr("APNs ServiceUnavailable", 0)}
	require.NoError(t, e.work(a), "a TTL of 0 gets exactly one attempt, even late")
	assert.Equal(t, 1, e.prov.calls())
	assert.Equal(t, StatusExpired, e.state(a).Status, "and is dropped instead of retried")
}

func TestDeliverDeadToken(t *testing.T) {
	e := newEnv(t)
	e.prov.errs = []error{&providers.Error{Kind: providers.Gone, Reason: "APNs Unregistered", Status: 410}}
	a := e.accept()
	require.NoError(t, e.work(a))
	l := e.state(a)
	assert.Equal(t, StatusGone, l.Status)
	assert.Equal(t, problem.SubscriptionGone, *l.ErrorCode)
	assert.Equal(t, "APNs Unregistered", *l.ErrorDetail)
	d, err := e.devices.Get(context.Background(), e.device)
	require.NoError(t, err)
	assert.Equal(t, devices.StatusGone, d.Status)

	// The instance learns about it on its next push.
	out, err := e.svc.Accept(context.Background(), Sender{InstanceID: e.instance, Origin: origin},
		[]Item{{Entry: Entry{SubscriptionID: e.device, Mode: providers.ModeIDOnly, NotificationID: "n", TTL: 60}}}, Idempotency{})
	require.NoError(t, err)
	assert.Equal(t, problem.SubscriptionGone, out.Results[0].Error.Code)
	assert.Equal(t, 410, out.Results[0].Error.Status)
}

func TestDeliverIgnoresDeadTokenReportForReplacedToken(t *testing.T) {
	e := newEnv(t)
	newToken := strings.Repeat("cd", 32)
	e.prov.errs = []error{&providers.Error{Kind: providers.Gone, Reason: "APNs Unregistered", Status: 410}}
	e.prov.hook = func() {
		// The client refreshes its token while the push to the old one is in flight.
		d, err := e.devices.Get(context.Background(), e.device)
		require.NoError(t, err)
		_, err = e.devices.Refresh(context.Background(), d, devices.RefreshInput{Token: &newToken}, nil)
		require.NoError(t, err)
	}
	a := e.accept()
	assert.Zero(t, snoozed(t, e.work(a)), "retried at once with the new token")
	d, err := e.devices.Get(context.Background(), e.device)
	require.NoError(t, err)
	assert.Equal(t, devices.StatusActive, d.Status, "a late rejection of a replaced token cannot kill the new one")

	require.NoError(t, e.work(a))
	assert.Equal(t, StatusSent, e.state(a).Status)
	assert.Equal(t, newToken, e.prov.targets[1].Token)
}

func TestDeliverRejected(t *testing.T) {
	e := newEnv(t)
	e.prov.errs = []error{&providers.Error{Kind: providers.Rejected, Reason: "APNs BadCollapseId", Status: 400}}
	a := e.accept()
	require.NoError(t, e.work(a))
	l := e.state(a)
	assert.Equal(t, StatusFailed, l.Status)
	assert.Equal(t, problem.ProviderRejected, *l.ErrorCode)
	assert.Equal(t, int32(1), l.Attempts, "permanent refusals are not retried")
}

func TestDeliverToRemovedSubscription(t *testing.T) {
	e := newEnv(t)
	a := e.accept()
	require.NoError(t, e.devices.DeleteForInstance(context.Background(), e.device, e.instance))
	require.NoError(t, e.work(a))
	l := e.state(a)
	assert.Equal(t, StatusFailed, l.Status)
	assert.Equal(t, problem.SubscriptionGone, *l.ErrorCode)
	assert.Zero(t, e.prov.calls())
}

func TestDeliverToGoneSubscription(t *testing.T) {
	e := newEnv(t)
	a := e.accept()
	d, err := e.devices.Get(context.Background(), e.device)
	require.NoError(t, err)
	_, err = e.devices.MarkGone(context.Background(), d.ID, d.TokenHash, d.ApnsEnvironment)
	require.NoError(t, err)
	require.NoError(t, e.work(a))
	assert.Equal(t, StatusGone, e.state(a).Status)
	assert.Zero(t, e.prov.calls())
}

func TestDeliverWithoutProvider(t *testing.T) {
	e := newEnv(t)
	a := e.accept()
	e.reg.Set("gotalk", devices.IOS, nil)
	require.NoError(t, e.work(a))
	l := e.state(a)
	assert.Equal(t, StatusFailed, l.Status)
	assert.Equal(t, problem.ProviderUnavailable, *l.ErrorCode)
}

func TestDeliverForDeletedInstance(t *testing.T) {
	e := newEnv(t)
	a := e.accept()
	_, err := e.pool.Exec(context.Background(), "DELETE FROM instances WHERE id = $1", e.instance)
	require.NoError(t, err)
	require.NoError(t, e.work(a), "the job is dropped with the instance")
	assert.Zero(t, e.prov.calls())
}

func TestUnexpectedErrorOnLastJobAttemptFailsThePush(t *testing.T) {
	e := newEnv(t)
	a := e.accept()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := e.worker.Work(ctx, &river.Job[DeliveryArgs]{
		JobRow: &rivertype.JobRow{ID: 1, Attempt: jobMaxAttempts, MaxAttempts: jobMaxAttempts}, Args: a,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled))
	l := e.state(a)
	assert.Equal(t, StatusFailed, l.Status, "river discards the job, so the push gets a final status")
	assert.Equal(t, problem.InternalError, *l.ErrorCode)
}

func TestAcceptRejections(t *testing.T) {
	e := newEnv(t)
	other := Sender{InstanceID: "inst_BBBBBBBBBBBB", Origin: "https://other.example"}
	out, err := e.svc.Accept(context.Background(), other,
		[]Item{{Entry: Entry{SubscriptionID: e.device, Mode: providers.ModeIDOnly, NotificationID: "n"}}}, Idempotency{})
	require.NoError(t, err)
	assert.Equal(t, problem.SubscriptionNotFound, out.Results[0].Error.Code, "another instance's subscription looks missing")
	assert.Empty(t, e.queue.jobs)

	e.reg.Set("gotalk", devices.IOS, nil)
	out, err = e.svc.Accept(context.Background(), Sender{InstanceID: e.instance, Origin: origin},
		[]Item{{Entry: Entry{SubscriptionID: e.device, Mode: providers.ModeIDOnly, NotificationID: "n"}}}, Idempotency{})
	require.NoError(t, err)
	assert.Equal(t, problem.ProviderUnavailable, out.Results[0].Error.Code)
	assert.Equal(t, 503, out.Results[0].Error.Status)
	_, rejected, _, _ := e.usage()
	assert.Equal(t, int64(1), rejected)
}

func TestBackoff(t *testing.T) {
	w := NewWorker(nil, nil, nil, WorkerOptions{})
	for attempt, full := range map[int]time.Duration{1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second, 4: 8 * time.Second} {
		for range 50 {
			d := w.backoff(attempt)
			assert.GreaterOrEqual(t, d, full/2)
			assert.LessOrEqual(t, d, full)
		}
	}
}

func TestPrune(t *testing.T) {
	e := newEnv(t)
	old := e.accept()
	fresh := e.accept()
	ctx := context.Background()
	_, err := e.pool.Exec(ctx, "UPDATE delivery_log SET created_at = now() - interval '73 hours' WHERE id = $1", old.PushID)
	require.NoError(t, err)
	_, err = e.pool.Exec(ctx, `INSERT INTO push_idempotency (instance_id, key, fingerprint, response, created_at)
		VALUES ($1, 'old', decode(repeat('00', 32), 'hex'), '[]', now() - interval '25 hours'),
		       ($1, 'new', decode(repeat('00', 32), 'hex'), '[]', now())`, e.instance)
	require.NoError(t, err)

	n, err := e.svc.Prune(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
	_, err = e.svc.Get(ctx, e.instance, old.PushID)
	var p *problem.Problem
	require.ErrorAs(t, err, &p)
	assert.Equal(t, problem.PushNotFound, p.Code)
	assert.Equal(t, StatusQueued, e.state(fresh).Status)
	var keys []string
	rows, err := e.pool.Query(ctx, "SELECT key FROM push_idempotency")
	require.NoError(t, err)
	keys, err = pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	assert.Equal(t, []string{"new"}, keys)
}

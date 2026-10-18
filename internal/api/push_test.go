package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/parkerbrown98/gotalk-gateway/internal/problem"
	"github.com/parkerbrown98/gotalk-gateway/internal/providers/providertest"
	"github.com/parkerbrown98/gotalk-gateway/internal/push"
)

const otherOrigin = "https://other.example"

func payload(n int) string { return base64.RawURLEncoding.EncodeToString(make([]byte, n)) }

func pushBody(sub string, kv ...any) map[string]any {
	b := map[string]any{"subscription_id": sub, "mode": "encrypted", "notification_id": "ntf_1", "payload": payload(150)}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == nil {
			delete(b, kv[i].(string))
		} else {
			b[kv[i].(string)] = kv[i+1]
		}
	}
	return b
}

func idempotencyKey(k string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Idempotency-Key", k) }
}

// activeInstanceAt registers and verifies origin with a fresh key.
func (g *gw) activeInstanceAt(origin string) (string, key) {
	k := newKey()
	reg := g.register(origin, &k).expect(201).obj()
	g.origins.advertise(origin, k)
	g.signed(k, "POST", "/v1/instances/"+reg["instance_id"].(string)+"/verify", nil).expect(200)
	return reg["instance_id"].(string), k
}

func androidBody(origin, app, token string) map[string]any {
	return map[string]any{"app_id": app, "instance_origin": origin, "platform": "android", "token": token}
}

func webBody(origin string) map[string]any {
	return map[string]any{"app_id": "gotalk", "instance_origin": origin, "platform": "web", "endpoint": webEndpoint}
}

// waitPush waits for a push to reach status and returns its status document.
func (g *gw) waitPush(k key, pushID, status string) map[string]any {
	g.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		l, err := g.push.Get(context.Background(), instanceOfKey(g, k), pushID)
		require.NoError(g.t, err)
		if l.Status == status {
			return g.signed(k, "GET", "/v1/pushes/"+pushID, nil).expect(200).obj()
		}
		if time.Now().After(deadline) {
			g.t.Fatalf("push %s is %s after 15s, want %s", pushID, l.Status, status)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func instanceOfKey(g *gw, k key) string {
	g.t.Helper()
	var id string
	require.NoError(g.t, g.pool.QueryRow(context.Background(), "SELECT instance_id FROM instance_keys WHERE id = $1", k.id).Scan(&id))
	return id
}

func (g *gw) count(query string, args ...any) int {
	g.t.Helper()
	var n int
	require.NoError(g.t, g.pool.QueryRow(context.Background(), query, args...).Scan(&n))
	return n
}

func TestPushDelivery(t *testing.T) {
	g := newGateway(t, withDelivery)
	id, k := g.activeInstance()
	token := apnsToken("ab")
	ios := g.newDevice(iosBody(testOrigin, token))
	fcmTok := fcmToken("Xy")
	android := g.newDevice(androidBody(testOrigin, "gotalk", fcmTok))

	body := payload(180)
	r := g.signed(k, "POST", "/v1/push", pushBody(ios.id, "payload", body, "urgency", "high", "collapse_key", "c_4f9a1b", "ttl", 600)).expect(202)
	assert.Empty(t, r.Header().Get("Idempotency-Replayed"))
	acc := r.obj()
	assert.Regexp(t, `^push_[A-Za-z0-9_-]{8,64}$`, acc["push_id"])
	assert.Equal(t, ios.id, acc["subscription_id"])
	assert.Equal(t, "queued", acc["status"])

	st := g.waitPush(k, acc["push_id"].(string), "sent")
	assert.Equal(t, 1.0, st["attempts"])
	assert.Nil(t, st["error"])
	assert.Equal(t, "ntf_1", st["notification_id"])
	reqs := g.apns.Requests(token)
	require.Len(t, reqs, 1)
	assert.Equal(t, "10", reqs[0].Header.Get("apns-priority"))
	assert.Equal(t, "c_4f9a1b", reqs[0].Header.Get("apns-collapse-id"))
	assert.Equal(t, "app.example.gotalk", reqs[0].Header.Get("apns-topic"))
	assert.Equal(t, map[string]any{"v": 1.0, "sub": ios.id, "mode": "encrypted", "body": body}, reqs[0].Body["gt"],
		"the payload is forwarded byte for byte")

	acc = g.signed(k, "POST", "/v1/push", pushBody(android.id, "mode", "id_only", "payload", nil, "notification_id", "ntf_2")).expect(202).obj()
	g.waitPush(k, acc["push_id"].(string), "sent")
	freqs := g.fcm.Requests(fcmTok)
	require.Len(t, freqs, 1)
	msg := freqs[0].Body["message"].(map[string]any)
	assert.Equal(t, map[string]any{
		"gt_v": "1", "gt_sub": android.id, "gt_mode": "id_only", "gt_instance": testOrigin, "gt_notification_id": "ntf_2",
	}, msg["data"])
	assert.Equal(t, "NORMAL", msg["android"].(map[string]any)["priority"])

	usage := g.signed(k, "GET", "/v1/instances/"+id, nil).expect(200).obj()["usage"].(map[string]any)
	assert.Equal(t, 2.0, usage["pushes_accepted"])
	assert.Equal(t, 0.0, usage["pushes_failed"])
}

func TestPushRetriesAndFailures(t *testing.T) {
	g := newGateway(t, withDelivery)
	_, k := g.activeInstance()
	token := apnsToken("ab")
	d := g.newDevice(iosBody(testOrigin, token))
	send := func() string {
		t.Helper()
		return g.signed(k, "POST", "/v1/push", pushBody(d.id)).expect(202).obj()["push_id"].(string)
	}

	// Transient failures are retried with growing, jittered delays.
	g.apns.Respond(token, providertest.Response{Status: 503, Reason: "ServiceUnavailable"}, providertest.Response{Status: 500, Reason: "InternalServerError"})
	st := g.waitPush(k, send(), "sent")
	assert.Equal(t, 3.0, st["attempts"])
	reqs := g.apns.Requests(token)
	require.Len(t, reqs, 3)
	assert.GreaterOrEqual(t, reqs[1].At.Sub(reqs[0].At), 10*time.Millisecond, "first retry after at least half the 20ms base")
	assert.GreaterOrEqual(t, reqs[2].At.Sub(reqs[1].At), 20*time.Millisecond, "second retry after at least half of 40ms")

	// A provider's Retry-After is honored.
	g.apns.Reset()
	g.apns.Respond(token, providertest.Response{Status: 429, Reason: "TooManyRequests", RetryAfter: "1"})
	g.waitPush(k, send(), "sent")
	reqs = g.apns.Requests(token)
	require.Len(t, reqs, 2)
	assert.GreaterOrEqual(t, reqs[1].At.Sub(reqs[0].At), time.Second)

	// Out of attempts: failed and dead-lettered in the queue.
	g.apns.Reset()
	for range push.MaxAttempts {
		g.apns.Respond(token, providertest.Response{Status: 500, Reason: "InternalServerError"})
	}
	pushID := send()
	st = g.waitPush(k, pushID, "failed")
	assert.Equal(t, float64(push.MaxAttempts), st["attempts"])
	assert.Equal(t, map[string]any{
		"code": "provider_unavailable", "message": "The provider could not be reached or kept failing (APNs InternalServerError).",
	}, st["error"])
	require.Eventually(t, func() bool {
		return g.count("SELECT count(*) FROM river_job WHERE args->>'push_id' = $1 AND state = 'cancelled'", pushID) == 1
	}, 5*time.Second, 20*time.Millisecond, "the job stays in the queue as a dead letter")

	// A permanent refusal is not retried.
	g.apns.Reset()
	g.apns.Respond(token, providertest.Response{Status: 400, Reason: "BadCollapseId"})
	st = g.waitPush(k, send(), "failed")
	assert.Equal(t, 1.0, st["attempts"])
	assert.Equal(t, "provider_rejected", st["error"].(map[string]any)["code"])
}

func TestPushDeadToken(t *testing.T) {
	g := newGateway(t, withDelivery)
	_, k := g.activeInstance()
	token := apnsToken("ab")
	d := g.newDevice(iosBody(testOrigin, token))

	g.apns.Respond(token, providertest.Response{Status: 410, Reason: "Unregistered"})
	pushID := g.signed(k, "POST", "/v1/push", pushBody(d.id)).expect(202).obj()["push_id"].(string)
	st := g.waitPush(k, pushID, "gone")
	assert.Equal(t, map[string]any{
		"code": "subscription_gone", "message": "The device token is no longer valid; delete the subscription (APNs Unregistered).",
	}, st["error"])
	status, _, _ := g.deviceRow(d.id)
	assert.Equal(t, "gone", status)

	// The instance is told on its next push, single or batched.
	g.signed(k, "POST", "/v1/push", pushBody(d.id)).expectProblem(410, problem.SubscriptionGone)
	res := g.signed(k, "POST", "/v1/push/batch", map[string]any{"pushes": []any{pushBody(d.id)}}).expect(202).obj()["results"].([]any)
	assert.Equal(t, "subscription_gone", res[0].(map[string]any)["error"].(map[string]any)["code"])

	// The client replacing its token reactivates the subscription.
	fresh := apnsToken("cd")
	g.withSecret(d.secret, "PUT", "/v1/devices/"+d.id, map[string]any{"token": fresh}).expect(200)
	g.waitPush(k, g.signed(k, "POST", "/v1/push", pushBody(d.id)).expect(202).obj()["push_id"].(string), "sent")
	assert.Len(t, g.apns.Requests(fresh), 1)

	// FCM's dead-token answer is handled the same way.
	fcmTok := fcmToken("Zz")
	android := g.newDevice(androidBody(testOrigin, "gotalk", fcmTok))
	g.fcm.Respond(fcmTok, providertest.Response{Status: 404, Reason: "UNREGISTERED"})
	g.waitPush(k, g.signed(k, "POST", "/v1/push", pushBody(android.id)).expect(202).obj()["push_id"].(string), "gone")
}

func TestPushValidation(t *testing.T) {
	g := newGateway(t)
	id, k := g.activeInstance()
	d := g.newDevice(iosBody(testOrigin, apnsToken("ab")))

	req, _ := newRequest("POST", "/v1/push", pushBody(d.id))
	g.serve(req).expectProblem(401, problem.InvalidSignature)

	p := g.signed(k, "POST", "/v1/push", map[string]any{"mode": "encrypted"}).expectProblem(422, problem.InvalidRequest)
	assert.ElementsMatch(t, []problem.FieldError{
		{Field: "subscription_id", Message: "required"}, {Field: "notification_id", Message: "required"},
		{Field: "payload", Message: "required in encrypted mode"},
	}, p.Errors)
	p = g.signed(k, "POST", "/v1/push", pushBody(d.id, "title", "Hello")).expectProblem(422, problem.InvalidRequest)
	assert.Equal(t, "title", p.Errors[0].Field, "unknown fields are refused")
	g.signed(k, "POST", "/v1/push", pushBody(d.id, "payload", payload(2201))).expectProblem(413, problem.PayloadTooLarge)
	p = g.signed(k, "POST", "/v1/push", pushBody(d.id, "padding", strings.Repeat("a", 17<<10))).expectProblem(413, problem.PayloadTooLarge)
	assert.Contains(t, p.Detail, "16384 bytes")
	g.signed(k, "POST", "/v1/push", pushBody(d.id), func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }).
		expectProblem(415, problem.UnsupportedMediaType)

	g.signed(k, "POST", "/v1/push", pushBody("sub_unknownAAAAAAAAAAAA")).expectProblem(404, problem.SubscriptionNotFound)
	web := g.newDevice(webBody(testOrigin))
	p = g.signed(k, "POST", "/v1/push", pushBody(web.id, "mode", "id_only", "payload", nil)).expectProblem(422, problem.InvalidRequest)
	assert.Equal(t, "mode", p.Errors[0].Field)
	p = g.signed(k, "POST", "/v1/push", pushBody(web.id)).expectProblem(503, problem.ProviderUnavailable)
	assert.Contains(t, p.Detail, "web devices", "Web Push arrives in Phase 5")
	droid := g.newDevice(androidBody(testOrigin, "droid", fcmToken("Dr")))
	g.signed(k, "POST", "/v1/push", pushBody(droid.id)).expectProblem(503, problem.ProviderUnavailable)
	g.markGone(d.id)
	g.signed(k, "POST", "/v1/push", pushBody(d.id)).expectProblem(410, problem.SubscriptionGone)

	assert.Zero(t, g.count("SELECT count(*) FROM delivery_log"))
	assert.Zero(t, g.count("SELECT count(*) FROM river_job"))
	assert.Equal(t, 8, g.count("SELECT rejected::int FROM usage_counters WHERE instance_id = $1", id),
		"entry rejections are counted; requests refused before parsing are not")

	_, err := g.pool.Exec(context.Background(), "UPDATE instances SET status = 'suspended' WHERE id = $1", id)
	require.NoError(t, err)
	g.signed(k, "POST", "/v1/push", pushBody(web.id)).expectProblem(403, problem.InstanceNotVerified)
	g.signed(k, "POST", "/v1/push/batch", map[string]any{"pushes": []any{pushBody(web.id)}}).expectProblem(403, problem.InstanceNotVerified)
}

func TestPushCrossInstance(t *testing.T) {
	g := newGateway(t)
	_, kA := g.activeInstance()
	_, kB := g.activeInstanceAt(otherOrigin)
	d := g.newDevice(iosBody(testOrigin, apnsToken("ab")))

	g.signed(kB, "POST", "/v1/push", pushBody(d.id)).expectProblem(404, problem.SubscriptionNotFound)
	res := g.signed(kB, "POST", "/v1/push/batch", map[string]any{"pushes": []any{pushBody(d.id)}}).expect(202).obj()["results"].([]any)
	assert.Equal(t, "subscription_not_found", res[0].(map[string]any)["error"].(map[string]any)["code"])

	pushID := g.signed(kA, "POST", "/v1/push", pushBody(d.id)).expect(202).obj()["push_id"].(string)
	st := g.signed(kA, "GET", "/v1/pushes/"+pushID, nil).expect(200).obj()
	assert.Equal(t, "queued", st["status"])
	assert.Equal(t, 0.0, st["attempts"])
	assert.Nil(t, st["error"])
	g.signed(kB, "GET", "/v1/pushes/"+pushID, nil).expectProblem(404, problem.PushNotFound)
	g.signed(kA, "GET", "/v1/pushes/push_unknownAAAAAAAAAAA", nil).expectProblem(404, problem.PushNotFound)
	assert.Equal(t, 1, g.count("SELECT count(*) FROM delivery_log"))
}

func TestPushBatch(t *testing.T) {
	g := newGateway(t)
	id, k := g.activeInstance()
	ios := g.newDevice(iosBody(testOrigin, apnsToken("ab")))
	android := g.newDevice(androidBody(testOrigin, "gotalk", fcmToken("Xy")))
	web := g.newDevice(webBody(testOrigin))

	res := g.signed(k, "POST", "/v1/push/batch", map[string]any{"pushes": []any{
		pushBody(ios.id),
		pushBody(android.id, "mode", "id_only", "payload", nil, "urgency", "low"),
		pushBody("sub_unknownAAAAAAAAAAAA"),
		pushBody(ios.id, "mode", nil),
		5,
		pushBody(ios.id, "payload", payload(3000)),
		pushBody(web.id, "mode", "id_only", "payload", nil),
		pushBody(ios.id, "notification_id", "ntf_2"),
	}}).expect(202).obj()["results"].([]any)
	require.Len(t, res, 8)
	type result struct{ status, sub, code string }
	var got []result
	for i, r := range res {
		m := r.(map[string]any)
		assert.Equal(t, float64(i), m["index"])
		rr := result{status: m["status"].(string), sub: m["subscription_id"].(string)}
		if e, ok := m["error"].(map[string]any); ok {
			rr.code = e["code"].(string)
			assert.NotEmpty(t, e["message"])
			assert.Nil(t, m["push_id"])
		} else {
			assert.Regexp(t, `^push_`, m["push_id"])
		}
		got = append(got, rr)
	}
	assert.Equal(t, []result{
		{"queued", ios.id, ""},
		{"queued", android.id, ""},
		{"rejected", "sub_unknownAAAAAAAAAAAA", "subscription_not_found"},
		{"rejected", ios.id, "invalid_request"},
		{"rejected", "", "invalid_request"},
		{"rejected", ios.id, "payload_too_large"},
		{"rejected", web.id, "invalid_request"},
		{"queued", ios.id, ""},
	}, got)
	assert.Equal(t, "Request validation failed: mode: required.", res[3].(map[string]any)["error"].(map[string]any)["message"])
	assert.Equal(t, 3, g.count("SELECT count(*) FROM delivery_log"))
	assert.Equal(t, 3, g.count("SELECT count(*) FROM river_job WHERE queue = 'push'"))
	assert.Equal(t, 1, g.count("SELECT count(*) FROM river_job WHERE priority = 3"), "low urgency is worked last")
	var accepted, rejected int
	require.NoError(t, g.pool.QueryRow(context.Background(), "SELECT accepted, rejected FROM usage_counters WHERE instance_id = $1", id).Scan(&accepted, &rejected))
	assert.Equal(t, []int{3, 5}, []int{accepted, rejected})

	tooMany := make([]any, 101)
	for i := range tooMany {
		tooMany[i] = pushBody(ios.id)
	}
	p := g.signed(k, "POST", "/v1/push/batch", map[string]any{"pushes": tooMany}).expectProblem(422, problem.InvalidRequest)
	assert.Equal(t, "pushes", p.Errors[0].Field)
	g.signed(k, "POST", "/v1/push/batch", map[string]any{"pushes": []any{}}).expectProblem(422, problem.InvalidRequest)
	g.signed(k, "POST", "/v1/push/batch", map[string]any{"pushes": []any{}, "extra": 1}).expectProblem(422, problem.InvalidRequest)
	g.signed(k, "POST", "/v1/push/batch", []any{}).expectProblem(400, problem.InvalidRequest)
	assert.Equal(t, 3, g.count("SELECT count(*) FROM delivery_log"), "a malformed envelope queues nothing")
}

func TestPushIdempotency(t *testing.T) {
	g := newGateway(t)
	_, k := g.activeInstance()
	_, kB := g.activeInstanceAt(otherOrigin)
	token := apnsToken("ab")
	d := g.newDevice(iosBody(testOrigin, token))
	body := pushBody(d.id)

	first := g.signed(k, "POST", "/v1/push", body, idempotencyKey("retry-1")).expect(202)
	second := g.signed(k, "POST", "/v1/push", body, idempotencyKey("retry-1")).expect(202)
	assert.Equal(t, "true", second.Header().Get("Idempotency-Replayed"))
	assert.Equal(t, first.obj(), second.obj())
	assert.Equal(t, 1, g.count("SELECT count(*) FROM delivery_log"))
	assert.Equal(t, 1, g.count("SELECT count(*) FROM river_job"))

	p := g.signed(k, "POST", "/v1/push", pushBody(d.id, "notification_id", "other"), idempotencyKey("retry-1")).
		expectProblem(422, problem.InvalidRequest)
	assert.Contains(t, p.Detail, "different request")
	g.signed(k, "POST", "/v1/push/batch", map[string]any{"pushes": []any{body}}, idempotencyKey("retry-1")).
		expectProblem(422, problem.InvalidRequest)

	// Keys belong to one instance.
	dB := g.newDevice(iosBody(otherOrigin, token))
	r := g.signed(kB, "POST", "/v1/push", pushBody(dB.id), idempotencyKey("retry-1")).expect(202)
	assert.Empty(t, r.Header().Get("Idempotency-Replayed"))

	// A rejected single push is not remembered: retrying after fixing the cause works.
	g.markGone(d.id)
	g.signed(k, "POST", "/v1/push", body, idempotencyKey("retry-2")).expectProblem(410, problem.SubscriptionGone)
	g.newDevice(iosBody(testOrigin, token))
	r = g.signed(k, "POST", "/v1/push", body, idempotencyKey("retry-2")).expect(202)
	assert.Empty(t, r.Header().Get("Idempotency-Replayed"))

	// Batches replay their whole result, rejections included.
	batch := map[string]any{"pushes": []any{body, pushBody("sub_unknownAAAAAAAAAAAA")}}
	b1 := g.signed(k, "POST", "/v1/push/batch", batch, idempotencyKey("batch-1")).expect(202)
	b2 := g.signed(k, "POST", "/v1/push/batch", batch, idempotencyKey("batch-1")).expect(202)
	assert.Equal(t, "true", b2.Header().Get("Idempotency-Replayed"))
	assert.Equal(t, b1.obj(), b2.obj())
	assert.Equal(t, 4, g.count("SELECT count(*) FROM delivery_log"))

	// Expired keys can be used again.
	_, err := g.pool.Exec(context.Background(), "UPDATE push_idempotency SET created_at = now() - interval '25 hours' WHERE key = 'batch-1'")
	require.NoError(t, err)
	b3 := g.signed(k, "POST", "/v1/push/batch", batch, idempotencyKey("batch-1")).expect(202)
	assert.Empty(t, b3.Header().Get("Idempotency-Replayed"))
	assert.Equal(t, 5, g.count("SELECT count(*) FROM delivery_log"))

	g.signed(k, "POST", "/v1/push", body, idempotencyKey(strings.Repeat("k", 65))).expectProblem(422, problem.InvalidRequest)
}

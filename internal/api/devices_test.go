package api

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/parkerbrown98/gotalk-gateway/internal/blocklist"
	"github.com/parkerbrown98/gotalk-gateway/internal/problem"
)

func apnsToken(seed string) string { return strings.Repeat(seed, 64/len(seed)) }

func fcmToken(seed string) string { return "fcm:" + strings.Repeat(seed, 120/len(seed)) }

const webEndpoint = "https://fcm.googleapis.com/fcm/send/cJ3xLTXwB7k:APA91bHPRgkF3JUikC4ENAHEeMrd41Zxv3hVZjC9KtT8OvPVGJ-hQMRKRrZuJAEcl7B338qju59zJMjw2DELjzEvxwYv7hH5Ynpc1ODQ0aT4U4OFEeco8ohsN5PjL1iC2dNtk2BAokeMCg2ZXKqpc8FXKmhX94kIxQ"

// device is a registered subscription as the client sees it.
type device struct {
	id, secret string
}

func (g *gw) registerDevice(body map[string]any) resp {
	req, _ := newRequest("POST", "/v1/devices", body)
	return g.serve(req)
}

func iosBody(origin, token string) map[string]any {
	return map[string]any{"app_id": "gotalk", "instance_origin": origin, "platform": "ios", "token": token}
}

func (g *gw) newDevice(body map[string]any) device {
	g.t.Helper()
	r := g.registerDevice(body).expect(201).obj()
	return device{id: r["subscription_id"].(string), secret: r["subscription_secret"].(string)}
}

// withSecret sends a request authorized by a subscription secret.
func (g *gw) withSecret(secret, method, path string, body any) resp {
	req, _ := newRequest(method, path, body)
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	return g.serve(req)
}

func (g *gw) deviceRow(id string) (status string, expires time.Time, token string) {
	g.t.Helper()
	require.NoError(g.t, g.pool.QueryRow(context.Background(),
		"SELECT status, expires_at, token FROM devices WHERE id = $1", id).Scan(&status, &expires, &token))
	return
}

// markGone reports the subscription's current token as dead, as a provider would.
func (g *gw) markGone(id string) {
	g.t.Helper()
	d, err := g.devices.Get(context.Background(), id)
	require.NoError(g.t, err)
	marked, err := g.devices.MarkGone(context.Background(), id, d.TokenHash, d.ApnsEnvironment)
	require.NoError(g.t, err)
	require.True(g.t, marked)
}

func TestDeviceLifecycle(t *testing.T) {
	g := newGateway(t)
	id, k := g.activeInstance()
	token := apnsToken("ab")

	r := g.registerDevice(iosBody(testOrigin, strings.ToUpper(token))).expect(201)
	assert.Equal(t, "no-store", r.Header().Get("Cache-Control"), "the secret must never be cached")
	reg := r.obj()
	d := device{id: reg["subscription_id"].(string), secret: reg["subscription_secret"].(string)}
	assert.Regexp(t, `^sub_[A-Za-z0-9_-]{8,64}$`, d.id)
	assert.Regexp(t, `^gtsec_[A-Za-z0-9_-]{43}$`, d.secret)
	exp, err := time.Parse(time.RFC3339, reg["expires_at"].(string))
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(60*24*time.Hour), exp, time.Minute)
	status, _, stored := g.deviceRow(d.id)
	assert.Equal(t, "active", status)
	assert.Equal(t, token, stored, "APNs tokens are normalized to lower case")

	var secretHash []byte
	require.NoError(t, g.pool.QueryRow(context.Background(), "SELECT secret_hash FROM devices WHERE id = $1", d.id).Scan(&secretHash))
	assert.NotContains(t, string(secretHash), d.secret, "only a hash of the secret is stored")

	usage := g.signed(k, "GET", "/v1/instances/"+id, nil).expect(200).obj()["usage"].(map[string]any)
	assert.Equal(t, 1.0, usage["active_subscriptions"])

	// Registering the same token again keeps the ID and rotates the secret.
	again := g.newDevice(iosBody(testOrigin, token))
	assert.Equal(t, d.id, again.id)
	assert.NotEqual(t, d.secret, again.secret)
	g.withSecret(d.secret, "PUT", "/v1/devices/"+d.id, map[string]any{}).expectProblem(404, problem.SubscriptionNotFound)

	// Refresh extends the expiry; a token change replaces the token.
	_, err = g.pool.Exec(context.Background(), "UPDATE devices SET expires_at = now() + interval '1 day' WHERE id = $1", d.id)
	require.NoError(t, err)
	ref := g.withSecret(again.secret, "PUT", "/v1/devices/"+d.id, map[string]any{}).expect(200)
	assert.Equal(t, "no-store", ref.Header().Get("Cache-Control"))
	assert.Equal(t, d.id, ref.obj()["subscription_id"])
	_, expires, _ := g.deviceRow(d.id)
	assert.WithinDuration(t, time.Now().Add(60*24*time.Hour), expires, time.Minute)

	newToken := apnsToken("cd")
	g.withSecret(again.secret, "PUT", "/v1/devices/"+d.id, map[string]any{"token": newToken, "apns_environment": "sandbox"}).expect(200)
	var env string
	require.NoError(t, g.pool.QueryRow(context.Background(), "SELECT token, apns_environment FROM devices WHERE id = $1", d.id).Scan(&stored, &env))
	assert.Equal(t, newToken, stored)
	assert.Equal(t, "sandbox", env)

	g.withSecret(again.secret, "DELETE", "/v1/devices/"+d.id, nil).expect(204)
	g.withSecret(again.secret, "DELETE", "/v1/devices/"+d.id, nil).expectProblem(404, problem.SubscriptionNotFound)
	g.withSecret(again.secret, "PUT", "/v1/devices/"+d.id, map[string]any{}).expectProblem(404, problem.SubscriptionNotFound)
}

func TestDevicePlatforms(t *testing.T) {
	g := newGateway(t)
	g.activeInstance()

	android := g.newDevice(map[string]any{"app_id": "droid", "instance_origin": testOrigin, "platform": "android", "token": fcmToken("Ab-_")})
	web := g.newDevice(map[string]any{
		"app_id": "gotalk", "instance_origin": testOrigin, "platform": "web", "endpoint": webEndpoint,
		"attestation": map[string]any{"reserved": true},
	})
	_, _, stored := g.deviceRow(web.id)
	assert.Equal(t, webEndpoint, stored)

	// Each platform refreshes with its own field.
	g.withSecret(web.secret, "PUT", "/v1/devices/"+web.id, map[string]any{"endpoint": webEndpoint + "x"}).expect(200)
	p := g.withSecret(web.secret, "PUT", "/v1/devices/"+web.id, map[string]any{"token": apnsToken("ab")}).expectProblem(422, problem.InvalidRequest)
	assert.Equal(t, "token", p.Errors[0].Field)
	p = g.withSecret(android.secret, "PUT", "/v1/devices/"+android.id, map[string]any{"endpoint": webEndpoint}).expectProblem(422, problem.InvalidRequest)
	assert.Equal(t, "endpoint", p.Errors[0].Field)
	p = g.withSecret(android.secret, "PUT", "/v1/devices/"+android.id, map[string]any{"apns_environment": "sandbox"}).expectProblem(422, problem.InvalidRequest)
	assert.Equal(t, "apns_environment", p.Errors[0].Field)
	p = g.withSecret(android.secret, "PUT", "/v1/devices/"+android.id, map[string]any{"token": strings.Repeat("a", 64) + "/"}).expectProblem(422, problem.InvalidToken)
	assert.Equal(t, "token", p.Errors[0].Field)
	p = g.withSecret(web.secret, "PUT", "/v1/devices/"+web.id, map[string]any{"endpoint": "https://evil.example/push"}).expectProblem(422, problem.InvalidToken)
	assert.Equal(t, "endpoint", p.Errors[0].Field)
}

func TestDeviceRegistrationValidation(t *testing.T) {
	g := newGateway(t)
	g.activeInstance()

	for name, tc := range map[string]struct {
		body   map[string]any
		status int
		code   string
		field  string
	}{
		"unknown app":        {map[string]any{"app_id": "nope", "instance_origin": testOrigin, "platform": "ios", "token": apnsToken("ab")}, 422, problem.UnknownApp, ""},
		"app not on ios":     {map[string]any{"app_id": "droid", "instance_origin": testOrigin, "platform": "ios", "token": apnsToken("ab")}, 422, problem.UnknownApp, ""},
		"bad apns token":     {iosBody(testOrigin, "xyz"), 422, problem.InvalidToken, "token"},
		"short fcm token":    {map[string]any{"app_id": "gotalk", "instance_origin": testOrigin, "platform": "android", "token": "short"}, 422, problem.InvalidToken, "token"},
		"private endpoint":   {map[string]any{"app_id": "gotalk", "instance_origin": testOrigin, "platform": "web", "endpoint": "https://10.0.0.1/push"}, 422, problem.InvalidToken, "endpoint"},
		"unknown service":    {map[string]any{"app_id": "gotalk", "instance_origin": testOrigin, "platform": "web", "endpoint": "https://evil.example/push"}, 422, problem.InvalidToken, "endpoint"},
		"missing token":      {map[string]any{"app_id": "gotalk", "instance_origin": testOrigin, "platform": "ios"}, 422, problem.InvalidRequest, "token"},
		"web with token":     {map[string]any{"app_id": "gotalk", "instance_origin": testOrigin, "platform": "web", "endpoint": webEndpoint, "token": "x"}, 422, problem.InvalidRequest, "token"},
		"ios with endpoint":  {map[string]any{"app_id": "gotalk", "instance_origin": testOrigin, "platform": "ios", "token": apnsToken("ab"), "endpoint": webEndpoint}, 422, problem.InvalidRequest, "endpoint"},
		"env on android":     {map[string]any{"app_id": "gotalk", "instance_origin": testOrigin, "platform": "android", "token": fcmToken("ab"), "apns_environment": "sandbox"}, 422, problem.InvalidRequest, "apns_environment"},
		"bad env":            {map[string]any{"app_id": "gotalk", "instance_origin": testOrigin, "platform": "ios", "token": apnsToken("ab"), "apns_environment": "dev"}, 422, problem.InvalidRequest, "apns_environment"},
		"bad platform":       {map[string]any{"app_id": "gotalk", "instance_origin": testOrigin, "platform": "windows", "token": "x"}, 422, problem.InvalidRequest, "platform"},
		"bad app id":         {map[string]any{"app_id": "Bad App", "instance_origin": testOrigin, "platform": "ios", "token": apnsToken("ab")}, 422, problem.InvalidRequest, "app_id"},
		"bad origin":         {iosBody("https://forum.example/path", apnsToken("ab")), 422, problem.InvalidRequest, "instance_origin"},
		"unknown field":      {map[string]any{"app_id": "gotalk", "instance_origin": testOrigin, "platform": "ios", "token": apnsToken("ab"), "p256dh": "x"}, 422, problem.InvalidRequest, "p256dh"},
		"wrong type":         {map[string]any{"app_id": 7, "instance_origin": testOrigin, "platform": "ios", "token": apnsToken("ab")}, 422, problem.InvalidRequest, "app_id"},
		"attestation string": {map[string]any{"app_id": "gotalk", "instance_origin": testOrigin, "platform": "ios", "token": apnsToken("ab"), "attestation": "x"}, 422, problem.InvalidRequest, "attestation"},
	} {
		t.Run(name, func(t *testing.T) {
			p := g.registerDevice(tc.body).expectProblem(tc.status, tc.code)
			if tc.field != "" {
				require.NotEmpty(t, p.Errors)
				assert.Equal(t, tc.field, p.Errors[0].Field)
			}
		})
	}

	req, _ := newRequest("POST", "/v1/devices", nil)
	req.Body = http.NoBody
	req.Header.Set("Content-Type", "application/json")
	g.serve(req).expectProblem(400, problem.InvalidRequest)
	req, _ = newRequest("POST", "/v1/devices", nil)
	req.Body = readCloser(`{"app_id":"gotalk"} {}`)
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	g.serve(req).expectProblem(400, problem.InvalidRequest)
	req, _ = newRequest("POST", "/v1/devices", iosBody(testOrigin, apnsToken("ab")))
	req.Header.Set("Content-Type", "text/plain")
	g.serve(req).expectProblem(415, problem.UnsupportedMediaType)
}

func TestDeviceRegistrationNeedsActiveInstance(t *testing.T) {
	g := newGateway(t)
	ctx := context.Background()

	g.registerDevice(iosBody("https://unknown.example", apnsToken("ab"))).expectProblem(404, problem.InstanceNotFound)

	pending := newKey()
	g.register("https://pending.example", &pending).expect(201)
	g.registerDevice(iosBody("https://pending.example", apnsToken("ab"))).expectProblem(403, problem.InstanceNotVerified)

	id, _ := g.activeInstance()
	g.registerDevice(iosBody("HTTPS://Forum.Example/", apnsToken("ab"))).expect(201)

	_, err := g.pool.Exec(ctx, "UPDATE instances SET status = 'suspended' WHERE id = $1", id)
	require.NoError(t, err)
	g.registerDevice(iosBody(testOrigin, apnsToken("cd"))).expectProblem(403, problem.InstanceNotVerified)

	_, err = g.pool.Exec(ctx, "UPDATE instances SET status = 'active' WHERE id = $1", id)
	require.NoError(t, err)
	require.NoError(t, g.svc.Block(ctx, id, "Spam."))
	assert.Equal(t, "Spam.", g.registerDevice(iosBody(testOrigin, apnsToken("cd"))).expectProblem(403, problem.InstanceBlocked).Detail)
	require.NoError(t, g.svc.Unblock(ctx, id))

	g.bl.Set([]blocklist.Entry{{Kind: blocklist.KindDomain, Value: "forum.example", Reason: "Listed."}})
	assert.Equal(t, "Listed.", g.registerDevice(iosBody(testOrigin, apnsToken("cd"))).expectProblem(403, problem.InstanceBlocked).Detail)
	g.bl.Set([]blocklist.Entry{{Kind: blocklist.KindCIDR, Value: "198.51.100.0/24", Reason: "Bad network."}})
	assert.Equal(t, "Bad network.", g.registerDevice(iosBody(testOrigin, apnsToken("cd"))).expectProblem(403, problem.InstanceBlocked).Detail)
}

func TestDeviceCrossInstanceMisuse(t *testing.T) {
	g := newGateway(t)
	idA, kA := g.activeInstance()
	kB := newKey()
	regB := g.register("https://other.example", &kB).expect(201).obj()
	g.origins.advertise("https://other.example", kB)
	g.signed(kB, "POST", "/v1/instances/"+regB["instance_id"].(string)+"/verify", nil).expect(200)

	token := apnsToken("ab")
	subA := g.newDevice(iosBody(testOrigin, token))
	subB := g.newDevice(iosBody("https://other.example", token))
	assert.NotEqual(t, subA.id, subB.id, "the same token gets a separate subscription per instance")
	g.newDevice(iosBody("https://other.example", token))
	g.withSecret(subA.secret, "PUT", "/v1/devices/"+subA.id, map[string]any{}).expect(200)

	// Another instance cannot delete A's subscription, and cannot tell that it exists.
	g.signed(kB, "DELETE", "/v1/devices/"+subA.id, nil).expectProblem(404, problem.SubscriptionNotFound)
	g.signed(kB, "DELETE", "/v1/devices/sub_doesnotexist0", nil).expectProblem(404, problem.SubscriptionNotFound)
	g.withSecret(subA.secret, "PUT", "/v1/devices/"+subA.id, map[string]any{}).expect(200)

	// A secret only works for its own subscription.
	g.withSecret(subA.secret, "PUT", "/v1/devices/"+subB.id, map[string]any{}).expectProblem(404, problem.SubscriptionNotFound)
	g.withSecret(subA.secret, "DELETE", "/v1/devices/"+subB.id, nil).expectProblem(404, problem.SubscriptionNotFound)

	// A secret holder cannot move a subscription onto another subscription's token.
	other := g.newDevice(iosBody(testOrigin, apnsToken("cd")))
	g.withSecret(other.secret, "PUT", "/v1/devices/"+other.id, map[string]any{"token": token}).expectProblem(409, problem.Conflict)

	// The bound instance can delete its subscription with a signature.
	g.signed(kA, "DELETE", "/v1/devices/"+subA.id, nil).expect(204)
	g.withSecret(subA.secret, "PUT", "/v1/devices/"+subA.id, map[string]any{}).expectProblem(404, problem.SubscriptionNotFound)

	// Deregistering an instance deletes its subscriptions.
	g.signed(kA, "DELETE", "/v1/instances/"+idA, nil).expect(204)
	g.withSecret(other.secret, "PUT", "/v1/devices/"+other.id, map[string]any{}).expectProblem(404, problem.SubscriptionNotFound)
}

func TestDeviceAuthErrors(t *testing.T) {
	g := newGateway(t)
	_, k := g.activeInstance()
	d := g.newDevice(iosBody(testOrigin, apnsToken("ab")))

	r := g.withSecret("", "PUT", "/v1/devices/"+d.id, map[string]any{})
	r.expectProblem(401, problem.Unauthorized)
	assert.Contains(t, r.Header().Get("WWW-Authenticate"), "Bearer")
	g.withSecret("", "DELETE", "/v1/devices/"+d.id, nil).expectProblem(401, problem.Unauthorized)
	req, _ := newRequest("PUT", "/v1/devices/"+d.id, map[string]any{})
	req.Header.Set("Authorization", "Basic "+d.secret)
	g.serve(req).expectProblem(401, problem.Unauthorized)
	g.withSecret("gtsec_wrong", "PUT", "/v1/devices/"+d.id, map[string]any{}).expectProblem(404, problem.SubscriptionNotFound)

	// A signature attempt is never downgraded to secret auth.
	g.signed(k, "DELETE", "/v1/devices/"+d.id, nil, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+d.secret)
		r.Header.Set("Gotalk-Signature", strings.Repeat("A", 86))
	}).expectProblem(401, problem.InvalidSignature)
	for _, h := range []string{"Gotalk-Timestamp", "Gotalk-Nonce", "Gotalk-Key-Id"} {
		req, _ := newRequest("DELETE", "/v1/devices/"+d.id, nil)
		req.Header.Set("Authorization", "Bearer "+d.secret)
		req.Header.Set(h, "1")
		g.serve(req).expectProblem(401, problem.InvalidSignature)
	}
	g.withSecret(d.secret, "PUT", "/v1/devices/"+d.id, map[string]any{}).expect(200)
}

func TestDeadTokens(t *testing.T) {
	g := newGateway(t)
	id, k := g.activeInstance()
	token := apnsToken("ab")
	d := g.newDevice(iosBody(testOrigin, token))

	g.markGone(d.id)
	status, _, _ := g.deviceRow(d.id)
	assert.Equal(t, "gone", status)
	usage := g.signed(k, "GET", "/v1/instances/"+id, nil).expect(200).obj()["usage"].(map[string]any)
	assert.Equal(t, 0.0, usage["active_subscriptions"])

	// Refreshing alone does not revive a dead token.
	g.withSecret(d.secret, "PUT", "/v1/devices/"+d.id, map[string]any{}).expect(200)
	status, _, _ = g.deviceRow(d.id)
	assert.Equal(t, "gone", status)

	// Registering the token again reactivates the same subscription.
	again := g.newDevice(iosBody(testOrigin, token))
	assert.Equal(t, d.id, again.id)
	status, _, _ = g.deviceRow(d.id)
	assert.Equal(t, "active", status)

	// So does switching to a new token.
	g.markGone(d.id)
	g.withSecret(again.secret, "PUT", "/v1/devices/"+d.id, map[string]any{"token": apnsToken("ef")}).expect(200)
	status, _, _ = g.deviceRow(d.id)
	assert.Equal(t, "active", status)

	// Deleting a gone subscription succeeds.
	g.markGone(d.id)
	g.signed(k, "DELETE", "/v1/devices/"+d.id, nil).expect(204)
}

// A provider rejection that arrives after the client replaced its token must not kill the
// subscription's new token.
func TestStaleRejectionIsIgnored(t *testing.T) {
	g := newGateway(t)
	ctx := context.Background()
	g.activeInstance()
	d := g.newDevice(iosBody(testOrigin, apnsToken("ab")))
	sent, err := g.devices.Get(ctx, d.id)
	require.NoError(t, err)

	g.withSecret(d.secret, "PUT", "/v1/devices/"+d.id, map[string]any{"apns_environment": "sandbox"}).expect(200)
	marked, err := g.devices.MarkGone(ctx, d.id, sent.TokenHash, sent.ApnsEnvironment)
	require.NoError(t, err)
	assert.False(t, marked, "rejection of the old environment is stale")

	g.withSecret(d.secret, "PUT", "/v1/devices/"+d.id, map[string]any{"token": apnsToken("cd")}).expect(200)
	current, err := g.devices.Get(ctx, d.id)
	require.NoError(t, err)
	marked, err = g.devices.MarkGone(ctx, d.id, sent.TokenHash, current.ApnsEnvironment)
	require.NoError(t, err)
	assert.False(t, marked, "rejection of the old token is stale")
	status, _, _ := g.deviceRow(d.id)
	assert.Equal(t, "active", status)

	marked, err = g.devices.MarkGone(ctx, d.id, current.TokenHash, current.ApnsEnvironment)
	require.NoError(t, err)
	assert.True(t, marked)
	marked, err = g.devices.MarkGone(ctx, d.id, current.TokenHash, current.ApnsEnvironment)
	require.NoError(t, err)
	assert.False(t, marked, "already gone")
}

func TestDevicePrune(t *testing.T) {
	g := newGateway(t)
	ctx := context.Background()
	g.activeInstance()
	expired := g.newDevice(iosBody(testOrigin, apnsToken("aa")))
	oldGone := g.newDevice(iosBody(testOrigin, apnsToken("bb")))
	newGone := g.newDevice(iosBody(testOrigin, apnsToken("cc")))
	live := g.newDevice(iosBody(testOrigin, apnsToken("dd")))

	_, err := g.pool.Exec(ctx, "UPDATE devices SET expires_at = now() - interval '1 second' WHERE id = $1", expired.id)
	require.NoError(t, err)
	_, err = g.pool.Exec(ctx, "UPDATE devices SET status = 'gone', gone_at = now() - interval '8 days' WHERE id = $1", oldGone.id)
	require.NoError(t, err)
	g.markGone(newGone.id)

	n, err := g.devices.Prune(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), n)
	for _, d := range []device{expired, oldGone} {
		g.withSecret(d.secret, "PUT", "/v1/devices/"+d.id, map[string]any{}).expectProblem(404, problem.SubscriptionNotFound)
	}
	for _, d := range []device{newGone, live} {
		g.withSecret(d.secret, "PUT", "/v1/devices/"+d.id, map[string]any{}).expect(200)
	}
}

func TestDeviceRateLimits(t *testing.T) {
	g := newGateway(t, func(o *gwOpts) {
		o.rates = map[string]string{"device_registration": "3-H", "device_token": "1-H", "device_update": "2-H"}
	})
	g.activeInstance()
	register := func(token, ip string) resp {
		req, _ := newRequest("POST", "/v1/devices", iosBody(testOrigin, token))
		req.RemoteAddr = ip + ":40000"
		return g.serve(req)
	}

	r := register(apnsToken("aa"), "198.51.100.10").expect(201)
	assert.Equal(t, "3", r.Header().Get("X-RateLimit-Limit"))
	register(apnsToken("aa"), "198.51.100.11").expectProblem(429, problem.RateLimited)
	r = register(apnsToken("bb"), "198.51.100.10").expect(201)
	register(apnsToken("cc"), "198.51.100.10").expect(201)
	register(apnsToken("dd"), "198.51.100.10").expectProblem(429, problem.RateLimited)

	d := device{id: r.obj()["subscription_id"].(string), secret: r.obj()["subscription_secret"].(string)}
	for range 3 {
		g.withSecret("gtsec_wrong", "PUT", "/v1/devices/"+d.id, map[string]any{}).expectProblem(404, problem.SubscriptionNotFound)
	}
	g.withSecret(d.secret, "PUT", "/v1/devices/"+d.id, map[string]any{}).expect(200)
	g.withSecret(d.secret, "PUT", "/v1/devices/"+d.id, map[string]any{}).expect(200)
	g.withSecret(d.secret, "PUT", "/v1/devices/"+d.id, map[string]any{}).expectProblem(429, problem.RateLimited)
}

func readCloser(s string) io.ReadCloser { return io.NopCloser(strings.NewReader(s)) }

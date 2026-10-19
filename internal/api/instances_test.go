package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/parkerbrown98/gotalk-gateway/internal/apps"
	"github.com/parkerbrown98/gotalk-gateway/internal/blocklist"
	"github.com/parkerbrown98/gotalk-gateway/internal/config"
	"github.com/parkerbrown98/gotalk-gateway/internal/devices"
	"github.com/parkerbrown98/gotalk-gateway/internal/instances"
	"github.com/parkerbrown98/gotalk-gateway/internal/nonce"
	"github.com/parkerbrown98/gotalk-gateway/internal/problem"
	"github.com/parkerbrown98/gotalk-gateway/internal/providers"
	"github.com/parkerbrown98/gotalk-gateway/internal/providers/apns"
	"github.com/parkerbrown98/gotalk-gateway/internal/providers/fcm"
	"github.com/parkerbrown98/gotalk-gateway/internal/providers/providertest"
	"github.com/parkerbrown98/gotalk-gateway/internal/providers/webpush"
	"github.com/parkerbrown98/gotalk-gateway/internal/push"
	"github.com/parkerbrown98/gotalk-gateway/internal/ratelimit"
	"github.com/parkerbrown98/gotalk-gateway/internal/signing"
	"github.com/parkerbrown98/gotalk-gateway/internal/testdb"
	"github.com/parkerbrown98/gotalk-gateway/internal/wellknown"
)

func TestMain(m *testing.M) {
	code := m.Run()
	testdb.Terminate()
	os.Exit(code)
}

const testOrigin = "https://forum.example"

// fakeOrigins plays the instances' well-known documents.
type fakeOrigins struct {
	mu   sync.Mutex
	keys map[string]map[string]bool
	err  map[string]error
	wk   *wellknown.Fetcher
}

func (f *fakeOrigins) Keys(_ context.Context, origin string) (map[string]bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.err[origin]; err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for k := range f.keys[origin] {
		out[k] = true
	}
	return out, nil
}

func (f *fakeOrigins) CheckOrigin(u *url.URL) error { return f.wk.CheckOrigin(u) }

// advertise sets the keys an origin's well-known document lists.
func (f *fakeOrigins) advertise(origin string, keys ...key) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[origin] = map[string]bool{}
	for _, k := range keys {
		f.keys[origin][k.pub()] = true
	}
	delete(f.err, origin)
}

func (f *fakeOrigins) fail(origin, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err[origin] = &wellknown.Error{Reason: reason}
}

type key struct {
	id   string
	priv ed25519.PrivateKey
}

func newKey() key {
	_, priv, _ := ed25519.GenerateKey(nil)
	return key{priv: priv}
}

func (k key) pub() string {
	return base64.RawURLEncoding.EncodeToString(k.priv.Public().(ed25519.PublicKey))
}

type gw struct {
	t       *testing.T
	srv     *Server
	pool    *pgxpool.Pool
	svc     *instances.Service
	devices *devices.Service
	origins *fakeOrigins
	bl      *blocklist.Cache
	push    *push.Service
	queue   *river.Client[pgx.Tx]
	apns    *providertest.APNs
	fcm     *providertest.FCM
	web     *providertest.WebPush
}

// fakeProviders are APNs, FCM and Web Push fakes shared by every test gateway (tests do not
// run in parallel), with clients for the gotalk app: iOS through APNs, Android through FCM and
// web through the Web Push fake, which answers for every push service host. The droid app has
// no credentials for any platform.
type sharedFakes struct {
	apns    *providertest.APNs
	fcm     *providertest.FCM
	web     *providertest.WebPush
	clients map[string]providers.Provider
}

var fakeProviders = sync.OnceValue(func() sharedFakes {
	apnsFake, fcmFake := providertest.NewAPNs(), providertest.NewFCM("gotalk-test")
	apnsURL, _, err := providertest.Serve("127.0.0.1:0", apnsFake)
	if err != nil {
		panic(err)
	}
	fcmURL, _, err := providertest.Serve("127.0.0.1:0", fcmFake)
	if err != nil {
		panic(err)
	}
	key, pub := providertest.NewAPNsKey()
	apnsFake.Key, apnsFake.Topic = pub, "app.example.gotalk"
	apnsClient, err := apns.New(apns.Config{BundleID: "app.example.gotalk", TeamID: "TEAM123456", KeyID: "KEY1234567",
		PrivateKey: key, ProductionURL: apnsURL, SandboxURL: apnsURL})
	if err != nil {
		panic(err)
	}
	sa, rsaPub := providertest.NewServiceAccount("gotalk-test", fcmURL+"/token")
	fcmFake.Key = rsaPub
	fcmClient, err := fcm.New(fcm.Config{ServiceAccount: sa, Endpoint: fcmURL})
	if err != nil {
		panic(err)
	}
	webFake := providertest.NewWebPush()
	webFake.PublicKey = testVAPIDKey
	webHTTP, _ := providertest.ServeTLS(webFake)
	webClient, err := webpush.New(webpush.Config{
		PublicKey: testVAPIDKey, PrivateKey: []byte(testVAPIDPrivate), Subject: "mailto:ops@push.example",
		CheckEndpoint: devices.WebPushPolicy{Hosts: devices.DefaultWebPushHosts}.Check, HTTPClient: webHTTP,
	})
	if err != nil {
		panic(err)
	}
	return sharedFakes{apnsFake, fcmFake, webFake, map[string]providers.Provider{
		devices.IOS: apnsClient, devices.Android: fcmClient, devices.Web: webClient,
	}}
})

// testApps are the apps every test gateway serves.
var testApps = []apps.App{
	{ID: "gotalk", Name: "Gotalk", IOS: &apps.IOS{BundleID: "app.example.gotalk"},
		Android: &apps.Android{PackageName: "app.example.gotalk"}, Web: &apps.Web{VAPIDPublicKey: testVAPIDKey}},
	{ID: "droid", Name: "Droid", Android: &apps.Android{PackageName: "com.example.droid"}, Web: &apps.Web{VAPIDPublicKey: testVAPIDKey}},
}

type gwOpts struct {
	rates map[string]string
	rdb   *redis.Client
	pool  *pgxpool.Pool
	// deliver starts push delivery workers.
	deliver bool
}

func withDelivery(o *gwOpts) { o.deliver = true }

func newGateway(t *testing.T, opts ...func(*gwOpts)) *gw {
	t.Helper()
	o := gwOpts{}
	for _, f := range opts {
		f(&o)
	}
	if o.pool == nil {
		o.pool = testdb.Pool(t)
	}
	cfg, err := config.Load("", nil)
	require.NoError(t, err)
	cfg.Server.PublicURL = "https://push.example"
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	origins := &fakeOrigins{keys: map[string]map[string]bool{}, err: map[string]error{}, wk: wellknown.New(wellknown.Options{AllowedPorts: []int{8443}})}
	bl := blocklist.NewCache(o.pool, log)
	svc := instances.New(o.pool, origins, bl, instances.Options{Logger: log})
	registry := apps.NewRegistry(o.pool)
	_, err = registry.Sync(context.Background(), testApps)
	require.NoError(t, err)
	devicesSvc := devices.New(o.pool, registry, bl, devices.Options{
		ExpiryDays: cfg.Gateway.SubscriptionExpiryDays, WebPush: devices.WebPushPolicy{Hosts: devices.DefaultWebPushHosts}, Logger: log,
	})
	limiter, err := ratelimit.New(o.rdb, o.rates)
	require.NoError(t, err)

	fakes := fakeProviders()
	apnsFake, fcmFake := fakes.apns, fakes.fcm
	apnsFake.Reset()
	fcmFake.Reset()
	fakes.web.Reset()
	reg := providers.NewRegistry()
	for platform, c := range fakes.clients {
		reg.Set("gotalk", platform, c)
	}
	worker := push.NewWorker(o.pool, devicesSvc, reg, push.WorkerOptions{ProviderTimeout: 5 * time.Second, RetryBase: 20 * time.Millisecond, Logger: log})
	workers := 0
	if o.deliver {
		workers = 4
	}
	queue, err := push.NewQueue(o.pool, worker, push.QueueOptions{Workers: workers, DeadLetterRetention: time.Hour, Logger: log, PollInterval: 20 * time.Millisecond})
	require.NoError(t, err)
	if o.deliver {
		require.NoError(t, queue.Start(context.Background()))
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = queue.Stop(ctx)
		})
	}
	pushSvc := push.NewService(o.pool, queue, reg, push.Options{Logger: log})

	srv := New(Deps{
		Config: cfg, Logger: log, Version: "test", Apps: registry, Metrics: NewMetrics("test"),
		Instances: svc, Devices: devicesSvc, Push: pushSvc, Nonces: nonce.New(o.rdb), Limiter: limiter, Blocklist: bl,
	})
	return &gw{t: t, srv: srv, pool: o.pool, svc: svc, devices: devicesSvc, origins: origins, bl: bl,
		push: pushSvc, queue: queue, apns: apnsFake, fcm: fcmFake, web: fakes.web}
}

type resp struct {
	*httptest.ResponseRecorder
	t *testing.T
}

func (r resp) obj() map[string]any {
	r.t.Helper()
	var v map[string]any
	require.NoError(r.t, json.Unmarshal(r.Body.Bytes(), &v), r.Body.String())
	return v
}

func (r resp) problem() problem.Problem {
	r.t.Helper()
	var p problem.Problem
	require.NoError(r.t, json.Unmarshal(r.Body.Bytes(), &p), r.Body.String())
	assert.Equal(r.t, "application/problem+json", r.Header().Get("Content-Type"))
	return p
}

func (r resp) expect(status int) resp {
	r.t.Helper()
	require.Equal(r.t, status, r.Code, r.Body.String())
	return r
}

func (r resp) expectProblem(status int, code string) problem.Problem {
	r.t.Helper()
	r.expect(status)
	p := r.problem()
	assert.Equal(r.t, code, p.Code, p.Detail)
	return p
}

func (g *gw) serve(req *http.Request) resp {
	rec := httptest.NewRecorder()
	g.srv.ServeHTTP(rec, req)
	return resp{rec, g.t}
}

func newRequest(method, path string, body any) (*http.Request, []byte) {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, "https://push.example"+path, bytes.NewReader(raw))
	req.RemoteAddr = "198.51.100.10:40000"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, raw
}

// signed sends a request signed by k. mutate may change the request after signing.
func (g *gw) signed(k key, method, path string, body any, mutate ...func(*http.Request)) resp {
	req, raw := newRequest(method, path, body)
	signing.SignHTTP(req, raw, k.id, k.priv, time.Now())
	for _, m := range mutate {
		m(req)
	}
	return g.serve(req)
}

func (g *gw) register(origin string, k *key) resp {
	req, _ := newRequest("POST", "/v1/instances", map[string]any{
		"origin": origin, "public_key": k.pub(), "contact_email": "ops@forum.example",
		"software": "gotalk", "software_version": "1.4.0",
	})
	r := g.serve(req)
	if r.Code == http.StatusCreated {
		k.id = r.obj()["key_id"].(string)
	}
	return r
}

// activeInstance registers and verifies testOrigin with a fresh key.
func (g *gw) activeInstance() (string, key) {
	k := newKey()
	reg := g.register(testOrigin, &k).expect(201).obj()
	g.origins.advertise(testOrigin, k)
	g.signed(k, "POST", "/v1/instances/"+reg["instance_id"].(string)+"/verify", nil).expect(200)
	return reg["instance_id"].(string), k
}

func TestInstanceLifecycle(t *testing.T) {
	g := newGateway(t)
	k1 := newKey()

	reg := g.register("HTTPS://Forum.Example:443/", &k1).expect(201).obj()
	id := reg["instance_id"].(string)
	assert.Regexp(t, `^inst_`, id)
	assert.Equal(t, "pending", reg["status"])
	v := reg["verification"].(map[string]any)
	assert.Equal(t, testOrigin+"/.well-known/gotalk-instance", v["well_known_url"])
	exp, err := time.Parse(time.RFC3339, v["expires_at"].(string))
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(24*time.Hour), exp, time.Minute)

	again := k1
	assert.Equal(t, id, g.register(testOrigin, &again).expect(201).obj()["instance_id"], "repeating a registration is idempotent")

	inst := g.signed(k1, "GET", "/v1/instances/"+id, nil).expect(200).obj()
	assert.Equal(t, "pending", inst["status"])
	assert.Equal(t, testOrigin, inst["origin"])
	assert.Nil(t, inst["verified_at"])
	g.signed(k1, "DELETE", "/v1/instances/"+id, nil).expectProblem(403, problem.InstanceNotVerified)

	p := g.signed(k1, "POST", "/v1/instances/"+id+"/verify", nil).expectProblem(422, problem.VerificationFailed)
	assert.Contains(t, p.Detail, "is not listed in https://forum.example/.well-known/gotalk-instance")

	g.origins.advertise(testOrigin, k1)
	inst = g.signed(k1, "POST", "/v1/instances/"+id+"/verify", nil).expect(200).obj()
	assert.Equal(t, "active", inst["status"])
	assert.NotNil(t, inst["verified_at"])
	assert.Equal(t, "active", inst["keys"].([]any)[0].(map[string]any)["status"])
	assert.Equal(t, map[string]any{"pushes_accepted": 0.0, "pushes_failed": 0.0, "active_subscriptions": 0.0}, inst["usage"])

	// Rotation: add a key, publish both, verify with the new key, revoke the old one.
	k2 := newKey()
	added := g.signed(k1, "POST", "/v1/instances/"+id+"/keys", map[string]any{"public_key": k2.pub()}).expect(201).obj()
	assert.Equal(t, "pending", added["status"])
	k2.id = added["key_id"].(string)
	g.signed(k1, "POST", "/v1/instances/"+id+"/keys", map[string]any{"public_key": k2.pub()}).expectProblem(409, problem.Conflict)
	g.signed(k2, "DELETE", "/v1/instances/"+id+"/keys/"+k1.id, nil).expectProblem(403, problem.InstanceNotVerified)
	g.signed(k2, "GET", "/v1/instances/"+id, nil).expect(200)

	g.signed(k2, "POST", "/v1/instances/"+id+"/verify", nil).expectProblem(422, problem.VerificationFailed)
	g.origins.advertise(testOrigin, k1, k2)
	inst = g.signed(k2, "POST", "/v1/instances/"+id+"/verify", nil).expect(200).obj()
	for _, k := range inst["keys"].([]any) {
		assert.Equal(t, "active", k.(map[string]any)["status"])
	}
	g.signed(k2, "DELETE", "/v1/instances/"+id+"/keys/"+k1.id, nil).expect(204)
	g.signed(k2, "DELETE", "/v1/instances/"+id+"/keys/"+k1.id, nil).expect(204)
	g.signed(k2, "DELETE", "/v1/instances/"+id+"/keys/key_doesnotexist", nil).expectProblem(404, problem.KeyNotFound)
	g.signed(k2, "DELETE", "/v1/instances/"+id+"/keys/"+k2.id, nil).expectProblem(409, problem.Conflict)
	g.signed(k1, "GET", "/v1/instances/"+id, nil).expectProblem(401, problem.UnknownKey)

	// Deregistration deletes the instance and everything bound to it.
	g.signed(k2, "DELETE", "/v1/instances/"+id, nil).expect(204)
	g.signed(k2, "GET", "/v1/instances/"+id, nil).expectProblem(401, problem.UnknownKey)
	var n int
	require.NoError(t, g.pool.QueryRow(context.Background(), "SELECT count(*) FROM instance_keys").Scan(&n))
	assert.Zero(t, n)
}

func TestKeyLimit(t *testing.T) {
	g := newGateway(t)
	id, k := g.activeInstance()
	for range 2 {
		g.signed(k, "POST", "/v1/instances/"+id+"/keys", map[string]any{"public_key": newKey().pub()}).expect(201)
	}
	p := g.signed(k, "POST", "/v1/instances/"+id+"/keys", map[string]any{"public_key": newKey().pub()}).expectProblem(409, problem.Conflict)
	assert.Contains(t, p.Detail, "at most 3")
}

func TestSignatureRejections(t *testing.T) {
	g := newGateway(t)
	id, k := g.activeInstance()
	path := "/v1/instances/" + id + "/keys"
	body := map[string]any{"public_key": newKey().pub()}

	sign := func(req *http.Request, raw []byte, at time.Time) { signing.SignHTTP(req, raw, k.id, k.priv, at) }

	t.Run("missing headers", func(t *testing.T) {
		req, _ := newRequest("GET", "/v1/instances/"+id, nil)
		g.serve(req).expectProblem(401, problem.InvalidSignature)
	})
	t.Run("unknown key", func(t *testing.T) {
		other := newKey()
		other.id = "key_unknown123"
		g.signed(other, "GET", "/v1/instances/"+id, nil).expectProblem(401, problem.UnknownKey)
	})
	t.Run("stale timestamp", func(t *testing.T) {
		for _, skew := range []time.Duration{-301 * time.Second, 301 * time.Second} {
			req, raw := newRequest("GET", "/v1/instances/"+id, nil)
			sign(req, raw, time.Now().Add(skew))
			r := g.serve(req)
			r.expectProblem(401, problem.StaleTimestamp)
			assert.NotEmpty(t, r.Header().Get("Date"), "Date helps instances fix their clock")
		}
		req, raw := newRequest("GET", "/v1/instances/"+id, nil)
		sign(req, raw, time.Now().Add(-290*time.Second))
		g.serve(req).expect(200)
	})
	t.Run("replayed nonce", func(t *testing.T) {
		req, raw := newRequest("GET", "/v1/instances/"+id, nil)
		sign(req, raw, time.Now())
		g.serve(req).expect(200)
		replay := httptest.NewRequest("GET", "https://push.example/v1/instances/"+id, nil)
		replay.Header = req.Header.Clone()
		g.serve(replay).expectProblem(401, problem.ReplayedNonce)
	})
	t.Run("wrong key", func(t *testing.T) {
		impostor := newKey()
		impostor.id = k.id
		g.signed(impostor, "GET", "/v1/instances/"+id, nil).expectProblem(401, problem.InvalidSignature)
	})
	t.Run("tampered body", func(t *testing.T) {
		req, raw := newRequest("POST", path, body)
		sign(req, raw, time.Now())
		req.Body = io.NopCloser(bytes.NewReader(bytes.Replace(raw, []byte("public_key"), []byte("public_kez"), 1)))
		p := g.serve(req).expectProblem(401, problem.InvalidSignature)
		assert.Contains(t, p.Detail, "Content-Digest")
	})
	t.Run("tampered body with matching digest", func(t *testing.T) {
		req, raw := newRequest("POST", path, body)
		sign(req, raw, time.Now())
		forged := bytes.Replace(raw, []byte("public_key"), []byte("public_kez"), 1)
		req.Body = io.NopCloser(bytes.NewReader(forged))
		req.Header.Set(signing.HeaderContentDigest, signing.ContentDigest(forged))
		g.serve(req).expectProblem(401, problem.InvalidSignature)
	})
	t.Run("digest required with a body", func(t *testing.T) {
		g.signed(k, "POST", path, body, func(r *http.Request) { r.Header.Del(signing.HeaderContentDigest) }).
			expectProblem(401, problem.InvalidSignature)
	})
	t.Run("signed for another gateway", func(t *testing.T) {
		req, raw := newRequest("GET", "/v1/instances/"+id, nil)
		req.Host = "other-gateway.example"
		sign(req, raw, time.Now())
		req.Host = "push.example"
		g.serve(req).expectProblem(401, problem.InvalidSignature)
	})
	t.Run("signed for another path", func(t *testing.T) {
		req, raw := newRequest("GET", "/v1/instances/"+id+"?x=1", nil)
		sign(req, raw, time.Now())
		replay := httptest.NewRequest("GET", "https://push.example/v1/instances/"+id, nil)
		replay.Header = req.Header.Clone()
		_ = raw
		g.serve(replay).expectProblem(401, problem.InvalidSignature)
	})
	t.Run("failed signatures do not burn the nonce", func(t *testing.T) {
		req, raw := newRequest("GET", "/v1/instances/"+id, nil)
		sign(req, raw, time.Now())
		forged := req.Header.Clone()
		sig := []byte(forged.Get(signing.HeaderSignature))
		sig[0] ^= 1
		forged.Set(signing.HeaderSignature, string(sig))
		bad := httptest.NewRequest("GET", "https://push.example/v1/instances/"+id, nil)
		bad.Header = forged
		g.serve(bad).expectProblem(401, problem.InvalidSignature)
		g.serve(req).expect(200)
	})
	t.Run("another instance", func(t *testing.T) {
		other := newKey()
		reg := g.register("https://other.example", &other).expect(201).obj()
		g.signed(k, "GET", "/v1/instances/"+reg["instance_id"].(string), nil).expectProblem(404, problem.InstanceNotFound)
		g.signed(other, "GET", "/v1/instances/"+id, nil).expectProblem(404, problem.InstanceNotFound)
	})
}

func TestRecovery(t *testing.T) {
	g := newGateway(t)
	id, k1 := g.activeInstance()

	k3 := newKey()
	reg := g.register(testOrigin, &k3).expect(201).obj()
	assert.Equal(t, id, reg["instance_id"], "re-registering a verified origin keeps the instance")
	assert.Equal(t, "active", reg["status"])

	g.signed(k3, "GET", "/v1/instances/"+id, nil).expectProblem(403, problem.InstanceNotVerified)
	// Whoever holds the old (possibly stolen) key cannot revoke the recovery key.
	g.signed(k1, "DELETE", "/v1/instances/"+id+"/keys/"+k3.id, nil).expectProblem(404, problem.KeyNotFound)
	p := g.signed(k3, "POST", "/v1/instances/"+id+"/verify", nil).expectProblem(422, problem.VerificationFailed)
	assert.Contains(t, p.Detail, k3.id)
	g.signed(k1, "GET", "/v1/instances/"+id, nil).expect(200)

	// Only the origin's owner can publish the recovery key.
	g.origins.advertise(testOrigin, k3)
	inst := g.signed(k3, "POST", "/v1/instances/"+id+"/verify", nil).expect(200).obj()
	statuses := map[string]string{}
	for _, k := range inst["keys"].([]any) {
		statuses[k.(map[string]any)["key_id"].(string)] = k.(map[string]any)["status"].(string)
	}
	assert.Equal(t, map[string]string{k1.id: "revoked", k3.id: "active"}, statuses)
	g.signed(k1, "GET", "/v1/instances/"+id, nil).expectProblem(401, problem.UnknownKey)

	k1again := k1
	g.register(testOrigin, &k1again).expectProblem(409, problem.Conflict)
}

func TestRecoveryKeysCannotFillKeySlots(t *testing.T) {
	g := newGateway(t)
	id, k := g.activeInstance()
	for range 5 {
		r := newKey()
		g.register(testOrigin, &r).expect(201)
	}
	var n int
	require.NoError(t, g.pool.QueryRow(context.Background(),
		"SELECT count(*) FROM instance_keys WHERE recovery").Scan(&n))
	assert.Equal(t, instances.MaxRecoveryKeys, n, "older recovery keys are dropped")
	g.signed(k, "POST", "/v1/instances/"+id+"/keys", map[string]any{"public_key": newKey().pub()}).expect(201)
}

func TestRegistrationValidation(t *testing.T) {
	g := newGateway(t)
	post := func(body any, contentType string) resp {
		req, _ := newRequest("POST", "/v1/instances", body)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		return g.serve(req)
	}
	good := func() map[string]any {
		return map[string]any{"origin": testOrigin, "public_key": newKey().pub(), "contact_email": "ops@forum.example"}
	}

	for origin, msg := range map[string]string{
		"http://forum.example":       "must use https",
		"https://forum.example/path": "must not contain",
		"https://forum.example:22":   "port 22 is not allowed",
		"forum.example":              "must be an origin",
		"https://user@forum.example": "must not contain",
		"https://-bad-.example":      "valid domain",
	} {
		b := good()
		b["origin"] = origin
		p := post(b, "").expectProblem(422, problem.InvalidRequest)
		require.Len(t, p.Errors, 1, origin)
		assert.Equal(t, "origin", p.Errors[0].Field)
		assert.Contains(t, p.Errors[0].Message, msg, origin)
	}
	b := good()
	b["origin"] = "https://forum.example:8443"
	assert.Equal(t, "pending", post(b, "").expect(201).obj()["status"], "allowed extra port")

	b = good()
	b["public_key"] = "too-short"
	post(b, "").expectProblem(422, problem.InvalidRequest)
	b = good()
	b["contact_email"] = "Ops <ops@forum.example>"
	post(b, "").expectProblem(422, problem.InvalidRequest)
	b = good()
	b["unexpected"] = true
	post(b, "").expectProblem(422, problem.InvalidRequest)
	post(good(), "text/plain").expectProblem(415, problem.UnsupportedMediaType)

	req := httptest.NewRequest("POST", "https://push.example/v1/instances", bytes.NewReader(bytes.Repeat([]byte("x"), 70<<10)))
	req.Header.Set("Content-Type", "application/json")
	g.serve(req).expectProblem(413, problem.PayloadTooLarge)
}

func TestBlocklist(t *testing.T) {
	g := newGateway(t)
	id, k := g.activeInstance()
	g.bl.Set([]blocklist.Entry{
		{Kind: blocklist.KindDomain, Value: "forum.example", Reason: "Spam reported by users."},
		{Kind: blocklist.KindCIDR, Value: "198.51.100.0/24", Reason: "Abusive network."},
	})

	p := g.signed(k, "GET", "/v1/instances/"+id, nil).expectProblem(403, problem.InstanceBlocked)
	assert.Equal(t, "Spam reported by users.", p.Detail)
	other := newKey()
	assert.Equal(t, "Abusive network.", g.register("https://new.example", &other).expectProblem(403, problem.InstanceBlocked).Detail)

	g.bl.Set([]blocklist.Entry{{Kind: blocklist.KindOrigin, Value: "https://spam.example", Reason: "No."}})
	assert.Equal(t, "No.", g.register("https://spam.example", &other).expectProblem(403, problem.InstanceBlocked).Detail)
	g.signed(k, "GET", "/v1/instances/"+id, nil).expect(200)

	require.NoError(t, g.svc.Block(context.Background(), id, "Operator block: abuse."))
	p = g.signed(k, "GET", "/v1/instances/"+id, nil).expectProblem(403, problem.InstanceBlocked)
	assert.Equal(t, "Operator block: abuse.", p.Detail)
	again := newKey()
	g.register(testOrigin, &again).expectProblem(403, problem.InstanceBlocked)

	require.NoError(t, g.svc.Unblock(context.Background(), id))
	assert.Equal(t, "active", g.signed(k, "GET", "/v1/instances/"+id, nil).expect(200).obj()["status"])
}

func TestRateLimits(t *testing.T) {
	g := newGateway(t, func(o *gwOpts) {
		o.rates = map[string]string{"registration": "2-H", "signed": "3-M", "verification": "1-H"}
	})
	k := newKey()
	r := g.register(testOrigin, &k).expect(201)
	assert.Equal(t, "2", r.Header().Get("X-RateLimit-Limit"))
	assert.Equal(t, "1", r.Header().Get("X-RateLimit-Remaining"))
	reset, err := strconv.ParseInt(r.Header().Get("X-RateLimit-Reset"), 10, 64)
	require.NoError(t, err)
	assert.Greater(t, reset, time.Now().Unix())
	k2 := newKey()
	g.register("https://second.example", &k2).expect(201)
	k3 := newKey()
	r = g.register("https://third.example", &k3)
	r.expectProblem(429, problem.RateLimited)
	retry, err := strconv.Atoi(r.Header().Get("Retry-After"))
	require.NoError(t, err)
	assert.Positive(t, retry)

	// Signed requests: 3 per minute per instance. Verification: 1 per hour per origin.
	g.origins.advertise(testOrigin, k)
	var id string
	require.NoError(t, g.pool.QueryRow(context.Background(), "SELECT id FROM instances WHERE origin = $1", testOrigin).Scan(&id))
	g.signed(k, "POST", "/v1/instances/"+id+"/verify", nil).expect(200)
	g.signed(k, "POST", "/v1/instances/"+id+"/verify", nil).expectProblem(429, problem.RateLimited)
	r = g.signed(k, "GET", "/v1/instances/"+id, nil).expect(200)
	assert.Equal(t, "0", r.Header().Get("X-RateLimit-Remaining"))
	r = g.signed(k, "GET", "/v1/instances/"+id, nil)
	r.expectProblem(429, problem.RateLimited)
	assert.NotEmpty(t, r.Header().Get("Retry-After"))
}

// A squatter's pending key has its own verify budget and cannot exhaust the owner's.
func TestVerifyBudgetIsPerKey(t *testing.T) {
	g := newGateway(t, func(o *gwOpts) { o.rates = map[string]string{"verification": "1-H"} })
	id, owner := g.activeInstance()
	squatter := newKey()
	g.register(testOrigin, &squatter).expect(201)
	g.signed(squatter, "POST", "/v1/instances/"+id+"/verify", nil).expectProblem(422, problem.VerificationFailed)
	g.signed(squatter, "POST", "/v1/instances/"+id+"/verify", nil).expectProblem(429, problem.RateLimited)

	rotated := newKey()
	rotated.id = g.signed(owner, "POST", "/v1/instances/"+id+"/keys", map[string]any{"public_key": rotated.pub()}).expect(201).obj()["key_id"].(string)
	g.origins.advertise(testOrigin, owner, rotated)
	g.signed(rotated, "POST", "/v1/instances/"+id+"/verify", nil).expect(200)
	g.signed(owner, "POST", "/v1/instances/"+id+"/verify", nil).expectProblem(429, problem.RateLimited)
}

func TestRegistrationLimitGroupsIPv6By64(t *testing.T) {
	assert.Equal(t, "2001:db8:1:2::/64", rateKeyForIP("2001:db8:1:2:aaaa::1"))
	assert.Equal(t, rateKeyForIP("2001:db8:1:2::1"), rateKeyForIP("2001:db8:1:2:ffff:ffff:ffff:ffff"))
	assert.NotEqual(t, rateKeyForIP("2001:db8:1:2::1"), rateKeyForIP("2001:db8:1:3::1"))
	assert.Equal(t, "203.0.113.7", rateKeyForIP("::ffff:203.0.113.7"))

	g := newGateway(t, func(o *gwOpts) { o.rates = map[string]string{"registration": "1-H"} })
	reg := func(addr string) resp {
		k := newKey()
		req, _ := newRequest("POST", "/v1/instances", map[string]any{
			"origin": "https://" + strings.ReplaceAll(addr, ":", "-") + ".example", "public_key": k.pub(), "contact_email": "ops@x.example",
		})
		req.RemoteAddr = "[" + addr + "]:40000"
		return g.serve(req)
	}
	reg("2001:db8:1:2::1").expect(201)
	reg("2001:db8:1:2::2").expectProblem(429, problem.RateLimited)
	reg("2001:db8:1:3::1").expect(201)
}

// Two pending registrations of one origin verifying at the same time: one wins, the other
// gets a conflict, never an internal error.
func TestConcurrentFirstVerification(t *testing.T) {
	g := newGateway(t)
	for range 5 {
		_, err := g.pool.Exec(context.Background(), "DELETE FROM instances")
		require.NoError(t, err)
		a, b := newKey(), newKey()
		idA := g.register(testOrigin, &a).expect(201).obj()["instance_id"].(string)
		idB := g.register(testOrigin, &b).expect(201).obj()["instance_id"].(string)
		g.origins.advertise(testOrigin, a, b)

		codes := make(chan int, 2)
		var wg sync.WaitGroup
		for _, c := range []struct {
			k  key
			id string
		}{{a, idA}, {b, idB}} {
			wg.Go(func() { codes <- g.signed(c.k, "POST", "/v1/instances/"+c.id+"/verify", nil).Code })
		}
		wg.Wait()
		close(codes)
		got := []int{}
		for c := range codes {
			got = append(got, c)
		}
		assert.ElementsMatch(t, []int{200, 409}, got)
	}
}

func TestScheduledReverification(t *testing.T) {
	g := newGateway(t)
	ctx := context.Background()
	id, k := g.activeInstance()
	due := func() {
		_, err := g.pool.Exec(ctx, "UPDATE instances SET next_verification_at = now() - interval '1 second'")
		require.NoError(t, err)
		n, err := g.svc.ReverifyDue(ctx, 20)
		require.NoError(t, err)
		require.Equal(t, 1, n)
	}
	status := func() map[string]any { return g.signed(k, "GET", "/v1/instances/"+id, nil).expect(200).obj() }

	n, err := g.svc.ReverifyDue(ctx, 20)
	require.NoError(t, err)
	assert.Zero(t, n, "nothing is due right after verification")

	g.origins.fail(testOrigin, "fetching https://forum.example/.well-known/gotalk-instance: HTTP 503")
	for range 3 {
		g.signed(k, "POST", "/v1/instances/"+id+"/verify", nil).expectProblem(422, problem.VerificationFailed)
	}
	assert.Equal(t, "active", status()["status"], "explicit verify failures never suspend")

	due()
	due()
	assert.Equal(t, "active", status()["status"])
	due()
	inst := status()
	assert.Equal(t, "suspended", inst["status"], "three scheduled failures suspend")
	assert.Contains(t, inst["status_reason"], "HTTP 503")

	g.origins.advertise(testOrigin, newKey())
	due()
	assert.Contains(t, status()["status_reason"], "is not listed", "an active key that is no longer advertised fails")

	g.origins.advertise(testOrigin, k)
	due()
	inst = status()
	assert.Equal(t, "active", inst["status"])
	assert.Nil(t, inst["status_reason"])
}

func TestPrune(t *testing.T) {
	g := newGateway(t)
	ctx := context.Background()
	id, _ := g.activeInstance()
	pending := newKey()
	g.register("https://pending.example", &pending).expect(201)
	recovery := newKey()
	g.register(testOrigin, &recovery).expect(201)

	_, err := g.pool.Exec(ctx, "UPDATE instances SET pending_expires_at = now() - interval '1 second' WHERE status = 'pending'")
	require.NoError(t, err)
	_, err = g.pool.Exec(ctx, "UPDATE instance_keys SET expires_at = now() - interval '1 second' WHERE recovery")
	require.NoError(t, err)
	g.signed(pending, "GET", "/v1/instances/x", nil).expectProblem(401, problem.UnknownKey)
	g.signed(recovery, "POST", "/v1/instances/"+id+"/verify", nil).expectProblem(401, problem.UnknownKey)

	require.NoError(t, g.svc.Prune(ctx))
	var instancesLeft, keysLeft int
	require.NoError(t, g.pool.QueryRow(ctx, "SELECT count(*) FROM instances").Scan(&instancesLeft))
	require.NoError(t, g.pool.QueryRow(ctx, "SELECT count(*) FROM instance_keys").Scan(&keysLeft))
	assert.Equal(t, 1, instancesLeft)
	assert.Equal(t, 1, keysLeft)
}

// Replicas sharing Redis share nonces and rate limits.
func TestReplicasShareNoncesThroughRedis(t *testing.T) {
	opts, err := redis.ParseURL(testdb.RedisURL(t))
	require.NoError(t, err)
	rdb := redis.NewClient(opts)
	defer func() { _ = rdb.Close() }()
	require.NoError(t, rdb.FlushDB(context.Background()).Err())

	a := newGateway(t, func(o *gwOpts) { o.rdb = rdb; o.rates = map[string]string{"signed": "1000-M"} })
	b := newGateway(t, func(o *gwOpts) { o.rdb = rdb; o.pool = a.pool; o.rates = map[string]string{"signed": "1000-M"} })
	b.origins = a.origins
	id, k := a.activeInstance()

	req, raw := newRequest("GET", "/v1/instances/"+id, nil)
	signing.SignHTTP(req, raw, k.id, k.priv, time.Now())
	r := a.serve(req).expect(200)
	assert.Equal(t, "1000", r.Header().Get("X-RateLimit-Limit"))
	replay := httptest.NewRequest("GET", "https://push.example/v1/instances/"+id, nil)
	replay.Header = req.Header.Clone()
	b.serve(replay).expectProblem(401, problem.ReplayedNonce)
}

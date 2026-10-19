//go:build e2e

// Package e2e drives a running gateway through instance registration, domain verification,
// signed requests, key rotation, recovery, device subscriptions, push delivery and
// deregistration. The test plays the instance, serving the well-known document the gateway
// verifies against, plays APNs and FCM with the fakes in providertest, and plays a browser and
// its push service with the Web Push fake. Start the stack with docker-compose.e2e.yml and
// run `make e2e`.
package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/parkerbrown98/gotalk-gateway/internal/providers/apns"
	"github.com/parkerbrown98/gotalk-gateway/internal/providers/providertest"
	"github.com/parkerbrown98/gotalk-gateway/internal/signing"
)

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

var (
	gateway = env("E2E_GATEWAY_URL", "http://localhost:8090")
	// origin is how the gateway reaches the well-known server below.
	origin     = env("E2E_ORIGIN", "http://host.docker.internal:18080")
	listenAddr = env("E2E_LISTEN", ":18080")
	apnsAddr   = env("E2E_APNS_LISTEN", ":18081")
	fcmAddr    = env("E2E_FCM_LISTEN", ":18082")
	webAddr    = env("E2E_WEBPUSH_LISTEN", ":18083")
	// webPushBase is how the gateway reaches the fake push service; browsers subscribe there.
	webPushBase = env("E2E_WEBPUSH_URL", "http://host.docker.internal:18083/push")
	// secrets holds the credentials internal/e2e/gen wrote for the gateway.
	secrets = env("E2E_SECRETS", filepath.Join("..", "..", ".e2e"))

	fakeAPNs = providertest.NewAPNs()
	fakeFCM  = providertest.NewFCM("e2e-project")
	fakeWeb  = providertest.NewWebPush()
)

// wellKnown serves the stand-in instance's /.well-known/gotalk-instance.
type wellKnown struct {
	mu  sync.Mutex
	doc []byte
}

func (w *wellKnown) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/.well-known/gotalk-instance" {
		http.NotFound(rw, r)
		return
	}
	w.mu.Lock()
	doc := w.doc
	w.mu.Unlock()
	rw.Header().Set("Content-Type", "application/json")
	_, _ = rw.Write(doc)
}

var site = &wellKnown{doc: []byte(`{"software":"gotalk","push":{"keys":[]}}`)}

func TestMain(m *testing.M) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listening for the stand-in instance:", err)
		os.Exit(1)
	}
	srv := &http.Server{Handler: site, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	if err := startFakes(); err != nil {
		fmt.Fprintln(os.Stderr, "starting the provider fakes:", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = srv.Close()
	os.Exit(code)
}

// startFakes serves APNs, FCM and Web Push fakes that check the gateway signs with the
// generated keys.
func startFakes() error {
	p8, err := os.ReadFile(filepath.Join(secrets, "apns.p8"))
	if err != nil {
		return fmt.Errorf("%w (run go run ./internal/e2e/gen .e2e)", err)
	}
	apnsKey, err := apns.ParseKey(p8)
	if err != nil {
		return err
	}
	fakeAPNs.Key, fakeAPNs.TeamID, fakeAPNs.KeyID, fakeAPNs.Topic = &apnsKey.PublicKey, "TEAM123456", "KEY1234567", "app.example.gotalk"
	raw, err := os.ReadFile(filepath.Join(secrets, "fcm.json"))
	if err != nil {
		return err
	}
	var sa struct {
		PrivateKey string `json:"private_key"`
	}
	if err := json.Unmarshal(raw, &sa); err != nil {
		return err
	}
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return fmt.Errorf("fcm.json has no PEM private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	fakeFCM.Key = &k.(*rsa.PrivateKey).PublicKey
	if _, _, err := providertest.Serve(apnsAddr, fakeAPNs); err != nil {
		return err
	}
	if _, _, err := providertest.Serve(webAddr, fakeWeb); err != nil {
		return err
	}
	_, _, err = providertest.Serve(fcmAddr, fakeFCM)
	return err
}

type key struct {
	id   string
	priv ed25519.PrivateKey
}

func newKey(t *testing.T) *key {
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return &key{priv: priv}
}

func (k *key) pub() string {
	return base64.RawURLEncoding.EncodeToString(k.priv.Public().(ed25519.PublicKey))
}

// publish sets the keys the origin's well-known document lists.
func publish(t *testing.T, keys ...*key) {
	t.Helper()
	list := []map[string]string{}
	for _, k := range keys {
		list = append(list, map[string]string{"alg": "Ed25519", "public_key": k.pub()})
	}
	doc, err := json.Marshal(map[string]any{"software": "gotalk", "instance_url": origin, "push": map[string]any{"keys": list}})
	require.NoError(t, err)
	site.mu.Lock()
	site.doc = doc
	site.mu.Unlock()
}

type result struct {
	status int
	header http.Header
	body   map[string]any
}

func do(t *testing.T, method, path string, body any, k *key, mutate ...func(*http.Request)) result {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req, err := http.NewRequest(method, gateway+path, bytes.NewReader(raw))
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if k != nil {
		signing.SignHTTP(req, raw, k.id, k.priv, time.Now())
	}
	for _, m := range mutate {
		m(req)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	out := result{status: resp.StatusCode, header: resp.Header}
	if len(data) > 0 {
		require.NoError(t, json.Unmarshal(data, &out.body), string(data))
	}
	return out
}

func expect(t *testing.T, r result, status int, code string) result {
	t.Helper()
	require.Equal(t, status, r.status, fmt.Sprint(r.body))
	if code != "" {
		assert.Equal(t, code, r.body["code"], fmt.Sprint(r.body))
	}
	return r
}

func TestInstanceFlow(t *testing.T) {
	k1 := newKey(t)
	publish(t)

	reg := expect(t, do(t, "POST", "/v1/instances", map[string]any{
		"origin": origin, "public_key": k1.pub(), "contact_email": "ops@instance.example", "software": "gotalk",
	}, nil), 201, "")
	id := reg.body["instance_id"].(string)
	k1.id = reg.body["key_id"].(string)
	assert.NotEmpty(t, reg.header.Get("X-RateLimit-Limit"))
	base := "/v1/instances/" + id

	expect(t, do(t, "POST", base+"/verify", nil, k1), 422, "verification_failed")
	publish(t, k1)
	inst := expect(t, do(t, "POST", base+"/verify", nil, k1), 200, "")
	assert.Equal(t, "active", inst.body["status"])

	// Replay, clock skew and tampering are rejected by the running binary.
	var captured http.Header
	expect(t, do(t, "GET", base, nil, k1, func(r *http.Request) { captured = r.Header.Clone() }), 200, "")
	expect(t, do(t, "GET", base, nil, nil, func(r *http.Request) { r.Header = captured }), 401, "replayed_nonce")
	stale := func(r *http.Request) {
		r.Header = http.Header{}
		signing.SignHTTP(r, nil, k1.id, k1.priv, time.Now().Add(-10*time.Minute))
	}
	expect(t, do(t, "GET", base, nil, nil, stale), 401, "stale_timestamp")
	expect(t, do(t, "GET", base, nil, k1, func(r *http.Request) { r.URL.RawQuery = "x=1" }), 401, "invalid_signature")

	// Rotation without downtime.
	k2 := newKey(t)
	added := expect(t, do(t, "POST", base+"/keys", map[string]any{"public_key": k2.pub()}, k1), 201, "")
	k2.id = added.body["key_id"].(string)
	publish(t, k1, k2)
	expect(t, do(t, "POST", base+"/verify", nil, k2), 200, "")
	expect(t, do(t, "DELETE", base+"/keys/"+k1.id, nil, k2), 204, "")
	publish(t, k2)
	expect(t, do(t, "GET", base, nil, k1), 401, "unknown_key")

	// Recovery with a fresh key revokes the old one.
	k3 := newKey(t)
	rec := expect(t, do(t, "POST", "/v1/instances", map[string]any{
		"origin": origin, "public_key": k3.pub(), "contact_email": "ops@instance.example",
	}, nil), 201, "")
	assert.Equal(t, id, rec.body["instance_id"])
	k3.id = rec.body["key_id"].(string)
	publish(t, k3)
	expect(t, do(t, "POST", base+"/verify", nil, k3), 200, "")
	expect(t, do(t, "GET", base, nil, k2), 401, "unknown_key")

	// Devices register for the verified instance and are bound to it.
	token := strings.Repeat("ab", 32)
	device := map[string]any{"app_id": "gotalk", "instance_origin": origin, "platform": "ios", "token": token}
	sub := expect(t, do(t, "POST", "/v1/devices", device, nil), 201, "")
	subID, secret := sub.body["subscription_id"].(string), sub.body["subscription_secret"].(string)
	assert.Equal(t, "no-store", sub.header.Get("Cache-Control"))
	again := expect(t, do(t, "POST", "/v1/devices", device, nil), 201, "")
	assert.Equal(t, subID, again.body["subscription_id"])
	bearer := func(s string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+s) }
	}
	expect(t, do(t, "PUT", "/v1/devices/"+subID, map[string]any{}, nil, bearer(secret)), 404, "subscription_not_found")
	secret = again.body["subscription_secret"].(string)
	expect(t, do(t, "PUT", "/v1/devices/"+subID, map[string]any{"token": strings.Repeat("cd", 32)}, nil, bearer(secret)), 200, "")
	inst = expect(t, do(t, "GET", base, nil, k3), 200, "")
	assert.Equal(t, 1.0, inst.body["usage"].(map[string]any)["active_subscriptions"])
	expect(t, do(t, "DELETE", "/v1/devices/"+subID, nil, k3), 204, "")
	expect(t, do(t, "DELETE", "/v1/devices/"+subID, nil, nil, bearer(secret)), 404, "subscription_not_found")
	expect(t, do(t, "POST", "/v1/devices", map[string]any{
		"app_id": "unknown", "instance_origin": origin, "platform": "ios", "token": token,
	}, nil), 422, "unknown_app")

	// Deregistration deletes the instance's subscriptions.
	sub = expect(t, do(t, "POST", "/v1/devices", device, nil), 201, "")
	expect(t, do(t, "DELETE", base, nil, k3), 204, "")
	expect(t, do(t, "GET", base, nil, k3), 401, "unknown_key")
	expect(t, do(t, "PUT", "/v1/devices/"+sub.body["subscription_id"].(string), map[string]any{}, nil,
		bearer(sub.body["subscription_secret"].(string))), 404, "subscription_not_found")
	expect(t, do(t, "POST", "/v1/devices", device, nil), 404, "instance_not_found")
}

// waitPush polls the push's status until it is no longer queued.
func waitPush(t *testing.T, pushID string, k *key) result {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		r := expect(t, do(t, "GET", "/v1/pushes/"+pushID, nil, k), 200, "")
		if r.body["status"] != "queued" || time.Now().After(deadline) {
			return r
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// activeInstance registers the stand-in instance with a fresh key and verifies it. The
// instance is deregistered when the test ends.
func activeInstance(t *testing.T) (string, *key) {
	t.Helper()
	k := newKey(t)
	publish(t)
	reg := expect(t, do(t, "POST", "/v1/instances", map[string]any{
		"origin": origin, "public_key": k.pub(), "contact_email": "ops@instance.example",
	}, nil), 201, "")
	id := reg.body["instance_id"].(string)
	k.id = reg.body["key_id"].(string)
	publish(t, k)
	expect(t, do(t, "POST", "/v1/instances/"+id+"/verify", nil, k), 200, "")
	t.Cleanup(func() { do(t, "DELETE", "/v1/instances/"+id, nil, k) })
	return id, k
}

func TestPushFlow(t *testing.T) {
	fakeAPNs.Reset()
	fakeFCM.Reset()
	id, k := activeInstance(t)

	iosToken := strings.Repeat("ef", 32)
	ios := expect(t, do(t, "POST", "/v1/devices", map[string]any{
		"app_id": "gotalk", "instance_origin": origin, "platform": "ios", "token": iosToken, "apns_environment": "sandbox",
	}, nil), 201, "").body["subscription_id"].(string)
	fcmToken := "e2e:" + strings.Repeat("Ab-_", 30)
	android := expect(t, do(t, "POST", "/v1/devices", map[string]any{
		"app_id": "gotalk", "instance_origin": origin, "platform": "android", "token": fcmToken,
	}, nil), 201, "").body["subscription_id"].(string)

	// An encrypted push reaches APNs with the gateway's signed provider token.
	body := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 200))
	acc := expect(t, do(t, "POST", "/v1/push", map[string]any{
		"subscription_id": ios, "mode": "encrypted", "notification_id": "ntf_e2e_1", "payload": body, "urgency": "high",
	}, k), 202, "")
	st := waitPush(t, acc.body["push_id"].(string), k)
	assert.Equal(t, "sent", st.body["status"], fmt.Sprint(st.body))
	reqs := fakeAPNs.Requests(iosToken)
	require.Len(t, reqs, 1)
	assert.Equal(t, 2, reqs[0].Proto)
	assert.Equal(t, "10", reqs[0].Header.Get("apns-priority"))
	assert.Equal(t, body, reqs[0].Body["gt"].(map[string]any)["body"])

	// A transient FCM failure is retried, with an OAuth token from the service account.
	fakeFCM.Respond(fcmToken, providertest.Response{Status: 503, Reason: "UNAVAILABLE"})
	acc = expect(t, do(t, "POST", "/v1/push", map[string]any{
		"subscription_id": android, "mode": "id_only", "notification_id": "ntf_e2e_2", "ttl": 300,
	}, k), 202, "")
	st = waitPush(t, acc.body["push_id"].(string), k)
	assert.Equal(t, "sent", st.body["status"], fmt.Sprint(st.body))
	assert.Equal(t, 2.0, st.body["attempts"])
	freqs := fakeFCM.Requests(fcmToken)
	require.Len(t, freqs, 2)
	assert.Equal(t, origin, freqs[1].Body["message"].(map[string]any)["data"].(map[string]any)["gt_instance"])
	// The gateway caches its OAuth token, so a previous run may have fetched it.
	assert.True(t, strings.HasPrefix(freqs[1].Header.Get("Authorization"), "Bearer fake-access-"))

	// A dead token marks the subscription gone, and the next push says so.
	fakeAPNs.Respond(iosToken, providertest.Response{Status: 410, Reason: "Unregistered"})
	batch := expect(t, do(t, "POST", "/v1/push/batch", map[string]any{"pushes": []any{
		map[string]any{"subscription_id": ios, "mode": "id_only", "notification_id": "ntf_e2e_3"},
		map[string]any{"subscription_id": "sub_doesnotexist", "mode": "id_only", "notification_id": "ntf_e2e_4"},
	}}, k), 202, "")
	results := batch.body["results"].([]any)
	assert.Equal(t, "rejected", results[1].(map[string]any)["status"])
	st = waitPush(t, results[0].(map[string]any)["push_id"].(string), k)
	assert.Equal(t, "gone", st.body["status"], fmt.Sprint(st.body))
	assert.Equal(t, "subscription_gone", st.body["error"].(map[string]any)["code"])
	expect(t, do(t, "POST", "/v1/push", map[string]any{
		"subscription_id": ios, "mode": "id_only", "notification_id": "ntf_e2e_5",
	}, k), 410, "subscription_gone")

	inst := expect(t, do(t, "GET", "/v1/instances/"+id, nil, k), 200, "")
	usage := inst.body["usage"].(map[string]any)
	assert.Equal(t, 3.0, usage["pushes_accepted"])
	assert.Equal(t, 1.0, usage["pushes_failed"])
}

// TestWebPushFlow plays a browser: it subscribes at the fake push service with the VAPID key
// from discovery, registers the endpoint, and receives a push that the stand-in instance
// encrypted to the browser's keys.
func TestWebPushFlow(t *testing.T) {
	fakeWeb.Reset()
	_, k := activeInstance(t)

	disc := expect(t, do(t, "GET", "/v1/gateway", nil, nil), 200, "")
	app := disc.body["apps"].([]any)[0].(map[string]any)
	vapid := app["platforms"].(map[string]any)["web"].(map[string]any)["vapid_public_key"].(string)
	fakeWeb.PublicKey = vapid

	sub := fakeWeb.Subscribe(webPushBase)
	device := expect(t, do(t, "POST", "/v1/devices", map[string]any{
		"app_id": "gotalk", "instance_origin": origin, "platform": "web", "endpoint": sub.Endpoint,
	}, nil), 201, "").body["subscription_id"].(string)

	plaintext := `{"v":1,"instance":"` + origin + `","type":"mention","notification_id":"ntf_web_1"}`
	body, err := providertest.Encrypt(sub.P256dh, sub.Auth, []byte(plaintext), 64)
	require.NoError(t, err)
	acc := expect(t, do(t, "POST", "/v1/push", map[string]any{
		"subscription_id": device, "mode": "encrypted", "notification_id": "ntf_web_1",
		"payload": base64.RawURLEncoding.EncodeToString(body), "urgency": "high", "ttl": 120, "collapse_key": "c_web",
	}, k), 202, "")
	st := waitPush(t, acc.body["push_id"].(string), k)
	assert.Equal(t, "sent", st.body["status"], fmt.Sprint(st.body))
	reqs := fakeWeb.Requests(sub.Token)
	require.Len(t, reqs, 1)
	require.NoError(t, reqs[0].DecryptErr)
	assert.Equal(t, plaintext, string(reqs[0].Plaintext), "the browser decrypts the instance's notification")
	assert.Equal(t, "high", reqs[0].Header.Get("Urgency"))
	assert.Equal(t, "c_web", reqs[0].Header.Get("Topic"))

	// The browser unsubscribes: the push service answers 410 and the subscription is gone.
	fakeWeb.Respond(sub.Token, providertest.Response{Status: 410})
	body, err = providertest.Encrypt(sub.P256dh, sub.Auth, []byte(`{"v":1}`), 0)
	require.NoError(t, err)
	push := map[string]any{
		"subscription_id": device, "mode": "encrypted", "notification_id": "ntf_web_2",
		"payload": base64.RawURLEncoding.EncodeToString(body),
	}
	acc = expect(t, do(t, "POST", "/v1/push", push, k), 202, "")
	st = waitPush(t, acc.body["push_id"].(string), k)
	assert.Equal(t, "gone", st.body["status"], fmt.Sprint(st.body))
	expect(t, do(t, "POST", "/v1/push", push, k), 410, "subscription_gone")
}

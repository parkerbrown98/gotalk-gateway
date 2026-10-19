package webpush_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/parkerbrown98/gotalk-gateway/internal/providers"
	"github.com/parkerbrown98/gotalk-gateway/internal/providers/providertest"
	"github.com/parkerbrown98/gotalk-gateway/internal/providers/webpush"
)

const subject = "mailto:ops@push.example"

type env struct {
	client *webpush.Client
	fake   *providertest.WebPush
	pub    string
	now    *time.Time
}

// newEnv serves the fake over TLS behind a real push service URL.
func newEnv(t *testing.T, cfg ...func(*webpush.Config)) env {
	t.Helper()
	priv, pub := providertest.NewVAPIDKey()
	fake := providertest.NewWebPush()
	fake.PublicKey = pub
	now := time.Now()
	fake.Now = func() time.Time { return now }
	hc, stop := providertest.ServeTLS(fake)
	t.Cleanup(stop)
	c := webpush.Config{PublicKey: pub, PrivateKey: []byte(priv), Subject: subject, HTTPClient: hc, Now: func() time.Time { return now }}
	for _, f := range cfg {
		f(&c)
	}
	client, err := webpush.New(c)
	require.NoError(t, err)
	return env{client: client, fake: fake, pub: pub, now: &now}
}

func (e env) send(t *testing.T, endpoint string, m providers.Message) *providers.Error {
	t.Helper()
	err := e.client.Send(context.Background(), providers.Target{Token: endpoint}, m)
	if err == nil {
		return nil
	}
	var perr *providers.Error
	require.ErrorAs(t, err, &perr)
	return perr
}

func encrypted(t *testing.T, s providertest.Subscription, plaintext string, exp time.Time) providers.Message {
	t.Helper()
	body, err := providertest.Encrypt(s.P256dh, s.Auth, []byte(plaintext), 0)
	require.NoError(t, err)
	return providers.Message{SubscriptionID: "sub_1", Mode: providers.ModeEncrypted, Body: body, Expiration: exp}
}

func TestSendDeliversToTheBrowser(t *testing.T) {
	e := newEnv(t)
	sub := e.fake.Subscribe("https://fcm.googleapis.com/fcm/send")
	m := encrypted(t, sub, `{"v":1,"type":"mention"}`, e.now.Add(time.Hour))
	m.Urgency, m.CollapseKey = providers.UrgencyHigh, "c_4f9a1b"
	require.Nil(t, e.send(t, sub.Endpoint, m))

	reqs := e.fake.Requests(sub.Token)
	require.Len(t, reqs, 1)
	r := reqs[0]
	require.NoError(t, r.DecryptErr)
	assert.JSONEq(t, `{"v":1,"type":"mention"}`, string(r.Plaintext), "the browser decrypts the instance's payload")
	assert.Equal(t, m.Body, r.Raw, "the body is forwarded byte for byte")
	assert.Equal(t, 2, r.Proto)
	assert.Equal(t, "aes128gcm", r.Header.Get("Content-Encoding"))
	assert.Equal(t, "application/octet-stream", r.Header.Get("Content-Type"))
	assert.Equal(t, "3600", r.Header.Get("TTL"))
	assert.Equal(t, "high", r.Header.Get("Urgency"))
	assert.Equal(t, "c_4f9a1b", r.Header.Get("Topic"))

	auth := r.Header.Get("Authorization")
	require.True(t, strings.HasPrefix(auth, "vapid t="), auth)
	assert.True(t, strings.HasSuffix(auth, ", k="+e.pub))
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(strings.TrimSuffix(strings.TrimPrefix(auth, "vapid t="), ", k="+e.pub), claims)
	require.NoError(t, err)
	assert.Equal(t, "https://fcm.googleapis.com", claims["aud"])
	assert.Equal(t, subject, claims["sub"])
	assert.InDelta(t, float64(e.now.Add(12*time.Hour).Unix()), claims["exp"], 1)
}

func TestHeaderMapping(t *testing.T) {
	e := newEnv(t)
	sub := e.fake.Subscribe("https://updates.push.services.mozilla.com/wpush/v2")
	for _, tc := range []struct {
		urgency, want string
		ttl           time.Duration
		wantTTL       string
	}{
		{providers.UrgencyLow, "low", 90 * time.Second, "90"},
		{providers.UrgencyNormal, "normal", 1500 * time.Millisecond, "2"},
		{"", "normal", -time.Second, "0"},
	} {
		m := encrypted(t, sub, "{}", e.now.Add(tc.ttl))
		m.Urgency = tc.urgency
		require.Nil(t, e.send(t, sub.Endpoint, m))
		reqs := e.fake.Requests(sub.Token)
		r := reqs[len(reqs)-1]
		assert.Equal(t, tc.want, r.Header.Get("Urgency"))
		assert.Equal(t, tc.wantTTL, r.Header.Get("TTL"), "the TTL left when the push is sent")
		assert.Empty(t, r.Header.Get("Topic"))
	}
}

func authToken(r providertest.Request) string {
	t, _, _ := strings.Cut(strings.TrimPrefix(r.Header.Get("Authorization"), "vapid t="), ",")
	return t
}

func TestVAPIDTokensAreCachedPerPushService(t *testing.T) {
	e := newEnv(t)
	fcmSub := e.fake.Subscribe("https://fcm.googleapis.com/fcm/send")
	appleSub := e.fake.Subscribe("https://web.push.apple.com")
	m := encrypted(t, fcmSub, "{}", e.now.Add(time.Hour))
	require.Nil(t, e.send(t, fcmSub.Endpoint, m))
	require.Nil(t, e.send(t, fcmSub.Endpoint, m))
	require.Nil(t, e.send(t, appleSub.Endpoint, m))
	f, a := e.fake.Requests(fcmSub.Token), e.fake.Requests(appleSub.Token)
	assert.Equal(t, authToken(f[0]), authToken(f[1]), "reused for the same push service")
	assert.NotEqual(t, authToken(f[0]), authToken(a[0]), "each push service has its own audience")

	// A token is replaced an hour before it expires.
	*e.now = e.now.Add(10*time.Hour + 59*time.Minute)
	require.Nil(t, e.send(t, fcmSub.Endpoint, m))
	*e.now = e.now.Add(2 * time.Minute)
	m.Expiration = e.now.Add(time.Hour)
	require.Nil(t, e.send(t, fcmSub.Endpoint, m))
	f = e.fake.Requests(fcmSub.Token)
	assert.Equal(t, authToken(f[0]), authToken(f[2]))
	assert.NotEqual(t, authToken(f[0]), authToken(f[3]))

	// A refused token is signed again for the next push.
	e.fake.Respond(fcmSub.Token, providertest.Response{Status: 403, Reason: "BadJwtToken"})
	perr := e.send(t, fcmSub.Endpoint, m)
	require.NotNil(t, perr)
	assert.Equal(t, providers.Retry, perr.Kind, "the gateway's credentials being refused is retried")
	*e.now = e.now.Add(time.Second)
	require.Nil(t, e.send(t, fcmSub.Endpoint, m))
	f = e.fake.Requests(fcmSub.Token)
	assert.NotEqual(t, authToken(f[4]), authToken(f[5]))
}

func TestProviderErrors(t *testing.T) {
	e := newEnv(t)
	sub := e.fake.Subscribe("https://fcm.googleapis.com/fcm/send")
	m := encrypted(t, sub, "{}", e.now.Add(time.Hour))
	for _, tc := range []struct {
		resp   providertest.Response
		kind   providers.Kind
		reason string
	}{
		{providertest.Response{Status: 410}, providers.Gone, "Web Push 410 Gone"},
		{providertest.Response{Status: 404}, providers.Gone, "Web Push 404 Not Found"},
		{providertest.Response{Status: 400, Reason: "BadDeviceToken"}, providers.Gone, "Web Push BadDeviceToken"},
		{providertest.Response{Status: 413}, providers.Rejected, "Web Push 413 Request Entity Too Large"},
		{providertest.Response{Status: 400, Reason: "Bad Topic: not/allowed"}, providers.Rejected, "Web Push 400 Bad Request"},
		{providertest.Response{Status: 429, RetryAfter: "30"}, providers.Retry, "Web Push 429 Too Many Requests"},
		{providertest.Response{Status: 503}, providers.Retry, "Web Push 503 Service Unavailable"},
		{providertest.Response{Status: 401}, providers.Retry, "Web Push 401 Unauthorized"},
	} {
		e.fake.Respond(sub.Token, tc.resp)
		perr := e.send(t, sub.Endpoint, m)
		require.NotNil(t, perr, tc.reason)
		assert.Equal(t, tc.kind, perr.Kind, tc.reason)
		assert.Equal(t, tc.reason, perr.Reason)
		assert.Equal(t, tc.resp.Status, perr.Status)
		if tc.resp.RetryAfter != "" {
			assert.Equal(t, 30*time.Second, perr.RetryAfter)
		}
	}
}

func TestRefusedBeforeSending(t *testing.T) {
	policyErr := errors.New("the gateway does not send to push service evil.example")
	e := newEnv(t, func(c *webpush.Config) {
		c.CheckEndpoint = func(endpoint string) error {
			if strings.Contains(endpoint, "evil.example") {
				return policyErr
			}
			return nil
		}
	})
	sub := e.fake.Subscribe("https://evil.example/push")
	perr := e.send(t, sub.Endpoint, encrypted(t, sub, "{}", e.now.Add(time.Hour)))
	require.NotNil(t, perr)
	assert.Equal(t, providers.Rejected, perr.Kind, "narrowing the policy covers existing subscriptions")
	assert.ErrorIs(t, perr, policyErr)

	perr = e.send(t, "https://fcm.googleapis.com/fcm/send/x", providers.Message{Mode: providers.ModeIDOnly, Expiration: e.now.Add(time.Hour)})
	require.NotNil(t, perr)
	assert.Equal(t, providers.Rejected, perr.Kind)
	assert.Empty(t, e.fake.Requests(), "nothing reaches the push service")
}

func TestConnectionsOnlyGoToPublicAddresses(t *testing.T) {
	priv, pub := providertest.NewVAPIDKey()
	fake := providertest.NewWebPush()
	url, stop, err := providertest.Serve("127.0.0.1:0", fake)
	require.NoError(t, err)
	t.Cleanup(stop)
	sub := fake.Subscribe(url + "/push")
	body, err := providertest.Encrypt(sub.P256dh, sub.Auth, []byte("{}"), 0)
	require.NoError(t, err)
	m := providers.Message{Mode: providers.ModeEncrypted, Body: body, Expiration: time.Now().Add(time.Minute)}

	guarded, err := webpush.New(webpush.Config{PublicKey: pub, PrivateKey: []byte(priv), Subject: subject})
	require.NoError(t, err)
	err = guarded.Send(context.Background(), providers.Target{Token: sub.Endpoint}, m)
	var perr *providers.Error
	require.ErrorAs(t, err, &perr)
	assert.Equal(t, providers.Rejected, perr.Kind)
	assert.Equal(t, "Web Push endpoint is not reachable from this gateway", perr.Reason)
	assert.Empty(t, fake.Requests())

	insecure, err := webpush.New(webpush.Config{PublicKey: pub, PrivateKey: []byte(priv), Subject: subject, Insecure: true})
	require.NoError(t, err)
	require.NoError(t, insecure.Send(context.Background(), providers.Target{Token: sub.Endpoint}, m), "development mode reaches a local fake")
	reqs := fake.Requests(sub.Token)
	require.Len(t, reqs, 1)
	assert.Equal(t, "{}", string(reqs[0].Plaintext))
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	e := newEnv(t)
	sub := e.fake.Subscribe("https://fcm.googleapis.com/fcm/send")
	e.fake.Respond(sub.Token, providertest.Response{Status: http.StatusTemporaryRedirect})
	perr := e.send(t, sub.Endpoint, encrypted(t, sub, "{}", e.now.Add(time.Hour)))
	require.NotNil(t, perr)
	assert.Equal(t, providers.Rejected, perr.Kind)
	assert.Len(t, e.fake.Requests(sub.Token), 1)
}

func TestKeys(t *testing.T) {
	priv, pub := providertest.NewVAPIDKey()
	k, err := webpush.ParsePrivateKey([]byte(priv + "\n"))
	require.NoError(t, err)
	got, err := webpush.PublicKeyOf(k)
	require.NoError(t, err)
	assert.Equal(t, pub, got)

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(ec)
	sec1, _ := x509.MarshalECPrivateKey(ec)
	for _, p := range []*pem.Block{{Type: "PRIVATE KEY", Bytes: pkcs8}, {Type: "EC PRIVATE KEY", Bytes: sec1}} {
		k, err := webpush.ParsePrivateKey(pem.EncodeToMemory(p))
		require.NoError(t, err, p.Type)
		assert.True(t, k.Equal(ec))
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(p384)
	for name, bad := range map[string][]byte{
		"short":  []byte("AAAA"),
		"p-384":  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		"no pem": []byte("-----BEGIN PRIVATE KEY-----\nnope"),
	} {
		_, err := webpush.ParsePrivateKey(bad)
		assert.Error(t, err, name)
	}

	_, other := providertest.NewVAPIDKey()
	_, err = webpush.New(webpush.Config{PublicKey: other, PrivateKey: []byte(priv), Subject: subject})
	assert.ErrorContains(t, err, "does not match vapid_public_key")
	_, err = webpush.New(webpush.Config{PublicKey: pub, PrivateKey: []byte(priv)})
	assert.ErrorContains(t, err, "subject")
}

func TestAudience(t *testing.T) {
	for endpoint, want := range map[string]string{
		"https://fcm.googleapis.com/fcm/send/x":         "https://fcm.googleapis.com",
		"https://FCM.googleapis.com:443/fcm/send/x":     "https://fcm.googleapis.com",
		"http://host.docker.internal:18083/push/x":      "http://host.docker.internal:18083",
		"https://wns2-par02p.notify.windows.com/w/?t=1": "https://wns2-par02p.notify.windows.com",
	} {
		got, err := webpush.Audience(endpoint)
		require.NoError(t, err, endpoint)
		assert.Equal(t, want, got)
	}
	_, err := webpush.Audience("not a url")
	assert.Error(t, err)
}

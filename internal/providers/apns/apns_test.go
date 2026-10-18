package apns_test

import (
	"context"
	"encoding/base64"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/parkerbrown98/gotalk-gateway/internal/providers"
	"github.com/parkerbrown98/gotalk-gateway/internal/providers/apns"
	"github.com/parkerbrown98/gotalk-gateway/internal/providers/providertest"
)

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

type setup struct {
	client  *apns.Client
	prod    *providertest.APNs
	sandbox *providertest.APNs
	clock   *clock
}

func newSetup(t *testing.T) setup {
	t.Helper()
	pemKey, pub := providertest.NewAPNsKey()
	s := setup{prod: providertest.NewAPNs(), sandbox: providertest.NewAPNs(), clock: &clock{t: time.Now().Add(-2 * time.Hour)}}
	for _, f := range []*providertest.APNs{s.prod, s.sandbox} {
		f.Key, f.TeamID, f.KeyID, f.Topic = pub, "TEAM123456", "KEY1234567", "app.example.gotalk"
	}
	prodURL, stop, err := providertest.Serve("127.0.0.1:0", s.prod)
	require.NoError(t, err)
	t.Cleanup(stop)
	sandboxURL, stop, err := providertest.Serve("127.0.0.1:0", s.sandbox)
	require.NoError(t, err)
	t.Cleanup(stop)
	s.client, err = apns.New(apns.Config{
		BundleID: "app.example.gotalk", TeamID: "TEAM123456", KeyID: "KEY1234567", PrivateKey: pemKey,
		ProductionURL: prodURL, SandboxURL: sandboxURL, Now: s.clock.now,
	})
	require.NoError(t, err)
	return s
}

const token = "abababababababababababababababababababababababababababababababab"

func TestSendEncrypted(t *testing.T) {
	s := newSetup(t)
	body := []byte("ciphertext-bytes")
	exp := s.clock.now().Add(time.Hour)
	err := s.client.Send(context.Background(), providers.Target{Token: token, APNsEnvironment: "production"}, providers.Message{
		SubscriptionID: "sub_1", Mode: providers.ModeEncrypted, Body: body, Urgency: providers.UrgencyHigh,
		Expiration: exp, CollapseKey: "c_1",
	})
	require.NoError(t, err)
	reqs := s.prod.Requests(token)
	require.Len(t, reqs, 1)
	r := reqs[0]
	assert.Equal(t, 2, r.Proto, "APNs is HTTP/2 only")
	assert.Equal(t, "app.example.gotalk", r.Header.Get("apns-topic"))
	assert.Equal(t, "alert", r.Header.Get("apns-push-type"))
	assert.Equal(t, "10", r.Header.Get("apns-priority"))
	assert.Equal(t, exp.Unix(), parseInt(t, r.Header.Get("apns-expiration")))
	assert.Equal(t, "c_1", r.Header.Get("apns-collapse-id"))
	assert.Equal(t, map[string]any{
		"aps": map[string]any{"alert": map[string]any{"loc-key": "GT_NEW_NOTIFICATION"}, "mutable-content": 1.0, "sound": "default"},
		"gt":  map[string]any{"v": 1.0, "sub": "sub_1", "mode": "encrypted", "body": base64.RawURLEncoding.EncodeToString(body)},
	}, r.Body)
	assert.Empty(t, s.sandbox.Requests())
}

func TestSendIDOnlyToSandbox(t *testing.T) {
	s := newSetup(t)
	err := s.client.Send(context.Background(), providers.Target{Token: token, APNsEnvironment: "sandbox"}, providers.Message{
		SubscriptionID: "sub_1", Mode: providers.ModeIDOnly, Instance: "https://forum.example", NotificationID: "ntf_1",
		Urgency: providers.UrgencyLow, Expiration: s.clock.now(),
	})
	require.NoError(t, err)
	reqs := s.sandbox.Requests(token)
	require.Len(t, reqs, 1)
	assert.Equal(t, "1", reqs[0].Header.Get("apns-priority"))
	assert.Equal(t, "0", reqs[0].Header.Get("apns-expiration"), "a TTL of 0 is deliver now or drop")
	assert.Empty(t, reqs[0].Header.Get("apns-collapse-id"))
	assert.Equal(t, map[string]any{
		"v": 1.0, "sub": "sub_1", "mode": "id_only", "instance": "https://forum.example", "notification_id": "ntf_1",
	}, reqs[0].Body["gt"])
	assert.Empty(t, s.prod.Requests())
}

func TestProviderTokenIsReusedAndRefreshed(t *testing.T) {
	s := newSetup(t)
	send := func() string {
		t.Helper()
		require.NoError(t, s.client.Send(context.Background(), providers.Target{Token: token}, providers.Message{Mode: providers.ModeEncrypted}))
		reqs := s.prod.Requests(token)
		return reqs[len(reqs)-1].Header.Get("Authorization")
	}
	first := send()
	assert.Equal(t, first, send(), "the provider token is reused")
	tok, _, err := jwt.NewParser().ParseUnverified(first[len("bearer "):], jwt.MapClaims{})
	require.NoError(t, err)
	assert.Equal(t, "KEY1234567", tok.Header["kid"])
	assert.Equal(t, "TEAM123456", tok.Claims.(jwt.MapClaims)["iss"])

	s.clock.add(51 * time.Minute)
	second := send()
	assert.NotEqual(t, first, second, "tokens are refreshed before Apple's one-hour limit")

	s.prod.Respond(token, providertest.Response{Status: 403, Reason: "ExpiredProviderToken"})
	err = s.client.Send(context.Background(), providers.Target{Token: token}, providers.Message{Mode: providers.ModeEncrypted})
	var perr *providers.Error
	require.ErrorAs(t, err, &perr)
	assert.Equal(t, providers.Retry, perr.Kind)
	s.clock.add(time.Second)
	assert.NotEqual(t, second, send(), "a token APNs calls expired is replaced")
}

func TestSendErrors(t *testing.T) {
	s := newSetup(t)
	s.prod.Respond(token,
		providertest.Response{Status: 410, Reason: "Unregistered"},
		providertest.Response{Status: 429, Reason: "TooManyRequests", RetryAfter: "7"},
		providertest.Response{Status: 400, Reason: "BadCollapseId"},
	)
	send := func() *providers.Error {
		err := s.client.Send(context.Background(), providers.Target{Token: token}, providers.Message{Mode: providers.ModeEncrypted})
		var perr *providers.Error
		require.ErrorAs(t, err, &perr)
		return perr
	}
	e := send()
	assert.Equal(t, providers.Gone, e.Kind)
	assert.Equal(t, "APNs Unregistered", e.Reason)
	e = send()
	assert.Equal(t, providers.Retry, e.Kind)
	assert.Equal(t, 7*time.Second, e.RetryAfter)
	e = send()
	assert.Equal(t, providers.Rejected, e.Kind)
	assert.Equal(t, 400, e.Status)
}

func TestTransportFailureIsRetried(t *testing.T) {
	pemKey, _ := providertest.NewAPNsKey()
	c, err := apns.New(apns.Config{BundleID: "a.b", TeamID: "TEAM123456", KeyID: "KEY1234567", PrivateKey: pemKey, ProductionURL: "http://127.0.0.1:1"})
	require.NoError(t, err)
	err = c.Send(context.Background(), providers.Target{Token: token}, providers.Message{Mode: providers.ModeEncrypted})
	var perr *providers.Error
	require.ErrorAs(t, err, &perr)
	assert.Equal(t, providers.Retry, perr.Kind)
	assert.Equal(t, "APNs unreachable", perr.Reason)
}

func TestClassify(t *testing.T) {
	for _, tc := range []struct {
		status int
		reason string
		want   providers.Kind
	}{
		{410, "Unregistered", providers.Gone},
		{410, "ExpiredToken", providers.Gone},
		{400, "BadDeviceToken", providers.Gone},
		{400, "DeviceTokenNotForTopic", providers.Gone},
		{400, "BadCollapseId", providers.Rejected},
		{400, "TopicDisallowed", providers.Rejected},
		{413, "PayloadTooLarge", providers.Rejected},
		{404, "BadPath", providers.Rejected},
		{403, "InvalidProviderToken", providers.Retry},
		{403, "BadCertificateEnvironment", providers.Retry},
		{429, "TooManyRequests", providers.Retry},
		{500, "InternalServerError", providers.Retry},
		{503, "ServiceUnavailable", providers.Retry},
	} {
		assert.Equal(t, tc.want, apns.Classify(tc.status, tc.reason).Kind, "%d %s", tc.status, tc.reason)
	}
}

func TestPriority(t *testing.T) {
	assert.Equal(t, "10", apns.Priority("high"))
	assert.Equal(t, "5", apns.Priority("normal"))
	assert.Equal(t, "1", apns.Priority("low"))
}

func TestParseKey(t *testing.T) {
	pemKey, _ := providertest.NewAPNsKey()
	_, err := apns.ParseKey(pemKey)
	require.NoError(t, err)
	_, err = apns.ParseKey([]byte("not pem"))
	assert.ErrorContains(t, err, "is not PEM")
	_, err = apns.New(apns.Config{PrivateKey: pemKey, ProductionURL: "ftp://x"})
	assert.ErrorContains(t, err, "not an absolute http(s) URL")
	assert.NoError(t, apns.ValidateID("ABCDE12345"))
	assert.Error(t, apns.ValidateID("abcde12345"))
}

func parseInt(t *testing.T, s string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(s, 10, 64)
	require.NoError(t, err)
	return n
}

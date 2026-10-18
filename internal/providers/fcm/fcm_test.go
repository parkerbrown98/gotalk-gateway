package fcm_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/parkerbrown98/gotalk-gateway/internal/providers"
	"github.com/parkerbrown98/gotalk-gateway/internal/providers/fcm"
	"github.com/parkerbrown98/gotalk-gateway/internal/providers/providertest"
)

const token = "fcm-token-1"

func newClient(t *testing.T) (*fcm.Client, *providertest.FCM) {
	t.Helper()
	fake := providertest.NewFCM("demo-project")
	url, stop, err := providertest.Serve("127.0.0.1:0", fake)
	require.NoError(t, err)
	t.Cleanup(stop)
	sa, pub := providertest.NewServiceAccount("demo-project", url+"/token")
	fake.Key = pub
	c, err := fcm.New(fcm.Config{ServiceAccount: sa, Endpoint: url})
	require.NoError(t, err)
	return c, fake
}

func send(t *testing.T, c *fcm.Client, m providers.Message) *providers.Error {
	t.Helper()
	err := c.Send(context.Background(), providers.Target{Token: token}, m)
	if err == nil {
		return nil
	}
	var perr *providers.Error
	require.ErrorAs(t, err, &perr)
	return perr
}

func TestSendEncrypted(t *testing.T) {
	c, fake := newClient(t)
	body := []byte("ciphertext")
	require.Nil(t, send(t, c, providers.Message{
		SubscriptionID: "sub_1", Mode: providers.ModeEncrypted, Body: body, Urgency: providers.UrgencyHigh,
		Expiration: time.Now().Add(time.Hour), CollapseKey: "c_1",
	}))
	reqs := fake.Requests(token)
	require.Len(t, reqs, 1)
	msg := reqs[0].Body["message"].(map[string]any)
	assert.Equal(t, map[string]any{
		"gt_v": "1", "gt_sub": "sub_1", "gt_mode": "encrypted", "gt_body": base64.RawURLEncoding.EncodeToString(body),
	}, msg["data"])
	assert.Equal(t, map[string]any{"priority": "HIGH", "ttl": "3600s", "collapse_key": "c_1"}, msg["android"])
	assert.NotContains(t, msg, "notification", "data-only, so the app always runs its handler")
}

func TestSendIDOnly(t *testing.T) {
	c, fake := newClient(t)
	require.Nil(t, send(t, c, providers.Message{
		SubscriptionID: "sub_1", Mode: providers.ModeIDOnly, Instance: "https://forum.example", NotificationID: "ntf_1",
		Urgency: providers.UrgencyLow, Expiration: time.Now().Add(-time.Second),
	}))
	msg := fake.Requests(token)[0].Body["message"].(map[string]any)
	assert.Equal(t, map[string]any{
		"gt_v": "1", "gt_sub": "sub_1", "gt_mode": "id_only", "gt_instance": "https://forum.example", "gt_notification_id": "ntf_1",
	}, msg["data"])
	assert.Equal(t, map[string]any{"priority": "NORMAL", "ttl": "0s"}, msg["android"])
}

func TestAccessTokenIsReusedAndReplacedWhenRefused(t *testing.T) {
	c, fake := newClient(t)
	m := providers.Message{Mode: providers.ModeEncrypted, Expiration: time.Now().Add(time.Minute)}
	require.Nil(t, send(t, c, m))
	require.Nil(t, send(t, c, m))
	assert.Equal(t, 1, fake.TokensIssued(), "the OAuth token is cached")

	fake.RevokeTokens()
	e := send(t, c, m)
	require.NotNil(t, e)
	assert.Equal(t, providers.Retry, e.Kind)
	assert.Equal(t, 401, e.Status)
	require.Nil(t, send(t, c, m), "a refused token is replaced on the next send")
	assert.Equal(t, 2, fake.TokensIssued())
}

func TestSendErrors(t *testing.T) {
	c, fake := newClient(t)
	fake.Respond(token,
		providertest.Response{Status: 404, Reason: "UNREGISTERED"},
		providertest.Response{Status: 400, Reason: "INVALID_ARGUMENT", BadTokenField: true},
		providertest.Response{Status: 400, Reason: "INVALID_ARGUMENT"},
		providertest.Response{Status: 429, Reason: "QUOTA_EXCEEDED", RetryAfter: "30"},
		providertest.Response{Status: 503, Reason: "UNAVAILABLE"},
		providertest.Response{Status: 403, Reason: "SENDER_ID_MISMATCH"},
	)
	m := providers.Message{Mode: providers.ModeEncrypted}
	e := send(t, c, m)
	assert.Equal(t, providers.Gone, e.Kind)
	assert.Equal(t, "FCM UNREGISTERED", e.Reason)
	assert.Equal(t, providers.Gone, send(t, c, m).Kind, "an invalid token is dead")
	assert.Equal(t, providers.Rejected, send(t, c, m).Kind, "other invalid arguments reject the push")
	e = send(t, c, m)
	assert.Equal(t, providers.Retry, e.Kind)
	assert.Equal(t, 30*time.Second, e.RetryAfter)
	assert.Equal(t, providers.Retry, send(t, c, m).Kind)
	assert.Equal(t, providers.Gone, send(t, c, m).Kind, "a token of another project is dead for this app")
}

func TestClassifyWithoutDetails(t *testing.T) {
	for status, want := range map[int]providers.Kind{
		400: providers.Rejected, 401: providers.Retry, 403: providers.Retry, 404: providers.Rejected,
		429: providers.Retry, 500: providers.Retry, 502: providers.Retry,
	} {
		assert.Equal(t, want, fcm.Classify(status, []byte("not json")).Kind, "%d", status)
	}
}

func TestNewValidatesServiceAccount(t *testing.T) {
	_, err := fcm.New(fcm.Config{ServiceAccount: []byte(`{"type":"authorized_user"}`)})
	assert.ErrorContains(t, err, "is not a service account key")
	sa, _ := providertest.NewServiceAccount("", "http://127.0.0.1:1/token")
	_, err = fcm.New(fcm.Config{ServiceAccount: sa})
	assert.ErrorContains(t, err, "project ID is unknown")
	_, err = fcm.New(fcm.Config{ServiceAccount: sa, ProjectID: "p"})
	assert.NoError(t, err)
}

func TestTokenEndpointFailureIsRetried(t *testing.T) {
	sa, _ := providertest.NewServiceAccount("p", "http://127.0.0.1:1/token")
	c, err := fcm.New(fcm.Config{ServiceAccount: sa, Endpoint: "http://127.0.0.1:1"})
	require.NoError(t, err)
	e := send(t, c, providers.Message{Mode: providers.ModeEncrypted})
	assert.Equal(t, providers.Retry, e.Kind)
	assert.Equal(t, "FCM access token unavailable", e.Reason)
}

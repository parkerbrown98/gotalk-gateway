package push

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/parkerbrown98/gotalk-gateway/internal/problem"
)

const subID = "sub_AAAAAAAAAAAAAAAAAAAAAA"

func payloadOf(n int) string { return base64.RawURLEncoding.EncodeToString(make([]byte, n)) }

func entryJSON(fields map[string]any) []byte {
	raw, _ := json.Marshal(fields)
	return raw
}

func fieldsOf(p *problem.Problem) map[string]string {
	out := map[string]string{}
	for _, e := range p.Errors {
		out[e.Field] = e.Message
	}
	return out
}

func TestParseEntryDefaults(t *testing.T) {
	e, p := ParseEntry(entryJSON(map[string]any{
		"subscription_id": subID, "mode": "encrypted", "notification_id": "ntf_01:a.b-c", "payload": payloadOf(103),
	}))
	require.Nil(t, p)
	assert.Equal(t, Entry{
		SubscriptionID: subID, Mode: "encrypted", NotificationID: "ntf_01:a.b-c", Payload: make([]byte, 103),
		Urgency: "normal", TTL: 86400,
	}, e)

	e, p = ParseEntry(entryJSON(map[string]any{
		"subscription_id": subID, "mode": "id_only", "notification_id": "n", "urgency": "high", "ttl": 0, "collapse_key": "c_4f-9",
	}))
	require.Nil(t, p)
	assert.Equal(t, "high", e.Urgency)
	assert.Zero(t, e.TTL, "0 is deliver now or drop, not the default")
	assert.Equal(t, "c_4f-9", e.CollapseKey)
	assert.Nil(t, e.Payload)
}

func TestParseEntryValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		fields map[string]any
		want   map[string]string
	}{
		"missing": {map[string]any{}, map[string]string{
			"subscription_id": "required", "notification_id": "required", "mode": "required",
		}},
		"formats": {map[string]any{
			"subscription_id": "sub_short", "mode": "loud", "notification_id": "has space", "urgency": "urgent",
			"ttl": 2419201, "collapse_key": strings.Repeat("k", 33),
		}, map[string]string{
			"subscription_id": "must match ^sub_[A-Za-z0-9_-]{8,64}$", "mode": "must be encrypted or id_only",
			"notification_id": "must be 1 to 64 characters of A-Z a-z 0-9 . _ : -", "urgency": "must be low, normal or high",
			"ttl": "must be an integer from 0 to 2419200", "collapse_key": "must be 1 to 32 characters of A-Z a-z 0-9 _ -",
		}},
		"encrypted without payload": {map[string]any{"subscription_id": subID, "mode": "encrypted", "notification_id": "n"},
			map[string]string{"payload": "required in encrypted mode"}},
		"id_only with payload": {map[string]any{"subscription_id": subID, "mode": "id_only", "notification_id": "n", "payload": payloadOf(200)},
			map[string]string{"payload": "not allowed in id_only mode"}},
		"short payload": {map[string]any{"subscription_id": subID, "mode": "encrypted", "notification_id": "n", "payload": payloadOf(102)},
			map[string]string{"payload": "is shorter than the smallest RFC 8291 body (103 bytes)"}},
		"padded payload": {map[string]any{"subscription_id": subID, "mode": "encrypted", "notification_id": "n", "payload": payloadOf(200) + "=="},
			map[string]string{"payload": "must be base64url without padding"}},
		"standard base64": {map[string]any{"subscription_id": subID, "mode": "encrypted", "notification_id": "n", "payload": strings.Repeat("+/", 100)},
			map[string]string{"payload": "must be base64url without padding"}},
		"fractional ttl": {map[string]any{"subscription_id": subID, "mode": "id_only", "notification_id": "n", "ttl": 1.5},
			map[string]string{"ttl": "must be an integer from 0 to 2419200"}},
		"unknown field": {map[string]any{"subscription_id": subID, "mode": "id_only", "notification_id": "n", "title": "Hi"},
			map[string]string{"title": "unknown field"}},
		"wrong type": {map[string]any{"subscription_id": 7, "mode": "id_only", "notification_id": "n"},
			map[string]string{"subscription_id": "must be a string"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, p := ParseEntry(entryJSON(tc.fields))
			require.NotNil(t, p)
			assert.Equal(t, 422, p.Status)
			assert.Equal(t, problem.InvalidRequest, p.Code)
			assert.Equal(t, tc.want, fieldsOf(p))
		})
	}
}

func TestParseEntryPayloadTooLarge(t *testing.T) {
	_, p := ParseEntry(entryJSON(map[string]any{"subscription_id": subID, "mode": "encrypted", "notification_id": "n", "payload": payloadOf(2200)}))
	assert.Nil(t, p, "2,200 bytes is the limit")
	e, p := ParseEntry(entryJSON(map[string]any{"subscription_id": subID, "mode": "encrypted", "notification_id": "", "payload": payloadOf(2201)}))
	require.NotNil(t, p)
	assert.Equal(t, 413, p.Status, "an oversized payload is 413 even with other problems")
	assert.Equal(t, problem.PayloadTooLarge, p.Code)
	assert.Equal(t, subID, e.SubscriptionID)
}

func TestParseEntryNotAnObject(t *testing.T) {
	for _, raw := range []string{`[]`, `5`, `null`, `"x"`, `{`, `{"mode":"id_only"} {}`} {
		_, p := ParseEntry([]byte(raw))
		require.NotNil(t, p, raw)
		assert.Equal(t, 400, p.Status, raw)
	}
	e, p := ParseEntry([]byte(`{"subscription_id":"` + subID + `","bogus":1}`))
	require.NotNil(t, p)
	assert.Equal(t, subID, e.SubscriptionID, "a rejected entry still reports its subscription")
}

func TestParseBatch(t *testing.T) {
	entries, p := ParseBatch([]byte(`{"pushes":[{"a":1},5]}`))
	require.Nil(t, p)
	assert.Len(t, entries, 2, "entries are validated one by one later")

	tooMany := `{"pushes":[` + strings.TrimSuffix(strings.Repeat(`{},`, 101), ",") + `]}`
	for raw, want := range map[string]string{
		`{"pushes":[]}`:       "must have 1 to 100 entries",
		tooMany:               "must have 1 to 100 entries",
		`{}`:                  "required",
		`{"pushes":null}`:     "required",
		`{"pushes":[],"x":1}`: "unknown field",
	} {
		_, p := ParseBatch([]byte(raw))
		require.NotNil(t, p, raw)
		assert.Equal(t, 422, p.Status)
		assert.Equal(t, want, p.Errors[0].Message, raw)
	}
	_, p = ParseBatch([]byte(`[]`))
	assert.Equal(t, 400, p.Status)
}

func TestItemMessage(t *testing.T) {
	p := problem.Invalid("payload", "required in encrypted mode")
	p.Errors = append(p.Errors, problem.FieldError{Field: "ttl", Message: "must be an integer from 0 to 2419200"})
	assert.Equal(t, "Request validation failed: payload: required in encrypted mode; ttl: must be an integer from 0 to 2419200.", ItemMessage(p))
	assert.Equal(t, "No such subscription.", ItemMessage(problem.New(404, problem.SubscriptionNotFound, "No such subscription.")))
}

func TestErrorMessage(t *testing.T) {
	d := "APNs Unregistered"
	assert.Equal(t, "The device token is no longer valid; delete the subscription (APNs Unregistered).", ErrorMessage(problem.SubscriptionGone, &d))
	assert.Equal(t, "The provider permanently refused the push.", ErrorMessage(problem.ProviderRejected, nil))
}

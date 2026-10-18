package push

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/parkerbrown98/gotalk-gateway/internal/problem"
	"github.com/parkerbrown98/gotalk-gateway/internal/protocol"
	"github.com/parkerbrown98/gotalk-gateway/internal/providers"
)

const (
	// MinPayloadBytes is the smallest valid RFC 8291 body: an 86-byte header, a 1-byte
	// delimiter and a 16-byte tag.
	MinPayloadBytes = 103
	// DefaultTTL applies when a push has no ttl.
	DefaultTTL = 24 * 60 * 60
	// MaxSingleBody and MaxBatchBody are the request body limits of the push endpoints.
	MaxSingleBody = 16 << 10
	MaxBatchBody  = 1 << 20
)

// Entry is one validated push request (docs/protocol.md, "Single push").
type Entry struct {
	SubscriptionID string
	Mode           string
	NotificationID string
	// Payload is the decoded RFC 8291 body in encrypted mode.
	Payload     []byte
	Urgency     string
	TTL         int
	CollapseKey string
}

var (
	subscriptionIDPattern = regexp.MustCompile(`^sub_[A-Za-z0-9_-]{8,64}$`)
	notificationIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
	collapseKeyPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
	base64URLPattern      = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)
	unknownFieldPattern   = regexp.MustCompile(`^json: unknown field "(.*)"$`)
)

type rawEntry struct {
	SubscriptionID *string      `json:"subscription_id"`
	Mode           *string      `json:"mode"`
	NotificationID *string      `json:"notification_id"`
	Payload        *string      `json:"payload"`
	Urgency        *string      `json:"urgency"`
	TTL            *json.Number `json:"ttl"`
	CollapseKey    *string      `json:"collapse_key"`
}

// decodeStrict decodes one JSON object into v, rejecting unknown fields and trailing data.
func decodeStrict(raw []byte, v any) *problem.Problem {
	notObject := problem.New(http.StatusBadRequest, problem.InvalidRequest, "The request body is not a JSON object.")
	if t := bytes.TrimSpace(raw); len(t) == 0 || t[0] != '{' {
		return notObject
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		var typeErr *json.UnmarshalTypeError
		switch {
		case unknownFieldPattern.MatchString(err.Error()):
			return problem.Invalid(unknownFieldPattern.FindStringSubmatch(err.Error())[1], "unknown field")
		case errors.As(err, &typeErr):
			want := "a " + typeErr.Type.String()
			switch typeErr.Type.String() {
			case "string":
				want = "a string"
			case "json.Number":
				want = "a number"
			}
			return problem.Invalid(typeErr.Field, "must be "+want)
		default:
			return notObject
		}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return problem.New(http.StatusBadRequest, problem.InvalidRequest, "The request body has data after the JSON object.")
	}
	return nil
}

// ParseEntry decodes and validates one push object. Failures are 400 or 422 invalid_request
// (with field errors), or 413 payload_too_large. The subscription ID is filled in whenever
// the object names one, so a rejected batch entry can report it.
func ParseEntry(raw []byte) (Entry, *problem.Problem) {
	var in rawEntry
	if p := decodeStrict(raw, &in); p != nil {
		// Recover the subscription ID for the batch result, if there is one.
		var loose struct {
			SubscriptionID string `json:"subscription_id"`
		}
		_ = json.Unmarshal(raw, &loose)
		return Entry{SubscriptionID: loose.SubscriptionID}, p
	}
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	e := Entry{
		SubscriptionID: str(in.SubscriptionID), Mode: str(in.Mode), NotificationID: str(in.NotificationID),
		Urgency: providers.UrgencyNormal, TTL: DefaultTTL, CollapseKey: str(in.CollapseKey),
	}
	var errs []problem.FieldError
	add := func(field, msg string) { errs = append(errs, problem.FieldError{Field: field, Message: msg}) }

	switch {
	case in.SubscriptionID == nil:
		add("subscription_id", "required")
	case !subscriptionIDPattern.MatchString(e.SubscriptionID):
		add("subscription_id", "must match "+subscriptionIDPattern.String())
	}
	switch {
	case in.NotificationID == nil:
		add("notification_id", "required")
	case !notificationIDPattern.MatchString(e.NotificationID):
		add("notification_id", "must be 1 to 64 characters of A-Z a-z 0-9 . _ : -")
	}
	switch e.Mode {
	case providers.ModeEncrypted:
		if in.Payload == nil {
			add("payload", "required in encrypted mode")
			break
		}
		// Size first: an oversized payload is 413 whatever else is wrong with it.
		if base64.RawURLEncoding.DecodedLen(len(*in.Payload)) > protocol.MaxEncryptedBodyBytes {
			return e, problem.Newf(http.StatusRequestEntityTooLarge, problem.PayloadTooLarge,
				"payload is larger than %d bytes after decoding; truncate the body or use id_only.", protocol.MaxEncryptedBodyBytes)
		}
		body, err := base64.RawURLEncoding.Strict().DecodeString(*in.Payload)
		switch {
		case err != nil || !base64URLPattern.MatchString(*in.Payload):
			add("payload", "must be base64url without padding")
		case len(body) < MinPayloadBytes:
			add("payload", "is shorter than the smallest RFC 8291 body (103 bytes)")
		default:
			e.Payload = body
		}
	case providers.ModeIDOnly:
		if in.Payload != nil {
			add("payload", "not allowed in id_only mode")
		}
	case "":
		add("mode", "required")
	default:
		add("mode", "must be encrypted or id_only")
	}
	if in.Urgency != nil {
		switch *in.Urgency {
		case providers.UrgencyLow, providers.UrgencyNormal, providers.UrgencyHigh:
			e.Urgency = *in.Urgency
		default:
			add("urgency", "must be low, normal or high")
		}
	}
	if in.TTL != nil {
		n, err := in.TTL.Int64()
		if err != nil || n < 0 || n > protocol.MaxTTLSeconds {
			add("ttl", "must be an integer from 0 to 2419200")
		} else {
			e.TTL = int(n)
		}
	}
	if in.CollapseKey != nil && !collapseKeyPattern.MatchString(e.CollapseKey) {
		add("collapse_key", "must be 1 to 32 characters of A-Z a-z 0-9 _ -")
	}
	if len(errs) > 0 {
		p := problem.New(http.StatusUnprocessableEntity, problem.InvalidRequest, "Request validation failed.")
		p.Errors = errs
		return e, p
	}
	return e, nil
}

// ParseBatch decodes the batch envelope. Entries are parsed one by one so a bad entry is
// reported in its result instead of failing the batch.
func ParseBatch(raw []byte) ([]json.RawMessage, *problem.Problem) {
	var in struct {
		Pushes *[]json.RawMessage `json:"pushes"`
	}
	if p := decodeStrict(raw, &in); p != nil {
		return nil, p
	}
	switch {
	case in.Pushes == nil:
		return nil, problem.Invalid("pushes", "required")
	case len(*in.Pushes) == 0 || len(*in.Pushes) > protocol.MaxBatchSize:
		return nil, problem.Invalid("pushes", "must have 1 to 100 entries")
	}
	return *in.Pushes, nil
}

// ItemMessage describes a problem in one line, for a batch result's error.message.
func ItemMessage(p *problem.Problem) string {
	if len(p.Errors) == 0 {
		return p.Detail
	}
	parts := make([]string, len(p.Errors))
	for i, fe := range p.Errors {
		parts[i] = fe.Field + ": " + fe.Message
	}
	return "Request validation failed: " + strings.Join(parts, "; ") + "."
}

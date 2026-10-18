package api

import (
	"context"
	"crypto/sha256"
	"net/http"
	"reflect"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/parkerbrown98/gotalk-gateway/internal/push"
)

// PushRequest documents one push. Requests are parsed by push.ParseEntry, because a batch
// reports invalid entries in its results instead of failing as a whole.
type PushRequest struct {
	SubscriptionID string `json:"subscription_id" pattern:"^sub_[A-Za-z0-9_-]{8,64}$" doc:"Must be bound to the signing instance."`
	Mode           string `json:"mode" enum:"encrypted,id_only"`
	NotificationID string `json:"notification_id" pattern:"^[A-Za-z0-9._:-]{1,64}$" doc:"The instance's notification ID."`
	Payload        string `json:"payload,omitempty" pattern:"^[A-Za-z0-9_-]+$" minLength:"138" maxLength:"2934" doc:"RFC 8291 aes128gcm body, base64url. 103 to 2,200 bytes decoded. Required when mode is encrypted, forbidden when id_only. Never inspected by the gateway."`
	Urgency        string `json:"urgency,omitempty" enum:"low,normal,high" default:"normal"`
	TTL            int    `json:"ttl,omitempty" minimum:"0" maximum:"2419200" default:"86400" doc:"Seconds the provider holds the push for an offline device. 0 means deliver now or drop."`
	CollapseKey    string `json:"collapse_key,omitempty" pattern:"^[A-Za-z0-9_-]{1,32}$" doc:"A newer push with the same key replaces an undelivered older one."`
}

type PushBatchRequest struct {
	Pushes []PushRequest `json:"pushes" minItems:"1" maxItems:"100"`
}

type PushAccepted struct {
	PushID         string `json:"push_id"`
	SubscriptionID string `json:"subscription_id"`
	Status         string `json:"status" enum:"queued"`
}

type PushBatchResponse struct {
	Results []PushBatchResult `json:"results" nullable:"false" doc:"One result per entry, in order."`
}

type PushBatchResult struct {
	Index          int        `json:"index" minimum:"0"`
	Status         string     `json:"status" enum:"queued,rejected"`
	SubscriptionID string     `json:"subscription_id"`
	PushID         string     `json:"push_id,omitempty"`
	Error          *ItemError `json:"error,omitempty"`
}

type ItemError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type PushStatus struct {
	PushID         string     `json:"push_id"`
	SubscriptionID string     `json:"subscription_id"`
	NotificationID string     `json:"notification_id"`
	Status         string     `json:"status" enum:"queued,sent,failed,expired,gone"`
	Attempts       int32      `json:"attempts" minimum:"0"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	Error          *ItemError `json:"error" required:"false" doc:"Why delivery failed, expired or found the subscription gone; null otherwise."`
}

type pushInput struct {
	IdempotencyKey string `header:"Idempotency-Key" minLength:"1" maxLength:"64" doc:"Repeats within 24 hours return the original response."`
	RawBody        []byte
}

type pushOutput struct {
	Replayed string `header:"Idempotency-Replayed" doc:"true when the response replays an earlier request with the same key."`
	Body     PushAccepted
}

type pushBatchOutput struct {
	Replayed string `header:"Idempotency-Replayed" doc:"true when the response replays an earlier request with the same key."`
	Body     PushBatchResponse
}

func fingerprint(path string, body []byte) []byte {
	h := sha256.New()
	h.Write([]byte(path + "\n"))
	h.Write(body)
	return h.Sum(nil)
}

func replayed(o *push.Outcome) string {
	if o.Replayed {
		return "true"
	}
	return ""
}

func (s *Server) registerPush(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "sendPush",
		Method:      http.MethodPost,
		Path:        "/v1/push",
		Summary:     "Queue one push",
		Description: "202 means the push passed validation and is queued, not that the device received it. Delivery " +
			"is reported by GET /v1/pushes/{push_id}.",
		Tags:          []string{"Push"},
		Security:      signed,
		DefaultStatus: http.StatusAccepted,
		MaxBodyBytes:  push.MaxSingleBody,
		Metadata:      map[string]any{metaAuth: authPush},
	}, func(ctx context.Context, in *pushInput) (*pushOutput, error) {
		p := principalFrom(ctx)
		e, perr := push.ParseEntry(in.RawBody)
		out, err := s.Push.Accept(ctx, push.Sender{InstanceID: p.InstanceID, Origin: p.Origin},
			[]push.Item{{Entry: e, Err: perr}},
			push.Idempotency{Key: in.IdempotencyKey, Fingerprint: fingerprint("/v1/push", in.RawBody), AcceptedOnly: true})
		if err != nil {
			return nil, s.serviceError(ctx, err)
		}
		r := out.Results[0]
		if r.Error != nil {
			return nil, withRequestID(ctx, r.Error)
		}
		return &pushOutput{Replayed: replayed(out), Body: PushAccepted{PushID: r.PushID, SubscriptionID: r.SubscriptionID, Status: push.StatusQueued}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "sendPushBatch",
		Method:        http.MethodPost,
		Path:          "/v1/push/batch",
		Summary:       "Queue up to 100 pushes",
		Description:   "Always 202 when the batch itself is valid; per-entry failures are reported in results.",
		Tags:          []string{"Push"},
		Security:      signed,
		DefaultStatus: http.StatusAccepted,
		MaxBodyBytes:  push.MaxBatchBody,
		Metadata:      map[string]any{metaAuth: authPush},
	}, func(ctx context.Context, in *pushInput) (*pushBatchOutput, error) {
		p := principalFrom(ctx)
		raw, perr := push.ParseBatch(in.RawBody)
		if perr != nil {
			return nil, withRequestID(ctx, perr)
		}
		items := make([]push.Item, len(raw))
		for i, r := range raw {
			items[i].Entry, items[i].Err = push.ParseEntry(r)
		}
		out, err := s.Push.Accept(ctx, push.Sender{InstanceID: p.InstanceID, Origin: p.Origin}, items,
			push.Idempotency{Key: in.IdempotencyKey, Fingerprint: fingerprint("/v1/push/batch", in.RawBody)})
		if err != nil {
			return nil, s.serviceError(ctx, err)
		}
		body := PushBatchResponse{Results: make([]PushBatchResult, len(out.Results))}
		for i, r := range out.Results {
			res := PushBatchResult{Index: i, Status: push.StatusQueued, SubscriptionID: r.SubscriptionID, PushID: r.PushID}
			if r.Error != nil {
				res.Status = "rejected"
				res.Error = &ItemError{Code: r.Error.Code, Message: push.ItemMessage(r.Error)}
			}
			body.Results[i] = res
		}
		return &pushBatchOutput{Replayed: replayed(out), Body: body}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "getPush",
		Method:      http.MethodGet,
		Path:        "/v1/pushes/{push_id}",
		Summary:     "Delivery status of a push",
		Description: "Entries are kept for 72 hours and contain no content.",
		Tags:        []string{"Push"},
		Security:    signed,
		Metadata:    map[string]any{metaAuth: authRead},
	}, func(ctx context.Context, in *struct {
		PushID string `path:"push_id" pattern:"^push_[A-Za-z0-9_-]{8,64}$"`
	}) (*struct{ Body PushStatus }, error) {
		l, err := s.Push.Get(ctx, principalFrom(ctx).InstanceID, in.PushID)
		if err != nil {
			return nil, s.serviceError(ctx, err)
		}
		st := PushStatus{
			PushID: l.ID, SubscriptionID: l.SubscriptionID, NotificationID: l.NotificationID, Status: l.Status,
			Attempts: l.Attempts, CreatedAt: ts(l.CreatedAt), UpdatedAt: ts(l.UpdatedAt),
		}
		// A queued push shows its last transient failure only once it is final.
		if l.ErrorCode != nil && l.Status != push.StatusQueued && l.Status != push.StatusSent {
			st.Error = &ItemError{Code: *l.ErrorCode, Message: push.ErrorMessage(*l.ErrorCode, l.ErrorDetail)}
		}
		return &struct{ Body PushStatus }{Body: st}, nil
	})
	documentPushRequests(api)
}

// documentPushRequests replaces the raw request bodies of the push operations with the
// contract's schemas.
func documentPushRequests(api huma.API) {
	oapi := api.OpenAPI()
	for path, t := range map[string]reflect.Type{
		"/v1/push":       reflect.TypeFor[PushRequest](),
		"/v1/push/batch": reflect.TypeFor[PushBatchRequest](),
	} {
		schema := oapi.Components.Schemas.Schema(t, true, "")
		oapi.Paths[path].Post.RequestBody = &huma.RequestBody{Required: true, Content: map[string]*huma.MediaType{
			"application/json": {Schema: schema},
		}}
	}
	status := oapi.Components.Schemas.Map()["PushStatus"]
	errSchema := status.Properties["error"]
	status.Properties["error"] = &huma.Schema{
		Description: errSchema.Description,
		OneOf:       []*huma.Schema{{Ref: errSchema.Ref}, {Type: "null"}},
	}
}

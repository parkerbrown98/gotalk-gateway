package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/parkerbrown98/gotalk-gateway/internal/devices"
	"github.com/parkerbrown98/gotalk-gateway/internal/problem"
	"github.com/parkerbrown98/gotalk-gateway/internal/ratelimit"
)

type RegisterDeviceResponse struct {
	SubscriptionID     string    `json:"subscription_id"`
	SubscriptionSecret string    `json:"subscription_secret" doc:"Shown once. Store it in secure storage. Never send it to the instance."`
	ExpiresAt          time.Time `json:"expires_at"`
}

type RefreshDeviceRequest struct {
	Token           *string `json:"token,omitempty" minLength:"64" maxLength:"4096" doc:"New APNs or FCM token."`
	Endpoint        *string `json:"endpoint,omitempty" format:"uri" maxLength:"2048" doc:"New Web Push endpoint."`
	APNsEnvironment *string `json:"apns_environment,omitempty" enum:"production,sandbox"`
}

type RefreshDeviceResponse struct {
	SubscriptionID string    `json:"subscription_id"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// deviceRegistration is the RegisterDeviceRequest body. It is parsed by hand because the
// contract describes it as a oneOf of three platform shapes.
type deviceRegistration struct {
	AppID           *string         `json:"app_id"`
	InstanceOrigin  *string         `json:"instance_origin"`
	Platform        *string         `json:"platform"`
	Token           *string         `json:"token"`
	Endpoint        *string         `json:"endpoint"`
	APNsEnvironment *string         `json:"apns_environment"`
	Attestation     json.RawMessage `json:"attestation"`
}

var appIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

var unknownFieldPattern = regexp.MustCompile(`^json: unknown field "(.*)"$`)

// parseDeviceRegistration decodes and structurally validates a registration. Token formats
// are checked by the devices service.
func parseDeviceRegistration(body []byte) (devices.RegisterInput, error) {
	var in deviceRegistration
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	fail := func(field, msg string) error {
		return problem.Invalid(field, msg)
	}
	if err := dec.Decode(&in); err != nil {
		var typeErr *json.UnmarshalTypeError
		switch {
		case unknownFieldPattern.MatchString(err.Error()):
			return devices.RegisterInput{}, fail(unknownFieldPattern.FindStringSubmatch(err.Error())[1], "unknown field")
		case errors.As(err, &typeErr):
			return devices.RegisterInput{}, fail(typeErr.Field, "must be a "+typeErr.Type.String())
		default:
			return devices.RegisterInput{}, problem.New(http.StatusBadRequest, problem.InvalidRequest, "The request body is not a JSON object.")
		}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return devices.RegisterInput{}, problem.New(http.StatusBadRequest, problem.InvalidRequest, "The request body has data after the JSON object.")
	}

	var errs []problem.FieldError
	add := func(field, msg string) { errs = append(errs, problem.FieldError{Field: field, Message: msg}) }
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	switch {
	case in.AppID == nil:
		add("app_id", "required")
	case !appIDPattern.MatchString(*in.AppID):
		add("app_id", "must match "+appIDPattern.String())
	}
	if in.InstanceOrigin == nil {
		add("instance_origin", "required")
	} else if len(*in.InstanceOrigin) > 253 {
		add("instance_origin", "must be at most 253 characters")
	}
	platform := str(in.Platform)
	switch platform {
	case devices.IOS, devices.Android:
		if in.Token == nil {
			add("token", "required for "+platform)
		}
		if in.Endpoint != nil {
			add("endpoint", "only web subscriptions have an endpoint")
		}
	case devices.Web:
		if in.Endpoint == nil {
			add("endpoint", "required for web")
		}
		if in.Token != nil {
			add("token", "web subscriptions use endpoint")
		}
	case "":
		add("platform", "required")
	default:
		add("platform", "must be one of ios, android, web")
	}
	if in.APNsEnvironment != nil {
		if platform != devices.IOS {
			add("apns_environment", "only iOS subscriptions have an APNs environment")
		} else if e := *in.APNsEnvironment; e != devices.APNsProduction && e != devices.APNsSandbox {
			add("apns_environment", "must be production or sandbox")
		}
	}
	if a := bytes.TrimSpace(in.Attestation); len(a) > 0 && a[0] != '{' && !bytes.Equal(a, []byte("null")) {
		add("attestation", "must be an object")
	}
	if len(errs) > 0 {
		p := problem.New(http.StatusUnprocessableEntity, problem.InvalidRequest, "Request validation failed.")
		p.Errors = errs
		return devices.RegisterInput{}, p
	}
	token := str(in.Token)
	if platform == devices.Web {
		token = str(in.Endpoint)
	}
	return devices.RegisterInput{
		AppID: *in.AppID, InstanceOrigin: *in.InstanceOrigin, Platform: platform,
		Token: token, APNsEnvironment: str(in.APNsEnvironment),
	}, nil
}

// bearerSecret extracts a subscription secret from an Authorization header.
func bearerSecret(header string) (string, *problem.Problem) {
	scheme, secret, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(secret) == "" {
		return "", problem.New(http.StatusUnauthorized, problem.Unauthorized,
			"Send the subscription secret as Authorization: Bearer <subscription_secret>.").
			WithHeader("WWW-Authenticate", `Bearer realm="gotalk-gateway"`)
	}
	return strings.TrimSpace(secret), nil
}

// admitToken applies the per-token rate limit.
func (s *Server) admitToken(ctx context.Context) devices.Admit {
	return func(tokenHash []byte) error {
		res, err := s.Limiter.Take(ctx, ratelimit.DeviceToken, hex.EncodeToString(tokenHash))
		if err == nil && res.Reached {
			return rateLimited(res, s.now())
		}
		return nil
	}
}

// subscriptionPath is the input of DELETE. huma does not read parameters from embedded
// structs, so inputs that also have a body repeat these fields.
type subscriptionPath struct {
	SubscriptionID string `path:"subscription_id"`
	Authorization  string `header:"Authorization" hidden:"true"`
}

func (s *Server) registerDevices(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "registerDevice",
		Method:      http.MethodPost,
		Path:        "/v1/devices",
		Summary:     "Register a platform token for one instance and account",
		Description: "Unauthenticated, rate limited per IP and per token. Registering the same token again returns the " +
			"same subscription ID with a new secret; the old secret stops working.",
		Tags:          []string{"Devices"},
		DefaultStatus: http.StatusCreated,
		MaxBodyBytes:  defaultMaxBody,
		Metadata:      map[string]any{metaIPRule: ratelimit.DeviceRegistration},
	}, func(ctx context.Context, in *struct{ RawBody []byte }) (*struct {
		CacheControl string `header:"Cache-Control"`
		Body         RegisterDeviceResponse
	}, error,
	) {
		input, err := parseDeviceRegistration(in.RawBody)
		if err != nil {
			return nil, s.serviceError(ctx, err)
		}
		reg, err := s.Devices.Register(ctx, input, s.admitToken(ctx))
		if err != nil {
			return nil, s.serviceError(ctx, err)
		}
		return &struct {
			CacheControl string `header:"Cache-Control"`
			Body         RegisterDeviceResponse
		}{CacheControl: "no-store", Body: RegisterDeviceResponse{
			SubscriptionID: reg.SubscriptionID, SubscriptionSecret: reg.Secret, ExpiresAt: ts(reg.ExpiresAt),
		}}, nil
	})
	documentDeviceRegistration(api)

	huma.Register(api, huma.Operation{
		OperationID:  "refreshDevice",
		Method:       http.MethodPut,
		Path:         "/v1/devices/{subscription_id}",
		Summary:      "Refresh a subscription or replace its token",
		Description:  "Always extends the expiry. An empty object only extends it.",
		Tags:         []string{"Devices"},
		Security:     []map[string][]string{{"subscriptionSecret": {}}},
		MaxBodyBytes: defaultMaxBody,
	}, func(ctx context.Context, in *struct {
		SubscriptionID string `path:"subscription_id"`
		Authorization  string `header:"Authorization" hidden:"true"`
		Body           RefreshDeviceRequest
	}) (*struct {
		CacheControl string `header:"Cache-Control"`
		Body         RefreshDeviceResponse
	}, error,
	) {
		secret, p := bearerSecret(in.Authorization)
		if p != nil {
			return nil, withRequestID(ctx, p)
		}
		d, err := s.Devices.Authenticate(ctx, in.SubscriptionID, secret)
		if err != nil {
			return nil, s.serviceError(ctx, err)
		}
		if res, err := s.Limiter.Take(ctx, ratelimit.DeviceUpdate, d.ID); err == nil && res.Reached {
			return nil, withRequestID(ctx, rateLimited(res, s.now()))
		}
		out, err := s.Devices.Refresh(ctx, d, devices.RefreshInput{
			Token: in.Body.Token, Endpoint: in.Body.Endpoint, APNsEnvironment: in.Body.APNsEnvironment,
		}, s.admitToken(ctx))
		if err != nil {
			return nil, s.serviceError(ctx, err)
		}
		return &struct {
			CacheControl string `header:"Cache-Control"`
			Body         RefreshDeviceResponse
		}{CacheControl: "no-store", Body: RefreshDeviceResponse{SubscriptionID: out.SubscriptionID, ExpiresAt: ts(out.ExpiresAt)}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "deleteDevice",
		Method:      http.MethodDelete,
		Path:        "/v1/devices/{subscription_id}",
		Summary:     "Delete a subscription",
		Description: "Authorized by the subscription secret or by a signature from the instance the subscription is bound " +
			"to. Deleting a gone subscription succeeds; deleting one that no longer exists returns " +
			"subscription_not_found, which callers can treat as success.",
		Tags:          []string{"Devices"},
		Security:      []map[string][]string{{"subscriptionSecret": {}}, {"instanceSignature": {}}},
		DefaultStatus: http.StatusNoContent,
		Metadata:      map[string]any{metaAuth: authManage, metaAuthOptional: true},
	}, func(ctx context.Context, in *subscriptionPath) (*struct{}, error) {
		if p := principalFrom(ctx); p.InstanceID != "" {
			if err := s.Devices.DeleteForInstance(ctx, in.SubscriptionID, p.InstanceID); err != nil {
				return nil, s.serviceError(ctx, err)
			}
			return nil, nil
		}
		secret, p := bearerSecret(in.Authorization)
		if p != nil {
			return nil, withRequestID(ctx, p)
		}
		if err := s.Devices.DeleteWithSecret(ctx, in.SubscriptionID, secret); err != nil {
			return nil, s.serviceError(ctx, err)
		}
		return nil, nil
	})
}

// documentDeviceRegistration replaces the generated request body of registerDevice (a raw
// body, validated by hand) with the contract's oneOf schemas.
func documentDeviceRegistration(api huma.API) {
	oapi := api.OpenAPI()
	ref := func(name string) *huma.Schema { return &huma.Schema{Ref: "#/components/schemas/" + name} }
	anything := func() *huma.Schema { return &huma.Schema{} }
	variant := func(platform string, required []string, props map[string]*huma.Schema) *huma.Schema {
		props["app_id"], props["instance_origin"], props["attestation"] = anything(), anything(), anything()
		props["platform"] = &huma.Schema{Const: platform}
		return &huma.Schema{AllOf: []*huma.Schema{ref("DeviceCommon"), {
			Type: "object", AdditionalProperties: false, Required: required, Properties: props,
		}}}
	}
	schemas := oapi.Components.Schemas.Map()
	schemas["DeviceCommon"] = &huma.Schema{
		Type:     "object",
		Required: []string{"app_id", "instance_origin", "platform"},
		Properties: map[string]*huma.Schema{
			"app_id":          {Type: "string", Pattern: appIDPattern.String()},
			"instance_origin": {Type: "string", Format: "uri", MaxLength: intPtr(253), Description: "The instance origin, https://host[:port]."},
			"attestation":     {Type: "object", AdditionalProperties: true, Description: "Reserved for Phase 8 (App Attest, Play Integrity). Ignored."},
		},
	}
	schemas["RegisterIosDevice"] = variant(devices.IOS, []string{"platform", "token"}, map[string]*huma.Schema{
		"token":            {Type: "string", Pattern: "^[0-9a-fA-F]{64,200}$"},
		"apns_environment": {Type: "string", Enum: []any{devices.APNsProduction, devices.APNsSandbox}, Default: devices.APNsProduction},
	})
	schemas["RegisterAndroidDevice"] = variant(devices.Android, []string{"platform", "token"}, map[string]*huma.Schema{
		"token": {Type: "string", MinLength: intPtr(100), MaxLength: intPtr(4096)},
	})
	schemas["RegisterWebDevice"] = variant(devices.Web, []string{"platform", "endpoint"}, map[string]*huma.Schema{
		"endpoint": {Type: "string", Format: "uri", MaxLength: intPtr(2048)},
	})
	schemas["RegisterDeviceRequest"] = &huma.Schema{
		Description: "One of the three platform shapes.",
		OneOf:       []*huma.Schema{ref("RegisterIosDevice"), ref("RegisterAndroidDevice"), ref("RegisterWebDevice")},
		Discriminator: &huma.Discriminator{PropertyName: "platform", Mapping: map[string]string{
			devices.IOS:     "#/components/schemas/RegisterIosDevice",
			devices.Android: "#/components/schemas/RegisterAndroidDevice",
			devices.Web:     "#/components/schemas/RegisterWebDevice",
		}},
	}
	op := oapi.Paths["/v1/devices"].Post
	op.RequestBody = &huma.RequestBody{Required: true, Content: map[string]*huma.MediaType{
		"application/json": {Schema: ref("RegisterDeviceRequest")},
	}}
}

func intPtr(n int) *int { return &n }

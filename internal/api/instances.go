package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/parkerbrown98/gotalk-gateway/internal/instances"
	"github.com/parkerbrown98/gotalk-gateway/internal/problem"
	"github.com/parkerbrown98/gotalk-gateway/internal/ratelimit"
	"github.com/parkerbrown98/gotalk-gateway/internal/store"
)

type RegisterInstanceRequest struct {
	Origin          string `json:"origin" maxLength:"253" doc:"The instance origin, https://host[:port]. It is normalized before use."`
	PublicKey       string `json:"public_key" pattern:"^[A-Za-z0-9_-]{43}$" doc:"32-byte Ed25519 public key, base64url without padding."`
	ContactEmail    string `json:"contact_email" format:"email" maxLength:"254" doc:"Used only for abuse and key notices."`
	Software        string `json:"software,omitempty" maxLength:"64"`
	SoftwareVersion string `json:"software_version,omitempty" maxLength:"64"`
}

type RegisterInstanceResponse struct {
	InstanceID   string                   `json:"instance_id"`
	KeyID        string                   `json:"key_id"`
	Status       string                   `json:"status" enum:"pending,active,suspended,blocked"`
	Verification RegistrationVerification `json:"verification"`
}

type RegistrationVerification struct {
	WellKnownURL string    `json:"well_known_url" format:"uri" doc:"The document that must list the key."`
	ExpiresAt    time.Time `json:"expires_at" doc:"The registration (or recovery key) is deleted if not verified by then."`
}

type Instance struct {
	InstanceID   string         `json:"instance_id"`
	Origin       string         `json:"origin"`
	Status       string         `json:"status" enum:"pending,active,suspended,blocked"`
	StatusReason *string        `json:"status_reason" required:"false" doc:"Operator-visible reason when blocked or suspended."`
	Keys         []InstanceKey  `json:"keys" nullable:"false"`
	ContactEmail string         `json:"contact_email" required:"false"`
	VerifiedAt   *time.Time     `json:"verified_at" required:"false"`
	CreatedAt    time.Time      `json:"created_at"`
	Usage        *InstanceUsage `json:"usage,omitempty" doc:"Usage for the current UTC day."`
}

type InstanceKey struct {
	KeyID     string    `json:"key_id"`
	PublicKey string    `json:"public_key"`
	Status    string    `json:"status" enum:"pending,active,revoked"`
	CreatedAt time.Time `json:"created_at"`
}

type InstanceUsage struct {
	PushesAccepted      int64 `json:"pushes_accepted"`
	PushesFailed        int64 `json:"pushes_failed"`
	ActiveSubscriptions int64 `json:"active_subscriptions"`
}

type AddKeyRequest struct {
	PublicKey string `json:"public_key" pattern:"^[A-Za-z0-9_-]{43}$" doc:"32-byte Ed25519 public key, base64url without padding."`
}

// instancePath is an input with only the instance ID. huma does not read parameters from
// embedded structs, so inputs that need more fields repeat it.
type instancePath struct {
	InstanceID string `path:"instance_id"`
}

type instanceOutput struct {
	Body Instance
}

func ts(t time.Time) time.Time { return t.UTC().Truncate(time.Second) }

func tsPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := ts(*t)
	return &v
}

func toInstanceKey(k store.InstanceKey) InstanceKey {
	return InstanceKey{KeyID: k.ID, PublicKey: instances.EncodeKey(k.PublicKey), Status: k.Status, CreatedAt: ts(k.CreatedAt)}
}

func toInstance(v *instances.View) Instance {
	out := Instance{
		InstanceID:   v.Instance.ID,
		Origin:       v.Instance.Origin,
		Status:       v.Instance.Status,
		StatusReason: v.StatusReason(),
		Keys:         make([]InstanceKey, 0, len(v.Keys)),
		ContactEmail: v.Instance.ContactEmail,
		VerifiedAt:   tsPtr(v.Instance.VerifiedAt),
		CreatedAt:    ts(v.Instance.CreatedAt),
		Usage: &InstanceUsage{
			PushesAccepted:      v.Usage.PushesAccepted,
			PushesFailed:        v.Usage.PushesFailed,
			ActiveSubscriptions: v.Usage.ActiveSubscriptions,
		},
	}
	for _, k := range v.Keys {
		out.Keys = append(out.Keys, toInstanceKey(k))
	}
	return out
}

// serviceError passes protocol problems through and hides anything else as internal_error.
func (s *Server) serviceError(ctx context.Context, err error) error {
	var p *problem.Problem
	if errors.As(err, &p) {
		return withRequestID(ctx, p)
	}
	s.Logger.ErrorContext(ctx, "unhandled error", "error", err.Error(), "request_id", requestIDFrom(ctx))
	p = problem.New(http.StatusInternalServerError, problem.InternalError, "Unexpected error.")
	p.RequestID = requestIDFrom(ctx)
	return p
}

var signed = []map[string][]string{{"instanceSignature": {}}}

func (s *Server) registerInstances(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:   "registerInstance",
		Method:        http.MethodPost,
		Path:          "/v1/instances",
		Summary:       "Register an instance origin and public key",
		Description:   "Unauthenticated, rate limited per IP. Re-registering a verified origin starts key recovery.",
		Tags:          []string{"Instances"},
		DefaultStatus: http.StatusCreated,
		MaxBodyBytes:  defaultMaxBody,
		Metadata:      map[string]any{metaIPRule: ratelimit.Registration},
	}, func(ctx context.Context, in *struct{ Body RegisterInstanceRequest }) (*struct{ Body RegisterInstanceResponse }, error) {
		reg, err := s.Instances.Register(ctx, instances.RegisterInput{
			Origin: in.Body.Origin, PublicKey: in.Body.PublicKey, ContactEmail: in.Body.ContactEmail,
			Software: in.Body.Software, SoftwareVersion: in.Body.SoftwareVersion,
		})
		if err != nil {
			return nil, s.serviceError(ctx, err)
		}
		return &struct{ Body RegisterInstanceResponse }{Body: RegisterInstanceResponse{
			InstanceID: reg.InstanceID, KeyID: reg.KeyID, Status: reg.Status,
			Verification: RegistrationVerification{WellKnownURL: reg.WellKnownURL, ExpiresAt: ts(reg.ExpiresAt)},
		}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "getInstance",
		Method:      http.MethodGet,
		Path:        "/v1/instances/{instance_id}",
		Summary:     "Instance status, keys and usage",
		Description: "Allowed while the instance is pending or suspended.",
		Tags:        []string{"Instances"},
		Security:    signed,
		Metadata:    map[string]any{metaAuth: authRead},
	}, func(ctx context.Context, _ *instancePath) (*instanceOutput, error) {
		v, err := s.Instances.View(ctx, principalFrom(ctx).InstanceID)
		if err != nil {
			return nil, s.serviceError(ctx, err)
		}
		return &instanceOutput{Body: toInstance(v)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "deleteInstance",
		Method:        http.MethodDelete,
		Path:          "/v1/instances/{instance_id}",
		Summary:       "Deregister the instance and delete all its subscriptions",
		Tags:          []string{"Instances"},
		Security:      signed,
		DefaultStatus: http.StatusNoContent,
		Metadata:      map[string]any{metaAuth: authManage},
	}, func(ctx context.Context, _ *instancePath) (*struct{}, error) {
		p := principalFrom(ctx)
		if err := s.Instances.Delete(ctx, p.InstanceID); err != nil {
			return nil, s.serviceError(ctx, err)
		}
		s.Logger.InfoContext(ctx, "instance deregistered", "instance_id", p.InstanceID, "origin", p.Origin)
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "verifyInstance",
		Method:      http.MethodPost,
		Path:        "/v1/instances/{instance_id}/verify",
		Summary:     "Run domain verification now",
		Description: "Fetches the origin's /.well-known/gotalk-instance and activates advertised pending keys. " +
			"Succeeds when the signing key is active and every active key is advertised.",
		Tags:     []string{"Instances"},
		Security: signed,
		Metadata: map[string]any{metaAuth: authVerify},
	}, func(ctx context.Context, _ *instancePath) (*instanceOutput, error) {
		p := principalFrom(ctx)
		// Per key, not per origin: anyone can register a pending key for any origin, so a
		// per-origin budget would let a squatter exhaust the owner's.
		res, err := s.Limiter.Take(ctx, ratelimit.Verification, p.KeyID)
		if err == nil && res.Reached {
			return nil, withRequestID(ctx, rateLimited(res, s.now()))
		}
		v, err := s.Instances.Verify(ctx, p)
		if err != nil {
			return nil, s.serviceError(ctx, err)
		}
		return &instanceOutput{Body: toInstance(v)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "addInstanceKey",
		Method:        http.MethodPost,
		Path:          "/v1/instances/{instance_id}/keys",
		Summary:       "Add a key for rotation",
		Description:   "The key becomes active once the origin's well-known document advertises it.",
		Tags:          []string{"Instances"},
		Security:      signed,
		DefaultStatus: http.StatusCreated,
		MaxBodyBytes:  defaultMaxBody,
		Metadata:      map[string]any{metaAuth: authManage},
	}, func(ctx context.Context, in *struct {
		InstanceID string `path:"instance_id"`
		Body       AddKeyRequest
	}) (*struct{ Body InstanceKey }, error) {
		k, err := s.Instances.AddKey(ctx, principalFrom(ctx), in.Body.PublicKey)
		if err != nil {
			return nil, s.serviceError(ctx, err)
		}
		return &struct{ Body InstanceKey }{Body: toInstanceKey(*k)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "revokeInstanceKey",
		Method:        http.MethodDelete,
		Path:          "/v1/instances/{instance_id}/keys/{key_id}",
		Summary:       "Revoke a key",
		Description:   "The last active key cannot be revoked; deregister the instance instead.",
		Tags:          []string{"Instances"},
		Security:      signed,
		DefaultStatus: http.StatusNoContent,
		Metadata:      map[string]any{metaAuth: authManage},
	}, func(ctx context.Context, in *struct {
		InstanceID string `path:"instance_id"`
		KeyID      string `path:"key_id"`
	}) (*struct{}, error) {
		if err := s.Instances.RevokeKey(ctx, principalFrom(ctx), in.KeyID); err != nil {
			return nil, s.serviceError(ctx, err)
		}
		return nil, nil
	})
}

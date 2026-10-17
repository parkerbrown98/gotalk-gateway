package api

import (
	"context"
	"net/http"
	"slices"

	"github.com/danielgtaylor/huma/v2"

	"github.com/parkerbrown98/gotalk-gateway/internal/protocol"
)

// Gateway is the discovery document (docs/protocol.md, "Discovery and versioning").
type Gateway struct {
	Software    string        `json:"software" enum:"gotalk-gateway" doc:"Always gotalk-gateway."`
	Name        string        `json:"name" doc:"Display name of this gateway."`
	Version     string        `json:"version" doc:"Software version."`
	APIVersions []string      `json:"api_versions" nullable:"false" doc:"Major API versions served, oldest first."`
	APIBaseURL  string        `json:"api_base_url" format:"uri" doc:"Base URL of the newest API version."`
	Platforms   []string      `json:"platforms" nullable:"false" doc:"Platforms at least one app supports."`
	Apps        []App         `json:"apps" nullable:"false" doc:"The app registry. Devices may only register for listed apps."`
	Limits      GatewayLimits `json:"limits"`
	TermsURL    string        `json:"terms_url,omitempty" format:"uri"`
	PrivacyURL  string        `json:"privacy_url,omitempty" format:"uri"`
}

type App struct {
	ID                  string       `json:"id" pattern:"^[a-z0-9][a-z0-9-]{0,31}$"`
	Name                string       `json:"name"`
	Platforms           AppPlatforms `json:"platforms"`
	AttestationRequired bool         `json:"attestation_required" required:"false" doc:"Reserved for Phase 8."`
}

type AppPlatforms struct {
	IOS     *AppIOS     `json:"ios,omitempty"`
	Android *AppAndroid `json:"android,omitempty"`
	Web     *AppWeb     `json:"web,omitempty"`
}

type AppIOS struct {
	BundleID string `json:"bundle_id"`
}

type AppAndroid struct {
	PackageName string `json:"package_name"`
}

type AppWeb struct {
	VAPIDPublicKey string `json:"vapid_public_key" doc:"Uncompressed P-256 public key, base64url without padding."`
}

type GatewayLimits struct {
	MaxPlaintextBytes      int `json:"max_plaintext_bytes"`
	MaxEncryptedBodyBytes  int `json:"max_encrypted_body_bytes"`
	MaxBatchSize           int `json:"max_batch_size"`
	MaxTTLSeconds          int `json:"max_ttl_seconds"`
	SubscriptionExpiryDays int `json:"subscription_expiry_days" required:"false"`
}

type gatewayOutput struct {
	CacheControl string `header:"Cache-Control"`
	Body         Gateway
}

func (s *Server) registerDiscovery(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "getWellKnownGateway",
		Method:      http.MethodGet,
		Path:        "/.well-known/gotalk-gateway",
		Summary:     "Gateway discovery (alias of GET /v1/gateway)",
		Tags:        []string{"Discovery"},
	}, s.getGateway)
	huma.Register(api, huma.Operation{
		OperationID: "getGateway",
		Method:      http.MethodGet,
		Path:        "/" + protocol.CurrentAPIVersion + "/gateway",
		Summary:     "Gateway discovery",
		Tags:        []string{"Discovery"},
	}, s.getGateway)
}

func (s *Server) getGateway(ctx context.Context, _ *struct{}) (*gatewayOutput, error) {
	list, err := s.Apps.List(ctx)
	if err != nil {
		s.Logger.ErrorContext(ctx, "listing apps for discovery", "error", err.Error(), "request_id", requestIDFrom(ctx))
		p := NewProblem(http.StatusServiceUnavailable, CodeProviderUnavailable, "The app registry is temporarily unavailable.")
		p.RequestID = requestIDFrom(ctx)
		return nil, p
	}

	doc := Gateway{
		Software:    protocol.Software,
		Name:        s.Config.Gateway.Name,
		Version:     s.Version,
		APIVersions: slices.Clone(protocol.APIVersions),
		APIBaseURL:  baseURLFrom(ctx) + "/" + protocol.CurrentAPIVersion,
		Platforms:   []string{},
		Apps:        make([]App, 0, len(list)),
		Limits: GatewayLimits{
			MaxPlaintextBytes:      protocol.MaxPlaintextBytes,
			MaxEncryptedBodyBytes:  protocol.MaxEncryptedBodyBytes,
			MaxBatchSize:           protocol.MaxBatchSize,
			MaxTTLSeconds:          protocol.MaxTTLSeconds,
			SubscriptionExpiryDays: s.Config.Gateway.SubscriptionExpiryDays,
		},
		TermsURL:   s.Config.Gateway.TermsURL,
		PrivacyURL: s.Config.Gateway.PrivacyURL,
	}
	served := map[string]bool{}
	for _, a := range list {
		app := App{ID: a.ID, Name: a.Name, AttestationRequired: a.AttestationRequired}
		if a.IOS != nil {
			app.Platforms.IOS = &AppIOS{BundleID: a.IOS.BundleID}
		}
		if a.Android != nil {
			app.Platforms.Android = &AppAndroid{PackageName: a.Android.PackageName}
		}
		if a.Web != nil {
			app.Platforms.Web = &AppWeb{VAPIDPublicKey: a.Web.VAPIDPublicKey}
		}
		for _, p := range a.Platforms() {
			served[p] = true
		}
		doc.Apps = append(doc.Apps, app)
	}
	for _, p := range protocol.Platforms {
		if served[p] {
			doc.Platforms = append(doc.Platforms, p)
		}
	}
	return &gatewayOutput{CacheControl: protocol.DiscoveryCacheControl, Body: doc}, nil
}

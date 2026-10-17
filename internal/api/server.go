// Package api serves the gateway over HTTP: a chi router hosting the huma-based protocol
// API under /v1, plus discovery, health, readiness and metrics.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"

	"github.com/parkerbrown98/gotalk-gateway/internal/apps"
	"github.com/parkerbrown98/gotalk-gateway/internal/blocklist"
	"github.com/parkerbrown98/gotalk-gateway/internal/config"
	"github.com/parkerbrown98/gotalk-gateway/internal/instances"
	"github.com/parkerbrown98/gotalk-gateway/internal/nonce"
	"github.com/parkerbrown98/gotalk-gateway/internal/problem"
	"github.com/parkerbrown98/gotalk-gateway/internal/protocol"
	"github.com/parkerbrown98/gotalk-gateway/internal/ratelimit"
	"github.com/parkerbrown98/gotalk-gateway/internal/signing"
)

// AppLister returns the apps listed in discovery.
type AppLister interface {
	List(ctx context.Context) ([]apps.App, error)
}

// Check is a dependency probed by /readyz.
type Check struct {
	Name string
	Ping func(context.Context) error
}

type Deps struct {
	Config  *config.Config
	Logger  *slog.Logger
	Version string
	Apps    AppLister
	// Checks must all pass for the gateway to report ready.
	Checks    []Check
	Metrics   *Metrics
	Instances *instances.Service
	// Nonces defaults to an in-memory store, Limiter to no limits and Blocklist to empty.
	Nonces    nonce.Store
	Limiter   *ratelimit.Limiter
	Blocklist *blocklist.Cache
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Server is the gateway's HTTP handler.
type Server struct {
	Deps
	api      huma.API
	proxies  []netip.Prefix
	handler  http.Handler
	draining atomic.Bool
}

func New(d Deps) *Server {
	if d.Nonces == nil {
		d.Nonces = nonce.NewMemory()
	}
	if d.Limiter == nil {
		d.Limiter, _ = ratelimit.New(nil, nil)
	}
	if d.Blocklist == nil {
		d.Blocklist = blocklist.NewCache(nil, d.Logger)
	}
	s := &Server{Deps: d, proxies: d.Config.Server.TrustedProxyPrefixes()}

	r := chi.NewRouter()
	r.Use(s.requestMeta)
	r.Use(s.observe)
	r.Use(s.recoverer)
	r.Use(securityHeaders)
	// The gateway uses no cookies or ambient credentials, so any origin may call it; browsers
	// need this for discovery and device registration.
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
		ExposedHeaders: []string{"Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", RequestIDHeader},
		MaxAge:         300,
	}))
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		writeProblem(r.Context(), w, problem.New(http.StatusNotFound, problem.NotFound, "No such endpoint."))
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeProblem(r.Context(), w, problem.New(http.StatusMethodNotAllowed, problem.MethodNotAllowed, "Method not allowed for this endpoint."))
	})

	r.Get("/healthz", s.handleHealthz)
	r.Get("/readyz", s.handleReadyz)
	if d.Config.Metrics.Enabled && d.Config.Metrics.Addr == "" {
		r.Handle("/metrics", d.Metrics.Handler())
	}

	s.api = s.newAPI(r, d.Version)
	s.handler = r
	return s
}

func (s *Server) newAPI(r chi.Router, version string) huma.API {
	cfg := huma.DefaultConfig("Gotalk Push Gateway API", version)
	cfg.Info.Description = "Push notification gateway for Gotalk instances and clients. The protocol is " +
		"specified in docs/protocol.md; docs/openapi.yaml is the full contract."
	cfg.Info.License = &huma.License{Name: "AGPL-3.0-only", Identifier: "AGPL-3.0-only"}
	cfg.OpenAPIPath = "/" + protocol.CurrentAPIVersion + "/openapi"
	cfg.DocsPath = ""
	cfg.SchemasPath = ""
	// Drop the default $schema link transformer to keep response bodies to the protocol.
	cfg.CreateHooks = nil
	cfg.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		"instanceSignature": {
			Type: "apiKey", In: "header", Name: signing.HeaderSignature,
			Description: "Ed25519 request signature. Also send Gotalk-Key-Id, Gotalk-Timestamp, Gotalk-Nonce and, " +
				"with a body, Content-Digest. The signing string is defined in docs/protocol.md#request-signing.",
		},
	}
	api := humachi.New(r, cfg)
	api.UseMiddleware(s.requireJSON, s.unsignedRules, s.signedRequests)
	s.registerDiscovery(api)
	s.registerInstances(api)
	return api
}

// OpenAPI returns the specification of the endpoints this build implements.
func OpenAPI(version string) *huma.OpenAPI {
	s := &Server{Deps: Deps{Config: &config.Config{}}}
	return s.newAPI(chi.NewRouter(), version).OpenAPI()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

// SetDraining makes /readyz fail so load balancers stop routing new requests here while
// in-flight ones finish.
func (s *Server) SetDraining() { s.draining.Store(true) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

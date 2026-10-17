package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/parkerbrown98/gotalk-gateway/internal/apps"
	"github.com/parkerbrown98/gotalk-gateway/internal/config"
)

const testVAPIDKey = "BExMJ__m8K0lZhFzYG_SNZhoRmRL6BbVOMd25fGlwCN2uGyylC_WegHE-InIhLxpzs3kl6KqUfAS6lMIoFdne2Y"

type fakeApps struct {
	list []apps.App
	err  error
}

func (f *fakeApps) List(context.Context) ([]apps.App, error) { return f.list, f.err }

type harness struct {
	t    *testing.T
	srv  *Server
	apps *fakeApps
}

func newHarness(t *testing.T, mutate func(*config.Config, *Deps)) *harness {
	t.Helper()
	cfg, err := config.Load("", nil)
	require.NoError(t, err)
	fa := &fakeApps{list: []apps.App{
		{ID: "gotalk", Name: "Gotalk", IOS: &apps.IOS{BundleID: "app.example.gotalk"},
			Android: &apps.Android{PackageName: "app.example.gotalk"}, Web: &apps.Web{VAPIDPublicKey: testVAPIDKey}},
		{ID: "droid", Name: "Droid", Android: &apps.Android{PackageName: "com.example.droid"}},
	}}
	d := Deps{
		Config: cfg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "1.2.3",
		Apps: fa, Metrics: NewMetrics("1.2.3"),
		Checks: []Check{{Name: "database", Ping: func(context.Context) error { return nil }}, {Name: "redis"}},
	}
	if mutate != nil {
		mutate(cfg, &d)
	}
	return &harness{t: t, srv: New(d), apps: fa}
}

func (h *harness) do(method, target string, header http.Header) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest(method, target, nil)
	req.RemoteAddr = "203.0.113.7:51000"
	for k, v := range header {
		req.Header[k] = v
	}
	rec := httptest.NewRecorder()
	h.srv.ServeHTTP(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &v), rec.Body.String())
	return v
}

func TestHealthz(t *testing.T) {
	h := newHarness(t, nil)
	rec := h.do("GET", "/healthz", nil)
	assert.Equal(t, 200, rec.Code)
	assert.Equal(t, "ok", decode[map[string]string](t, rec)["status"])
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
}

func TestReadyz(t *testing.T) {
	var dbErr error
	h := newHarness(t, func(_ *config.Config, d *Deps) {
		d.Checks[0].Ping = func(context.Context) error { return dbErr }
	})

	rec := h.do("GET", "/readyz", nil)
	assert.Equal(t, 200, rec.Code)
	body := decode[map[string]any](t, rec)
	assert.Equal(t, "ready", body["status"])
	assert.Equal(t, map[string]any{"database": "ok", "redis": "not_configured"}, body["checks"])

	dbErr = errors.New("dial tcp 10.0.0.5:5432: connection refused")
	rec = h.do("GET", "/readyz", nil)
	assert.Equal(t, 503, rec.Code)
	assert.NotContains(t, rec.Body.String(), "10.0.0.5", "internal error details must not leak")
	assert.Equal(t, "error", decode[map[string]any](t, rec)["checks"].(map[string]any)["database"])

	dbErr = nil
	h.srv.SetDraining()
	rec = h.do("GET", "/readyz", nil)
	assert.Equal(t, 503, rec.Code)
	assert.Equal(t, "draining", decode[map[string]any](t, rec)["status"])
	assert.Equal(t, 200, h.do("GET", "/healthz", nil).Code, "liveness is unaffected by draining")
}

func TestDiscovery(t *testing.T) {
	h := newHarness(t, func(c *config.Config, _ *Deps) {
		c.Gateway.Name = "Test Gateway"
		c.Gateway.TermsURL = "https://push.example/terms"
	})

	wk := h.do("GET", "/.well-known/gotalk-gateway", http.Header{"Host": {"push.example"}})
	require.Equal(t, 200, wk.Code, wk.Body.String())
	assert.Equal(t, "public, max-age=300", wk.Header().Get("Cache-Control"))
	assert.Equal(t, "*", h.do("GET", "/v1/gateway", http.Header{"Origin": {"https://app.example"}}).Header().Get("Access-Control-Allow-Origin"))

	doc := decode[map[string]any](t, wk)
	assert.Equal(t, "gotalk-gateway", doc["software"])
	assert.Equal(t, "Test Gateway", doc["name"])
	assert.Equal(t, "1.2.3", doc["version"])
	assert.Equal(t, []any{"v1"}, doc["api_versions"])
	assert.Equal(t, "http://example.com/v1", doc["api_base_url"], "derived from the request when public_url is unset")
	assert.Equal(t, []any{"ios", "android", "web"}, doc["platforms"])
	assert.Equal(t, "https://push.example/terms", doc["terms_url"])
	assert.NotContains(t, doc, "privacy_url")
	assert.Equal(t, map[string]any{
		"max_plaintext_bytes": 2048.0, "max_encrypted_body_bytes": 2200.0, "max_batch_size": 100.0,
		"max_ttl_seconds": 2419200.0, "subscription_expiry_days": 60.0,
	}, doc["limits"])
	assert.Equal(t, []any{
		map[string]any{"id": "gotalk", "name": "Gotalk", "attestation_required": false, "platforms": map[string]any{
			"ios":     map[string]any{"bundle_id": "app.example.gotalk"},
			"android": map[string]any{"package_name": "app.example.gotalk"},
			"web":     map[string]any{"vapid_public_key": testVAPIDKey},
		}},
		map[string]any{"id": "droid", "name": "Droid", "attestation_required": false, "platforms": map[string]any{
			"android": map[string]any{"package_name": "com.example.droid"},
		}},
	}, doc["apps"])

	v1 := h.do("GET", "/v1/gateway", nil)
	require.Equal(t, 200, v1.Code)
	assert.JSONEq(t, wk.Body.String(), v1.Body.String(), "both discovery paths return the same document")
}

func TestDiscoveryWithoutApps(t *testing.T) {
	h := newHarness(t, nil)
	h.apps.list = nil
	doc := decode[map[string]any](t, h.do("GET", "/v1/gateway", nil))
	assert.Equal(t, []any{}, doc["apps"])
	assert.Equal(t, []any{}, doc["platforms"])
}

func TestDiscoveryRegistryUnavailable(t *testing.T) {
	h := newHarness(t, nil)
	h.apps.err = errors.New("connection refused")
	rec := h.do("GET", "/v1/gateway", nil)
	assert.Equal(t, 503, rec.Code)
	assert.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
	p := decode[Problem](t, rec)
	assert.Equal(t, CodeProviderUnavailable, p.Code)
	assert.Equal(t, rec.Header().Get(RequestIDHeader), p.RequestID)
	assert.NotContains(t, rec.Body.String(), "connection refused")
}

func TestPublicURLAndTrustedProxy(t *testing.T) {
	h := newHarness(t, func(c *config.Config, _ *Deps) { c.Server.PublicURL = "https://push.example" })
	rec := h.do("GET", "/v1/gateway", http.Header{"X-Forwarded-Host": {"attacker.example"}})
	doc := decode[map[string]any](t, rec)
	assert.Equal(t, "https://push.example/v1", doc["api_base_url"])
	assert.NotContains(t, rec.Header().Values("Vary"), "Host, X-Forwarded-Host, X-Forwarded-Proto",
		"a configured public URL does not depend on the request")

	h = newHarness(t, func(c *config.Config, _ *Deps) {
		c.Server.TrustProxy = true
		c.Server.TrustedProxies = []string{"203.0.113.0/24"}
	})
	fwd := http.Header{"X-Forwarded-Proto": {"https"}, "X-Forwarded-Host": {"Push.Example"}}
	rec = h.do("GET", "/v1/gateway", fwd)
	doc = decode[map[string]any](t, rec)
	assert.Equal(t, "https://push.example/v1", doc["api_base_url"])
	assert.Contains(t, rec.Header().Values("Vary"), "Host, X-Forwarded-Host, X-Forwarded-Proto",
		"a derived base URL must not be shared across requests by caches")
	assert.Contains(t, rec.Header().Values("Vary"), "Origin", "CORS Vary is preserved")

	h = newHarness(t, func(c *config.Config, _ *Deps) { c.Server.TrustProxy = true })
	doc = decode[map[string]any](t, h.do("GET", "/v1/gateway", fwd))
	assert.Equal(t, "http://example.com/v1", doc["api_base_url"], "headers from an untrusted peer are ignored")
}

func TestClientIP(t *testing.T) {
	h := newHarness(t, func(c *config.Config, _ *Deps) {
		c.Server.TrustProxy = true
		c.Server.TrustedProxies = []string{"203.0.113.0/24", "10.0.0.0/8"}
	})
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.7:1"
	req.Header.Set("X-Forwarded-For", "198.51.100.66, 192.0.2.1, 10.1.2.3")
	ip, via := h.srv.clientIP(req)
	assert.True(t, via)
	assert.Equal(t, "192.0.2.1", ip, "right-most untrusted hop; spoofed left entries are ignored")
}

func TestProblems(t *testing.T) {
	h := newHarness(t, nil)

	rec := h.do("GET", "/v1/nope", nil)
	assert.Equal(t, 404, rec.Code)
	assert.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
	p := decode[Problem](t, rec)
	assert.Equal(t, CodeNotFound, p.Code)
	assert.Equal(t, "https://gotalk.app/problems/not-found", p.Type)
	assert.Equal(t, 404, p.Status)
	assert.True(t, strings.HasPrefix(p.RequestID, "req_"))
	assert.Equal(t, rec.Header().Get(RequestIDHeader), p.RequestID)

	rec = h.do("POST", "/v1/gateway", nil)
	assert.Equal(t, 405, rec.Code)
	assert.Equal(t, CodeMethodNotAllowed, decode[Problem](t, rec).Code)
}

func TestRequestIDIsNotTakenFromClient(t *testing.T) {
	h := newHarness(t, nil)
	rec := h.do("GET", "/healthz", http.Header{RequestIDHeader: {"forged"}})
	assert.True(t, strings.HasPrefix(rec.Header().Get(RequestIDHeader), "req_"))
}

func TestPanicBecomesProblem(t *testing.T) {
	h := newHarness(t, func(_ *config.Config, d *Deps) {
		d.Checks = []Check{{Name: "boom", Ping: func(context.Context) error { panic("boom") }}}
	})
	rec := h.do("GET", "/readyz", nil)
	assert.Equal(t, 500, rec.Code)
	assert.Equal(t, CodeInternalError, decode[Problem](t, rec).Code)
}

func TestMetrics(t *testing.T) {
	h := newHarness(t, nil)
	h.do("GET", "/v1/gateway", nil)
	h.do("BREW", "/v1/gateway", nil)
	rec := h.do("GET", "/metrics", nil)
	require.Equal(t, 200, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, `gotalk_gateway_http_requests_total{method="GET",route="/v1/gateway",status="200"} 1`)
	assert.Contains(t, body, `method="OTHER"`)
	assert.Contains(t, body, `gotalk_gateway_build_info{goversion=`)
	assert.Contains(t, body, "go_goroutines")

	h = newHarness(t, func(c *config.Config, _ *Deps) { c.Metrics.Addr = ":9090" })
	assert.Equal(t, 404, h.do("GET", "/metrics", nil).Code, "served on its own listener instead")

	h = newHarness(t, func(c *config.Config, _ *Deps) { c.Metrics.Enabled = false })
	assert.Equal(t, 404, h.do("GET", "/metrics", nil).Code)
}

func TestOpenAPIServed(t *testing.T) {
	h := newHarness(t, nil)
	rec := h.do("GET", "/v1/openapi.json", nil)
	require.Equal(t, 200, rec.Code)
	assert.Contains(t, rec.Body.String(), `"getGateway"`)
}

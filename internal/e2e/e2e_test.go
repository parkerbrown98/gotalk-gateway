//go:build e2e

// Package e2e drives a running gateway through instance registration, domain verification,
// signed requests, key rotation, recovery and deregistration. The test plays the instance:
// it serves the well-known document the gateway verifies against. Start the stack with
// docker-compose.e2e.yml and run `make e2e`.
package e2e

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/parkerbrown98/gotalk-gateway/internal/signing"
)

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

var (
	gateway = env("E2E_GATEWAY_URL", "http://localhost:8090")
	// origin is how the gateway reaches the well-known server below.
	origin     = env("E2E_ORIGIN", "http://host.docker.internal:18080")
	listenAddr = env("E2E_LISTEN", ":18080")
)

// wellKnown serves the stand-in instance's /.well-known/gotalk-instance.
type wellKnown struct {
	mu  sync.Mutex
	doc []byte
}

func (w *wellKnown) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/.well-known/gotalk-instance" {
		http.NotFound(rw, r)
		return
	}
	w.mu.Lock()
	doc := w.doc
	w.mu.Unlock()
	rw.Header().Set("Content-Type", "application/json")
	_, _ = rw.Write(doc)
}

var site = &wellKnown{doc: []byte(`{"software":"gotalk","push":{"keys":[]}}`)}

func TestMain(m *testing.M) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listening for the stand-in instance:", err)
		os.Exit(1)
	}
	srv := &http.Server{Handler: site, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	code := m.Run()
	_ = srv.Close()
	os.Exit(code)
}

type key struct {
	id   string
	priv ed25519.PrivateKey
}

func newKey(t *testing.T) *key {
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return &key{priv: priv}
}

func (k *key) pub() string {
	return base64.RawURLEncoding.EncodeToString(k.priv.Public().(ed25519.PublicKey))
}

// publish sets the keys the origin's well-known document lists.
func publish(t *testing.T, keys ...*key) {
	t.Helper()
	list := []map[string]string{}
	for _, k := range keys {
		list = append(list, map[string]string{"alg": "Ed25519", "public_key": k.pub()})
	}
	doc, err := json.Marshal(map[string]any{"software": "gotalk", "instance_url": origin, "push": map[string]any{"keys": list}})
	require.NoError(t, err)
	site.mu.Lock()
	site.doc = doc
	site.mu.Unlock()
}

type result struct {
	status int
	header http.Header
	body   map[string]any
}

func do(t *testing.T, method, path string, body any, k *key, mutate ...func(*http.Request)) result {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req, err := http.NewRequest(method, gateway+path, bytes.NewReader(raw))
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if k != nil {
		signing.SignHTTP(req, raw, k.id, k.priv, time.Now())
	}
	for _, m := range mutate {
		m(req)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	out := result{status: resp.StatusCode, header: resp.Header}
	if len(data) > 0 {
		require.NoError(t, json.Unmarshal(data, &out.body), string(data))
	}
	return out
}

func expect(t *testing.T, r result, status int, code string) result {
	t.Helper()
	require.Equal(t, status, r.status, fmt.Sprint(r.body))
	if code != "" {
		assert.Equal(t, code, r.body["code"], fmt.Sprint(r.body))
	}
	return r
}

func TestInstanceFlow(t *testing.T) {
	k1 := newKey(t)
	publish(t)

	reg := expect(t, do(t, "POST", "/v1/instances", map[string]any{
		"origin": origin, "public_key": k1.pub(), "contact_email": "ops@instance.example", "software": "gotalk",
	}, nil), 201, "")
	id := reg.body["instance_id"].(string)
	k1.id = reg.body["key_id"].(string)
	assert.NotEmpty(t, reg.header.Get("X-RateLimit-Limit"))
	base := "/v1/instances/" + id

	expect(t, do(t, "POST", base+"/verify", nil, k1), 422, "verification_failed")
	publish(t, k1)
	inst := expect(t, do(t, "POST", base+"/verify", nil, k1), 200, "")
	assert.Equal(t, "active", inst.body["status"])

	// Replay, clock skew and tampering are rejected by the running binary.
	var captured http.Header
	expect(t, do(t, "GET", base, nil, k1, func(r *http.Request) { captured = r.Header.Clone() }), 200, "")
	expect(t, do(t, "GET", base, nil, nil, func(r *http.Request) { r.Header = captured }), 401, "replayed_nonce")
	stale := func(r *http.Request) {
		r.Header = http.Header{}
		signing.SignHTTP(r, nil, k1.id, k1.priv, time.Now().Add(-10*time.Minute))
	}
	expect(t, do(t, "GET", base, nil, nil, stale), 401, "stale_timestamp")
	expect(t, do(t, "GET", base, nil, k1, func(r *http.Request) { r.URL.RawQuery = "x=1" }), 401, "invalid_signature")

	// Rotation without downtime.
	k2 := newKey(t)
	added := expect(t, do(t, "POST", base+"/keys", map[string]any{"public_key": k2.pub()}, k1), 201, "")
	k2.id = added.body["key_id"].(string)
	publish(t, k1, k2)
	expect(t, do(t, "POST", base+"/verify", nil, k2), 200, "")
	expect(t, do(t, "DELETE", base+"/keys/"+k1.id, nil, k2), 204, "")
	publish(t, k2)
	expect(t, do(t, "GET", base, nil, k1), 401, "unknown_key")

	// Recovery with a fresh key revokes the old one.
	k3 := newKey(t)
	rec := expect(t, do(t, "POST", "/v1/instances", map[string]any{
		"origin": origin, "public_key": k3.pub(), "contact_email": "ops@instance.example",
	}, nil), 201, "")
	assert.Equal(t, id, rec.body["instance_id"])
	k3.id = rec.body["key_id"].(string)
	publish(t, k3)
	expect(t, do(t, "POST", base+"/verify", nil, k3), 200, "")
	expect(t, do(t, "GET", base, nil, k2), 401, "unknown_key")

	expect(t, do(t, "DELETE", base, nil, k3), 204, "")
	expect(t, do(t, "GET", base, nil, k3), 401, "unknown_key")
}

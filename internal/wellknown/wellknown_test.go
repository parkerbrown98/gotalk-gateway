package wellknown

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const key1 = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"

func tlsServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *Fetcher, string) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	f := New(Options{
		AllowPrivateNetworks: true,
		AllowedPorts:         []int{port},
		Timeout:              time.Second,
		TLSConfig:            srv.Client().Transport.(*http.Transport).TLSClientConfig,
	})
	return srv, f, srv.URL
}

func TestKeys(t *testing.T) {
	_, f, origin := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, Path, r.URL.Path)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"software":"gotalk","push":{"keys":[
			{"alg":"Ed25519","public_key":"` + key1 + `"},
			{"alg":"RSA","public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbX"},
			{"alg":"Ed25519","public_key":"short"}]}}`))
	})
	keys, err := f.Keys(context.Background(), origin)
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{key1: true}, keys, "only well-formed Ed25519 keys count")
}

func TestKeysFailures(t *testing.T) {
	cases := map[string]struct {
		handler http.HandlerFunc
		reason  string
	}{
		"redirect": {func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
		}, "redirects are not followed"},
		"status": {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) }, "HTTP 404"},
		"content type": {func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`{"push":{"keys":[]}}`))
		}, "Content-Type"},
		"too large": {func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"pad":"` + strings.Repeat("x", MaxBytes) + `"}`))
		}, "larger than 64 KiB"},
		"not json": {func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`nope`))
		}, "not valid JSON"},
		"no push": {func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"software":"gotalk"}`))
		}, `no "push" object`},
		"timeout": {func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-time.After(3 * time.Second):
			case <-r.Context().Done():
			}
		}, "timed out"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, f, origin := tlsServer(t, tc.handler)
			_, err := f.Keys(context.Background(), origin)
			var ve *Error
			require.ErrorAs(t, err, &ve)
			assert.Contains(t, ve.Reason, tc.reason)
			assert.Contains(t, ve.Reason, origin+Path)
		})
	}
}

func TestPrivateAddressesAreRefused(t *testing.T) {
	srv, _, _ := tlsServer(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the private server must not be reached")
	})
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	f := New(Options{AllowedPorts: []int{port}, Timeout: time.Second})

	for _, origin := range []string{
		"https://127.0.0.1:" + u.Port(),
		"https://localhost:" + u.Port(), // the check runs on the resolved address
	} {
		_, err := f.Keys(context.Background(), origin)
		var ve *Error
		require.ErrorAs(t, err, &ve, origin)
		assert.Contains(t, ve.Reason, "is not a public address", origin)
	}
}

func TestPortRules(t *testing.T) {
	f := New(Options{AllowedPorts: []int{8443}})
	for raw, ok := range map[string]bool{
		"https://forum.example":      true,
		"https://forum.example:443":  true,
		"https://forum.example:8443": true,
		"https://forum.example:22":   false,
		"http://forum.example:80":    true,
		"http://forum.example:443":   false,
	} {
		u, _ := url.Parse(raw)
		assert.Equal(t, ok, f.CheckOrigin(u) == nil, raw)
	}
	_, err := f.Keys(context.Background(), "https://forum.example:22")
	assert.ErrorContains(t, err, "port 22 is not allowed")

	assert.Error(t, f.checkConnect("tcp", "93.184.216.34:6379", nil), "connect-time port check")
	assert.NoError(t, f.checkConnect("tcp", "93.184.216.34:8443", nil))
}

func TestIsPublic(t *testing.T) {
	for addr, want := range map[string]bool{
		"93.184.216.34": true, "2606:2800:220:1:248:1893:25c8:1946": true,
		"127.0.0.1": false, "10.1.2.3": false, "172.16.0.1": false, "192.168.1.1": false,
		"169.254.169.254": false, "100.64.0.1": false, "0.0.0.0": false, "224.0.0.1": false,
		"255.255.255.255": false, "198.18.0.1": false, "::1": false, "fe80::1": false, "fc00::1": false,
		"::ffff:10.0.0.1": false, "64:ff9b::a00:1": false, "2002:a00:1::": false, "2001:db8::1": false,
	} {
		assert.Equal(t, want, IsPublic(netip.MustParseAddr(addr)), addr)
	}
}

func TestConcurrencyCap(t *testing.T) {
	release := make(chan struct{})
	_, f, origin := tlsServer(t, func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"push":{"keys":[]}}`))
	})
	f.sem = make(chan struct{}, 1)
	done := make(chan struct{})
	go func() { _, _ = f.Keys(context.Background(), origin); close(done) }()
	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := f.Keys(ctx, origin)
	assert.ErrorContains(t, err, "busy")
	close(release)
	<-done
}

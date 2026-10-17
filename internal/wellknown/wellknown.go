// Package wellknown fetches an instance origin's /.well-known/gotalk-instance document for
// domain verification. Fetches follow the protocol's SSRF rules: HTTPS only (unless
// development mode allows HTTP), public addresses only (checked on every connection, after
// DNS resolution), allowed ports only, no redirects and no proxies, a 5 second timeout and
// a 64 KiB response limit. A global semaphore caps concurrent fetches.
package wellknown

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Path is the instance discovery document path.
const Path = "/.well-known/gotalk-instance"

const (
	DefaultTimeout       = 5 * time.Second
	MaxBytes             = 64 << 10
	DefaultMaxConcurrent = 16
)

type Options struct {
	// AllowPrivateNetworks permits loopback, private and other non-public addresses.
	AllowPrivateNetworks bool
	// AllowedPorts lists ports allowed besides the scheme's default.
	AllowedPorts []int
	// Timeout bounds the whole fetch; DefaultTimeout when zero.
	Timeout time.Duration
	// MaxConcurrent caps simultaneous fetches; DefaultMaxConcurrent when zero.
	MaxConcurrent int
	// TLSConfig overrides the TLS client configuration (tests).
	TLSConfig *tls.Config
	UserAgent string
}

// Error is a verification failure to report to the instance. Its message never contains
// gateway-internal details.
type Error struct {
	Reason string
}

func (e *Error) Error() string { return e.Reason }

type Fetcher struct {
	opts   Options
	client *http.Client
	sem    chan struct{}
}

func New(opts Options) *Fetcher {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.MaxConcurrent <= 0 {
		opts.MaxConcurrent = DefaultMaxConcurrent
	}
	f := &Fetcher{opts: opts, sem: make(chan struct{}, opts.MaxConcurrent)}
	dialer := &net.Dialer{Timeout: opts.Timeout, Control: f.checkConnect}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		TLSClientConfig:        opts.TLSConfig,
		TLSHandshakeTimeout:    opts.Timeout,
		ResponseHeaderTimeout:  opts.Timeout,
		MaxResponseHeaderBytes: 16 << 10,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      true,
	}
	f.client = &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return f
}

// URL returns the well-known document URL of origin.
func URL(origin string) string { return origin + Path }

// Keys fetches origin's document and returns the Ed25519 public keys it advertises, as
// unpadded base64url strings.
func (f *Fetcher) Keys(ctx context.Context, origin string) (map[string]bool, error) {
	target := URL(origin)
	fail := func(format string, args ...any) (map[string]bool, error) {
		return nil, &Error{Reason: "fetching " + target + ": " + fmt.Sprintf(format, args...)}
	}
	u, err := url.Parse(target)
	if err != nil {
		return fail("invalid origin")
	}
	if err := f.CheckOrigin(u); err != nil {
		return fail("%v", err)
	}

	select {
	case f.sem <- struct{}{}:
		defer func() { <-f.sem }()
	case <-ctx.Done():
		return fail("gateway is busy, retry later")
	}

	ctx, cancel := context.WithTimeout(ctx, f.opts.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return fail("invalid origin")
	}
	req.Header.Set("Accept", "application/json")
	if f.opts.UserAgent != "" {
		req.Header.Set("User-Agent", f.opts.UserAgent)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		var be *blockedError
		if errors.As(err, &be) {
			return fail("%v", be)
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fail("timed out after %s", f.opts.Timeout)
		}
		return fail("request failed (%s)", describeNetError(err))
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return fail("HTTP %d: redirects are not followed", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return fail("HTTP %d", resp.StatusCode)
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return fail("Content-Type must be application/json")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBytes+1))
	if err != nil {
		return fail("reading response failed")
	}
	if len(body) > MaxBytes {
		return fail("response is larger than %d KiB", MaxBytes>>10)
	}

	var doc struct {
		Push *struct {
			Keys []struct {
				Alg       string `json:"alg"`
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"push"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fail("response is not valid JSON")
	}
	if doc.Push == nil {
		return fail(`document has no "push" object`)
	}
	keys := map[string]bool{}
	for _, k := range doc.Push.Keys {
		raw, err := base64.RawURLEncoding.DecodeString(k.PublicKey)
		if strings.EqualFold(k.Alg, "Ed25519") && err == nil && len(raw) == ed25519.PublicKeySize {
			keys[k.PublicKey] = true
		}
	}
	return keys, nil
}

// CheckOrigin applies the scheme and port rules to an origin or document URL.
func (f *Fetcher) CheckOrigin(u *url.URL) error {
	port := u.Port()
	if port == "" {
		return nil
	}
	n, err := strconv.Atoi(port)
	if err != nil || !f.portAllowed(u.Scheme, n) {
		return fmt.Errorf("port %s is not allowed by this gateway", port)
	}
	return nil
}

func (f *Fetcher) portAllowed(scheme string, port int) bool {
	if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
		return true
	}
	return slices.Contains(f.opts.AllowedPorts, port)
}

type blockedError struct{ msg string }

func (e *blockedError) Error() string { return e.msg }

// checkConnect runs for every connection attempt with the resolved address, so DNS answers
// pointing at internal addresses (including rebinding between lookups) are refused.
func (f *Fetcher) checkConnect(_, address string, _ syscall.RawConn) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return &blockedError{"invalid address"}
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return &blockedError{"invalid address"}
	}
	if !f.opts.AllowPrivateNetworks && !IsPublic(addr) {
		return &blockedError{fmt.Sprintf("address %s is not a public address", addr.Unmap())}
	}
	if p, err := strconv.Atoi(port); err != nil || (p != 443 && p != 80 && !slices.Contains(f.opts.AllowedPorts, p)) {
		return &blockedError{"port " + port + " is not allowed by this gateway"}
	}
	return nil
}

// nonPublic lists special-purpose ranges that are not reachable public unicast addresses
// beyond what netip's predicates cover (RFC 6890 and the IANA special-purpose registries).
var nonPublic = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
		"64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/32", "2001:2::/48", "2001:db8::/32",
		"2002::/16", "3fff::/20",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// IsPublic reports whether addr is a globally routable unicast address.
func IsPublic(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

func describeNetError(err error) string {
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr):
		return "DNS lookup failed"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case strings.Contains(err.Error(), "tls:") || strings.Contains(err.Error(), "x509:"):
		return "TLS handshake failed"
	default:
		return "network error"
	}
}

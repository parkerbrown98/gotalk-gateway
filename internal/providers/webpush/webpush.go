// Package webpush delivers pushes to browsers through their push services (RFC 8030),
// authenticated with VAPID (RFC 8292). The body is the instance's RFC 8291 (aes128gcm)
// ciphertext, forwarded byte for byte; docs/payload.md defines the request.
//
// Endpoints come from browsers, so every delivery is treated as a request to an untrusted
// URL: the endpoint is checked against the gateway's policy again, connections go only to
// public addresses on port 443, and redirects and proxies are never followed.
package webpush

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/parkerbrown98/gotalk-gateway/internal/providers"
	"github.com/parkerbrown98/gotalk-gateway/internal/wellknown"
)

const (
	// tokenLifetime is the exp of a VAPID token. Push services refuse tokens that expire
	// more than 24 hours ahead.
	tokenLifetime = 12 * time.Hour
	// tokenRenewal is how long before it expires a cached token is replaced, so a token is
	// never sent with less than this left (clock skew, queued requests).
	tokenRenewal = time.Hour
	// maxCachedTokens bounds the per-audience token cache. Real deployments talk to a
	// handful of push services; without an allowlist, endpoints could name many more.
	maxCachedTokens = 256
)

// Config is one app's VAPID identity and delivery policy.
type Config struct {
	// PublicKey is the app's VAPID public key as discovery publishes it: an uncompressed
	// P-256 point in base64url without padding. Browsers subscribed with it.
	PublicKey string
	// PrivateKey is the matching private key: the 32-byte scalar in base64url, or PEM
	// (PKCS #8 or SEC 1).
	PrivateKey []byte
	// Subject is the VAPID sub claim, a mailto: or https: contact URL.
	Subject string
	// CheckEndpoint re-validates an endpoint before each delivery (devices.WebPushPolicy).
	CheckEndpoint func(endpoint string) error
	// Insecure lets connections go to any address and port. Development only.
	Insecure bool
	// HTTPClient overrides the guarded, pooled client (tests).
	HTTPClient *http.Client
	Now        func() time.Time
}

// Client sends Web Push messages for one app. It is safe for concurrent use.
type Client struct {
	publicKey string
	subject   string
	key       *ecdsa.PrivateKey
	check     func(string) error
	http      *http.Client
	now       func() time.Time

	mu     sync.Mutex
	tokens map[string]vapidToken
}

type vapidToken struct {
	value string
	exp   time.Time
}

// ParsePrivateKey reads a VAPID private key: the raw 32-byte P-256 scalar in base64url (as
// web-push tools print it) or a PEM PKCS #8 or SEC 1 key.
func ParsePrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	s := strings.TrimSpace(string(data))
	if strings.HasPrefix(s, "-----BEGIN") {
		block, _ := pem.Decode([]byte(s))
		if block == nil {
			return nil, errors.New("is not valid PEM")
		}
		var k any
		var err error
		if block.Type == "EC PRIVATE KEY" {
			k, err = x509.ParseECPrivateKey(block.Bytes)
		} else {
			k, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		}
		if err != nil {
			return nil, fmt.Errorf("is not a PKCS #8 or SEC 1 private key: %w", err)
		}
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok || ec.Curve != elliptic.P256() {
			return nil, errors.New("is not a P-256 key")
		}
		return ec, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil || len(raw) != 32 {
		return nil, errors.New("must be the 32-byte P-256 private key in base64url, or a PEM key")
	}
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		return nil, errors.New("is not a valid P-256 private key")
	}
	return k, nil
}

// PublicKeyOf returns the base64url uncompressed public key of k, the form discovery uses.
func PublicKeyOf(k *ecdsa.PrivateKey) (string, error) {
	raw, err := k.PublicKey.Bytes()
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func New(cfg Config) (*Client, error) {
	key, err := ParsePrivateKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("VAPID private key %w", err)
	}
	pub, err := PublicKeyOf(key)
	if err != nil {
		return nil, fmt.Errorf("VAPID private key: %w", err)
	}
	if pub != cfg.PublicKey {
		return nil, errors.New("the VAPID private key does not match vapid_public_key")
	}
	if cfg.Subject == "" {
		return nil, errors.New("the VAPID subject is required")
	}
	c := &Client{
		publicKey: pub, subject: cfg.Subject, key: key, check: cfg.CheckEndpoint, http: cfg.HTTPClient, now: cfg.Now,
		tokens: map[string]vapidToken{},
	}
	if c.http == nil {
		c.http = NewHTTPClient(cfg.Insecure)
	}
	if c.now == nil {
		c.now = time.Now
	}
	return c, nil
}

// NewHTTPClient is the pooled client for push services: HTTP/2 or HTTP/1.1 over TLS, no
// proxies, no redirects, and (unless insecure) connections only to public addresses on
// port 443, checked after DNS resolution on every connection.
func NewHTTPClient(insecure bool) *http.Client {
	t := providers.NewHTTPTransport(true)
	t.Proxy = nil
	t.MaxResponseHeaderBytes = 16 << 10
	if !insecure {
		d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: checkConnect}
		t.DialContext = d.DialContext
	}
	return &http.Client{
		Transport:     t,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type blockedError struct{ msg string }

func (e *blockedError) Error() string { return e.msg }

func checkConnect(_, address string, _ syscall.RawConn) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return &blockedError{"invalid address"}
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !wellknown.IsPublic(addr) {
		return &blockedError{"address " + host + " is not a public address"}
	}
	if port != "443" {
		return &blockedError{"port " + port + " is not allowed"}
	}
	return nil
}

func (c *Client) Name() string { return "webpush" }

// Audience is the aud claim for an endpoint: the origin of the push resource.
func Audience(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", errors.New("not an absolute http(s) URL")
	}
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port == "" || (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		return u.Scheme + "://" + host, nil
	}
	return u.Scheme + "://" + host + ":" + port, nil
}

// token returns a cached VAPID JWT for aud, signing a new one when it is close to expiry.
func (c *Client) token(aud string) (string, error) {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.tokens[aud]; ok && now.Before(t.exp.Add(-tokenRenewal)) {
		return t.value, nil
	}
	exp := now.Add(tokenLifetime)
	signed, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"aud": aud, "exp": exp.Unix(), "sub": c.subject,
	}).SignedString(c.key)
	if err != nil {
		return "", err
	}
	if len(c.tokens) >= maxCachedTokens {
		clear(c.tokens)
	}
	c.tokens[aud] = vapidToken{value: signed, exp: exp}
	return signed, nil
}

// dropToken forgets aud's token after the push service refused it.
func (c *Client) dropToken(aud string) {
	c.mu.Lock()
	delete(c.tokens, aud)
	c.mu.Unlock()
}

// Urgency maps the protocol's urgency to the Urgency header (RFC 8030 §5.3).
func Urgency(u string) string {
	switch u {
	case providers.UrgencyHigh, providers.UrgencyLow:
		return u
	default:
		return providers.UrgencyNormal
	}
}

func (c *Client) Send(ctx context.Context, t providers.Target, m providers.Message) error {
	if m.Mode != providers.ModeEncrypted {
		return &providers.Error{Kind: providers.Rejected, Reason: "Web Push needs an encrypted payload"}
	}
	if c.check != nil {
		if err := c.check(t.Token); err != nil {
			return &providers.Error{Kind: providers.Rejected, Reason: "Web Push endpoint is not allowed by this gateway", Err: err}
		}
	}
	aud, err := Audience(t.Token)
	if err != nil {
		return &providers.Error{Kind: providers.Rejected, Reason: "Web Push endpoint is invalid", Err: err}
	}
	jwtToken, err := c.token(aud)
	if err != nil {
		return &providers.Error{Kind: providers.Retry, Reason: "VAPID token could not be signed", Err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.Token, bytes.NewReader(m.Body))
	if err != nil {
		return &providers.Error{Kind: providers.Rejected, Reason: "Web Push request could not be built", Err: err}
	}
	req.Header.Set("Authorization", "vapid t="+jwtToken+", k="+c.publicKey)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("TTL", strconv.FormatInt(max(0, int64(math.Ceil(m.Expiration.Sub(c.now()).Seconds()))), 10))
	req.Header.Set("Urgency", Urgency(m.Urgency))
	if m.CollapseKey != "" {
		req.Header.Set("Topic", m.CollapseKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		var be *blockedError
		if errors.As(err, &be) {
			// The endpoint's host resolves to an internal address: never connect.
			return &providers.Error{Kind: providers.Rejected, Reason: "Web Push endpoint is not reachable from this gateway", Err: err}
		}
		return providers.Transport("Web Push", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	e := Classify(resp.StatusCode, data)
	e.RetryAfter = providers.ParseRetryAfter(resp.Header, c.now())
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		c.dropToken(aud)
	}
	return e
}

// reasonPattern accepts the short error reasons push services return (Apple's "reason"),
// and nothing that could carry an endpoint or other detail.
var reasonPattern = regexp.MustCompile(`^[A-Za-z]{1,64}$`)

// Classify maps a push service's error response to the gateway's handling. The services
// follow RFC 8030 for the status codes that matter: 404 and 410 mean the subscription has
// expired or was removed, 413 a body that is too large, 429 throttling.
func Classify(status int, body []byte) *providers.Error {
	var b struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(body, &b)
	reason := ""
	if reasonPattern.MatchString(b.Reason) {
		reason = b.Reason
	}
	e := &providers.Error{Status: status, Reason: "Web Push " + strconv.Itoa(status) + " " + http.StatusText(status)}
	if reason != "" {
		e.Reason = "Web Push " + reason
	}
	switch {
	case status == http.StatusNotFound, status == http.StatusGone,
		reason == "Unregistered", reason == "ExpiredToken", reason == "BadDeviceToken":
		e.Kind = providers.Gone
	case status == http.StatusTooManyRequests, status >= 500:
		e.Kind = providers.Retry
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		// The VAPID token was refused. A bad key or subject affects every subscription, so it
		// is retried while the operator fixes it rather than killing subscriptions.
		e.Kind = providers.Retry
	default:
		// 400 (bad headers), 413 (body too large) and anything else unexpected.
		e.Kind = providers.Rejected
	}
	return e
}

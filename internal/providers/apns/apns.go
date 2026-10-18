// Package apns delivers pushes to the Apple Push Notification service over HTTP/2 with
// token-based (.p8 key) authentication. The payload is defined in docs/payload.md.
package apns

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
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/parkerbrown98/gotalk-gateway/internal/providers"
)

const (
	ProductionURL = "https://api.push.apple.com"
	SandboxURL    = "https://api.sandbox.push.apple.com"

	EnvironmentProduction = "production"
	EnvironmentSandbox    = "sandbox"

	// tokenLifetime is how long a provider token is reused. Apple rejects tokens older than an
	// hour and asks that they be refreshed no more than once every 20 minutes.
	tokenLifetime = 50 * time.Minute
)

// Config is one app's APNs credentials.
type Config struct {
	BundleID string
	TeamID   string
	KeyID    string
	// PrivateKey is the PEM contents of the .p8 key.
	PrivateKey []byte
	// ProductionURL and SandboxURL override Apple's endpoints (tests).
	ProductionURL string
	SandboxURL    string
	// HTTPClient overrides the pooled HTTP/2 client (tests).
	HTTPClient *http.Client
	Now        func() time.Time
}

// Client sends to APNs for one app. It is safe for concurrent use.
type Client struct {
	topic, teamID, keyID string
	key                  *ecdsa.PrivateKey
	urls                 map[string]string
	http                 *http.Client
	now                  func() time.Time

	mu       sync.Mutex
	token    string
	issuedAt time.Time
}

var idPattern = regexp.MustCompile(`^[A-Z0-9]{10}$`)

// ValidateID checks a Team ID or Key ID: 10 upper-case letters or digits.
func ValidateID(id string) error {
	if !idPattern.MatchString(id) {
		return errors.New("must be 10 upper-case letters or digits")
	}
	return nil
}

// ParseKey reads a .p8 APNs signing key: a PKCS #8 P-256 private key in PEM.
func ParseKey(p8 []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(p8)
	if block == nil {
		return nil, errors.New("is not PEM; use the contents of the .p8 file Apple issued")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("is not a PKCS #8 private key: %w", err)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("is not a P-256 key")
	}
	return ec, nil
}

func New(cfg Config) (*Client, error) {
	key, err := ParseKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("APNs private key %w", err)
	}
	c := &Client{
		topic: cfg.BundleID, teamID: cfg.TeamID, keyID: cfg.KeyID, key: key, http: cfg.HTTPClient, now: cfg.Now,
		urls: map[string]string{
			EnvironmentProduction: cmpOr(cfg.ProductionURL, ProductionURL),
			EnvironmentSandbox:    cmpOr(cfg.SandboxURL, SandboxURL),
		},
	}
	for env, u := range c.urls {
		if p, err := url.Parse(u); err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Host == "" {
			return nil, fmt.Errorf("APNs %s URL %q is not an absolute http(s) URL", env, u)
		}
	}
	if c.http == nil {
		// HTTP/2 only: APNs does not speak HTTP/1.1.
		c.http = &http.Client{Transport: providers.NewHTTPTransport(false)}
	}
	if c.now == nil {
		c.now = time.Now
	}
	return c, nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (c *Client) Name() string { return "apns" }

// providerToken returns the cached ES256 provider token, signing a new one when it is older
// than tokenLifetime.
func (c *Client) providerToken() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.token != "" && now.Sub(c.issuedAt) < tokenLifetime {
		return c.token, nil
	}
	t := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"iss": c.teamID, "iat": now.Unix()})
	t.Header["kid"] = c.keyID
	signed, err := t.SignedString(c.key)
	if err != nil {
		return "", err
	}
	c.token, c.issuedAt = signed, now
	return signed, nil
}

// expireToken forces a new provider token for the next request.
func (c *Client) expireToken() {
	c.mu.Lock()
	c.token = ""
	c.mu.Unlock()
}

type payload struct {
	APS aps      `json:"aps"`
	GT  envelope `json:"gt"`
}

type aps struct {
	Alert          alert  `json:"alert"`
	MutableContent int    `json:"mutable-content"`
	Sound          string `json:"sound"`
}

type alert struct {
	LocKey string `json:"loc-key"`
}

type envelope struct {
	V              int    `json:"v"`
	Sub            string `json:"sub"`
	Mode           string `json:"mode"`
	Body           string `json:"body,omitempty"`
	Instance       string `json:"instance,omitempty"`
	NotificationID string `json:"notification_id,omitempty"`
}

// Body builds the APNs JSON payload. Every push is a visible alert with mutable-content, so
// the Notification Service Extension runs, decrypts and replaces the generic fallback text.
// The badge is set by the extension from the decrypted payload.
func Body(m providers.Message) ([]byte, error) {
	p := payload{
		APS: aps{Alert: alert{LocKey: providers.FallbackLocKey}, MutableContent: 1, Sound: "default"},
		GT:  envelope{V: 1, Sub: m.SubscriptionID, Mode: m.Mode},
	}
	if m.Mode == providers.ModeIDOnly {
		p.GT.Instance, p.GT.NotificationID = m.Instance, m.NotificationID
	} else {
		p.GT.Body = base64.RawURLEncoding.EncodeToString(m.Body)
	}
	return json.Marshal(p)
}

// Priority maps urgency to apns-priority.
func Priority(urgency string) string {
	switch urgency {
	case providers.UrgencyHigh:
		return "10"
	case providers.UrgencyLow:
		return "1"
	default:
		return "5"
	}
}

func (c *Client) Send(ctx context.Context, t providers.Target, m providers.Message) error {
	base, ok := c.urls[t.APNsEnvironment]
	if !ok {
		base = c.urls[EnvironmentProduction]
	}
	body, err := Body(m)
	if err != nil {
		return &providers.Error{Kind: providers.Rejected, Reason: "APNs payload could not be encoded", Err: err}
	}
	token, err := c.providerToken()
	if err != nil {
		return &providers.Error{Kind: providers.Retry, Reason: "APNs provider token could not be signed", Err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/3/device/"+url.PathEscape(t.Token), bytes.NewReader(body))
	if err != nil {
		return &providers.Error{Kind: providers.Rejected, Reason: "APNs request could not be built", Err: err}
	}
	req.Header.Set("Authorization", "bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apns-topic", c.topic)
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("apns-priority", Priority(m.Urgency))
	expiration := "0"
	if m.Expiration.After(c.now()) {
		expiration = strconv.FormatInt(m.Expiration.Unix(), 10)
	}
	req.Header.Set("apns-expiration", expiration)
	if m.CollapseKey != "" {
		req.Header.Set("apns-collapse-id", m.CollapseKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return providers.Transport("APNs", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	var r struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(data, &r)
	e := Classify(resp.StatusCode, r.Reason)
	e.RetryAfter = providers.ParseRetryAfter(resp.Header, c.now())
	if r.Reason == "ExpiredProviderToken" || r.Reason == "InvalidProviderToken" {
		c.expireToken()
	}
	return e
}

// Classify maps an APNs error response to the gateway's handling. See Apple's "Handling
// notification responses from APNs".
func Classify(status int, reason string) *providers.Error {
	e := &providers.Error{Status: status, Reason: "APNs " + cmpOr(reason, http.StatusText(status))}
	switch {
	case status == http.StatusGone, reason == "BadDeviceToken", reason == "DeviceTokenNotForTopic", reason == "Unregistered":
		// 410 is Unregistered or ExpiredToken. BadDeviceToken also covers a token sent to the
		// wrong environment; the client re-registers with the right one.
		e.Kind = providers.Gone
	case status == http.StatusTooManyRequests, status >= 500:
		e.Kind = providers.Retry
	case status == http.StatusForbidden:
		// The gateway's credentials were refused (expired or invalid provider token, wrong
		// team or environment). Not the push's fault, so it is retried while the operator fixes it.
		e.Kind = providers.Retry
	default:
		// 400 (bad topic, collapse ID, priority, payload), 404, 405 and 413.
		e.Kind = providers.Rejected
	}
	return e
}

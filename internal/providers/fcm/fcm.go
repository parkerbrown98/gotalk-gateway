// Package fcm delivers pushes to Android devices through the Firebase Cloud Messaging HTTP v1
// API, authenticated with a service account's OAuth 2.0 tokens. The message is defined in
// docs/payload.md.
package fcm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/parkerbrown98/gotalk-gateway/internal/providers"
)

const (
	DefaultEndpoint = "https://fcm.googleapis.com"
	// Scope is the only permission the gateway's service account needs.
	Scope = "https://www.googleapis.com/auth/firebase.messaging"
)

// Config is one app's FCM credentials.
type Config struct {
	// ServiceAccount is the JSON key of a Google service account with the Firebase Cloud
	// Messaging API Admin role (or just cloudmessaging.messages.create).
	ServiceAccount []byte
	// ProjectID overrides the project of the service account.
	ProjectID string
	// Endpoint overrides https://fcm.googleapis.com (tests).
	Endpoint string
	// HTTPClient overrides the pooled client used for messages and tokens (tests).
	HTTPClient *http.Client
	Now        func() time.Time
}

// Client sends to FCM for one Firebase project. It is safe for concurrent use.
type Client struct {
	sendURL string
	http    *http.Client
	// newTokens returns a token source that caches until shortly before expiry.
	newTokens func() oauth2.TokenSource
	now       func() time.Time

	mu     sync.Mutex
	tokens oauth2.TokenSource
}

// ProjectOf returns the project_id of a service account key, validating its shape.
func ProjectOf(serviceAccount []byte) (string, error) {
	var sa struct {
		Type       string `json:"type"`
		ProjectID  string `json:"project_id"`
		PrivateKey string `json:"private_key"`
		Email      string `json:"client_email"`
	}
	if err := json.Unmarshal(serviceAccount, &sa); err != nil {
		return "", errors.New("is not a JSON service account key")
	}
	if sa.Type != "service_account" || sa.PrivateKey == "" || sa.Email == "" {
		return "", errors.New(`is not a service account key (needs "type": "service_account", private_key and client_email)`)
	}
	return sa.ProjectID, nil
}

func New(cfg Config) (*Client, error) {
	project, err := ProjectOf(cfg.ServiceAccount)
	if err != nil {
		return nil, fmt.Errorf("FCM service account %w", err)
	}
	if cfg.ProjectID != "" {
		project = cfg.ProjectID
	}
	if project == "" {
		return nil, errors.New("FCM project ID is unknown: the service account has no project_id; set project_id")
	}
	jwtCfg, err := google.JWTConfigFromJSON(cfg.ServiceAccount, Scope)
	if err != nil {
		return nil, fmt.Errorf("FCM service account: %w", err)
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	if u, err := url.Parse(endpoint); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("FCM endpoint %q is not an absolute http(s) URL", endpoint)
	}
	c := &Client{
		sendURL: endpoint + "/v1/projects/" + url.PathEscape(project) + "/messages:send",
		http:    cfg.HTTPClient, now: cfg.Now,
	}
	if c.http == nil {
		c.http = &http.Client{Transport: providers.NewHTTPTransport(true)}
	}
	if c.now == nil {
		c.now = time.Now
	}
	// Token requests use the same pooled client, bounded so a hung token endpoint cannot
	// stall deliveries; each send also has its own deadline.
	tokenClient := *c.http
	tokenClient.Timeout = 15 * time.Second
	tokenCtx := context.WithValue(context.Background(), oauth2.HTTPClient, &tokenClient)
	c.newTokens = func() oauth2.TokenSource { return jwtCfg.TokenSource(tokenCtx) }
	c.tokens = c.newTokens()
	return c, nil
}

func (c *Client) Name() string { return "fcm" }

// accessToken returns a cached OAuth token, fetching a new one shortly before it expires.
func (c *Client) accessToken() (*oauth2.Token, error) {
	c.mu.Lock()
	ts := c.tokens
	c.mu.Unlock()
	return ts.Token()
}

// resetToken discards the cached token after FCM refused it.
func (c *Client) resetToken() {
	c.mu.Lock()
	c.tokens = c.newTokens()
	c.mu.Unlock()
}

type request struct {
	Message message `json:"message"`
}

type message struct {
	Token   string            `json:"token"`
	Data    map[string]string `json:"data"`
	Android android           `json:"android"`
}

type android struct {
	Priority    string `json:"priority"`
	TTL         string `json:"ttl"`
	CollapseKey string `json:"collapse_key,omitempty"`
}

// Body builds the FCM v1 request: a data-only message, so the app's messaging service always
// runs and builds the notification itself.
func Body(token string, m providers.Message, now time.Time) ([]byte, error) {
	data := map[string]string{"gt_v": "1", "gt_sub": m.SubscriptionID, "gt_mode": m.Mode}
	if m.Mode == providers.ModeIDOnly {
		data["gt_instance"], data["gt_notification_id"] = m.Instance, m.NotificationID
	} else {
		data["gt_body"] = base64.RawURLEncoding.EncodeToString(m.Body)
	}
	priority := "NORMAL"
	if m.Urgency == providers.UrgencyHigh {
		priority = "HIGH"
	}
	ttl := max(0, int64(math.Ceil(m.Expiration.Sub(now).Seconds())))
	return json.Marshal(request{Message: message{
		Token: token, Data: data,
		Android: android{Priority: priority, TTL: strconv.FormatInt(ttl, 10) + "s", CollapseKey: m.CollapseKey},
	}})
}

func (c *Client) Send(ctx context.Context, t providers.Target, m providers.Message) error {
	body, err := Body(t.Token, m, c.now())
	if err != nil {
		return &providers.Error{Kind: providers.Rejected, Reason: "FCM message could not be encoded", Err: err}
	}
	tok, err := c.accessToken()
	if err != nil {
		return &providers.Error{Kind: providers.Retry, Reason: "FCM access token unavailable", Err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.sendURL, bytes.NewReader(body))
	if err != nil {
		return &providers.Error{Kind: providers.Rejected, Reason: "FCM request could not be built", Err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	tok.SetAuthHeader(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return providers.Transport("FCM", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	e := Classify(resp.StatusCode, data)
	e.RetryAfter = providers.ParseRetryAfter(resp.Header, c.now())
	if resp.StatusCode == http.StatusUnauthorized {
		c.resetToken()
	}
	return e
}

type errorBody struct {
	Error struct {
		Status  string `json:"status"`
		Details []struct {
			Type            string `json:"@type"`
			ErrorCode       string `json:"errorCode"`
			FieldViolations []struct {
				Field string `json:"field"`
			} `json:"fieldViolations"`
		} `json:"details"`
	} `json:"error"`
}

// Classify maps an FCM v1 error response to the gateway's handling. See Firebase's
// "FCM error codes" (google.firebase.fcm.v1.FcmError).
func Classify(status int, body []byte) *providers.Error {
	var b errorBody
	_ = json.Unmarshal(body, &b)
	code, badToken := "", false
	for _, d := range b.Error.Details {
		if d.ErrorCode != "" {
			code = d.ErrorCode
		}
		for _, v := range d.FieldViolations {
			if v.Field == "message.token" {
				badToken = true
			}
		}
	}
	reason := code
	if reason == "" {
		reason = cmpOr(b.Error.Status, http.StatusText(status))
	}
	e := &providers.Error{Status: status, Reason: "FCM " + reason}
	switch {
	case code == "UNREGISTERED", code == "SENDER_ID_MISMATCH", badToken:
		// The token was unregistered, belongs to another Firebase project, or is malformed.
		e.Kind = providers.Gone
	case code == "QUOTA_EXCEEDED", code == "UNAVAILABLE", code == "INTERNAL", code == "THIRD_PARTY_AUTH_ERROR":
		e.Kind = providers.Retry
	case code == "INVALID_ARGUMENT":
		e.Kind = providers.Rejected
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		// The gateway's credentials were refused; retried while the operator fixes them.
		e.Kind = providers.Retry
	case status == http.StatusTooManyRequests, status >= 500:
		e.Kind = providers.Retry
	default:
		e.Kind = providers.Rejected
	}
	return e
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

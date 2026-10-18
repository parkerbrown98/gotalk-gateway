// Package providers defines how the gateway hands a push to a platform provider (APNs, FCM
// and, from Phase 5, Web Push) and how provider failures map to the protocol's outcomes. The
// provider clients live in subpackages; docs/payload.md specifies what each one sends.
package providers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Push modes (docs/payload.md).
const (
	ModeEncrypted = "encrypted"
	ModeIDOnly    = "id_only"
)

// Urgencies (docs/protocol.md, "Push requests").
const (
	UrgencyLow    = "low"
	UrgencyNormal = "normal"
	UrgencyHigh   = "high"
)

// FallbackLocKey is the localized string the app bundle ships for a notification it could
// not decrypt. It is the only text a user can see that the instance did not encrypt.
const FallbackLocKey = "GT_NEW_NOTIFICATION"

// Message is one push as a provider forwards it. The gateway never reads Body.
type Message struct {
	SubscriptionID string
	Mode           string
	// Body is the RFC 8291 body in encrypted mode.
	Body []byte
	// Instance and NotificationID form the cleartext envelope in id_only mode.
	Instance       string
	NotificationID string
	Urgency        string
	// Expiration is when the provider should stop trying. A push with a TTL of 0 has its
	// acceptance time here: deliver now or drop.
	Expiration  time.Time
	CollapseKey string
}

// Target is where a provider delivers: the subscription's token or endpoint as it was read
// for this attempt.
type Target struct {
	Token           string
	APNsEnvironment string
}

// Provider delivers to one platform of one app.
type Provider interface {
	// Name labels metrics and logs: "apns" or "fcm".
	Name() string
	// Send delivers m. Failures are *Error.
	Send(ctx context.Context, t Target, m Message) error
}

// Kind is how the gateway handles a provider failure.
type Kind int

const (
	// Retry is a transient failure: provider 5xx, throttling, timeouts, or the gateway's own
	// credentials being refused. The push is retried with backoff.
	Retry Kind = iota
	// Gone means the token or endpoint is dead; the subscription is marked gone.
	Gone
	// Rejected is a permanent refusal of this push, such as an invalid payload or topic.
	Rejected
)

func (k Kind) String() string {
	switch k {
	case Gone:
		return "gone"
	case Rejected:
		return "rejected"
	default:
		return "retry"
	}
}

// Error is a provider failure, already classified.
type Error struct {
	Kind Kind
	// Reason is the provider's short reason, such as "APNs BadDeviceToken". It is reported to
	// the instance and must never contain content.
	Reason string
	// Status is the provider's HTTP status, or 0 for a transport failure.
	Status int
	// RetryAfter is the provider's Retry-After, if any.
	RetryAfter time.Duration
	Err        error
}

func (e *Error) Error() string {
	msg := fmt.Sprintf("%s: %s", e.Kind, e.Reason)
	if e.Status != 0 {
		msg += fmt.Sprintf(" (HTTP %d)", e.Status)
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *Error) Unwrap() error { return e.Err }

// Transport wraps a failure to reach the provider as a retryable error.
func Transport(provider string, err error) *Error {
	reason := provider + " unreachable"
	if errors.Is(err, context.DeadlineExceeded) {
		reason = provider + " timed out"
	}
	return &Error{Kind: Retry, Reason: reason, Err: err}
}

// ParseRetryAfter reads a Retry-After header in seconds or as an HTTP date.
func ParseRetryAfter(h http.Header, now time.Time) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(v); err == nil && s > 0 {
		return time.Duration(s) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}

// Registry maps an app's platform to its provider. Platforms without credentials have none,
// and pushes to them are refused before queueing.
type Registry struct {
	mu sync.RWMutex
	m  map[string]Provider
}

func NewRegistry() *Registry { return &Registry{m: map[string]Provider{}} }

func (r *Registry) Set(appID, platform string, p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[appID+"/"+platform] = p
}

// Get returns the provider of an app's platform, or nil.
func (r *Registry) Get(appID, platform string) Provider {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.m[appID+"/"+platform]
}

// Len is the number of configured providers.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.m)
}

// NewHTTPTransport is the pooled transport for provider connections: HTTP/2 over TLS, or
// unencrypted HTTP/2 for http:// endpoints (local fakes). Go keeps one multiplexed connection
// per host and opens more when the server's stream limit is reached; idle connections are
// health-checked with pings so a silently dropped connection is replaced.
func NewHTTPTransport(http1 bool) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.ForceAttemptHTTP2 = true
	t.MaxIdleConnsPerHost = 16
	t.IdleConnTimeout = 10 * time.Minute
	t.HTTP2 = &http.HTTP2Config{SendPingTimeout: time.Minute, PingTimeout: 15 * time.Second}
	p := new(http.Protocols)
	p.SetHTTP1(http1)
	p.SetHTTP2(true)
	p.SetUnencryptedHTTP2(!http1)
	t.Protocols = p
	return t
}

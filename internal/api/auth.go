package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/jackc/pgx/v5"

	"github.com/parkerbrown98/gotalk-gateway/internal/instances"
	"github.com/parkerbrown98/gotalk-gateway/internal/problem"
	"github.com/parkerbrown98/gotalk-gateway/internal/ratelimit"
	"github.com/parkerbrown98/gotalk-gateway/internal/signing"
)

// authLevel is what a signed operation requires of the signing key and its instance.
type authLevel int

const (
	// authVerify accepts any live key, including a pending recovery key: only verification.
	authVerify authLevel = iota + 1
	// authRead accepts active keys and pending rotation or registration keys.
	authRead
	// authManage needs an active key of an active or suspended instance.
	authManage
)

const (
	metaAuth = "gotalk.auth"
	// metaAuthOptional makes the signature optional: requests without signing headers reach
	// the handler without a principal (for endpoints that also accept another credential).
	metaAuthOptional = "gotalk.auth_optional"
	// metaIPRule names the per-IP rate limit rule of an unsigned operation.
	metaIPRule = "gotalk.ip_rule"
	// defaultMaxBody is the protocol's default request body limit.
	defaultMaxBody = 64 << 10
)

type principalKey struct{}

func principalFrom(ctx context.Context) instances.Principal {
	p, _ := ctx.Value(principalKey{}).(instances.Principal)
	return p
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// abort writes p and stops the operation.
func abort(ctx huma.Context, p *problem.Problem) {
	r, w := humachi.Unwrap(ctx)
	writeProblem(r.Context(), w, p)
}

// requireJSON refuses request bodies that are not JSON (415 unsupported_media_type).
func (s *Server) requireJSON(ctx huma.Context, next func(huma.Context)) {
	r, _ := humachi.Unwrap(ctx)
	if r.ContentLength != 0 && (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch) {
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
			if r.ContentLength > 0 || r.Header.Get("Content-Type") != "" {
				abort(ctx, problem.New(http.StatusUnsupportedMediaType, problem.UnsupportedMediaType, "Request bodies must be application/json."))
				return
			}
		}
	}
	next(ctx)
}

// unsignedRules applies the client IP blocklist and per-IP rate limit of unsigned operations.
func (s *Server) unsignedRules(ctx huma.Context, next func(huma.Context)) {
	rule, ok := ctx.Operation().Metadata[metaIPRule].(string)
	if !ok {
		next(ctx)
		return
	}
	ip := clientIPFrom(ctx.Context())
	if e := s.Blocklist.MatchIP(ip); e != nil {
		abort(ctx, problem.New(http.StatusForbidden, problem.InstanceBlocked, e.Reason))
		return
	}
	if p := s.takeRate(ctx, rule, rateKeyForIP(ip)); p != nil {
		abort(ctx, p)
		return
	}
	next(ctx)
}

// rateKeyForIP keys per-IP limits by address for IPv4 and by /64 for IPv6, since a single
// IPv6 client usually controls a whole /64 and could otherwise rotate addresses freely.
func rateKeyForIP(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is6() {
		return netip.PrefixFrom(addr, 64).Masked().String()
	}
	return addr.String()
}

// takeRate consumes from a rate limit rule, sets the X-RateLimit-* headers, and returns a
// problem when the limit is reached.
func (s *Server) takeRate(ctx huma.Context, rule, key string) *problem.Problem {
	res, err := s.Limiter.Take(ctx.Context(), rule, key)
	if err != nil {
		s.Logger.WarnContext(ctx.Context(), "rate limiter unavailable; allowing request", "rule", rule, "error", err.Error())
		return nil
	}
	if !res.Limited() {
		return nil
	}
	ctx.SetHeader("X-RateLimit-Limit", strconv.FormatInt(res.Limit, 10))
	ctx.SetHeader("X-RateLimit-Remaining", strconv.FormatInt(res.Remaining, 10))
	ctx.SetHeader("X-RateLimit-Reset", strconv.FormatInt(res.Reset.Unix(), 10))
	if !res.Reached {
		return nil
	}
	return rateLimited(res, s.now())
}

func rateLimited(res ratelimit.Result, now time.Time) *problem.Problem {
	retry := int64(math.Max(1, math.Ceil(res.Reset.Sub(now).Seconds())))
	return problem.Newf(http.StatusTooManyRequests, problem.RateLimited, "Rate limit reached; retry in %d seconds.", retry).
		WithHeader("Retry-After", strconv.FormatInt(retry, 10)).
		WithHeader("X-RateLimit-Limit", strconv.FormatInt(res.Limit, 10)).
		WithHeader("X-RateLimit-Remaining", "0").
		WithHeader("X-RateLimit-Reset", strconv.FormatInt(res.Reset.Unix(), 10))
}

// signedRequests authenticates operations that require an instance signature, in the
// order docs/protocol.md specifies, and stores the principal in the context.
func (s *Server) signedRequests(ctx huma.Context, next func(huma.Context)) {
	op := ctx.Operation()
	level, ok := op.Metadata[metaAuth].(authLevel)
	if !ok {
		next(ctx)
		return
	}
	if optional, _ := op.Metadata[metaAuthOptional].(bool); optional && !hasSigningHeaders(ctx) {
		next(ctx)
		return
	}
	p, prob := s.authenticate(ctx, op, level)
	if prob != nil {
		abort(ctx, prob)
		return
	}
	next(huma.WithValue(ctx, principalKey{}, p))
}

// hasSigningHeaders reports whether a request attempts instance authentication. Such a
// request is always authenticated as an instance and never falls back to another credential.
func hasSigningHeaders(ctx huma.Context) bool {
	for _, h := range []string{signing.HeaderSignature, signing.HeaderKeyID, signing.HeaderTimestamp, signing.HeaderNonce} {
		if ctx.Header(h) != "" {
			return true
		}
	}
	return false
}

func (s *Server) authenticate(ctx huma.Context, op *huma.Operation, level authLevel) (instances.Principal, *problem.Problem) {
	r, _ := humachi.Unwrap(ctx)
	rctx := r.Context()
	invalid := func(detail string) *problem.Problem {
		return problem.New(http.StatusUnauthorized, problem.InvalidSignature, detail)
	}
	unknownKey := problem.New(http.StatusUnauthorized, problem.UnknownKey, "Unknown or revoked key.")

	limit := op.MaxBodyBytes
	if limit <= 0 {
		limit = defaultMaxBody
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return instances.Principal{}, problem.New(http.StatusBadRequest, problem.InvalidRequest, "Could not read the request body.")
	}
	if int64(len(body)) > limit {
		return instances.Principal{}, problem.Newf(http.StatusRequestEntityTooLarge, problem.PayloadTooLarge,
			"Request body is larger than %d bytes.", limit)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	// 1. Headers present and well formed.
	h, err := signing.ParseHeaders(r.Header, len(body) > 0)
	if err != nil {
		return instances.Principal{}, invalid(err.Error())
	}

	// 2. The key exists and is live.
	key, err := s.Instances.LookupKey(rctx, h.KeyID)
	if errors.Is(err, pgx.ErrNoRows) {
		return instances.Principal{}, unknownKey
	} else if err != nil {
		s.Logger.ErrorContext(rctx, "looking up signing key", "error", err.Error(), "request_id", requestIDFrom(rctx))
		return instances.Principal{}, problem.New(http.StatusServiceUnavailable, problem.ProviderUnavailable, "Temporarily unable to authenticate requests.")
	}
	now := s.now()
	if key.Status == instances.KeyRevoked ||
		(key.ExpiresAt != nil && !key.ExpiresAt.After(now)) ||
		(key.InstanceStatus == instances.StatusPending && (key.PendingExpiresAt == nil || !key.PendingExpiresAt.After(now))) {
		return instances.Principal{}, unknownKey
	}

	// 3. Timestamp within the skew window.
	if d := now.Sub(time.Unix(h.Timestamp, 0)); d > signing.MaxSkew || d < -signing.MaxSkew {
		return instances.Principal{}, problem.Newf(http.StatusUnauthorized, problem.StaleTimestamp,
			"Gotalk-Timestamp is %s from the gateway's clock; the limit is %s. Check the instance's clock.",
			d.Abs().Round(time.Second), signing.MaxSkew).
			WithHeader("Date", now.UTC().Format(http.TimeFormat))
	}

	// 4. Content-Digest, when present, matches the body.
	sum := sha256.Sum256(body)
	if h.Digest != nil && subtle.ConstantTimeCompare(h.Digest, sum[:]) != 1 {
		return instances.Principal{}, invalid("Content-Digest does not match the body.")
	}

	// 5. The signature verifies.
	sr := signing.Request{
		Method: r.Method, Host: s.signingHost(r), Target: requestTarget(r),
		Timestamp: h.Timestamp, Nonce: h.Nonce, KeyID: h.KeyID, Body: body,
	}
	if !signing.Verify(key.PublicKey, sr, h.Signature) {
		return instances.Principal{}, invalid("The signature does not verify for this key, host, request and body.")
	}

	// 6. The nonce is new; recorded only after the signature verifies.
	fresh, err := s.Nonces.Claim(rctx, h.KeyID+":"+h.Nonce, signing.NonceTTL)
	if err != nil {
		s.Logger.ErrorContext(rctx, "recording nonce", "error", err.Error(), "request_id", requestIDFrom(rctx))
		return instances.Principal{}, problem.New(http.StatusServiceUnavailable, problem.ProviderUnavailable, "Temporarily unable to authenticate requests.")
	}
	if !fresh {
		return instances.Principal{}, problem.New(http.StatusUnauthorized, problem.ReplayedNonce, "This nonce was already used for this key.")
	}

	// 7. The instance status allows the operation.
	if key.InstanceStatus == instances.StatusBlocked {
		reason := "This instance is blocked."
		if key.BlockedReason != nil {
			reason = *key.BlockedReason
		}
		return instances.Principal{}, problem.New(http.StatusForbidden, problem.InstanceBlocked, reason)
	}
	if e := s.Blocklist.MatchOrigin(key.Origin); e != nil {
		return instances.Principal{}, problem.New(http.StatusForbidden, problem.InstanceBlocked, e.Reason)
	}
	if id := ctx.Param("instance_id"); id != "" && id != key.InstanceID {
		return instances.Principal{}, problem.New(http.StatusNotFound, problem.InstanceNotFound, "No such instance.")
	}
	notVerified := func(detail string) *problem.Problem {
		return problem.New(http.StatusForbidden, problem.InstanceNotVerified, detail)
	}
	switch {
	case level >= authRead && key.Recovery:
		return instances.Principal{}, notVerified("This recovery key is pending verification; it can only call verify.")
	case level >= authManage && key.InstanceStatus == instances.StatusPending:
		return instances.Principal{}, notVerified("The instance is pending domain verification.")
	case level >= authManage && key.Status != instances.KeyActive:
		return instances.Principal{}, notVerified("This key is pending verification.")
	}

	// 8. Rate limits.
	if p := s.takeRate(ctx, ratelimit.Signed, key.InstanceID); p != nil {
		return instances.Principal{}, p
	}

	if err := s.Instances.Touch(rctx, key.ID); err != nil {
		s.Logger.WarnContext(rctx, "recording key use", "error", err.Error())
	}
	return instances.Principal{
		InstanceID: key.InstanceID, KeyID: key.ID, Origin: key.Origin,
		KeyStatus: key.Status, Recovery: key.Recovery, InstanceStatus: key.InstanceStatus,
	}, nil
}

// signingHost is the HOST of the signing string: the host of server.public_url when it
// is configured (so proxies may rewrite Host), otherwise the request's host.
func (s *Server) signingHost(r *http.Request) string {
	if u, err := url.Parse(baseURLFrom(r.Context())); err == nil && u.Host != "" {
		return u.Host
	}
	return r.Host
}

// requestTarget is the path and query exactly as sent.
func requestTarget(r *http.Request) string {
	if r.RequestURI == "" || r.RequestURI[0] == '/' {
		if r.RequestURI == "" {
			return r.URL.RequestURI()
		}
		return r.RequestURI
	}
	if u, err := url.Parse(r.RequestURI); err == nil {
		return u.RequestURI()
	}
	return r.RequestURI
}

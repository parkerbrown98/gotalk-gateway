package api

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/parkerbrown98/gotalk-gateway/internal/ids"
	"github.com/parkerbrown98/gotalk-gateway/internal/problem"
)

type ctxKey int

const (
	requestIDKey ctxKey = iota
	clientIPKey
	baseURLKey
)

// RequestIDHeader carries the request ID on every response. Incoming values are ignored so
// callers cannot forge IDs into the operator's logs.
const RequestIDHeader = "X-Request-Id"

func requestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

func clientIPFrom(ctx context.Context) string {
	ip, _ := ctx.Value(clientIPKey).(string)
	return ip
}

func baseURLFrom(ctx context.Context) string {
	u, _ := ctx.Value(baseURLKey).(string)
	return u
}

// requestMeta assigns the request ID and resolves the client address and public base URL.
func (s *Server) requestMeta(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := ids.New(ids.Request)
		w.Header().Set(RequestIDHeader, id)
		if s.Config.Server.PublicURL == "" {
			// The base URL comes from the request, so shared caches must not serve a response
			// built from one client's (possibly forged) forwarding headers to another.
			w.Header().Add("Vary", "Host, X-Forwarded-Host, X-Forwarded-Proto")
		}
		ip, viaProxy := s.clientIP(r)
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		ctx = context.WithValue(ctx, clientIPKey, ip)
		ctx = context.WithValue(ctx, baseURLKey, s.baseURL(r, viaProxy))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) trustedProxy(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range s.proxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// clientIP resolves the caller's address. Forwarding headers are only honored when proxy
// trust is enabled and the direct peer is a trusted proxy; the client is then the
// right-most X-Forwarded-For hop that is not itself a trusted proxy, since entries to its
// left can be forged by the client.
func (s *Server) clientIP(r *http.Request) (ip string, viaProxy bool) {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !s.Config.Server.TrustProxy || !s.trustedProxy(peer) {
		return host, false
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		if !s.trustedProxy(hop) {
			return hop.Unmap().String(), true
		}
	}
	return host, true
}

// baseURL is server.public_url when configured, otherwise derived from the request.
func (s *Server) baseURL(r *http.Request, viaProxy bool) string {
	if s.Config.Server.PublicURL != "" {
		return s.Config.Server.PublicURL
	}
	scheme, host := "http", r.Host
	if r.TLS != nil {
		scheme = "https"
	}
	if viaProxy {
		if p := firstHeaderValue(r, "X-Forwarded-Proto"); p == "http" || p == "https" {
			scheme = p
		}
		if h := firstHeaderValue(r, "X-Forwarded-Host"); h != "" {
			host = h
		}
	}
	return scheme + "://" + strings.ToLower(host)
}

func firstHeaderValue(r *http.Request, name string) string {
	v, _, _ := strings.Cut(r.Header.Get(name), ",")
	return strings.TrimSpace(v)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// quietPaths are logged at debug level because probes and scrapers hit them constantly.
var quietPaths = map[string]bool{"/healthz": true, "/readyz": true, "/metrics": true}

func logLevel(path string, status int) slog.Level {
	switch {
	case status >= 500:
		return slog.LevelError
	case quietPaths[path]:
		return slog.LevelDebug
	default:
		return slog.LevelInfo
	}
}

// observe logs every request and records it in the HTTP metrics.
func (s *Server) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		s.Metrics.inFlight.Inc()
		defer s.Metrics.inFlight.Dec()
		next.ServeHTTP(ww, r)
		elapsed := time.Since(start)

		route := "unmatched"
		if rc := chi.RouteContext(r.Context()); rc != nil && rc.RoutePattern() != "" {
			route = rc.RoutePattern()
		}
		s.Metrics.observe(r.Method, route, ww.Status(), elapsed)

		s.Logger.Log(r.Context(), logLevel(r.URL.Path, ww.Status()), "http request",
			"method", r.Method,
			"route", route,
			"path", r.URL.Path,
			"status", ww.Status(),
			"bytes", ww.BytesWritten(),
			"duration_ms", elapsed.Milliseconds(),
			"client_ip", clientIPFrom(r.Context()),
			"request_id", requestIDFrom(r.Context()),
		)
	})
}

// recoverer turns a panic into a 500 problem and logs the stack.
func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			if rec == http.ErrAbortHandler { //nolint:errorlint // sentinel compared by identity, as net/http does
				panic(rec)
			}
			s.Logger.ErrorContext(r.Context(), "panic serving request",
				"panic", fmt.Sprint(rec), "stack", string(debug.Stack()), "request_id", requestIDFrom(r.Context()))
			writeProblem(r.Context(), w, problem.New(http.StatusInternalServerError, problem.InternalError, "Unexpected error."))
		}()
		next.ServeHTTP(w, r)
	})
}

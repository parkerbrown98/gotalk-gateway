package api

import (
	"context"
	"net/http"
	"time"
)

// handleHealthz is a liveness probe: the process is up and serving HTTP.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReadyz is a readiness probe: every dependency answers and the gateway is not
// shutting down. Error details are logged, not returned, because the endpoint is public.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.draining.Load() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "draining"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	checks := map[string]string{}
	ready := true
	for _, c := range s.Checks {
		if c.Ping == nil {
			checks[c.Name] = "not_configured"
			continue
		}
		if err := c.Ping(ctx); err != nil {
			s.Logger.WarnContext(ctx, "readiness check failed", "check", c.Name, "error", err.Error())
			checks[c.Name] = "error"
			ready = false
			continue
		}
		checks[c.Name] = "ok"
	}
	if !ready {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable", "checks": checks})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "checks": checks})
}

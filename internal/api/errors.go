package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/parkerbrown98/gotalk-gateway/internal/problem"
)

func init() {
	// Every error huma produces (validation, unknown fields, body limits) uses the
	// protocol's problem format.
	huma.NewError = func(status int, msg string, errs ...error) huma.StatusError {
		p := problem.New(status, "", msg)
		for _, err := range errs {
			if err == nil {
				continue
			}
			fe := problem.FieldError{Message: err.Error()}
			var d huma.ErrorDetailer
			if errors.As(err, &d) {
				detail := d.ErrorDetail()
				fe = problem.FieldError{Field: strings.TrimPrefix(detail.Location, "body."), Message: detail.Message}
			}
			p.Errors = append(p.Errors, fe)
		}
		return p
	}
	huma.NewErrorWithContext = func(ctx huma.Context, status int, msg string, errs ...error) huma.StatusError {
		p := huma.NewError(status, msg, errs...)
		if pp, ok := p.(*problem.Problem); ok && ctx != nil {
			pp.RequestID = requestIDFrom(ctx.Context())
		}
		return p
	}
}

// writeProblem writes p for handlers outside huma.
func writeProblem(ctx context.Context, w http.ResponseWriter, p *problem.Problem) {
	p.RequestID = requestIDFrom(ctx)
	for k, v := range p.GetHeaders() {
		w.Header()[k] = v
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

// withRequestID stamps the request ID on a problem returned by a service.
func withRequestID(ctx context.Context, err error) error {
	var p *problem.Problem
	if errors.As(err, &p) {
		p.RequestID = requestIDFrom(ctx)
		return p
	}
	return err
}

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
)

// Error codes from docs/protocol.md. Callers branch on these; titles and details are for humans.
const (
	CodeInvalidRequest       = "invalid_request"
	CodeUnauthorized         = "unauthorized"
	CodeNotFound             = "not_found"
	CodeMethodNotAllowed     = "method_not_allowed"
	CodeConflict             = "conflict"
	CodePayloadTooLarge      = "payload_too_large"
	CodeUnsupportedMediaType = "unsupported_media_type"
	CodeRateLimited          = "rate_limited"
	CodeInternalError        = "internal_error"
	CodeProviderUnavailable  = "provider_unavailable"
)

const problemTypeBase = "https://gotalk.app/problems/"

// statusCodes maps an HTTP status to the protocol code used when no specific code applies.
var statusCodes = map[int]string{
	http.StatusBadRequest:            CodeInvalidRequest,
	http.StatusUnprocessableEntity:   CodeInvalidRequest,
	http.StatusUnauthorized:          CodeUnauthorized,
	http.StatusNotFound:              CodeNotFound,
	http.StatusMethodNotAllowed:      CodeMethodNotAllowed,
	http.StatusConflict:              CodeConflict,
	http.StatusRequestEntityTooLarge: CodePayloadTooLarge,
	http.StatusUnsupportedMediaType:  CodeUnsupportedMediaType,
	http.StatusTooManyRequests:       CodeRateLimited,
	http.StatusInternalServerError:   CodeInternalError,
	http.StatusServiceUnavailable:    CodeProviderUnavailable,
}

// Problem is an RFC 9457 problem details body with the protocol's stable code.
type Problem struct {
	Type      string       `json:"type" doc:"URI identifying the problem type."`
	Title     string       `json:"title" doc:"Short human-readable summary."`
	Status    int          `json:"status" doc:"HTTP status code."`
	Code      string       `json:"code" doc:"Stable machine-readable error code. Callers must tolerate unlisted values."`
	Detail    string       `json:"detail,omitempty" doc:"Human-readable explanation of this occurrence."`
	RequestID string       `json:"request_id,omitempty" doc:"Request ID to quote to the gateway operator."`
	Errors    []FieldError `json:"errors,omitempty" nullable:"false" doc:"Field-level problems for invalid_request."`
}

type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (p *Problem) Error() string             { return p.Code + ": " + p.Detail }
func (p *Problem) GetStatus() int            { return p.Status }
func (p *Problem) ContentType(string) string { return "application/problem+json" }

// NewProblem builds a problem with an explicit code.
func NewProblem(status int, code, detail string) *Problem {
	if code == "" {
		code = codeForStatus(status)
	}
	return &Problem{
		Type:   problemTypeBase + strings.ReplaceAll(code, "_", "-"),
		Title:  http.StatusText(status),
		Status: status,
		Code:   code,
		Detail: detail,
	}
}

func codeForStatus(status int) string {
	if c, ok := statusCodes[status]; ok {
		return c
	}
	if status >= 500 {
		return CodeInternalError
	}
	return CodeInvalidRequest
}

func init() {
	// Every error huma produces (validation, unknown fields, missing bodies) uses the
	// protocol's problem format.
	huma.NewError = func(status int, msg string, errs ...error) huma.StatusError {
		p := NewProblem(status, "", msg)
		for _, err := range errs {
			if err == nil {
				continue
			}
			fe := FieldError{Message: err.Error()}
			if d, ok := err.(huma.ErrorDetailer); ok {
				detail := d.ErrorDetail()
				fe = FieldError{Field: strings.TrimPrefix(detail.Location, "body."), Message: detail.Message}
			}
			p.Errors = append(p.Errors, fe)
		}
		return p
	}
	huma.NewErrorWithContext = func(ctx huma.Context, status int, msg string, errs ...error) huma.StatusError {
		p := huma.NewError(status, msg, errs...)
		if pp, ok := p.(*Problem); ok && ctx != nil {
			pp.RequestID = requestIDFrom(ctx.Context())
		}
		return p
	}
}

// writeProblem writes p for handlers outside huma.
func writeProblem(ctx context.Context, w http.ResponseWriter, p *Problem) {
	p.RequestID = requestIDFrom(ctx)
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

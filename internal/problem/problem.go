// Package problem defines the gateway's RFC 9457 error responses and the protocol's stable
// error codes (docs/protocol.md, "Errors"). Services return *Problem values and the HTTP
// layer writes them as they are.
package problem

import (
	"fmt"
	"net/http"
	"strings"
)

// Codes from docs/protocol.md. Callers branch on these; titles and details are for humans.
const (
	InvalidRequest       = "invalid_request"
	InvalidSignature     = "invalid_signature"
	UnknownKey           = "unknown_key"
	StaleTimestamp       = "stale_timestamp"
	ReplayedNonce        = "replayed_nonce"
	Unauthorized         = "unauthorized"
	InstanceNotVerified  = "instance_not_verified"
	InstanceBlocked      = "instance_blocked"
	VerificationFailed   = "verification_failed"
	InstanceNotFound     = "instance_not_found"
	KeyNotFound          = "key_not_found"
	NotFound             = "not_found"
	MethodNotAllowed     = "method_not_allowed"
	Conflict             = "conflict"
	PayloadTooLarge      = "payload_too_large"
	UnsupportedMediaType = "unsupported_media_type"
	RateLimited          = "rate_limited"
	InternalError        = "internal_error"
	ProviderUnavailable  = "provider_unavailable"
)

const typeBase = "https://gotalk.app/problems/"

// statusCodes maps an HTTP status to the code used when no specific code applies.
var statusCodes = map[int]string{
	http.StatusBadRequest:            InvalidRequest,
	http.StatusUnprocessableEntity:   InvalidRequest,
	http.StatusUnauthorized:          Unauthorized,
	http.StatusNotFound:              NotFound,
	http.StatusMethodNotAllowed:      MethodNotAllowed,
	http.StatusConflict:              Conflict,
	http.StatusRequestEntityTooLarge: PayloadTooLarge,
	http.StatusUnsupportedMediaType:  UnsupportedMediaType,
	http.StatusTooManyRequests:       RateLimited,
	http.StatusInternalServerError:   InternalError,
	http.StatusServiceUnavailable:    ProviderUnavailable,
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

	// headers are extra response headers, such as Retry-After.
	headers http.Header
}

type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (p *Problem) Error() string             { return p.Code + ": " + p.Detail }
func (p *Problem) GetStatus() int            { return p.Status }
func (p *Problem) ContentType(string) string { return "application/problem+json" }

// GetHeaders returns extra response headers. huma writes them with the problem.
func (p *Problem) GetHeaders() http.Header { return p.headers }

// WithHeader adds a response header and returns p.
func (p *Problem) WithHeader(name, value string) *Problem {
	if p.headers == nil {
		p.headers = http.Header{}
	}
	p.headers.Set(name, value)
	return p
}

// New builds a problem. An empty code is derived from the status.
func New(status int, code, detail string) *Problem {
	if code == "" {
		code = CodeForStatus(status)
	}
	return &Problem{
		Type:   typeBase + strings.ReplaceAll(code, "_", "-"),
		Title:  http.StatusText(status),
		Status: status,
		Code:   code,
		Detail: detail,
	}
}

// Newf builds a problem with a formatted detail.
func Newf(status int, code, format string, args ...any) *Problem {
	return New(status, code, fmt.Sprintf(format, args...))
}

// Invalid is a 422 invalid_request with one field error.
func Invalid(field, message string) *Problem {
	p := New(http.StatusUnprocessableEntity, InvalidRequest, "Request validation failed.")
	p.Errors = []FieldError{{Field: field, Message: message}}
	return p
}

func CodeForStatus(status int) string {
	if c, ok := statusCodes[status]; ok {
		return c
	}
	if status >= 500 {
		return InternalError
	}
	return InvalidRequest
}

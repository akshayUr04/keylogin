// pkg/apierror/apierror.go
// Defines a canonical, JSON-serialisable error type used by all HTTP
// handlers.  Clients receive a consistent error envelope regardless of
// where in the stack the error originated.
package apierror

import (
	"encoding/json"
	"net/http"
)

// Error codes used across the application.
const (
	CodeUnauthorized   = "UNAUTHORIZED"
	CodeForbidden      = "FORBIDDEN"
	CodeNotFound       = "NOT_FOUND"
	CodeBadRequest     = "BAD_REQUEST"
	CodeConflict       = "CONFLICT"
	CodeInternal       = "INTERNAL_ERROR"
	CodeValidation     = "VALIDATION_ERROR"
	CodeTenantNotFound = "TENANT_NOT_FOUND"
	CodeRateLimited    = "RATE_LIMITED"
)

// APIError is the canonical error structure returned to clients.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
	// HTTPStatus is NOT serialised to JSON – only used internally to set
	// the response status code.
	HTTPStatus int `json:"-"`
}

func (e *APIError) Error() string { return e.Message }

// ── Constructors ─────────────────────────────────────────────────────────────

func New(httpStatus int, code, message string) *APIError {
	return &APIError{HTTPStatus: httpStatus, Code: code, Message: message}
}

func Unauthorized(msg string) *APIError {
	return New(http.StatusUnauthorized, CodeUnauthorized, msg)
}

func Forbidden(msg string) *APIError {
	return New(http.StatusForbidden, CodeForbidden, msg)
}

func NotFound(msg string) *APIError {
	return New(http.StatusNotFound, CodeNotFound, msg)
}

func BadRequest(msg string) *APIError {
	return New(http.StatusBadRequest, CodeBadRequest, msg)
}

func Conflict(msg string) *APIError {
	return New(http.StatusConflict, CodeConflict, msg)
}

func Internal(msg string) *APIError {
	return New(http.StatusInternalServerError, CodeInternal, msg)
}

func Validation(msg string, details any) *APIError {
	e := New(http.StatusUnprocessableEntity, CodeValidation, msg)
	e.Details = details
	return e
}

func RateLimited() *APIError {
	return New(http.StatusTooManyRequests, CodeRateLimited, "rate limit exceeded – please slow down")
}

// ── HTTP helpers ─────────────────────────────────────────────────────────────

// Write serialises the error to the ResponseWriter with the correct HTTP
// status code.
func Write(w http.ResponseWriter, err *APIError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.HTTPStatus)
	_ = json.NewEncoder(w).Encode(err)
}

// WriteHTTP creates and writes a one-shot APIError without needing to
// construct one explicitly.
func WriteHTTP(w http.ResponseWriter, httpStatus int, code, msg string) {
	Write(w, New(httpStatus, code, msg))
}

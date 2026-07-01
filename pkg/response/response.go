// pkg/response/response.go
// Standardised HTTP response helpers used by all HTTP handlers.
// Keeps the JSON envelope consistent across every endpoint.
package response

import (
	"encoding/json"
	"net/http"
)

// envelope wraps every successful response.
type envelope struct {
	Success bool `json:"success"`
	Data    any  `json:"data,omitempty"`
	Meta    any  `json:"meta,omitempty"`
}

// JSON writes a 200 OK JSON response.
func JSON(w http.ResponseWriter, data any) {
	JSONWithStatus(w, http.StatusOK, data)
}

// JSONCreated writes a 201 Created JSON response.
func JSONCreated(w http.ResponseWriter, data any) {
	JSONWithStatus(w, http.StatusCreated, data)
}

// JSONWithStatus writes a JSON response with the given HTTP status code.
func JSONWithStatus(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(envelope{Success: true, Data: data})
}

// JSONWithMeta writes a JSON response that includes pagination metadata.
func JSONWithMeta(w http.ResponseWriter, data, meta any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(envelope{Success: true, Data: data, Meta: meta})
}

// NoContent writes a 204 No Content response.
func NoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// PaginationMeta is the standard pagination metadata attached to list
// responses.
type PaginationMeta struct {
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// internal/auth/context.go
// Context key definitions and helper functions for attaching / extracting
// authentication data from request contexts.
//
// Using typed context keys (not plain strings) prevents key collisions
// between different packages that both store data in the context.
package auth

import "context"

// contextKey is an unexported type used for context keys in this package.
// Using a distinct type prevents key collisions with other packages.
type contextKey int

const (
	// claimsKey stores the verified *Claims in the request context.
	claimsKey contextKey = iota

	// realmKey stores the resolved tenant realm name in the context.
	realmKey

	// requestIDKey stores the per-request unique ID.
	requestIDKey
)

// WithClaims attaches verified JWT claims to a context.
func WithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

// ClaimsFromContext extracts the verified JWT claims from a context.
// Returns nil if no claims are present (unauthenticated request).
func ClaimsFromContext(ctx context.Context) *Claims {
	c, _ := ctx.Value(claimsKey).(*Claims)
	return c
}

// WithRealm attaches a resolved realm name to a context.
func WithRealm(ctx context.Context, realm string) context.Context {
	return context.WithValue(ctx, realmKey, realm)
}

// RealmFromContext extracts the realm name from a context.
func RealmFromContext(ctx context.Context) string {
	r, _ := ctx.Value(realmKey).(string)
	return r
}

// WithRequestID attaches a unique request ID to a context.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestIDFromContext extracts the request ID from a context.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

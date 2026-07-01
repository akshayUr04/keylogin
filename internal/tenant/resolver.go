// internal/tenant/resolver.go
// Tenant Resolver system.
//
// A Tenant Resolver determines which tenant (Keycloak realm) a given HTTP
// request belongs to.  The CompositeResolver tries multiple strategies in
// order – the first one that returns a non-empty realm wins.
//
// Built-in strategies:
//   1. SubdomainResolver  – extracts tenant from the request's Host header
//      (e.g. acmecorp.saas.example.com → "acmecorp")
//   2. HeaderResolver     – reads X-Tenant-Realm header (useful for testing
//      and API clients that cannot use subdomains)
//   3. QueryParamResolver – reads ?realm=<name> from the URL (last resort)
//
// Adding a new strategy: implement the Resolver interface and append it to
// the CompositeResolver.
package tenant

import (
	"net/http"
	"strings"
)

// Resolver is the interface every tenant resolution strategy must implement.
type Resolver interface {
	// Resolve returns the realm name for the given request, or "" if this
	// strategy cannot determine the tenant.
	Resolve(r *http.Request) string
}

// ── Composite resolver ───────────────────────────────────────────────────────

// CompositeResolver tries each nested Resolver in order and returns the
// first non-empty result.
type CompositeResolver struct {
	resolvers []Resolver
}

// NewCompositeResolver creates a CompositeResolver from the provided strategies.
func NewCompositeResolver(resolvers ...Resolver) *CompositeResolver {
	return &CompositeResolver{resolvers: resolvers}
}

// Resolve iterates through the nested resolvers until one succeeds.
func (c *CompositeResolver) Resolve(r *http.Request) string {
	for _, res := range c.resolvers {
		if realm := res.Resolve(r); realm != "" {
			return realm
		}
	}
	return ""
}

// ── Subdomain resolver ───────────────────────────────────────────────────────

// SubdomainResolver extracts the tenant realm from the first label of the
// Host header.  Given baseDomain "saas.example.com":
//   - "acme.saas.example.com" → "acme"
//   - "saas.example.com"      → "" (no tenant prefix)
//   - "localhost:8080"        → "" (development – skipped)
type SubdomainResolver struct {
	baseDomain string // e.g. "saas.example.com"
}

// NewSubdomainResolver creates a SubdomainResolver for the given base domain.
func NewSubdomainResolver(baseDomain string) *SubdomainResolver {
	return &SubdomainResolver{baseDomain: strings.ToLower(strings.TrimRight(baseDomain, "."))}
}

// Resolve extracts the subdomain component from the Host header.
func (s *SubdomainResolver) Resolve(r *http.Request) string {
	host := strings.ToLower(r.Host)
	// Strip port if present
	if idx := strings.LastIndex(host, ":"); idx >= 0 {
		host = host[:idx]
	}

	if !strings.HasSuffix(host, "."+s.baseDomain) {
		return ""
	}

	prefix := strings.TrimSuffix(host, "."+s.baseDomain)
	// Must be a single label (no dots) to be a valid tenant subdomain
	if strings.Contains(prefix, ".") || prefix == "" {
		return ""
	}
	return prefix
}

// ── Header resolver ──────────────────────────────────────────────────────────

// HeaderResolver reads the X-Tenant-Realm request header.
// Useful for API clients, test suites, and API gateways that cannot use
// subdomains.
type HeaderResolver struct{}

// NewHeaderResolver creates a HeaderResolver.
func NewHeaderResolver() *HeaderResolver { return &HeaderResolver{} }

// Resolve reads the X-Tenant-Realm header.
func (h *HeaderResolver) Resolve(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Tenant-Realm"))
}

// ── Query-parameter resolver ─────────────────────────────────────────────────

// QueryParamResolver reads the "realm" query parameter.
// This should only be used during development or for debugging – it is
// a lower-trust signal than the Host header.
type QueryParamResolver struct{}

// NewQueryParamResolver creates a QueryParamResolver.
func NewQueryParamResolver() *QueryParamResolver { return &QueryParamResolver{} }

// Resolve reads the "realm" query parameter.
func (q *QueryParamResolver) Resolve(r *http.Request) string {
	return strings.TrimSpace(r.URL.Query().Get("realm"))
}

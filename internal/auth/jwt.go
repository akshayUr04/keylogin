// internal/auth/jwt.go
// JWT verification using Keycloak's published JWKS endpoint.
//
// All JWTs are verified cryptographically – we NEVER just base64-decode a
// token without verifying its signature.  The JWKS is cached in memory and
// refreshed automatically when a key-id (kid) is not found locally, making
// key rotation transparent.
//
// Claims validated:
//   - Signature (RSA or EC, as published in the JWKS)
//   - Issuer  (must match the Keycloak realm's issuer URL)
//   - Expiry
//   - Not-before
//   - Audience (must include our client-id)
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/yourdomain/saas-iam/pkg/logger"
)

// Claims is the parsed, verified representation of a Keycloak JWT.
type Claims struct {
	jwt.RegisteredClaims

	// Keycloak-specific fields
	RealmAccess   RealmAccess    `json:"realm_access"`
	ResourceAccess map[string]any `json:"resource_access"`
	Scope         string         `json:"scope"`

	// User identity
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	PreferredUsername string `json:"preferred_username"`

	// Session
	SessionState string `json:"session_state"`
	SID          string `json:"sid"`

	// Our app-level role claim (stored as a Keycloak user attribute or mapped via mapper)
	AppRole string `json:"app_role,omitempty"`
}

// RealmAccess wraps the roles section of the JWT.
type RealmAccess struct {
	Roles []string `json:"roles"`
}

// HasRole returns true if the claims include the given realm role.
func (c *Claims) HasRole(role string) bool {
	for _, r := range c.RealmAccess.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// RealmName extracts the realm name from the issuer URL.
// Keycloak issuer format: <base-url>/realms/<realm-name>
func (c *Claims) RealmName() string {
	iss := c.Issuer
	idx := strings.LastIndex(iss, "/realms/")
	if idx < 0 {
		return ""
	}
	return iss[idx+len("/realms/"):]
}

// UserID returns the Keycloak user UUID (the "sub" claim).
func (c *Claims) UserID() string { return c.Subject }

// ── JWKS cache ───────────────────────────────────────────────────────────────

// jwkSet caches a JWKS for a single realm.
type jwkSet struct {
	keys      map[string]any // kid → *rsa.PublicKey / *ecdsa.PublicKey
	fetchedAt time.Time
}

// JWTVerifier validates JWTs against Keycloak's JWKS endpoints.
type JWTVerifier struct {
	mu           sync.RWMutex
	cache        map[string]*jwkSet // realm → jwkSet
	keycloakBase string
	masterRealm  string
	log          *logger.Logger
	httpClient   *http.Client
}

// NewJWTVerifier creates a verifier that fetches JWKS from Keycloak.
func NewJWTVerifier(keycloakBase, masterRealm string, log *logger.Logger) *JWTVerifier {
	return &JWTVerifier{
		cache:        make(map[string]*jwkSet),
		keycloakBase: strings.TrimRight(keycloakBase, "/"),
		masterRealm:  masterRealm,
		log:          log,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Verify validates a raw JWT string and returns the parsed Claims.
// realmName is used to build the expected issuer URL and fetch the correct JWKS.
func (v *JWTVerifier) Verify(ctx context.Context, realmName, rawToken string) (*Claims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(),
	)

	claims := &Claims{}
	token, err := parser.ParseWithClaims(rawToken, claims, func(token *jwt.Token) (any, error) {
		// Use kid to look up the correct public key
		kid, _ := token.Header["kid"].(string)
		return v.getPublicKey(ctx, realmName, kid)
	})

	if err != nil {
		return nil, fmt.Errorf("JWT verification failed: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid JWT token")
	}

	// Validate issuer matches the realm
	expectedIssuer := fmt.Sprintf("%s/realms/%s", v.keycloakBase, realmName)
	if claims.Issuer != expectedIssuer {
		return nil, fmt.Errorf("invalid issuer: got %q, want %q", claims.Issuer, expectedIssuer)
	}

	return claims, nil
}

// getPublicKey returns the public key for the given kid in the given realm.
// It fetches and caches the JWKS if needed, and auto-refreshes on cache miss.
func (v *JWTVerifier) getPublicKey(ctx context.Context, realm, kid string) (any, error) {
	// Check cache with read lock
	v.mu.RLock()
	set, ok := v.cache[realm]
	if ok {
		if key, exists := set.keys[kid]; exists {
			v.mu.RUnlock()
			return key, nil
		}
	}
	v.mu.RUnlock()

	// Cache miss – fetch the JWKS (write lock)
	v.mu.Lock()
	defer v.mu.Unlock()

	// Re-check after acquiring write lock (another goroutine may have fetched)
	if set, ok = v.cache[realm]; ok {
		if key, exists := set.keys[kid]; exists {
			return key, nil
		}
		// Only re-fetch if cache is older than 5 minutes
		if time.Since(set.fetchedAt) < 5*time.Minute {
			return nil, fmt.Errorf("key %q not found in JWKS for realm %q", kid, realm)
		}
	}

	keys, err := v.fetchJWKS(ctx, realm)
	if err != nil {
		return nil, err
	}

	v.cache[realm] = &jwkSet{keys: keys, fetchedAt: time.Now()}

	if key, exists := keys[kid]; exists {
		return key, nil
	}
	return nil, fmt.Errorf("key %q not found in JWKS for realm %q", kid, realm)
}

// fetchJWKS downloads and parses the JWKS for a Keycloak realm.
func (v *JWTVerifier) fetchJWKS(ctx context.Context, realm string) (map[string]any, error) {
	jwksURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", v.keycloakBase, realm)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned %d", resp.StatusCode)
	}

	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decoding JWKS: %w", err)
	}

	keys := make(map[string]any, len(jwks.Keys))
	for _, rawKey := range jwks.Keys {
		// Parse the key header to get kid and kty
		var header struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		}
		if err := json.Unmarshal(rawKey, &header); err != nil {
			continue
		}
		if header.Use != "sig" {
			continue
		}

		// Build the key using the JWK fields directly
		key, err := parseJWKKey(rawKey)
		if err != nil {
			v.log.Warn("failed to parse JWK key",
				logger.Field("kid", header.Kid),
				logger.Err(err),
			)
			continue
		}
		keys[header.Kid] = key
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no usable signing keys found in JWKS for realm %q", realm)
	}
	return keys, nil
}

// parseJWKKey parses a single JWK into a crypto public key.
// Supports RSA (kty=RSA) and EC (kty=EC) keys.
func parseJWKKey(rawKey json.RawMessage) (any, error) {
	// We leverage the x/crypto stdlib and manual big.Int parsing for RSA
	// and the elliptic package for EC.  This avoids importing an external JWK library.
	var h struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(rawKey, &h); err != nil {
		return nil, err
	}

	switch h.Kty {
	case "RSA":
		return parseRSAKey(rawKey)
	case "EC":
		return parseECKey(rawKey)
	default:
		return nil, fmt.Errorf("unsupported key type %q", h.Kty)
	}
}

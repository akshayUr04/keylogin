// internal/keycloak/client.go
// Keycloak Admin REST API client.
//
// This package is the ONLY place in the application that communicates with
// Keycloak directly.  Every other package goes through this interface.
// The client automatically manages admin access tokens (including refresh)
// so callers never have to handle token lifecycle.
//
// Design decisions:
//   - HTTP transport is the standard library net/http (no external SDKs).
//   - Token refresh is handled transparently by a token manager goroutine.
//   - All errors are wrapped with context so callers can make informed decisions.
//   - Retries are applied to transient 5xx responses with exponential back-off.
package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/yourdomain/saas-iam/pkg/logger"
)

// Config holds the coordinates for the Keycloak server.
type Config struct {
	BaseURL      string // e.g. "http://localhost:8080"
	AdminUser    string // master-realm admin username
	AdminPass    string // master-realm admin password
	MasterRealm  string // usually "master"
	ClientID     string // backend client id
	ClientSecret string // backend client secret
}

// adminToken stores a Keycloak admin access token and its expiry.
type adminToken struct {
	mu          sync.RWMutex
	accessToken string
	expiresAt   time.Time
}

// Client is the Keycloak Admin REST API client.
type Client struct {
	cfg    Config
	http   *http.Client
	token  adminToken
	log    *logger.Logger
}

// NewClient constructs a fully initialised Keycloak client.
func NewClient(cfg Config, log *logger.Logger) *Client {
	return &Client{
		cfg: cfg,
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:       50,
				MaxConnsPerHost:    50,
				IdleConnTimeout:    90 * time.Second,
				DisableCompression: false,
			},
		},
		log: log,
	}
}

// ── Admin token management ───────────────────────────────────────────────────

// ensureAdminToken obtains or refreshes the Keycloak master-realm admin token.
// This is called internally before every API request.
func (c *Client) ensureAdminToken(ctx context.Context) (string, error) {
	c.token.mu.RLock()
	if time.Now().Before(c.token.expiresAt.Add(-30 * time.Second)) {
		tok := c.token.accessToken
		c.token.mu.RUnlock()
		return tok, nil
	}
	c.token.mu.RUnlock()

	// Upgrade to write lock and re-fetch
	c.token.mu.Lock()
	defer c.token.mu.Unlock()

	// Double-checked locking
	if time.Now().Before(c.token.expiresAt.Add(-30 * time.Second)) {
		return c.token.accessToken, nil
	}

	tok, expiresIn, err := c.fetchAdminToken(ctx)
	if err != nil {
		return "", fmt.Errorf("refreshing admin token: %w", err)
	}

	c.token.accessToken = tok
	c.token.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	return tok, nil
}

// fetchAdminToken performs the Resource Owner Password Credentials (ROPC)
// grant against the Keycloak master realm to obtain an admin access token.
// ROPC is acceptable here because this is a server-side backend-to-backend
// call using the platform super-admin credentials, not an end-user flow.
func (c *Client) fetchAdminToken(ctx context.Context) (string, int, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
		strings.TrimRight(c.cfg.BaseURL, "/"), c.cfg.MasterRealm)

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "admin-cli")
	form.Set("username", c.cfg.AdminUser)
	form.Set("password", c.cfg.AdminPass)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", 0, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, body)
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", 0, fmt.Errorf("decoding token response: %w", err)
	}

	return result.AccessToken, result.ExpiresIn, nil
}

// ── Generic HTTP helpers ─────────────────────────────────────────────────────

// doAdminRequest performs an authenticated request to the Keycloak Admin REST
// API, injecting the admin Bearer token automatically.
func (c *Client) doAdminRequest(ctx context.Context, method, path string, body any) (*http.Response, error) {
	adminToken, err := c.ensureAdminToken(ctx)
	if err != nil {
		return nil, err
	}

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshalling request body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	fullURL := strings.TrimRight(c.cfg.BaseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Simple retry logic – up to 3 attempts for 5xx errors
	var resp *http.Response
	for attempt := 1; attempt <= 3; attempt++ {
		resp, err = c.http.Do(req)
		if err == nil && resp.StatusCode < 500 {
			break
		}
		if attempt < 3 {
			time.Sleep(time.Duration(attempt*attempt) * 200 * time.Millisecond)
			// Re-clone request (body already buffered, re-use original reader)
			if body != nil {
				b, _ := json.Marshal(body)
				req.Body = io.NopCloser(bytes.NewReader(b))
			}
		}
	}
	return resp, err
}

// decodeOrError reads a JSON response body into dest, or returns an error
// if the response status is not in the 2xx range.
func decodeOrError(resp *http.Response, dest any) error {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Attempt to parse a Keycloak error response
		var kcErr struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"errorMessage"`
		}
		_ = json.Unmarshal(body, &kcErr)
		msg := kcErr.ErrorDescription
		if msg == "" {
			msg = kcErr.Error
		}
		if msg == "" {
			msg = string(body)
		}
		return &KCError{StatusCode: resp.StatusCode, Message: msg}
	}

	if dest != nil && len(body) > 0 {
		if err := json.Unmarshal(body, dest); err != nil {
			return fmt.Errorf("decoding JSON (%d bytes): %w", len(body), err)
		}
	}
	return nil
}

// KCError is returned when Keycloak responds with a non-2xx status.
type KCError struct {
	StatusCode int
	Message    string
}

func (e *KCError) Error() string {
	return fmt.Sprintf("keycloak error %d: %s", e.StatusCode, e.Message)
}

// IsNotFound returns true when the Keycloak error represents a 404.
func IsNotFound(err error) bool {
	if ke, ok := err.(*KCError); ok {
		return ke.StatusCode == http.StatusNotFound
	}
	return false
}

// IsConflict returns true when the Keycloak error represents a 409.
func IsConflict(err error) bool {
	if ke, ok := err.(*KCError); ok {
		return ke.StatusCode == http.StatusConflict
	}
	return false
}

// adminPath builds an Admin REST API path under /admin/realms/…
func adminPath(realm, resource string) string {
	return fmt.Sprintf("/admin/realms/%s/%s", realm, resource)
}

// ── User-token authentication (for end-user login) ──────────────────────────

// TokenResponse is returned by Keycloak's token endpoint.
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	TokenType        string `json:"token_type"`
	IDToken          string `json:"id_token"`
	Scope            string `json:"scope"`
}

// Login performs a Resource Owner Password Credentials grant for an end user
// against the specified realm.  Returns the token set on success.
//
// NOTE: ROPC is used here because we own the login page and never expose
// the Keycloak login UI to end users.  The credentials are never stored.
func (c *Client) Login(ctx context.Context, realm, username, password string) (*TokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
		strings.TrimRight(c.cfg.BaseURL, "/"), realm)

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", c.cfg.ClientID)
	form.Set("client_secret", c.cfg.ClientSecret)
	form.Set("username", username)
	form.Set("password", password)
	form.Set("scope", "openid profile email offline_access")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("login request: %w", err)
	}

	var tr TokenResponse
	if err := decodeOrError(resp, &tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

// RefreshToken exchanges a refresh token for a new token set.
func (c *Client) RefreshToken(ctx context.Context, realm, refreshToken string) (*TokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
		strings.TrimRight(c.cfg.BaseURL, "/"), realm)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", c.cfg.ClientID)
	form.Set("client_secret", c.cfg.ClientSecret)
	form.Set("refresh_token", refreshToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh token request: %w", err)
	}

	var tr TokenResponse
	if err := decodeOrError(resp, &tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

// Logout revokes the refresh token and terminates the Keycloak session.
func (c *Client) Logout(ctx context.Context, realm, refreshToken string) error {
	logoutURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/logout",
		strings.TrimRight(c.cfg.BaseURL, "/"), realm)

	form := url.Values{}
	form.Set("client_id", c.cfg.ClientID)
	form.Set("client_secret", c.cfg.ClientSecret)
	form.Set("refresh_token", refreshToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, logoutURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("logout request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("logout returned %d: %s", resp.StatusCode, body)
	}
	return nil
}

// ExchangeCode exchanges an authorization code (from PKCE flow) for tokens.
// This uses the authorization_code grant type with code_verifier (PKCE).
// No client_secret is required because the Keycloak client is configured
// as a public client with PKCE enforcement.
func (c *Client) ExchangeCode(ctx context.Context, realm, clientID, code, codeVerifier, redirectURI string) (*TokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
		strings.TrimRight(c.cfg.BaseURL, "/"), realm)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	form.Set("code", code)
	form.Set("code_verifier", codeVerifier)
	form.Set("redirect_uri", redirectURI)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("code exchange request: %w", err)
	}

	var tr TokenResponse
	if err := decodeOrError(resp, &tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

// RefreshTokenPublic exchanges a refresh token using a public client (no secret).
// Used by the PKCE flow where clients don't have a client_secret.
func (c *Client) RefreshTokenPublic(ctx context.Context, realm, clientID, refreshToken string) (*TokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
		strings.TrimRight(c.cfg.BaseURL, "/"), realm)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", clientID)
	form.Set("refresh_token", refreshToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("public refresh token request: %w", err)
	}

	var tr TokenResponse
	if err := decodeOrError(resp, &tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

// LogoutPublic revokes the refresh token using a public client (no secret).
func (c *Client) LogoutPublic(ctx context.Context, realm, clientID, refreshToken string) error {
	logoutURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/logout",
		strings.TrimRight(c.cfg.BaseURL, "/"), realm)

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("refresh_token", refreshToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, logoutURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("public logout request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("public logout returned %d: %s", resp.StatusCode, body)
	}
	return nil
}

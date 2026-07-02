// internal/services/auth_service.go
// Authentication service.
//
// Handles the full lifecycle of user authentication:
//   - PKCE Authorization initiation (generates state + code_verifier)
//   - PKCE Callback (exchanges code for tokens, creates session)
//   - Token refresh (transparently swaps expired access tokens via PKCE public client)
//   - Logout (revokes refresh token + destroys local session)
//   - Session validation
//
// The service never stores raw passwords and never returns Keycloak tokens
// directly to the frontend – instead it issues an opaque session ID cookie
// that the session repository maps to the real token set.
package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/yourdomain/saas-iam/config"
	"github.com/yourdomain/saas-iam/internal/auth"
	"github.com/yourdomain/saas-iam/internal/keycloak"
	"github.com/yourdomain/saas-iam/internal/repository"
	"github.com/yourdomain/saas-iam/pkg/logger"
)

// AuthService provides authentication operations.
type AuthService struct {
	kc          *keycloak.Client
	sessionSvc  *SessionService
	pkceRepo    *repository.PKCERepository
	jwtVerifier *auth.JWTVerifier
	cfg         *config.Config
	log         *logger.Logger
}

// NewAuthService constructs an AuthService.
func NewAuthService(
	kc *keycloak.Client,
	sessionSvc *SessionService,
	pkceRepo *repository.PKCERepository,
	jwtVerifier *auth.JWTVerifier,
	cfg *config.Config,
	log *logger.Logger,
) *AuthService {
	return &AuthService{
		kc:          kc,
		sessionSvc:  sessionSvc,
		pkceRepo:    pkceRepo,
		jwtVerifier: jwtVerifier,
		cfg:         cfg,
		log:         log,
	}
}

// LoginResult is returned after a successful login.
type LoginResult struct {
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	AppRole   string `json:"app_role"`
	RealmName string `json:"realm_name"`
	ExpiresIn int    `json:"expires_in"`
}

// ── PKCE Flow ──────────────────────────────────────────────────────────────────

// PKCEAuthorizeResult contains the URL to redirect the user to for authentication.
type PKCEAuthorizeResult struct {
	AuthorizationURL string `json:"authorization_url"`
	State            string `json:"state"`
}

// InitiatePKCE generates PKCE parameters and returns the Keycloak authorization URL.
// The code_verifier is stored server-side in Redis (never sent to the browser).
// portal is either "admin" or "user" to determine which client/redirect to use.
func (s *AuthService) InitiatePKCE(ctx context.Context, portal, realm string) (*PKCEAuthorizeResult, error) {
	// 1. Generate cryptographically random code_verifier (43-128 chars, base64url)
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("generating code verifier: %w", err)
	}

	// 2. Compute code_challenge = BASE64URL(SHA256(code_verifier))
	codeChallenge := computeCodeChallenge(codeVerifier)

	// 3. Generate random state parameter
	state, err := generateRandomState()
	if err != nil {
		return nil, fmt.Errorf("generating state: %w", err)
	}

	// 4. Determine client ID and redirect URI based on portal type
	var clientID, redirectURI string
	switch portal {
	case "admin":
		clientID = s.cfg.PKCEAdminClientID
		redirectURI = s.cfg.PKCEAdminRedirectURL
		if realm == "" {
			realm = s.cfg.KeycloakMasterRealm
		}
	case "user":
		clientID = s.cfg.PKCEUserClientID
		redirectURI = s.cfg.PKCEUserRedirectURL
	default:
		return nil, fmt.Errorf("invalid portal type %q, must be 'admin' or 'user'", portal)
	}

	if realm == "" {
		return nil, fmt.Errorf("realm is required for PKCE flow")
	}

	// 5. Store PKCE state in Redis (server-side only, 5-min TTL)
	pkceState := &repository.PKCEState{
		State:        state,
		CodeVerifier: codeVerifier,
		Realm:        realm,
		ClientID:     clientID,
		RedirectURI:  redirectURI,
		Portal:       portal,
	}
	if err := s.pkceRepo.Save(ctx, pkceState); err != nil {
		return nil, fmt.Errorf("saving PKCE state: %w", err)
	}

	// 6. Build Keycloak authorization URL
	// Use the frontend URL (what the browser sees), not the internal backend URL
	authURL := fmt.Sprintf(
		"%s/realms/%s/protocol/openid-connect/auth?"+
			"response_type=code"+
			"&client_id=%s"+
			"&redirect_uri=%s"+
			"&state=%s"+
			"&code_challenge=%s"+
			"&code_challenge_method=S256"+
			"&scope=openid+profile+email+offline_access",
		strings.TrimRight(s.cfg.KeycloakFrontendURL, "/"),
		realm,
		clientID,
		redirectURI,
		state,
		codeChallenge,
	)

	return &PKCEAuthorizeResult{
		AuthorizationURL: authURL,
		State:            state,
	}, nil
}

// HandlePKCECallback processes the Keycloak callback with the authorization code.
// It exchanges the code for tokens using the stored code_verifier, verifies
// the JWT, and creates a session.
func (s *AuthService) HandlePKCECallback(ctx context.Context, code, state, ipAddress, userAgent string) (*LoginResult, error) {
	// 1. Retrieve and consume the PKCE state (atomic get-and-delete)
	pkceState, err := s.pkceRepo.Consume(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("consuming PKCE state: %w", err)
	}
	if pkceState == nil {
		return nil, fmt.Errorf("invalid or expired PKCE state")
	}

	// 2. Exchange the authorization code + code_verifier for tokens
	tokens, err := s.kc.ExchangeCode(
		ctx,
		pkceState.Realm,
		pkceState.ClientID,
		code,
		pkceState.CodeVerifier,
		pkceState.RedirectURI,
	)
	if err != nil {
		return nil, fmt.Errorf("code exchange failed: %w", err)
	}

	// 3. Verify and parse the access token
	claims, err := s.jwtVerifier.Verify(ctx, pkceState.Realm, tokens.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	// 4. Determine the application-level role from realm roles
	appRole := resolveAppRole(claims)

	// 5. Create a session in Redis
	sessionID := uuid.New().String()
	session := &repository.SessionData{
		SessionID:    sessionID,
		UserID:       claims.UserID(),
		Username:     claims.PreferredUsername,
		Email:        claims.Email,
		RealmName:    pkceState.Realm,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		IDToken:      tokens.IDToken,
		Roles:        claims.RealmAccess.Roles,
		AppRole:      appRole,
		PKCEClientID: pkceState.ClientID,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(s.cfg.SessionTTL),
		LastActiveAt: time.Now(),
	}

	if err := s.sessionSvc.repo.Save(ctx, session, s.cfg.SessionTTL); err != nil {
		return nil, fmt.Errorf("saving session: %w", err)
	}

	return &LoginResult{
		SessionID: sessionID,
		UserID:    claims.UserID(),
		Username:  claims.PreferredUsername,
		Email:     claims.Email,
		AppRole:   appRole,
		RealmName: pkceState.Realm,
		ExpiresIn: tokens.ExpiresIn,
	}, nil
}

// ── Legacy ROPC Login (kept for backend-to-backend, will be deprecated) ─────

// Login authenticates a user against the given Keycloak realm using ROPC.
// Returns an opaque session ID that the client must include in every
// subsequent request (as a cookie or Bearer token).
func (s *AuthService) Login(ctx context.Context, realm, username, password, ipAddress, userAgent string) (*LoginResult, error) {
	// 1. Obtain tokens from Keycloak
	tokens, err := s.kc.Login(ctx, realm, username, password)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// 2. Verify and parse the access token
	claims, err := s.jwtVerifier.Verify(ctx, realm, tokens.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	// 3. Determine the application-level role from realm roles
	appRole := resolveAppRole(claims)

	// 4. Create a session in Redis
	sessionID := uuid.New().String()
	session := &repository.SessionData{
		SessionID:    sessionID,
		UserID:       claims.UserID(),
		Username:     claims.PreferredUsername,
		Email:        claims.Email,
		RealmName:    realm,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		IDToken:      tokens.IDToken,
		Roles:        claims.RealmAccess.Roles,
		AppRole:      appRole,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(s.cfg.SessionTTL),
		LastActiveAt: time.Now(),
	}

	if err := s.sessionSvc.repo.Save(ctx, session, s.cfg.SessionTTL); err != nil {
		return nil, fmt.Errorf("saving session: %w", err)
	}

	return &LoginResult{
		SessionID: sessionID,
		UserID:    claims.UserID(),
		Username:  claims.PreferredUsername,
		Email:     claims.Email,
		AppRole:   appRole,
		RealmName: realm,
		ExpiresIn: tokens.ExpiresIn,
	}, nil
}

// Logout revokes the user's Keycloak refresh token, destroys the local
// session, and returns.  Errors are logged but not returned so that the
// client-side logout always succeeds from the user's perspective.
func (s *AuthService) Logout(ctx context.Context, sessionID string) error {
	session, err := s.sessionSvc.repo.Get(ctx, sessionID)
	if err != nil || session == nil {
		return nil // session already gone
	}

	// Revoke the refresh token in Keycloak (best effort)
	if session.RefreshToken != "" {
		if session.PKCEClientID != "" {
			// PKCE session – use public client logout
			if err := s.kc.LogoutPublic(ctx, session.RealmName, session.PKCEClientID, session.RefreshToken); err != nil {
				s.log.Warn("failed to revoke refresh token via public client",
					logger.Field("session_id", sessionID),
					logger.Err(err),
				)
			}
		} else {
			// Confidential client logout (legacy ROPC)
			if err := s.kc.Logout(ctx, session.RealmName, session.RefreshToken); err != nil {
				s.log.Warn("failed to revoke refresh token in Keycloak",
					logger.Field("session_id", sessionID),
					logger.Err(err),
				)
			}
		}
	}

	// Delete local session
	return s.sessionSvc.repo.Delete(ctx, sessionID)
}

// RefreshSession exchanges the stored refresh token for a new access token
// and updates the session in Redis.
func (s *AuthService) RefreshSession(ctx context.Context, sessionID string) (*repository.SessionData, error) {
	session, err := s.sessionSvc.repo.Get(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("loading session: %w", err)
	}
	if session == nil {
		return nil, fmt.Errorf("session not found or expired")
	}

	var tokens *keycloak.TokenResponse
	if session.PKCEClientID != "" {
		// PKCE session – use public client refresh
		tokens, err = s.kc.RefreshTokenPublic(ctx, session.RealmName, session.PKCEClientID, session.RefreshToken)
	} else {
		// Confidential client refresh (legacy ROPC)
		tokens, err = s.kc.RefreshToken(ctx, session.RealmName, session.RefreshToken)
	}
	if err != nil {
		return nil, fmt.Errorf("refreshing token: %w", err)
	}

	// Re-verify the new access token to get fresh claims
	claims, err := s.jwtVerifier.Verify(ctx, session.RealmName, tokens.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("verifying refreshed token: %w", err)
	}

	// Update session with new tokens
	session.AccessToken = tokens.AccessToken
	session.RefreshToken = tokens.RefreshToken
	session.Roles = claims.RealmAccess.Roles
	session.LastActiveAt = time.Now()

	if err := s.sessionSvc.repo.Save(ctx, session, s.cfg.SessionTTL); err != nil {
		return nil, fmt.Errorf("updating session: %w", err)
	}
	return session, nil
}

// GetSession returns the session data for an active session.
func (s *AuthService) GetSession(ctx context.Context, sessionID string) (*repository.SessionData, error) {
	return s.sessionSvc.repo.Get(ctx, sessionID)
}

// ── PKCE Cryptographic helpers ─────────────────────────────────────────────

// generateCodeVerifier produces a cryptographically random 64-byte
// base64url-encoded string suitable for PKCE code_verifier.
func generateCodeVerifier() (string, error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// computeCodeChallenge computes BASE64URL(SHA256(codeVerifier)).
func computeCodeChallenge(codeVerifier string) string {
	h := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// generateRandomState produces a cryptographically random 32-byte
// base64url-encoded string for the OAuth state parameter.
func generateRandomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ── Role resolution ────────────────────────────────────────────────────────

// resolveAppRole maps Keycloak realm roles to application-level roles.
// Priority: super_admin > realm_admin > end_user.
func resolveAppRole(claims *auth.Claims) string {
	for _, r := range claims.RealmAccess.Roles {
		lower := strings.ToLower(r)
		if lower == "super_admin" || lower == "super-admin" {
			return "super_admin"
		}
	}
	for _, r := range claims.RealmAccess.Roles {
		lower := strings.ToLower(r)
		if lower == "realm_admin" || lower == "realm-admin" || lower == "manage-realm" {
			return "realm_admin"
		}
	}
	return "end_user"
}

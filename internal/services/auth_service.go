// internal/services/auth_service.go
// Authentication service.
//
// Handles the full lifecycle of user authentication:
//   - Login (Resource Owner Password Credentials against the correct realm)
//   - Token refresh (transparently swaps expired access tokens)
//   - Logout (revokes refresh token + destroys local session)
//   - Session validation
//
// The service never stores raw passwords and never returns Keycloak tokens
// directly to the frontend – instead it issues an opaque session ID cookie
// that the session repository maps to the real token set.
package services

import (
	"context"
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
	jwtVerifier *auth.JWTVerifier
	cfg         *config.Config
	log         *logger.Logger
}

// NewAuthService constructs an AuthService.
func NewAuthService(
	kc *keycloak.Client,
	sessionSvc *SessionService,
	jwtVerifier *auth.JWTVerifier,
	cfg *config.Config,
	log *logger.Logger,
) *AuthService {
	return &AuthService{
		kc:          kc,
		sessionSvc:  sessionSvc,
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

// Login authenticates a user against the given Keycloak realm.
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
		if err := s.kc.Logout(ctx, session.RealmName, session.RefreshToken); err != nil {
			s.log.Warn("failed to revoke refresh token in Keycloak",
				logger.Field("session_id", sessionID),
				logger.Err(err),
			)
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

	tokens, err := s.kc.RefreshToken(ctx, session.RealmName, session.RefreshToken)
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

// ── helpers ─────────────────────────────────────────────────────────────────

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

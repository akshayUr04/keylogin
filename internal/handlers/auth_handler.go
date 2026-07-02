// internal/handlers/auth_handler.go
// Authentication HTTP handlers.
// Supports PKCE (Authorization Code + Proof Key for Code Exchange) flow
// for both tenant admin and end-user portals.
package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/yourdomain/saas-iam/internal/audit"
	"github.com/yourdomain/saas-iam/internal/auth"
	"github.com/yourdomain/saas-iam/internal/middleware"
	"github.com/yourdomain/saas-iam/pkg/apierror"
	"github.com/yourdomain/saas-iam/pkg/logger"
	"github.com/yourdomain/saas-iam/pkg/response"
)

// ── PKCE Flow Handlers ──────────────────────────────────────────────────────

// PKCEAdminAuthorize handles GET /admin/login/authorize
// Initiates the PKCE flow for the admin portal.
// Query params: realm (optional, defaults to master)
func (h *Handlers) PKCEAdminAuthorize(w http.ResponseWriter, r *http.Request) {
	realm := r.URL.Query().Get("realm")
	if realm == "" {
		realm = h.deps.Config.KeycloakMasterRealm
	}

	result, err := h.deps.AuthService.InitiatePKCE(r.Context(), "admin", realm)
	if err != nil {
		h.deps.Logger.Error("PKCE admin authorize failed", logger.Err(err))
		apierror.Write(w, apierror.Internal("failed to initiate authentication"))
		return
	}

	// Redirect browser to Keycloak login page
	http.Redirect(w, r, result.AuthorizationURL, http.StatusFound)
}

// PKCEUserAuthorize handles GET /login/authorize
// Initiates the PKCE flow for the end-user portal.
// Query params: realm (required for user login)
func (h *Handlers) PKCEUserAuthorize(w http.ResponseWriter, r *http.Request) {
	realm := r.URL.Query().Get("realm")
	if realm == "" {
		// Try to resolve from tenant context
		realm = auth.RealmFromContext(r.Context())
	}
	if realm == "" {
		apierror.Write(w, apierror.BadRequest("realm is required – provide ?realm= or use a tenant subdomain"))
		return
	}

	result, err := h.deps.AuthService.InitiatePKCE(r.Context(), "user", realm)
	if err != nil {
		h.deps.Logger.Error("PKCE user authorize failed", logger.Err(err))
		apierror.Write(w, apierror.Internal("failed to initiate authentication"))
		return
	}

	// Redirect browser to Keycloak login page
	http.Redirect(w, r, result.AuthorizationURL, http.StatusFound)
}

// PKCEAdminCallback handles GET /admin/callback
// Receives the authorization code from Keycloak after admin login.
func (h *Handlers) PKCEAdminCallback(w http.ResponseWriter, r *http.Request) {
	h.handlePKCECallback(w, r, "/dashboard/realm-admin.html")
}

// PKCEUserCallback handles GET /user/callback
// Receives the authorization code from Keycloak after user login.
func (h *Handlers) PKCEUserCallback(w http.ResponseWriter, r *http.Request) {
	h.handlePKCECallback(w, r, "/user/dashboard")
}

// handlePKCECallback is the shared callback handler for both admin and user PKCE flows.
func (h *Handlers) handlePKCECallback(w http.ResponseWriter, r *http.Request, successRedirect string) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	kcError := r.URL.Query().Get("error")

	// Handle Keycloak error responses
	if kcError != "" {
		desc := r.URL.Query().Get("error_description")
		h.deps.Logger.Warn("Keycloak returned error in PKCE callback",
			logger.Field("error", kcError),
			logger.Field("description", desc),
		)
		// Redirect back to login with error
		http.Redirect(w, r, "/?error="+kcError, http.StatusFound)
		return
	}

	if code == "" || state == "" {
		apierror.Write(w, apierror.BadRequest("missing code or state parameter"))
		return
	}

	result, err := h.deps.AuthService.HandlePKCECallback(
		r.Context(),
		code,
		state,
		middleware.IPFromRequest(r),
		r.UserAgent(),
	)
	if err != nil {
		h.deps.Logger.Error("PKCE callback failed",
			logger.Err(err),
			logger.Field("state", state),
		)
		http.Redirect(w, r, "/?error=auth_failed", http.StatusFound)
		return
	}

	// Set secure HttpOnly session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    result.SessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.deps.Config.Env != "development",
		SameSite: http.SameSiteLaxMode, // Lax required for OAuth redirects
		Expires:  time.Now().Add(h.deps.Config.SessionTTL),
	})

	// Audit the login event
	h.deps.AuditService.Log(r.Context(), audit.LogEntry{
		ActorID:      result.UserID,
		ActorEmail:   result.Email,
		ActorRole:    result.AppRole,
		Action:       audit.ActionLogin,
		ResourceType: "session",
		Details:      map[string]any{"realm": result.RealmName, "method": "pkce"},
		IPAddress:    middleware.IPFromRequest(r),
		UserAgent:    r.UserAgent(),
	})

	// Determine redirect based on role
	switch result.AppRole {
	case "super_admin":
		successRedirect = "/dashboard/super-admin.html"
	case "realm_admin":
		successRedirect = "/dashboard/realm-admin.html"
	default:
		successRedirect = "/user/dashboard"
	}

	http.Redirect(w, r, successRedirect, http.StatusFound)
}

// ── Session-based endpoints (unchanged) ─────────────────────────────────────

// Logout handles POST /api/v1/auth/logout
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	sessionID := extractSessionID(r)
	if sessionID == "" {
		apierror.Write(w, apierror.Unauthorized("no active session"))
		return
	}

	if err := h.deps.AuthService.Logout(r.Context(), sessionID); err != nil {
		h.deps.Logger.Error("logout error", logger.Err(err))
	}

	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})

	// If Accept header is JSON, return JSON; otherwise redirect to login
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		response.NoContent(w)
	} else {
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// RefreshToken handles POST /api/v1/auth/refresh
func (h *Handlers) RefreshToken(w http.ResponseWriter, r *http.Request) {
	sessionID := extractSessionID(r)
	if sessionID == "" {
		apierror.Write(w, apierror.Unauthorized("no active session"))
		return
	}

	session, err := h.deps.AuthService.RefreshSession(r.Context(), sessionID)
	if err != nil {
		apierror.Write(w, apierror.Unauthorized("session expired or invalid"))
		return
	}

	response.JSON(w, map[string]any{
		"session_id": session.SessionID,
		"user_id":    session.UserID,
		"app_role":   session.AppRole,
		"realm":      session.RealmName,
	})
}

// Me handles GET /api/v1/auth/me
func (h *Handlers) Me(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		apierror.Write(w, apierror.Unauthorized("unauthenticated"))
		return
	}

	response.JSON(w, map[string]any{
		"id":       claims.UserID(),
		"username": claims.PreferredUsername,
		"email":    claims.Email,
		"name":     claims.Name,
		"realm":    claims.RealmName(),
		"roles":    claims.RealmAccess.Roles,
	})
}

// SessionInfo handles GET /api/v1/auth/session – returns session info from cookie.
// Does not require JWT auth middleware – uses the session cookie directly.
func (h *Handlers) SessionInfo(w http.ResponseWriter, r *http.Request) {
	sessionID := extractSessionID(r)
	if sessionID == "" {
		apierror.Write(w, apierror.Unauthorized("no active session"))
		return
	}

	session, err := h.deps.AuthService.GetSession(r.Context(), sessionID)
	if err != nil || session == nil {
		apierror.Write(w, apierror.Unauthorized("session expired"))
		return
	}

	response.JSON(w, map[string]any{
		"user_id":  session.UserID,
		"username": session.Username,
		"email":    session.Email,
		"app_role": session.AppRole,
		"realm":    session.RealmName,
		"roles":    session.Roles,
	})
}

// ── helper ───────────────────────────────────────────────────────────────────

// extractSessionID reads the session ID from the cookie or Authorization header.
func extractSessionID(r *http.Request) string {
	if c, err := r.Cookie("session_id"); err == nil && c.Value != "" {
		return c.Value
	}
	hdr := r.Header.Get("Authorization")
	parts := strings.SplitN(hdr, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "session") {
		return parts[1]
	}
	return ""
}

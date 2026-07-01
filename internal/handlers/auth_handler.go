// internal/handlers/auth_handler.go
// Authentication HTTP handlers.
package handlers

import (
	"encoding/json"
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

// loginRequest is the JSON body sent by the frontend login page.
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Realm    string `json:"realm"` // optional explicit realm name
}

// Login handles POST /api/v1/auth/login
func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.Write(w, apierror.BadRequest("invalid request body"))
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.Realm = strings.TrimSpace(req.Realm)

	if req.Username == "" || req.Password == "" {
		apierror.Write(w, apierror.BadRequest("username and password are required"))
		return
	}

	// Resolve realm: explicit field > tenant resolver > master realm
	realm := req.Realm
	if realm == "" {
		realm = auth.RealmFromContext(r.Context())
	}
	if realm == "" {
		realm = h.deps.Config.KeycloakMasterRealm
	}

	result, err := h.deps.AuthService.Login(
		r.Context(),
		realm,
		req.Username,
		req.Password,
		middleware.IPFromRequest(r),
		r.UserAgent(),
	)
	if err != nil {
		h.deps.Logger.Warn("login failed",
			logger.Field("username", req.Username),
			logger.Field("realm", realm),
			logger.Err(err),
		)
		apierror.Write(w, apierror.Unauthorized("invalid credentials"))
		return
	}

	// Secure HttpOnly session cookie for browser clients
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    result.SessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.deps.Config.Env != "development",
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(h.deps.Config.SessionTTL),
	})

	// Audit the login event
	h.deps.AuditService.Log(r.Context(), audit.LogEntry{
		ActorID:      result.UserID,
		ActorEmail:   result.Email,
		ActorRole:    result.AppRole,
		Action:       audit.ActionLogin,
		ResourceType: "session",
		Details:      map[string]any{"realm": realm},
		IPAddress:    middleware.IPFromRequest(r),
		UserAgent:    r.UserAgent(),
	})

	response.JSON(w, result)
}

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

	response.NoContent(w)
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

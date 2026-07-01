// internal/handlers/user_handler.go
// Realm Admin – User management HTTP handlers.
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/yourdomain/saas-iam/internal/auth"
	"github.com/yourdomain/saas-iam/internal/middleware"
	"github.com/yourdomain/saas-iam/internal/services"
	"github.com/yourdomain/saas-iam/pkg/apierror"
	"github.com/yourdomain/saas-iam/pkg/response"
)

// createUserRequest is the JSON body for user creation.
type createUserRequest struct {
	Username   string              `json:"username"`
	Email      string              `json:"email"`
	FirstName  string              `json:"first_name"`
	LastName   string              `json:"last_name"`
	Password   string              `json:"password"`
	Temporary  bool                `json:"temporary_password"`
	Enabled    bool                `json:"enabled"`
	Attributes map[string][]string `json:"attributes"`
}

// CreateUser handles POST /api/v1/realms/{realm}/users
func (h *Handlers) CreateUser(w http.ResponseWriter, r *http.Request) {
	realm := mux.Vars(r)["realm"]
	if err := h.assertRealmAccess(r, realm); err != nil {
		apierror.Write(w, err)
		return
	}

	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.Write(w, apierror.BadRequest("invalid request body"))
		return
	}
	if req.Email == "" {
		apierror.Write(w, apierror.BadRequest("email is required"))
		return
	}
	if req.Username == "" {
		req.Username = req.Email
	}

	claims := auth.ClaimsFromContext(r.Context())
	user, err := h.deps.UserService.CreateUser(r.Context(), services.CreateUserInput{
		RealmName:  realm,
		Username:   req.Username,
		Email:      req.Email,
		FirstName:  req.FirstName,
		LastName:   req.LastName,
		Password:   req.Password,
		Temporary:  req.Temporary,
		Enabled:    req.Enabled,
		Attributes: req.Attributes,
		ActorID:    claims.UserID(),
		ActorEmail: claims.Email,
		ActorRole:  string(resolveRole(claims)),
		IPAddress:  middleware.IPFromRequest(r),
	})
	if err != nil {
		apierror.Write(w, apierror.BadRequest(err.Error()))
		return
	}
	response.JSONCreated(w, user)
}

// ListUsers handles GET /api/v1/realms/{realm}/users
func (h *Handlers) ListUsers(w http.ResponseWriter, r *http.Request) {
	realm := mux.Vars(r)["realm"]
	if err := h.assertRealmAccess(r, realm); err != nil {
		apierror.Write(w, err)
		return
	}

	search := r.URL.Query().Get("search")
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit == 0 || limit > 100 {
		limit = 20
	}

	users, total, err := h.deps.UserService.ListUsers(r.Context(), realm, search, offset, limit)
	if err != nil {
		apierror.Write(w, apierror.Internal("failed to list users"))
		return
	}

	response.JSONWithMeta(w, users, response.PaginationMeta{Total: total, Limit: limit, Offset: offset})
}

// GetUser handles GET /api/v1/realms/{realm}/users/{id}
func (h *Handlers) GetUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	realm, userID := vars["realm"], vars["id"]
	if err := h.assertRealmAccess(r, realm); err != nil {
		apierror.Write(w, err)
		return
	}

	user, err := h.deps.UserService.GetUser(r.Context(), realm, userID)
	if err != nil {
		apierror.Write(w, apierror.NotFound(err.Error()))
		return
	}
	response.JSON(w, user)
}

// updateUserRequest holds mutable user fields.
type updateUserRequest struct {
	Email      string              `json:"email"`
	FirstName  string              `json:"first_name"`
	LastName   string              `json:"last_name"`
	Attributes map[string][]string `json:"attributes"`
}

// UpdateUser handles PUT /api/v1/realms/{realm}/users/{id}
func (h *Handlers) UpdateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	realm, userID := vars["realm"], vars["id"]
	if err := h.assertRealmAccess(r, realm); err != nil {
		apierror.Write(w, err)
		return
	}

	var req updateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.Write(w, apierror.BadRequest("invalid request body"))
		return
	}

	claims := auth.ClaimsFromContext(r.Context())
	err := h.deps.UserService.UpdateUser(r.Context(), realm, userID, services.UpdateUserInput{
		Email:      req.Email,
		FirstName:  req.FirstName,
		LastName:   req.LastName,
		Attributes: req.Attributes,
		ActorID:    claims.UserID(),
		ActorEmail: claims.Email,
		ActorRole:  string(resolveRole(claims)),
		IPAddress:  middleware.IPFromRequest(r),
	})
	if err != nil {
		apierror.Write(w, apierror.Internal(err.Error()))
		return
	}
	response.NoContent(w)
}

// DeleteUser handles DELETE /api/v1/realms/{realm}/users/{id}
func (h *Handlers) DeleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	realm, userID := vars["realm"], vars["id"]
	if err := h.assertRealmAccess(r, realm); err != nil {
		apierror.Write(w, err)
		return
	}

	claims := auth.ClaimsFromContext(r.Context())
	if err := h.deps.UserService.DeleteUser(r.Context(), realm, userID,
		claims.UserID(), claims.Email, string(resolveRole(claims)), middleware.IPFromRequest(r)); err != nil {
		apierror.Write(w, apierror.NotFound(err.Error()))
		return
	}
	response.NoContent(w)
}

// enableUserRequest specifies whether to enable or disable.
type enableUserRequest struct {
	Enabled bool `json:"enabled"`
}

// SetUserEnabled handles PUT /api/v1/realms/{realm}/users/{id}/enabled
func (h *Handlers) SetUserEnabled(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	realm, userID := vars["realm"], vars["id"]
	if err := h.assertRealmAccess(r, realm); err != nil {
		apierror.Write(w, err)
		return
	}

	var req enableUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.Write(w, apierror.BadRequest("invalid request body"))
		return
	}

	claims := auth.ClaimsFromContext(r.Context())
	if err := h.deps.UserService.EnableUser(r.Context(), realm, userID, req.Enabled,
		claims.UserID(), claims.Email, string(resolveRole(claims)), middleware.IPFromRequest(r)); err != nil {
		apierror.Write(w, apierror.Internal(err.Error()))
		return
	}
	response.NoContent(w)
}

// resetPasswordRequest carries the new password.
type resetPasswordRequest struct {
	Password  string `json:"password"`
	Temporary bool   `json:"temporary"`
}

// ResetUserPassword handles PUT /api/v1/realms/{realm}/users/{id}/reset-password
func (h *Handlers) ResetUserPassword(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	realm, userID := vars["realm"], vars["id"]
	if err := h.assertRealmAccess(r, realm); err != nil {
		apierror.Write(w, err)
		return
	}

	var req resetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.Write(w, apierror.BadRequest("invalid request body"))
		return
	}
	if len(req.Password) < 8 {
		apierror.Write(w, apierror.BadRequest("password must be at least 8 characters"))
		return
	}

	claims := auth.ClaimsFromContext(r.Context())
	if err := h.deps.UserService.ResetPassword(r.Context(), realm, userID, req.Password, req.Temporary,
		claims.UserID(), claims.Email, string(resolveRole(claims)), middleware.IPFromRequest(r)); err != nil {
		apierror.Write(w, apierror.Internal(err.Error()))
		return
	}
	response.NoContent(w)
}

// AssignRoles handles POST /api/v1/realms/{realm}/users/{id}/roles
func (h *Handlers) AssignRoles(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	realm, userID := vars["realm"], vars["id"]
	if err := h.assertRealmAccess(r, realm); err != nil {
		apierror.Write(w, err)
		return
	}

	var req struct {
		Roles []string `json:"roles"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.Write(w, apierror.BadRequest("invalid request body"))
		return
	}

	claims := auth.ClaimsFromContext(r.Context())
	if err := h.deps.UserService.AssignRoles(r.Context(), realm, userID, req.Roles,
		claims.UserID(), claims.Email, string(resolveRole(claims)), middleware.IPFromRequest(r)); err != nil {
		apierror.Write(w, apierror.Internal(err.Error()))
		return
	}
	response.NoContent(w)
}

// RemoveRoles handles DELETE /api/v1/realms/{realm}/users/{id}/roles
func (h *Handlers) RemoveRoles(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	realm, userID := vars["realm"], vars["id"]
	if err := h.assertRealmAccess(r, realm); err != nil {
		apierror.Write(w, err)
		return
	}

	var req struct {
		Roles []string `json:"roles"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.Write(w, apierror.BadRequest("invalid request body"))
		return
	}

	claims := auth.ClaimsFromContext(r.Context())
	if err := h.deps.UserService.RemoveRoles(r.Context(), realm, userID, req.Roles,
		claims.UserID(), claims.Email, string(resolveRole(claims)), middleware.IPFromRequest(r)); err != nil {
		apierror.Write(w, apierror.Internal(err.Error()))
		return
	}
	response.NoContent(w)
}

// GetUserSessions handles GET /api/v1/realms/{realm}/users/{id}/sessions
func (h *Handlers) GetUserSessions(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	realm, userID := vars["realm"], vars["id"]
	if err := h.assertRealmAccess(r, realm); err != nil {
		apierror.Write(w, err)
		return
	}

	sessions, err := h.deps.SessionService.ListUserSessions(r.Context(), realm, userID)
	if err != nil {
		apierror.Write(w, apierror.Internal("failed to list sessions"))
		return
	}
	response.JSON(w, sessions)
}

// ── Helper ────────────────────────────────────────────────────────────────────

// assertRealmAccess verifies that the current user has access to the given realm.
// Super admins can access any realm; realm admins can only access their own.
func (h *Handlers) assertRealmAccess(r *http.Request, targetRealm string) *apierror.APIError {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		return apierror.Unauthorized("unauthenticated")
	}
	if claims.HasRole("super_admin") {
		return nil // super admins can access all realms
	}
	if claims.RealmName() != targetRealm {
		return apierror.Forbidden("access to realm " + targetRealm + " is not permitted")
	}
	return nil
}

// resolveRole is a local alias to resolveRoleStr, defined in helpers.go
func resolveRole(claims *auth.Claims) string {
	return resolveRoleStr(claims)
}

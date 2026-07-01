// internal/handlers/role_handler.go
// Realm Admin – Role management HTTP handlers.
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/yourdomain/saas-iam/internal/auth"
	"github.com/yourdomain/saas-iam/internal/middleware"
	"github.com/yourdomain/saas-iam/pkg/apierror"
	"github.com/yourdomain/saas-iam/pkg/response"
)

// CreateRole handles POST /api/v1/realms/{realm}/roles
func (h *Handlers) CreateRole(w http.ResponseWriter, r *http.Request) {
	realm := mux.Vars(r)["realm"]
	if err := h.assertRealmAccess(r, realm); err != nil {
		apierror.Write(w, err)
		return
	}

	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		apierror.Write(w, apierror.BadRequest("role name is required"))
		return
	}

	claims := auth.ClaimsFromContext(r.Context())
	if err := h.deps.RoleService.CreateRole(r.Context(), realm, req.Name, req.Description,
		claims.UserID(), claims.Email, resolveRoleStr(claims), middleware.IPFromRequest(r)); err != nil {
		apierror.Write(w, apierror.BadRequest(err.Error()))
		return
	}
	response.JSONCreated(w, map[string]string{"name": req.Name})
}

// ListRoles handles GET /api/v1/realms/{realm}/roles
func (h *Handlers) ListRoles(w http.ResponseWriter, r *http.Request) {
	realm := mux.Vars(r)["realm"]
	if err := h.assertRealmAccess(r, realm); err != nil {
		apierror.Write(w, err)
		return
	}

	roles, err := h.deps.RoleService.ListRoles(r.Context(), realm)
	if err != nil {
		apierror.Write(w, apierror.Internal("failed to list roles"))
		return
	}
	response.JSON(w, roles)
}

// GetRole handles GET /api/v1/realms/{realm}/roles/{name}
func (h *Handlers) GetRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	realm, roleName := vars["realm"], vars["name"]
	if err := h.assertRealmAccess(r, realm); err != nil {
		apierror.Write(w, err)
		return
	}

	role, err := h.deps.RoleService.GetRole(r.Context(), realm, roleName)
	if err != nil {
		apierror.Write(w, apierror.NotFound(err.Error()))
		return
	}
	response.JSON(w, role)
}

// DeleteRole handles DELETE /api/v1/realms/{realm}/roles/{name}
func (h *Handlers) DeleteRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	realm, roleName := vars["realm"], vars["name"]
	if err := h.assertRealmAccess(r, realm); err != nil {
		apierror.Write(w, err)
		return
	}

	claims := auth.ClaimsFromContext(r.Context())
	if err := h.deps.RoleService.DeleteRole(r.Context(), realm, roleName,
		claims.UserID(), claims.Email, resolveRoleStr(claims), middleware.IPFromRequest(r)); err != nil {
		apierror.Write(w, apierror.NotFound(err.Error()))
		return
	}
	response.NoContent(w)
}

// GetRoleUsers handles GET /api/v1/realms/{realm}/roles/{name}/users
func (h *Handlers) GetRoleUsers(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	realm, roleName := vars["realm"], vars["name"]
	if err := h.assertRealmAccess(r, realm); err != nil {
		apierror.Write(w, err)
		return
	}

	users, err := h.deps.RoleService.GetRoleUsers(r.Context(), realm, roleName)
	if err != nil {
		apierror.Write(w, apierror.Internal("failed to list role users"))
		return
	}
	response.JSON(w, users)
}

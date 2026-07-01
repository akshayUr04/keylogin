// internal/handlers/group_handler.go
// Realm Admin – Group management HTTP handlers.
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/yourdomain/saas-iam/internal/auth"
	"github.com/yourdomain/saas-iam/internal/middleware"
	"github.com/yourdomain/saas-iam/pkg/apierror"
	"github.com/yourdomain/saas-iam/pkg/response"
)

// CreateGroup handles POST /api/v1/realms/{realm}/groups
func (h *Handlers) CreateGroup(w http.ResponseWriter, r *http.Request) {
	realm := mux.Vars(r)["realm"]
	if err := h.assertRealmAccess(r, realm); err != nil {
		apierror.Write(w, err)
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		apierror.Write(w, apierror.BadRequest("name is required"))
		return
	}

	claims := auth.ClaimsFromContext(r.Context())
	groupID, err := h.deps.GroupService.CreateGroup(r.Context(), realm, req.Name,
		claims.UserID(), claims.Email, resolveRoleStr(claims), middleware.IPFromRequest(r))
	if err != nil {
		apierror.Write(w, apierror.BadRequest(err.Error()))
		return
	}
	response.JSONCreated(w, map[string]string{"id": groupID, "name": req.Name})
}

// ListGroups handles GET /api/v1/realms/{realm}/groups
func (h *Handlers) ListGroups(w http.ResponseWriter, r *http.Request) {
	realm := mux.Vars(r)["realm"]
	if err := h.assertRealmAccess(r, realm); err != nil {
		apierror.Write(w, err)
		return
	}

	search := r.URL.Query().Get("search")
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit == 0 || limit > 100 {
		limit = 50
	}

	groups, err := h.deps.GroupService.ListGroups(r.Context(), realm, search, offset, limit)
	if err != nil {
		apierror.Write(w, apierror.Internal("failed to list groups"))
		return
	}
	response.JSON(w, groups)
}

// GetGroup handles GET /api/v1/realms/{realm}/groups/{id}
func (h *Handlers) GetGroup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	realm, groupID := vars["realm"], vars["id"]
	if err := h.assertRealmAccess(r, realm); err != nil {
		apierror.Write(w, err)
		return
	}

	group, err := h.deps.GroupService.GetGroup(r.Context(), realm, groupID)
	if err != nil {
		apierror.Write(w, apierror.NotFound(err.Error()))
		return
	}
	response.JSON(w, group)
}

// UpdateGroup handles PUT /api/v1/realms/{realm}/groups/{id}
func (h *Handlers) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	realm, groupID := vars["realm"], vars["id"]
	if err := h.assertRealmAccess(r, realm); err != nil {
		apierror.Write(w, err)
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		apierror.Write(w, apierror.BadRequest("name is required"))
		return
	}

	claims := auth.ClaimsFromContext(r.Context())
	if err := h.deps.GroupService.UpdateGroup(r.Context(), realm, groupID, req.Name,
		claims.UserID(), claims.Email, resolveRoleStr(claims), middleware.IPFromRequest(r)); err != nil {
		apierror.Write(w, apierror.Internal(err.Error()))
		return
	}
	response.NoContent(w)
}

// DeleteGroup handles DELETE /api/v1/realms/{realm}/groups/{id}
func (h *Handlers) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	realm, groupID := vars["realm"], vars["id"]
	if err := h.assertRealmAccess(r, realm); err != nil {
		apierror.Write(w, err)
		return
	}

	claims := auth.ClaimsFromContext(r.Context())
	if err := h.deps.GroupService.DeleteGroup(r.Context(), realm, groupID,
		claims.UserID(), claims.Email, resolveRoleStr(claims), middleware.IPFromRequest(r)); err != nil {
		apierror.Write(w, apierror.NotFound(err.Error()))
		return
	}
	response.NoContent(w)
}

// GetGroupMembers handles GET /api/v1/realms/{realm}/groups/{id}/members
func (h *Handlers) GetGroupMembers(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	realm, groupID := vars["realm"], vars["id"]
	if err := h.assertRealmAccess(r, realm); err != nil {
		apierror.Write(w, err)
		return
	}

	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit == 0 {
		limit = 20
	}

	members, err := h.deps.GroupService.GetGroupMembers(r.Context(), realm, groupID, offset, limit)
	if err != nil {
		apierror.Write(w, apierror.Internal("failed to list group members"))
		return
	}
	response.JSON(w, members)
}

// AddUserToGroup handles PUT /api/v1/realms/{realm}/groups/{groupId}/members/{userId}
func (h *Handlers) AddUserToGroup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	realm, groupID, userID := vars["realm"], vars["groupId"], vars["userId"]
	if err := h.assertRealmAccess(r, realm); err != nil {
		apierror.Write(w, err)
		return
	}

	claims := auth.ClaimsFromContext(r.Context())
	if err := h.deps.GroupService.AddUserToGroup(r.Context(), realm, userID, groupID,
		claims.UserID(), claims.Email, resolveRoleStr(claims), middleware.IPFromRequest(r)); err != nil {
		apierror.Write(w, apierror.Internal(err.Error()))
		return
	}
	response.NoContent(w)
}

// RemoveUserFromGroup handles DELETE /api/v1/realms/{realm}/groups/{groupId}/members/{userId}
func (h *Handlers) RemoveUserFromGroup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	realm, groupID, userID := vars["realm"], vars["groupId"], vars["userId"]
	if err := h.assertRealmAccess(r, realm); err != nil {
		apierror.Write(w, err)
		return
	}

	claims := auth.ClaimsFromContext(r.Context())
	if err := h.deps.GroupService.RemoveUserFromGroup(r.Context(), realm, userID, groupID,
		claims.UserID(), claims.Email, resolveRoleStr(claims), middleware.IPFromRequest(r)); err != nil {
		apierror.Write(w, apierror.Internal(err.Error()))
		return
	}
	response.NoContent(w)
}

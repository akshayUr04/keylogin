// internal/handlers/profile_handler.go
// End User – Profile management HTTP handlers.
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/yourdomain/saas-iam/internal/auth"
	"github.com/yourdomain/saas-iam/pkg/apierror"
	"github.com/yourdomain/saas-iam/pkg/response"
)

// GetProfile handles GET /api/v1/profile
// Returns the authenticated user's full profile including roles and groups.
func (h *Handlers) GetProfile(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		apierror.Write(w, apierror.Unauthorized("unauthenticated"))
		return
	}

	realm := claims.RealmName()
	userID := claims.UserID()

	profile, err := h.deps.ProfileService.GetProfile(r.Context(), realm, userID)
	if err != nil {
		apierror.Write(w, apierror.Internal("failed to retrieve profile"))
		return
	}
	response.JSON(w, profile)
}

// UpdateProfile handles PUT /api/v1/profile
func (h *Handlers) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		apierror.Write(w, apierror.Unauthorized("unauthenticated"))
		return
	}

	var req struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.Write(w, apierror.BadRequest("invalid request body"))
		return
	}

	if err := h.deps.ProfileService.UpdateProfile(r.Context(),
		claims.RealmName(), claims.UserID(), req.FirstName, req.LastName); err != nil {
		apierror.Write(w, apierror.Internal("failed to update profile"))
		return
	}
	response.NoContent(w)
}

// ChangePassword handles POST /api/v1/profile/change-password
func (h *Handlers) ChangePassword(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		apierror.Write(w, apierror.Unauthorized("unauthenticated"))
		return
	}

	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.Write(w, apierror.BadRequest("invalid request body"))
		return
	}
	if len(req.NewPassword) < 8 {
		apierror.Write(w, apierror.BadRequest("password must be at least 8 characters"))
		return
	}

	if err := h.deps.ProfileService.ChangePassword(r.Context(),
		claims.RealmName(), claims.UserID(), req.NewPassword); err != nil {
		apierror.Write(w, apierror.Internal("failed to change password"))
		return
	}
	response.NoContent(w)
}

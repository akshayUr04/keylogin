// internal/handlers/tenant_handler.go
// Super Admin – Tenant management HTTP handlers.
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/yourdomain/saas-iam/internal/auth"
	"github.com/yourdomain/saas-iam/internal/middleware"
	"github.com/yourdomain/saas-iam/internal/models"
	"github.com/yourdomain/saas-iam/internal/services"
	"github.com/yourdomain/saas-iam/pkg/apierror"
	"github.com/yourdomain/saas-iam/pkg/response"
)

// createTenantRequest is the expected JSON body for tenant creation.
type createTenantRequest struct {
	Name      string                  `json:"name"`
	RealmName string                  `json:"realm_name"`
	Domain    string                  `json:"domain"`
	Plan      models.TenantPlan       `json:"plan"`
	Settings  models.TenantSettings   `json:"settings"`
}

// CreateTenant handles POST /api/v1/admin/tenants
func (h *Handlers) CreateTenant(w http.ResponseWriter, r *http.Request) {
	var req createTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.Write(w, apierror.BadRequest("invalid request body"))
		return
	}
	if req.Name == "" || req.RealmName == "" {
		apierror.Write(w, apierror.BadRequest("name and realm_name are required"))
		return
	}
	if req.Plan == "" {
		req.Plan = models.PlanFree
	}

	claims := auth.ClaimsFromContext(r.Context())

	tenant, err := h.deps.TenantService.CreateTenant(r.Context(), services.CreateTenantInput{
		Name:       req.Name,
		RealmName:  req.RealmName,
		Domain:     req.Domain,
		Plan:       req.Plan,
		Settings:   req.Settings,
		ActorID:    claims.UserID(),
		ActorEmail: claims.Email,
		IPAddress:  middleware.IPFromRequest(r),
	})
	if err != nil {
		apierror.Write(w, apierror.BadRequest(err.Error()))
		return
	}

	response.JSONCreated(w, tenant)
}

// ListTenants handles GET /api/v1/admin/tenants
func (h *Handlers) ListTenants(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit == 0 || limit > 100 {
		limit = 20
	}

	tenants, total, err := h.deps.TenantService.ListTenants(r.Context(), status, offset, limit)
	if err != nil {
		apierror.Write(w, apierror.Internal("failed to list tenants"))
		return
	}

	response.JSONWithMeta(w, tenants, response.PaginationMeta{
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}

// GetTenant handles GET /api/v1/admin/tenants/{id}
func (h *Handlers) GetTenant(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(mux.Vars(r)["id"])
	if err != nil {
		apierror.Write(w, apierror.BadRequest("invalid tenant ID"))
		return
	}

	tenant, err := h.deps.TenantService.GetTenant(r.Context(), id)
	if err != nil {
		apierror.Write(w, apierror.NotFound(err.Error()))
		return
	}

	response.JSON(w, tenant)
}

// SuspendTenant handles POST /api/v1/admin/tenants/{id}/suspend
func (h *Handlers) SuspendTenant(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(mux.Vars(r)["id"])
	if err != nil {
		apierror.Write(w, apierror.BadRequest("invalid tenant ID"))
		return
	}
	claims := auth.ClaimsFromContext(r.Context())
	if err := h.deps.TenantService.SuspendTenant(r.Context(), id,
		claims.UserID(), claims.Email, middleware.IPFromRequest(r)); err != nil {
		apierror.Write(w, apierror.BadRequest(err.Error()))
		return
	}
	response.NoContent(w)
}

// EnableTenant handles POST /api/v1/admin/tenants/{id}/enable
func (h *Handlers) EnableTenant(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(mux.Vars(r)["id"])
	if err != nil {
		apierror.Write(w, apierror.BadRequest("invalid tenant ID"))
		return
	}
	claims := auth.ClaimsFromContext(r.Context())
	if err := h.deps.TenantService.EnableTenant(r.Context(), id,
		claims.UserID(), claims.Email, middleware.IPFromRequest(r)); err != nil {
		apierror.Write(w, apierror.BadRequest(err.Error()))
		return
	}
	response.NoContent(w)
}

// DeleteTenant handles DELETE /api/v1/admin/tenants/{id}
func (h *Handlers) DeleteTenant(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(mux.Vars(r)["id"])
	if err != nil {
		apierror.Write(w, apierror.BadRequest("invalid tenant ID"))
		return
	}
	claims := auth.ClaimsFromContext(r.Context())
	if err := h.deps.TenantService.DeleteTenant(r.Context(), id,
		claims.UserID(), claims.Email, middleware.IPFromRequest(r)); err != nil {
		apierror.Write(w, apierror.Internal(err.Error()))
		return
	}
	response.NoContent(w)
}

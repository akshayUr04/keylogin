// internal/handlers/audit_handler.go
// Audit Log HTTP handlers.
package handlers

import (
	"net/http"
	"strconv"

	"github.com/yourdomain/saas-iam/internal/auth"
	"github.com/yourdomain/saas-iam/internal/repository"
	"github.com/yourdomain/saas-iam/pkg/apierror"
	"github.com/yourdomain/saas-iam/pkg/response"
)

// ListAuditLogs handles GET /api/v1/admin/audit-logs
// Super admins see all logs; realm admins see only their tenant's logs.
func (h *Handlers) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		apierror.Write(w, apierror.Unauthorized("unauthenticated"))
		return
	}

	params := repository.AuditListParams{
		ActorID: r.URL.Query().Get("actor_id"),
		Action:  r.URL.Query().Get("action"),
	}
	params.Offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))
	params.Limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	if params.Limit == 0 || params.Limit > 200 {
		params.Limit = 50
	}

	// Realm admins are scoped to their tenant
	if !claims.HasRole("super_admin") {
		// Try to resolve tenant_id from the realm name
		tenant, err := h.deps.TenantService.GetTenantByRealm(r.Context(), claims.RealmName())
		if err == nil && tenant != nil {
			params.TenantID = tenant.ID.String()
		}
	} else {
		params.TenantID = r.URL.Query().Get("tenant_id")
	}

	logs, total, err := h.deps.AuditService.List(r.Context(), params)
	if err != nil {
		apierror.Write(w, apierror.Internal("failed to list audit logs"))
		return
	}

	response.JSONWithMeta(w, logs, response.PaginationMeta{
		Total:  total,
		Limit:  params.Limit,
		Offset: params.Offset,
	})
}

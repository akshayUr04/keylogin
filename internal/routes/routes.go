// internal/routes/routes.go
// HTTP router configuration.
// All routes are registered here using gorilla/mux.
// The router is structured as:
//   /api/v1/auth/…          – public authentication endpoints
//   /api/v1/profile/…       – authenticated end-user endpoints
//   /api/v1/admin/…         – super-admin only endpoints
//   /api/v1/realms/{realm}/… – realm-admin + super-admin endpoints
//   /                        – serves the SPA frontend static files
package routes

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/yourdomain/saas-iam/config"
	"github.com/yourdomain/saas-iam/internal/handlers"
	"github.com/yourdomain/saas-iam/internal/middleware"
)

// Register wires all HTTP routes and middleware to the mux router.
func Register(h *handlers.Handlers, mw *middleware.Middleware, cfg *config.Config) http.Handler {
	r := mux.NewRouter()

	// ── Global middleware (applied to every request) ────────────────────
	r.Use(mw.RequestID)
	r.Use(mw.Logger)
	r.Use(mw.Recovery)
	r.Use(mw.CORS())
	r.Use(mw.TenantResolution)
	r.Use(mw.RateLimiter)

	// ── API v1 sub-router ──────────────────────────────────────────────
	api := r.PathPrefix("/api/v1").Subrouter()

	// ── Auth endpoints (public – no JWT required) ──────────────────────
	auth := api.PathPrefix("/auth").Subrouter()
	auth.HandleFunc("/login", h.Login).Methods(http.MethodPost, http.MethodOptions)
	auth.HandleFunc("/logout", h.Logout).Methods(http.MethodPost, http.MethodOptions)
	auth.HandleFunc("/refresh", h.RefreshToken).Methods(http.MethodPost, http.MethodOptions)

	// ── Authenticated auth endpoints ────────────────────────────────────
	authProtected := api.PathPrefix("/auth").Subrouter()
	authProtected.Use(mw.Authenticate)
	authProtected.HandleFunc("/me", h.Me).Methods(http.MethodGet)

	// ── Profile endpoints (end-user, any authenticated role) ───────────
	profile := api.PathPrefix("/profile").Subrouter()
	profile.Use(mw.Authenticate)
	profile.HandleFunc("", h.GetProfile).Methods(http.MethodGet)
	profile.HandleFunc("", h.UpdateProfile).Methods(http.MethodPut)
	profile.HandleFunc("/change-password", h.ChangePassword).Methods(http.MethodPost)

	// ── Super Admin endpoints ──────────────────────────────────────────
	admin := api.PathPrefix("/admin").Subrouter()
	admin.Use(mw.Authenticate)
	admin.Use(mw.RequireSuperAdmin)

	// Tenant management
	admin.HandleFunc("/tenants", h.ListTenants).Methods(http.MethodGet)
	admin.HandleFunc("/tenants", h.CreateTenant).Methods(http.MethodPost)
	admin.HandleFunc("/tenants/{id}", h.GetTenant).Methods(http.MethodGet)
	admin.HandleFunc("/tenants/{id}", h.DeleteTenant).Methods(http.MethodDelete)
	admin.HandleFunc("/tenants/{id}/suspend", h.SuspendTenant).Methods(http.MethodPost)
	admin.HandleFunc("/tenants/{id}/enable", h.EnableTenant).Methods(http.MethodPost)

	// Audit logs (super admin sees all)
	admin.HandleFunc("/audit-logs", h.ListAuditLogs).Methods(http.MethodGet)

	// ── Realm-scoped endpoints (realm admin + super admin) ─────────────
	realm := api.PathPrefix("/realms/{realm}").Subrouter()
	realm.Use(mw.Authenticate)
	realm.Use(mw.RequireRealmAdmin)

	// Users
	realm.HandleFunc("/users", h.ListUsers).Methods(http.MethodGet)
	realm.HandleFunc("/users", h.CreateUser).Methods(http.MethodPost)
	realm.HandleFunc("/users/{id}", h.GetUser).Methods(http.MethodGet)
	realm.HandleFunc("/users/{id}", h.UpdateUser).Methods(http.MethodPut)
	realm.HandleFunc("/users/{id}", h.DeleteUser).Methods(http.MethodDelete)
	realm.HandleFunc("/users/{id}/enabled", h.SetUserEnabled).Methods(http.MethodPut)
	realm.HandleFunc("/users/{id}/reset-password", h.ResetUserPassword).Methods(http.MethodPut)
	realm.HandleFunc("/users/{id}/roles", h.AssignRoles).Methods(http.MethodPost)
	realm.HandleFunc("/users/{id}/roles", h.RemoveRoles).Methods(http.MethodDelete)
	realm.HandleFunc("/users/{id}/sessions", h.GetUserSessions).Methods(http.MethodGet)

	// Groups
	realm.HandleFunc("/groups", h.ListGroups).Methods(http.MethodGet)
	realm.HandleFunc("/groups", h.CreateGroup).Methods(http.MethodPost)
	realm.HandleFunc("/groups/{id}", h.GetGroup).Methods(http.MethodGet)
	realm.HandleFunc("/groups/{id}", h.UpdateGroup).Methods(http.MethodPut)
	realm.HandleFunc("/groups/{id}", h.DeleteGroup).Methods(http.MethodDelete)
	realm.HandleFunc("/groups/{groupId}/members", h.GetGroupMembers).Methods(http.MethodGet)
	realm.HandleFunc("/groups/{groupId}/members/{userId}", h.AddUserToGroup).Methods(http.MethodPut)
	realm.HandleFunc("/groups/{groupId}/members/{userId}", h.RemoveUserFromGroup).Methods(http.MethodDelete)

	// Roles
	realm.HandleFunc("/roles", h.ListRoles).Methods(http.MethodGet)
	realm.HandleFunc("/roles", h.CreateRole).Methods(http.MethodPost)
	realm.HandleFunc("/roles/{name}", h.GetRole).Methods(http.MethodGet)
	realm.HandleFunc("/roles/{name}", h.DeleteRole).Methods(http.MethodDelete)
	realm.HandleFunc("/roles/{name}/users", h.GetRoleUsers).Methods(http.MethodGet)

	// Audit logs (realm-scoped)
	realm.HandleFunc("/audit-logs", h.ListAuditLogs).Methods(http.MethodGet)

	// ── Health check ──────────────────────────────────────────────────
	r.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}).Methods(http.MethodGet)

	// ── Frontend SPA – serve static files ─────────────────────────────
	// All unmatched routes serve the frontend's index.html so that
	// client-side routing works correctly.
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./web/dist")))

	return r
}

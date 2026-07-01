// internal/handlers/handlers.go
// HTTP handler factory.
// Handlers receive all dependencies through a single Dependencies struct,
// keeping the function signatures clean and making testing straightforward.
package handlers

import (
	"github.com/yourdomain/saas-iam/config"
	"github.com/yourdomain/saas-iam/internal/audit"
	"github.com/yourdomain/saas-iam/internal/services"
	"github.com/yourdomain/saas-iam/pkg/logger"
)

// Dependencies holds all service-layer dependencies for HTTP handlers.
type Dependencies struct {
	AuthService    *services.AuthService
	TenantService  *services.TenantService
	UserService    *services.UserService
	GroupService   *services.GroupService
	RoleService    *services.RoleService
	SessionService *services.SessionService
	ProfileService *services.ProfileService
	AuditService   *audit.Service
	Config         *config.Config
	Logger         *logger.Logger
}

// Handlers groups all HTTP handler implementations.
// Each sub-domain (auth, tenants, users, …) has its own file in this package.
type Handlers struct {
	deps Dependencies
}

// New creates a new Handlers instance with the given dependencies.
func New(deps Dependencies) *Handlers {
	return &Handlers{deps: deps}
}

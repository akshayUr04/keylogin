// internal/services/role_service.go
// Role management service – wraps Keycloak role operations with audit logging.
package services

import (
	"context"
	"fmt"

	"github.com/yourdomain/saas-iam/internal/audit"
	"github.com/yourdomain/saas-iam/internal/keycloak"
	"github.com/yourdomain/saas-iam/pkg/logger"
)

// RoleService handles role management operations.
type RoleService struct {
	kc       *keycloak.Client
	auditSvc *audit.Service
	log      *logger.Logger
}

// NewRoleService creates a RoleService.
func NewRoleService(kc *keycloak.Client, auditSvc *audit.Service, log *logger.Logger) *RoleService {
	return &RoleService{kc: kc, auditSvc: auditSvc, log: log}
}

// CreateRole creates a realm-level role.
func (s *RoleService) CreateRole(ctx context.Context, realm, name, description, actorID, actorEmail, actorRole, ip string) error {
	role := keycloak.RoleRepresentation{Name: name, Description: description}
	if err := s.kc.CreateRealmRole(ctx, realm, role); err != nil {
		if keycloak.IsConflict(err) {
			return fmt.Errorf("role %q already exists", name)
		}
		return err
	}

	s.auditSvc.Log(ctx, audit.LogEntry{
		ActorID: actorID, ActorEmail: actorEmail, ActorRole: actorRole,
		Action:       audit.ActionCreateRole,
		ResourceType: "role", ResourceID: name,
		Details:   map[string]any{"realm": realm, "description": description},
		IPAddress: ip,
	})
	return nil
}

// ListRoles returns all realm roles.
func (s *RoleService) ListRoles(ctx context.Context, realm string) ([]keycloak.RoleRepresentation, error) {
	return s.kc.ListRealmRoles(ctx, realm)
}

// GetRole returns a specific role by name.
func (s *RoleService) GetRole(ctx context.Context, realm, roleName string) (*keycloak.RoleRepresentation, error) {
	r, err := s.kc.GetRealmRole(ctx, realm, roleName)
	if err != nil {
		if keycloak.IsNotFound(err) {
			return nil, fmt.Errorf("role %q not found", roleName)
		}
		return nil, err
	}
	return r, nil
}

// DeleteRole removes a realm role.
func (s *RoleService) DeleteRole(ctx context.Context, realm, roleName, actorID, actorEmail, actorRole, ip string) error {
	if err := s.kc.DeleteRealmRole(ctx, realm, roleName); err != nil {
		if keycloak.IsNotFound(err) {
			return fmt.Errorf("role %q not found", roleName)
		}
		return err
	}

	s.auditSvc.Log(ctx, audit.LogEntry{
		ActorID: actorID, ActorEmail: actorEmail, ActorRole: actorRole,
		Action:       audit.ActionDeleteRole,
		ResourceType: "role", ResourceID: roleName,
		Details:   map[string]any{"realm": realm},
		IPAddress: ip,
	})
	return nil
}

// GetRoleUsers returns users assigned to a specific role.
func (s *RoleService) GetRoleUsers(ctx context.Context, realm, roleName string) ([]keycloak.UserRepresentation, error) {
	return s.kc.GetRoleUsers(ctx, realm, roleName)
}

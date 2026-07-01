// internal/services/user_service.go
// User management service.
// All user operations are scoped to a specific realm, enforcing tenant
// isolation at the service layer in addition to the Keycloak API level.
package services

import (
	"context"
	"fmt"
	"time"

	"github.com/yourdomain/saas-iam/internal/audit"
	"github.com/yourdomain/saas-iam/internal/keycloak"
	"github.com/yourdomain/saas-iam/internal/models"
	"github.com/yourdomain/saas-iam/pkg/logger"
)

// UserService handles user management operations.
type UserService struct {
	kc       *keycloak.Client
	auditSvc *audit.Service
	log      *logger.Logger
}

// NewUserService creates a UserService.
func NewUserService(kc *keycloak.Client, auditSvc *audit.Service, log *logger.Logger) *UserService {
	return &UserService{kc: kc, auditSvc: auditSvc, log: log}
}

// CreateUserInput holds fields for creating a new realm user.
type CreateUserInput struct {
	RealmName   string
	Username    string
	Email       string
	FirstName   string
	LastName    string
	Password    string
	Temporary   bool // force password change on first login
	Enabled     bool
	Attributes  map[string][]string
	// Actor info for audit logging
	ActorID    string
	ActorEmail string
	ActorRole  string
	IPAddress  string
}

// CreateUser creates a new user in the given realm.
func (s *UserService) CreateUser(ctx context.Context, input CreateUserInput) (*models.User, error) {
	kcUser := keycloak.UserRepresentation{
		Username:      input.Username,
		Email:         input.Email,
		FirstName:     input.FirstName,
		LastName:      input.LastName,
		Enabled:       input.Enabled,
		EmailVerified: false,
		Attributes:    input.Attributes,
	}

	if input.Password != "" {
		kcUser.Credentials = []keycloak.CredentialRepresentation{
			{Type: "password", Value: input.Password, Temporary: input.Temporary},
		}
	}

	userID, err := s.kc.CreateUser(ctx, input.RealmName, kcUser)
	if err != nil {
		if keycloak.IsConflict(err) {
			return nil, fmt.Errorf("user with email %q already exists in realm %q", input.Email, input.RealmName)
		}
		return nil, fmt.Errorf("creating user: %w", err)
	}

	s.auditSvc.Log(ctx, audit.LogEntry{
		ActorID: input.ActorID, ActorEmail: input.ActorEmail, ActorRole: input.ActorRole,
		Action:       audit.ActionCreateUser,
		ResourceType: "user", ResourceID: userID,
		Details:   map[string]any{"realm": input.RealmName, "email": input.Email},
		IPAddress: input.IPAddress,
	})

	return &models.User{
		ID:        userID,
		RealmName: input.RealmName,
		Username:  input.Username,
		Email:     input.Email,
		FirstName: input.FirstName,
		LastName:  input.LastName,
		Enabled:   input.Enabled,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}, nil
}

// GetUser retrieves a user by ID within a realm.
func (s *UserService) GetUser(ctx context.Context, realm, userID string) (*models.User, error) {
	u, err := s.kc.GetUser(ctx, realm, userID)
	if err != nil {
		if keycloak.IsNotFound(err) {
			return nil, fmt.Errorf("user %q not found in realm %q", userID, realm)
		}
		return nil, err
	}
	return kcUserToModel(realm, u), nil
}

// ListUsers returns paginated users in a realm.
func (s *UserService) ListUsers(ctx context.Context, realm, search string, offset, limit int) ([]*models.User, int, error) {
	params := keycloak.ListUsersParams{
		Search: search,
		Offset: offset,
		Limit:  limit,
	}

	kcUsers, err := s.kc.ListUsers(ctx, realm, params)
	if err != nil {
		return nil, 0, err
	}

	total, err := s.kc.CountUsers(ctx, realm)
	if err != nil {
		total = len(kcUsers)
	}

	users := make([]*models.User, 0, len(kcUsers))
	for i := range kcUsers {
		users = append(users, kcUserToModel(realm, &kcUsers[i]))
	}
	return users, total, nil
}

// UpdateUser updates a user's profile fields.
func (s *UserService) UpdateUser(ctx context.Context, realm, userID string, updates UpdateUserInput) error {
	kcUser := keycloak.UserRepresentation{
		Email:      updates.Email,
		FirstName:  updates.FirstName,
		LastName:   updates.LastName,
		Attributes: updates.Attributes,
	}
	if err := s.kc.UpdateUser(ctx, realm, userID, kcUser); err != nil {
		return fmt.Errorf("updating user: %w", err)
	}

	s.auditSvc.Log(ctx, audit.LogEntry{
		ActorID: updates.ActorID, ActorEmail: updates.ActorEmail, ActorRole: updates.ActorRole,
		Action:       audit.ActionUpdateUser,
		ResourceType: "user", ResourceID: userID,
		Details:   map[string]any{"realm": realm},
		IPAddress: updates.IPAddress,
	})
	return nil
}

// UpdateUserInput holds the mutable fields of a user.
type UpdateUserInput struct {
	Email      string
	FirstName  string
	LastName   string
	Attributes map[string][]string
	ActorID    string
	ActorEmail string
	ActorRole  string
	IPAddress  string
}

// DeleteUser removes a user from the realm.
func (s *UserService) DeleteUser(ctx context.Context, realm, userID, actorID, actorEmail, actorRole, ip string) error {
	if err := s.kc.DeleteUser(ctx, realm, userID); err != nil {
		if keycloak.IsNotFound(err) {
			return fmt.Errorf("user not found")
		}
		return err
	}

	s.auditSvc.Log(ctx, audit.LogEntry{
		ActorID: actorID, ActorEmail: actorEmail, ActorRole: actorRole,
		Action:       audit.ActionDeleteUser,
		ResourceType: "user", ResourceID: userID,
		Details:   map[string]any{"realm": realm},
		IPAddress: ip,
	})
	return nil
}

// EnableUser enables or disables a user.
func (s *UserService) EnableUser(ctx context.Context, realm, userID string, enabled bool, actorID, actorEmail, actorRole, ip string) error {
	if err := s.kc.EnableUser(ctx, realm, userID, enabled); err != nil {
		return err
	}

	action := audit.ActionEnableUser
	if !enabled {
		action = audit.ActionDisableUser
	}
	s.auditSvc.Log(ctx, audit.LogEntry{
		ActorID: actorID, ActorEmail: actorEmail, ActorRole: actorRole,
		Action:       action,
		ResourceType: "user", ResourceID: userID,
		Details:   map[string]any{"realm": realm, "enabled": enabled},
		IPAddress: ip,
	})
	return nil
}

// ResetPassword sets a new password for a user.
func (s *UserService) ResetPassword(ctx context.Context, realm, userID, newPassword string, temporary bool, actorID, actorEmail, actorRole, ip string) error {
	if err := s.kc.ResetPassword(ctx, realm, userID, newPassword, temporary); err != nil {
		return fmt.Errorf("resetting password: %w", err)
	}

	s.auditSvc.Log(ctx, audit.LogEntry{
		ActorID: actorID, ActorEmail: actorEmail, ActorRole: actorRole,
		Action:       audit.ActionResetPassword,
		ResourceType: "user", ResourceID: userID,
		Details:   map[string]any{"realm": realm, "temporary": temporary},
		IPAddress: ip,
	})
	return nil
}

// AssignRoles assigns realm roles to a user.
func (s *UserService) AssignRoles(ctx context.Context, realm, userID string, roleNames []string, actorID, actorEmail, actorRole, ip string) error {
	// Resolve role names to RoleRepresentation objects
	roles := make([]keycloak.RoleRepresentation, 0, len(roleNames))
	for _, name := range roleNames {
		r, err := s.kc.GetRealmRole(ctx, realm, name)
		if err != nil {
			return fmt.Errorf("role %q not found: %w", name, err)
		}
		roles = append(roles, *r)
	}

	if err := s.kc.AssignRealmRoles(ctx, realm, userID, roles); err != nil {
		return err
	}

	s.auditSvc.Log(ctx, audit.LogEntry{
		ActorID: actorID, ActorEmail: actorEmail, ActorRole: actorRole,
		Action:       audit.ActionAssignRole,
		ResourceType: "user", ResourceID: userID,
		Details:   map[string]any{"realm": realm, "roles": roleNames},
		IPAddress: ip,
	})
	return nil
}

// RemoveRoles removes realm roles from a user.
func (s *UserService) RemoveRoles(ctx context.Context, realm, userID string, roleNames []string, actorID, actorEmail, actorRole, ip string) error {
	roles := make([]keycloak.RoleRepresentation, 0, len(roleNames))
	for _, name := range roleNames {
		r, err := s.kc.GetRealmRole(ctx, realm, name)
		if err != nil {
			return fmt.Errorf("role %q not found: %w", name, err)
		}
		roles = append(roles, *r)
	}

	if err := s.kc.RemoveRealmRoles(ctx, realm, userID, roles); err != nil {
		return err
	}

	s.auditSvc.Log(ctx, audit.LogEntry{
		ActorID: actorID, ActorEmail: actorEmail, ActorRole: actorRole,
		Action:       audit.ActionRemoveRole,
		ResourceType: "user", ResourceID: userID,
		Details:   map[string]any{"realm": realm, "roles": roleNames},
		IPAddress: ip,
	})
	return nil
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// kcUserToModel converts a Keycloak user representation to our domain model.
func kcUserToModel(realm string, u *keycloak.UserRepresentation) *models.User {
	created := time.Unix(u.CreatedTimestamp/1000, 0)
	return &models.User{
		ID:            u.ID,
		RealmName:     realm,
		Username:      u.Username,
		Email:         u.Email,
		FirstName:     u.FirstName,
		LastName:      u.LastName,
		Enabled:       u.Enabled,
		EmailVerified: u.EmailVerified,
		Attributes:    u.Attributes,
		CreatedAt:     created,
		UpdatedAt:     created, // Keycloak doesn't expose an updated_at
	}
}

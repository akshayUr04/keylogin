// internal/services/group_service.go
// Group management service – scoped per realm for tenant isolation.
package services

import (
	"context"
	"fmt"

	"github.com/yourdomain/saas-iam/internal/audit"
	"github.com/yourdomain/saas-iam/internal/keycloak"
	"github.com/yourdomain/saas-iam/pkg/logger"
)

// GroupService handles group management operations.
type GroupService struct {
	kc       *keycloak.Client
	auditSvc *audit.Service
	log      *logger.Logger
}

// NewGroupService creates a GroupService.
func NewGroupService(kc *keycloak.Client, auditSvc *audit.Service, log *logger.Logger) *GroupService {
	return &GroupService{kc: kc, auditSvc: auditSvc, log: log}
}

// CreateGroup creates a new group in the given realm.
func (s *GroupService) CreateGroup(ctx context.Context, realm, name, actorID, actorEmail, actorRole, ip string) (string, error) {
	groupID, err := s.kc.CreateGroup(ctx, realm, keycloak.GroupRepresentation{Name: name})
	if err != nil {
		if keycloak.IsConflict(err) {
			return "", fmt.Errorf("group %q already exists", name)
		}
		return "", err
	}

	s.auditSvc.Log(ctx, audit.LogEntry{
		ActorID: actorID, ActorEmail: actorEmail, ActorRole: actorRole,
		Action:       audit.ActionCreateGroup,
		ResourceType: "group", ResourceID: groupID,
		Details:   map[string]any{"realm": realm, "name": name},
		IPAddress: ip,
	})
	return groupID, nil
}

// GetGroup retrieves a single group by ID.
func (s *GroupService) GetGroup(ctx context.Context, realm, groupID string) (*keycloak.GroupRepresentation, error) {
	g, err := s.kc.GetGroup(ctx, realm, groupID)
	if err != nil {
		if keycloak.IsNotFound(err) {
			return nil, fmt.Errorf("group not found")
		}
		return nil, err
	}
	return g, nil
}

// ListGroups returns all top-level groups in a realm.
func (s *GroupService) ListGroups(ctx context.Context, realm, search string, offset, limit int) ([]keycloak.GroupRepresentation, error) {
	return s.kc.ListGroups(ctx, realm, search, offset, limit)
}

// UpdateGroup renames a group.
func (s *GroupService) UpdateGroup(ctx context.Context, realm, groupID, name, actorID, actorEmail, actorRole, ip string) error {
	if err := s.kc.UpdateGroup(ctx, realm, groupID, keycloak.GroupRepresentation{Name: name}); err != nil {
		return err
	}

	s.auditSvc.Log(ctx, audit.LogEntry{
		ActorID: actorID, ActorEmail: actorEmail, ActorRole: actorRole,
		Action:       audit.ActionUpdateGroup,
		ResourceType: "group", ResourceID: groupID,
		Details:   map[string]any{"realm": realm, "name": name},
		IPAddress: ip,
	})
	return nil
}

// DeleteGroup removes a group from the realm.
func (s *GroupService) DeleteGroup(ctx context.Context, realm, groupID, actorID, actorEmail, actorRole, ip string) error {
	if err := s.kc.DeleteGroup(ctx, realm, groupID); err != nil {
		if keycloak.IsNotFound(err) {
			return fmt.Errorf("group not found")
		}
		return err
	}

	s.auditSvc.Log(ctx, audit.LogEntry{
		ActorID: actorID, ActorEmail: actorEmail, ActorRole: actorRole,
		Action:       audit.ActionDeleteGroup,
		ResourceType: "group", ResourceID: groupID,
		Details:   map[string]any{"realm": realm},
		IPAddress: ip,
	})
	return nil
}

// AddUserToGroup adds a user to a group.
func (s *GroupService) AddUserToGroup(ctx context.Context, realm, userID, groupID, actorID, actorEmail, actorRole, ip string) error {
	if err := s.kc.AddUserToGroup(ctx, realm, userID, groupID); err != nil {
		return err
	}
	s.auditSvc.Log(ctx, audit.LogEntry{
		ActorID: actorID, ActorEmail: actorEmail, ActorRole: actorRole,
		Action:       audit.ActionAddUserGroup,
		ResourceType: "group", ResourceID: groupID,
		Details:   map[string]any{"realm": realm, "user_id": userID},
		IPAddress: ip,
	})
	return nil
}

// RemoveUserFromGroup removes a user from a group.
func (s *GroupService) RemoveUserFromGroup(ctx context.Context, realm, userID, groupID, actorID, actorEmail, actorRole, ip string) error {
	if err := s.kc.RemoveUserFromGroup(ctx, realm, userID, groupID); err != nil {
		return err
	}
	s.auditSvc.Log(ctx, audit.LogEntry{
		ActorID: actorID, ActorEmail: actorEmail, ActorRole: actorRole,
		Action:       audit.ActionRemoveUserGroup,
		ResourceType: "group", ResourceID: groupID,
		Details:   map[string]any{"realm": realm, "user_id": userID},
		IPAddress: ip,
	})
	return nil
}

// GetGroupMembers returns the members of a group.
func (s *GroupService) GetGroupMembers(ctx context.Context, realm, groupID string, offset, limit int) ([]keycloak.UserRepresentation, error) {
	return s.kc.GetGroupMembers(ctx, realm, groupID, offset, limit)
}

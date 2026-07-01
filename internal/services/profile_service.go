// internal/services/profile_service.go
// Profile management service for end-user self-service operations.
package services

import (
	"context"
	"fmt"

	"github.com/yourdomain/saas-iam/internal/keycloak"
	"github.com/yourdomain/saas-iam/internal/models"
	"github.com/yourdomain/saas-iam/pkg/logger"
)

// ProfileService allows end-users to manage their own profile data.
type ProfileService struct {
	kc  *keycloak.Client
	log *logger.Logger
}

// NewProfileService creates a ProfileService.
func NewProfileService(kc *keycloak.Client, log *logger.Logger) *ProfileService {
	return &ProfileService{kc: kc, log: log}
}

// GetProfile retrieves a user's own profile.
func (s *ProfileService) GetProfile(ctx context.Context, realm, userID string) (*models.User, error) {
	u, err := s.kc.GetUser(ctx, realm, userID)
	if err != nil {
		if keycloak.IsNotFound(err) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	user := kcUserToModel(realm, u)

	// Fetch roles
	roles, err := s.kc.GetUserRoles(ctx, realm, userID)
	if err == nil {
		for _, r := range roles {
			user.Roles = append(user.Roles, r.Name)
		}
	}

	// Fetch groups
	groups, err := s.kc.GetUserGroups(ctx, realm, userID)
	if err == nil {
		for _, g := range groups {
			user.Groups = append(user.Groups, g.Name)
		}
	}

	return user, nil
}

// UpdateProfile allows a user to update their own first/last name.
func (s *ProfileService) UpdateProfile(ctx context.Context, realm, userID, firstName, lastName string) error {
	return s.kc.UpdateUser(ctx, realm, userID, keycloak.UserRepresentation{
		FirstName: firstName,
		LastName:  lastName,
	})
}

// ChangePassword allows a user to change their own password.
func (s *ProfileService) ChangePassword(ctx context.Context, realm, userID, newPassword string) error {
	return s.kc.ResetPassword(ctx, realm, userID, newPassword, false)
}

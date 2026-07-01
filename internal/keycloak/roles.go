// internal/keycloak/roles.go
// Keycloak Role management operations.
package keycloak

import (
	"context"
	"fmt"
	"net/http"
)

// RoleRepresentation mirrors Keycloak's role JSON structure.
type RoleRepresentation struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Composite   bool   `json:"composite,omitempty"`
	ClientRole  bool   `json:"clientRole,omitempty"`
	ContainerID string `json:"containerId,omitempty"`
}

// CreateRealmRole creates a new realm-level role.
func (c *Client) CreateRealmRole(ctx context.Context, realm string, role RoleRepresentation) error {
	path := adminPath(realm, "roles")
	resp, err := c.doAdminRequest(ctx, http.MethodPost, path, role)
	if err != nil {
		return fmt.Errorf("create role %q in realm %q: %w", role.Name, realm, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusCreated {
		return nil
	}
	return decodeOrError(resp, nil)
}

// GetRealmRole retrieves a realm role by name.
func (c *Client) GetRealmRole(ctx context.Context, realm, roleName string) (*RoleRepresentation, error) {
	path := adminPath(realm, "roles/"+roleName)
	resp, err := c.doAdminRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("get role %q in realm %q: %w", roleName, realm, err)
	}

	var r RoleRepresentation
	if err := decodeOrError(resp, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// UpdateRealmRole updates a realm role's name or description.
func (c *Client) UpdateRealmRole(ctx context.Context, realm, roleName string, role RoleRepresentation) error {
	path := adminPath(realm, "roles/"+roleName)
	resp, err := c.doAdminRequest(ctx, http.MethodPut, path, role)
	if err != nil {
		return fmt.Errorf("update role %q in realm %q: %w", roleName, realm, err)
	}
	return decodeOrError(resp, nil)
}

// DeleteRealmRole deletes a realm role by name.
func (c *Client) DeleteRealmRole(ctx context.Context, realm, roleName string) error {
	path := adminPath(realm, "roles/"+roleName)
	resp, err := c.doAdminRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("delete role %q in realm %q: %w", roleName, realm, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return decodeOrError(resp, nil)
}

// ListRealmRoles returns all realm-level roles.
func (c *Client) ListRealmRoles(ctx context.Context, realm string) ([]RoleRepresentation, error) {
	path := adminPath(realm, "roles")
	resp, err := c.doAdminRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("list roles in realm %q: %w", realm, err)
	}

	var roles []RoleRepresentation
	if err := decodeOrError(resp, &roles); err != nil {
		return nil, err
	}
	return roles, nil
}

// GetRoleUsers returns users that have a specific realm role assigned.
func (c *Client) GetRoleUsers(ctx context.Context, realm, roleName string) ([]UserRepresentation, error) {
	path := adminPath(realm, fmt.Sprintf("roles/%s/users", roleName))
	resp, err := c.doAdminRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("get users for role %q: %w", roleName, err)
	}

	var users []UserRepresentation
	if err := decodeOrError(resp, &users); err != nil {
		return nil, err
	}
	return users, nil
}

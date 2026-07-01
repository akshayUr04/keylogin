// internal/keycloak/groups.go
// Keycloak Group management operations.
package keycloak

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// GroupRepresentation mirrors Keycloak's group JSON structure.
type GroupRepresentation struct {
	ID         string                `json:"id,omitempty"`
	Name       string                `json:"name,omitempty"`
	Path       string                `json:"path,omitempty"`
	Attributes map[string][]string   `json:"attributes,omitempty"`
	RealmRoles []string              `json:"realmRoles,omitempty"`
	SubGroups  []GroupRepresentation `json:"subGroups,omitempty"`
	Access     map[string]bool       `json:"access,omitempty"`
}

// CreateGroup creates a new group in the realm.
// Returns the new group's ID from the Location header.
func (c *Client) CreateGroup(ctx context.Context, realm string, group GroupRepresentation) (string, error) {
	path := adminPath(realm, "groups")
	resp, err := c.doAdminRequest(ctx, http.MethodPost, path, group)
	if err != nil {
		return "", fmt.Errorf("create group in realm %q: %w", realm, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", decodeOrError(resp, nil)
	}

	loc := resp.Header.Get("Location")
	parts := splitLast(loc, "/")
	return parts[1], nil
}

// GetGroup retrieves a single group by ID.
func (c *Client) GetGroup(ctx context.Context, realm, groupID string) (*GroupRepresentation, error) {
	path := adminPath(realm, "groups/"+groupID)
	resp, err := c.doAdminRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("get group %q in realm %q: %w", groupID, realm, err)
	}

	var g GroupRepresentation
	if err := decodeOrError(resp, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

// UpdateGroup updates a group's name or attributes.
func (c *Client) UpdateGroup(ctx context.Context, realm, groupID string, group GroupRepresentation) error {
	path := adminPath(realm, "groups/"+groupID)
	resp, err := c.doAdminRequest(ctx, http.MethodPut, path, group)
	if err != nil {
		return fmt.Errorf("update group %q in realm %q: %w", groupID, realm, err)
	}
	return decodeOrError(resp, nil)
}

// DeleteGroup permanently removes a group from a realm.
func (c *Client) DeleteGroup(ctx context.Context, realm, groupID string) error {
	path := adminPath(realm, "groups/"+groupID)
	resp, err := c.doAdminRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("delete group %q in realm %q: %w", groupID, realm, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return decodeOrError(resp, nil)
}

// ListGroups returns all top-level groups in a realm.
func (c *Client) ListGroups(ctx context.Context, realm string, search string, offset, limit int) ([]GroupRepresentation, error) {
	q := url.Values{}
	if search != "" {
		q.Set("search", search)
	}
	q.Set("first", strconv.Itoa(offset))
	q.Set("max", strconv.Itoa(clamp(limit, 1, 500)))

	path := adminPath(realm, "groups?"+q.Encode())
	resp, err := c.doAdminRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("list groups in realm %q: %w", realm, err)
	}

	var groups []GroupRepresentation
	if err := decodeOrError(resp, &groups); err != nil {
		return nil, err
	}
	return groups, nil
}

// GetGroupMembers returns the users that belong to a specific group.
func (c *Client) GetGroupMembers(ctx context.Context, realm, groupID string, offset, limit int) ([]UserRepresentation, error) {
	q := url.Values{}
	q.Set("first", strconv.Itoa(offset))
	q.Set("max", strconv.Itoa(clamp(limit, 1, 500)))

	path := adminPath(realm, fmt.Sprintf("groups/%s/members?%s", groupID, q.Encode()))
	resp, err := c.doAdminRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("get members for group %q: %w", groupID, err)
	}

	var users []UserRepresentation
	if err := decodeOrError(resp, &users); err != nil {
		return nil, err
	}
	return users, nil
}

// AssignRolesToGroup assigns realm roles to a group.
func (c *Client) AssignRolesToGroup(ctx context.Context, realm, groupID string, roles []RoleRepresentation) error {
	path := adminPath(realm, fmt.Sprintf("groups/%s/role-mappings/realm", groupID))
	resp, err := c.doAdminRequest(ctx, http.MethodPost, path, roles)
	if err != nil {
		return fmt.Errorf("assign roles to group %q: %w", groupID, err)
	}
	return decodeOrError(resp, nil)
}

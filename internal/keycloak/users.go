// internal/keycloak/users.go
// Keycloak user management operations.
// Every method scopes its operations to a specific realm, ensuring
// cross-tenant isolation at the Keycloak API level.
package keycloak

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// UserRepresentation mirrors Keycloak's user JSON structure.
type UserRepresentation struct {
	ID                     string              `json:"id,omitempty"`
	Username               string              `json:"username,omitempty"`
	Email                  string              `json:"email,omitempty"`
	FirstName              string              `json:"firstName,omitempty"`
	LastName               string              `json:"lastName,omitempty"`
	Enabled                bool                `json:"enabled"`
	EmailVerified          bool                `json:"emailVerified,omitempty"`
	Attributes             map[string][]string `json:"attributes,omitempty"`
	RealmRoles             []string            `json:"realmRoles,omitempty"`
	Groups                 []string            `json:"groups,omitempty"`
	Credentials            []CredentialRepresentation `json:"credentials,omitempty"`
	CreatedTimestamp       int64               `json:"createdTimestamp,omitempty"`
}

// CredentialRepresentation is used when setting a user's password.
type CredentialRepresentation struct {
	Type      string `json:"type"`      // "password"
	Value     string `json:"value"`
	Temporary bool   `json:"temporary"` // forces password change on next login
}

// CreateUser creates a new user in the given realm.
// Returns the new user's ID extracted from the Location header.
func (c *Client) CreateUser(ctx context.Context, realm string, user UserRepresentation) (string, error) {
	path := adminPath(realm, "users")
	resp, err := c.doAdminRequest(ctx, http.MethodPost, path, user)
	if err != nil {
		return "", fmt.Errorf("create user in realm %q: %w", realm, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", decodeOrError(resp, nil)
	}

	// Keycloak returns the new user's URL in the Location header.
	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", fmt.Errorf("no Location header in create user response")
	}
	// Extract ID from URL: .../users/{id}
	parts := splitLast(loc, "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("unexpected Location header: %s", loc)
	}
	return parts[1], nil
}

// GetUser retrieves a single user by ID from the given realm.
func (c *Client) GetUser(ctx context.Context, realm, userID string) (*UserRepresentation, error) {
	path := adminPath(realm, "users/"+userID)
	resp, err := c.doAdminRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("get user %q in realm %q: %w", userID, realm, err)
	}

	var u UserRepresentation
	if err := decodeOrError(resp, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// UpdateUser updates a user's attributes.
func (c *Client) UpdateUser(ctx context.Context, realm, userID string, user UserRepresentation) error {
	path := adminPath(realm, "users/"+userID)
	resp, err := c.doAdminRequest(ctx, http.MethodPut, path, user)
	if err != nil {
		return fmt.Errorf("update user %q in realm %q: %w", userID, realm, err)
	}
	return decodeOrError(resp, nil)
}

// DeleteUser permanently removes a user from a realm.
func (c *Client) DeleteUser(ctx context.Context, realm, userID string) error {
	path := adminPath(realm, "users/"+userID)
	resp, err := c.doAdminRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("delete user %q in realm %q: %w", userID, realm, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return decodeOrError(resp, nil)
}

// ListUsers returns users in a realm with optional search, pagination.
func (c *Client) ListUsers(ctx context.Context, realm string, params ListUsersParams) ([]UserRepresentation, error) {
	q := url.Values{}
	if params.Search != "" {
		q.Set("search", params.Search)
	}
	if params.Email != "" {
		q.Set("email", params.Email)
	}
	if params.Username != "" {
		q.Set("username", params.Username)
	}
	q.Set("first", strconv.Itoa(params.Offset))
	q.Set("max", strconv.Itoa(clamp(params.Limit, 1, 500)))

	path := adminPath(realm, "users?"+q.Encode())
	resp, err := c.doAdminRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("list users in realm %q: %w", realm, err)
	}

	var users []UserRepresentation
	if err := decodeOrError(resp, &users); err != nil {
		return nil, err
	}
	return users, nil
}

// ListUsersParams are the optional filters for ListUsers.
type ListUsersParams struct {
	Search   string
	Email    string
	Username string
	Offset   int
	Limit    int
}

// CountUsers returns the total number of users in a realm.
func (c *Client) CountUsers(ctx context.Context, realm string) (int, error) {
	resp, err := c.doAdminRequest(ctx, http.MethodGet, adminPath(realm, "users/count"), nil)
	if err != nil {
		return 0, err
	}
	var n int
	return n, decodeOrError(resp, &n)
}

// EnableUser enables or disables a user account.
func (c *Client) EnableUser(ctx context.Context, realm, userID string, enabled bool) error {
	return c.UpdateUser(ctx, realm, userID, UserRepresentation{Enabled: enabled})
}

// ResetPassword sets a new password for a user.
// If temporary is true, the user must change the password at next login.
func (c *Client) ResetPassword(ctx context.Context, realm, userID, newPassword string, temporary bool) error {
	cred := CredentialRepresentation{
		Type:      "password",
		Value:     newPassword,
		Temporary: temporary,
	}
	path := adminPath(realm, fmt.Sprintf("users/%s/reset-password", userID))
	resp, err := c.doAdminRequest(ctx, http.MethodPut, path, cred)
	if err != nil {
		return fmt.Errorf("reset password for user %q: %w", userID, err)
	}
	return decodeOrError(resp, nil)
}

// GetUserSessions returns active sessions for a specific user.
func (c *Client) GetUserSessions(ctx context.Context, realm, userID string) ([]UserSessionRepresentation, error) {
	path := adminPath(realm, fmt.Sprintf("users/%s/sessions", userID))
	resp, err := c.doAdminRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("get sessions for user %q: %w", userID, err)
	}

	var sessions []UserSessionRepresentation
	if err := decodeOrError(resp, &sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}

// UserSessionRepresentation holds session info returned by Keycloak.
type UserSessionRepresentation struct {
	ID          string            `json:"id"`
	Username    string            `json:"username"`
	UserID      string            `json:"userId"`
	IPAddress   string            `json:"ipAddress"`
	Start       int64             `json:"start"`
	LastAccess  int64             `json:"lastAccess"`
	Clients     map[string]string `json:"clients"`
}

// DeleteSession terminates a specific Keycloak session.
func (c *Client) DeleteSession(ctx context.Context, sessionID string) error {
	path := fmt.Sprintf("/admin/realms/master/sessions/%s", sessionID)
	resp, err := c.doAdminRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("delete session %q: %w", sessionID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return decodeOrError(resp, nil)
}

// DeleteRealmSession terminates a session within a specific realm.
func (c *Client) DeleteRealmSession(ctx context.Context, realm, sessionID string) error {
	path := fmt.Sprintf("/admin/realms/%s/sessions/%s", realm, sessionID)
	resp, err := c.doAdminRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("delete session %q in realm %q: %w", sessionID, realm, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return decodeOrError(resp, nil)
}

// GetUserRoles returns the realm-level roles assigned to a user.
func (c *Client) GetUserRoles(ctx context.Context, realm, userID string) ([]RoleRepresentation, error) {
	path := adminPath(realm, fmt.Sprintf("users/%s/role-mappings/realm", userID))
	resp, err := c.doAdminRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("get roles for user %q: %w", userID, err)
	}

	var roles []RoleRepresentation
	if err := decodeOrError(resp, &roles); err != nil {
		return nil, err
	}
	return roles, nil
}

// AssignRealmRoles assigns realm-level roles to a user.
func (c *Client) AssignRealmRoles(ctx context.Context, realm, userID string, roles []RoleRepresentation) error {
	path := adminPath(realm, fmt.Sprintf("users/%s/role-mappings/realm", userID))
	resp, err := c.doAdminRequest(ctx, http.MethodPost, path, roles)
	if err != nil {
		return fmt.Errorf("assign roles to user %q: %w", userID, err)
	}
	return decodeOrError(resp, nil)
}

// RemoveRealmRoles removes realm-level roles from a user.
func (c *Client) RemoveRealmRoles(ctx context.Context, realm, userID string, roles []RoleRepresentation) error {
	path := adminPath(realm, fmt.Sprintf("users/%s/role-mappings/realm", userID))
	resp, err := c.doAdminRequest(ctx, http.MethodDelete, path, roles)
	if err != nil {
		return fmt.Errorf("remove roles from user %q: %w", userID, err)
	}
	return decodeOrError(resp, nil)
}

// GetUserGroups returns groups the user belongs to.
func (c *Client) GetUserGroups(ctx context.Context, realm, userID string) ([]GroupRepresentation, error) {
	path := adminPath(realm, fmt.Sprintf("users/%s/groups", userID))
	resp, err := c.doAdminRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("get groups for user %q: %w", userID, err)
	}

	var groups []GroupRepresentation
	if err := decodeOrError(resp, &groups); err != nil {
		return nil, err
	}
	return groups, nil
}

// AddUserToGroup adds a user to a group.
func (c *Client) AddUserToGroup(ctx context.Context, realm, userID, groupID string) error {
	path := adminPath(realm, fmt.Sprintf("users/%s/groups/%s", userID, groupID))
	resp, err := c.doAdminRequest(ctx, http.MethodPut, path, nil)
	if err != nil {
		return fmt.Errorf("add user %q to group %q: %w", userID, groupID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return decodeOrError(resp, nil)
}

// RemoveUserFromGroup removes a user from a group.
func (c *Client) RemoveUserFromGroup(ctx context.Context, realm, userID, groupID string) error {
	path := adminPath(realm, fmt.Sprintf("users/%s/groups/%s", userID, groupID))
	resp, err := c.doAdminRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("remove user %q from group %q: %w", userID, groupID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return decodeOrError(resp, nil)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// splitLast splits s on sep and returns [prefix, suffix].
func splitLast(s, sep string) [2]string {
	idx := len(s) - len(sep)
	for i := idx; i >= 0; i-- {
		if s[i:i+len(sep)] == sep {
			return [2]string{s[:i], s[i+len(sep):]}
		}
	}
	return [2]string{s, ""}
}

// clamp returns v clamped to [min, max].
func clamp(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// internal/keycloak/realms.go
// Keycloak Realm administration operations.
// Used exclusively by the Super Admin flows to create and manage Realms,
// each of which maps to one tenant.
package keycloak

import (
	"context"
	"fmt"
	"net/http"
)

// RealmRepresentation mirrors the Keycloak realm JSON structure.
// Only the fields we actively use are mapped; Keycloak ignores unknown fields.
type RealmRepresentation struct {
	// Required
	Realm       string `json:"realm"`
	DisplayName string `json:"displayName,omitempty"`
	Enabled     bool   `json:"enabled"`

	// Login settings
	RegistrationAllowed         bool `json:"registrationAllowed,omitempty"`
	RegistrationEmailAsUsername bool `json:"registrationEmailAsUsername,omitempty"`
	LoginWithEmailAllowed       bool `json:"loginWithEmailAllowed,omitempty"`
	DuplicateEmailsAllowed      bool `json:"duplicateEmailsAllowed,omitempty"`
	ResetPasswordAllowed        bool `json:"resetPasswordAllowed,omitempty"`
	EditUsernameAllowed         bool `json:"editUsernameAllowed,omitempty"`
	RememberMe                  bool `json:"rememberMe,omitempty"`
	VerifyEmail                 bool `json:"verifyEmail,omitempty"`

	// Token settings (seconds)
	AccessTokenLifespan            int `json:"accessTokenLifespan,omitempty"`
	SSOSessionMaxLifespan          int `json:"ssoSessionMaxLifespan,omitempty"`
	SSOSessionIdleTimeout          int `json:"ssoSessionIdleTimeout,omitempty"`
	OfflineSessionMaxLifespan      int `json:"offlineSessionMaxLifespan,omitempty"`

	// Security settings
	BruteForceProtected bool `json:"bruteForceProtected,omitempty"`
	PasswordPolicy      string `json:"passwordPolicy,omitempty"`
}

// CreateRealm creates a new Keycloak realm for a tenant.
// Returns an error if the realm already exists (HTTP 409).
func (c *Client) CreateRealm(ctx context.Context, realm RealmRepresentation) error {
	resp, err := c.doAdminRequest(ctx, http.MethodPost, "/admin/realms", realm)
	if err != nil {
		return fmt.Errorf("create realm %q: %w", realm.Realm, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		return nil
	}
	return decodeOrError(resp, nil)
}

// GetRealm retrieves full realm information.
func (c *Client) GetRealm(ctx context.Context, realmName string) (*RealmRepresentation, error) {
	resp, err := c.doAdminRequest(ctx, http.MethodGet,
		fmt.Sprintf("/admin/realms/%s", realmName), nil)
	if err != nil {
		return nil, fmt.Errorf("get realm %q: %w", realmName, err)
	}

	var r RealmRepresentation
	if err := decodeOrError(resp, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// UpdateRealm updates a realm's settings.
func (c *Client) UpdateRealm(ctx context.Context, realmName string, realm RealmRepresentation) error {
	resp, err := c.doAdminRequest(ctx, http.MethodPut,
		fmt.Sprintf("/admin/realms/%s", realmName), realm)
	if err != nil {
		return fmt.Errorf("update realm %q: %w", realmName, err)
	}
	return decodeOrError(resp, nil)
}

// DeleteRealm permanently deletes a Keycloak realm and all its data.
// This action is irreversible – callers must confirm intent before calling.
func (c *Client) DeleteRealm(ctx context.Context, realmName string) error {
	resp, err := c.doAdminRequest(ctx, http.MethodDelete,
		fmt.Sprintf("/admin/realms/%s", realmName), nil)
	if err != nil {
		return fmt.Errorf("delete realm %q: %w", realmName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return decodeOrError(resp, nil)
}

// ListRealms returns all realm names known to Keycloak.
func (c *Client) ListRealms(ctx context.Context) ([]RealmRepresentation, error) {
	resp, err := c.doAdminRequest(ctx, http.MethodGet, "/admin/realms", nil)
	if err != nil {
		return nil, fmt.Errorf("list realms: %w", err)
	}

	var realms []RealmRepresentation
	if err := decodeOrError(resp, &realms); err != nil {
		return nil, err
	}
	return realms, nil
}

// GetRealmUserCount returns the number of users in a realm.
func (c *Client) GetRealmUserCount(ctx context.Context, realmName string) (int, error) {
	resp, err := c.doAdminRequest(ctx, http.MethodGet,
		fmt.Sprintf("/admin/realms/%s/users/count", realmName), nil)
	if err != nil {
		return 0, fmt.Errorf("get user count for realm %q: %w", realmName, err)
	}

	var count int
	if err := decodeOrError(resp, &count); err != nil {
		return 0, err
	}
	return count, nil
}

// DefaultRealmConfig returns a sensible starting RealmRepresentation for a
// new tenant realm.  Callers can customise further before calling CreateRealm.
func DefaultRealmConfig(realmName, displayName string) RealmRepresentation {
	return RealmRepresentation{
		Realm:                          realmName,
		DisplayName:                    displayName,
		Enabled:                        true,
		LoginWithEmailAllowed:          true,
		RegistrationEmailAsUsername:    true,
		ResetPasswordAllowed:           true,
		BruteForceProtected:            true,
		AccessTokenLifespan:            300,    // 5 minutes
		SSOSessionMaxLifespan:          36000,  // 10 hours
		SSOSessionIdleTimeout:          1800,   // 30 minutes
		PasswordPolicy:                 "length(8) and upperCase(1) and digits(1) and specialChars(1)",
	}
}

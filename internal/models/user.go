// internal/models/user.go
// User-related domain models.  These are thin wrappers around Keycloak
// user representations enriched with application-level metadata.
package models

import "time"

// UserRole represents the application-level role of a user.
type UserRole string

const (
	RoleSuperAdmin UserRole = "super_admin"
	RoleRealmAdmin UserRole = "realm_admin"
	RoleEndUser    UserRole = "end_user"
)

// User is the application's representation of a Keycloak user, extended
// with fields needed by the SaaS IAM layer.
type User struct {
	// ID is the Keycloak-assigned UUID for this user.
	ID string `json:"id"`

	// RealmName is the Keycloak realm this user belongs to.
	RealmName string `json:"realm_name"`

	Username    string `json:"username"`
	Email       string `json:"email"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	Enabled     bool   `json:"enabled"`
	EmailVerified bool `json:"email_verified"`

	// Roles holds the composite role names assigned to this user
	// (both realm roles and client roles relevant to our app).
	Roles  []string `json:"roles,omitempty"`
	Groups []string `json:"groups,omitempty"`

	// AppRole is the resolved application-level role.
	AppRole UserRole `json:"app_role,omitempty"`

	// Attributes are arbitrary key-value pairs stored against the user in
	// Keycloak (used for tenant-specific metadata).
	Attributes map[string][]string `json:"attributes,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// FullName returns the display name for the user.
func (u *User) FullName() string {
	if u.FirstName != "" && u.LastName != "" {
		return u.FirstName + " " + u.LastName
	}
	if u.FirstName != "" {
		return u.FirstName
	}
	return u.Username
}

// Session represents an active Keycloak user session.
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	IPAddress string    `json:"ip_address"`
	Started   time.Time `json:"started"`
	LastAccess time.Time `json:"last_access"`
	Clients   map[string]string `json:"clients,omitempty"`
}

// AuditLog is the application representation of an audit event.
type AuditLog struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id,omitempty"`
	ActorID      string    `json:"actor_id"`
	ActorEmail   string    `json:"actor_email"`
	ActorRole    string    `json:"actor_role"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id,omitempty"`
	Details      map[string]any `json:"details,omitempty"`
	IPAddress    string    `json:"ip_address,omitempty"`
	UserAgent    string    `json:"user_agent,omitempty"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
}

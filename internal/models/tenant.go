// internal/models/tenant.go
// Domain models for the Tenant aggregate.
// These structs are used by the service layer and repositories.
// They are NOT directly exposed over HTTP – DTOs handle that mapping.
package models

import (
	"time"

	"github.com/google/uuid"
)

// TenantStatus represents the lifecycle state of a tenant.
type TenantStatus string

const (
	TenantStatusActive    TenantStatus = "active"
	TenantStatusSuspended TenantStatus = "suspended"
	TenantStatusDeleted   TenantStatus = "deleted"
)

// TenantPlan represents the subscription plan.
type TenantPlan string

const (
	PlanFree       TenantPlan = "free"
	PlanStarter    TenantPlan = "starter"
	PlanPro        TenantPlan = "pro"
	PlanEnterprise TenantPlan = "enterprise"
)

// Tenant represents a customer organisation on the SaaS platform.
// Every Tenant corresponds to exactly one Keycloak Realm to ensure
// complete data and configuration isolation.
type Tenant struct {
	ID        uuid.UUID    `json:"id" db:"id"`
	Name      string       `json:"name" db:"name"`
	RealmName string       `json:"realm_name" db:"realm_name"`
	Domain    string       `json:"domain" db:"domain"`
	Status    TenantStatus `json:"status" db:"status"`
	Plan      TenantPlan   `json:"plan" db:"plan"`
	Settings  TenantSettings `json:"settings" db:"settings"`
	CreatedAt time.Time    `json:"created_at" db:"created_at"`
	UpdatedAt time.Time    `json:"updated_at" db:"updated_at"`
	DeletedAt *time.Time   `json:"deleted_at,omitempty" db:"deleted_at"`

	// Populated lazily from Keycloak – not stored in Postgres.
	UserCount  int `json:"user_count,omitempty"`
	GroupCount int `json:"group_count,omitempty"`
}

// TenantSettings holds arbitrary per-tenant configuration.
type TenantSettings struct {
	// MaxUsers is the maximum number of users allowed in this realm.
	// 0 means unlimited.
	MaxUsers int `json:"max_users,omitempty"`
	// PasswordPolicy is a Keycloak password policy expression.
	PasswordPolicy string `json:"password_policy,omitempty"`
	// MFARequired forces multi-factor authentication for all realm users.
	MFARequired bool `json:"mfa_required,omitempty"`
	// SessionIdleTimeout in seconds (0 = use Keycloak default).
	SessionIdleTimeout int `json:"session_idle_timeout,omitempty"`
	// BrandingLogoURL is a URL to the tenant's logo, shown on the login page.
	BrandingLogoURL string `json:"branding_logo_url,omitempty"`
	// AllowedEmailDomains restricts user self-registration to specific domains.
	AllowedEmailDomains []string `json:"allowed_email_domains,omitempty"`
}

// IsActive returns true when the tenant is allowed to receive traffic.
func (t *Tenant) IsActive() bool { return t.Status == TenantStatusActive }

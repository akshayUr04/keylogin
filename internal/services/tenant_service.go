// internal/services/tenant_service.go
// Tenant management service.
// Orchestrates the creation, modification, and deletion of tenants by
// coordinating between the PostgreSQL repository and the Keycloak API.
// Every Tenant operation is atomic from the caller's perspective:
//   - A Keycloak realm is created before the tenant row is inserted.
//   - If the DB insert fails, the realm is deleted (best-effort cleanup).
package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/yourdomain/saas-iam/internal/audit"
	"github.com/yourdomain/saas-iam/internal/keycloak"
	"github.com/yourdomain/saas-iam/internal/models"
	"github.com/yourdomain/saas-iam/internal/repository"
	"github.com/yourdomain/saas-iam/pkg/logger"
)

// TenantService orchestrates tenant lifecycle operations.
type TenantService struct {
	repo     *repository.TenantRepository
	kc       *keycloak.Client
	auditSvc *audit.Service
	log      *logger.Logger
}

// NewTenantService creates a TenantService.
func NewTenantService(
	repo *repository.TenantRepository,
	kc *keycloak.Client,
	auditSvc *audit.Service,
	log *logger.Logger,
) *TenantService {
	return &TenantService{repo: repo, kc: kc, auditSvc: auditSvc, log: log}
}

// CreateTenantInput holds the fields needed to create a new tenant.
type CreateTenantInput struct {
	Name        string
	RealmName   string
	Domain      string
	Plan        models.TenantPlan
	Settings    models.TenantSettings
	ActorID     string
	ActorEmail  string
	IPAddress   string
}

// CreateTenant creates a Keycloak realm and persists the tenant record.
func (s *TenantService) CreateTenant(ctx context.Context, input CreateTenantInput) (*models.Tenant, error) {
	// Sanitise realm name: lowercase, no spaces
	realmName := sanitiseRealmName(input.RealmName)
	if realmName == "" {
		return nil, fmt.Errorf("invalid realm name")
	}

	// 1. Create Keycloak realm
	realmCfg := keycloak.DefaultRealmConfig(realmName, input.Name)
	if input.Settings.PasswordPolicy != "" {
		realmCfg.PasswordPolicy = input.Settings.PasswordPolicy
	}
	if input.Settings.SessionIdleTimeout > 0 {
		realmCfg.SSOSessionIdleTimeout = input.Settings.SessionIdleTimeout
	}

	if err := s.kc.CreateRealm(ctx, realmCfg); err != nil {
		if keycloak.IsConflict(err) {
			return nil, fmt.Errorf("realm %q already exists", realmName)
		}
		return nil, fmt.Errorf("creating Keycloak realm: %w", err)
	}

	// 2. Persist tenant in PostgreSQL
	tenant := &models.Tenant{
		ID:        uuid.New(),
		Name:      input.Name,
		RealmName: realmName,
		Domain:    input.Domain,
		Status:    models.TenantStatusActive,
		Plan:      input.Plan,
		Settings:  input.Settings,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.repo.Create(ctx, tenant); err != nil {
		// Best-effort rollback: delete the realm we just created
		if delErr := s.kc.DeleteRealm(ctx, realmName); delErr != nil {
			s.log.Error("failed to delete realm during rollback",
				logger.Field("realm", realmName),
				logger.Err(delErr),
			)
		}
		return nil, fmt.Errorf("persisting tenant: %w", err)
	}

	s.auditSvc.Log(ctx, audit.LogEntry{
		ActorID:      input.ActorID,
		ActorEmail:   input.ActorEmail,
		ActorRole:    string(models.RoleSuperAdmin),
		Action:       audit.ActionCreateTenant,
		ResourceType: "tenant",
		ResourceID:   tenant.ID.String(),
		Details: map[string]any{
			"realm":  realmName,
			"name":   input.Name,
			"plan":   input.Plan,
		},
		IPAddress: input.IPAddress,
	})

	return tenant, nil
}

// GetTenant retrieves a tenant by ID.
func (s *TenantService) GetTenant(ctx context.Context, id uuid.UUID) (*models.Tenant, error) {
	t, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, fmt.Errorf("tenant not found")
	}

	// Enrich with live Keycloak stats
	userCount, err := s.kc.GetRealmUserCount(ctx, t.RealmName)
	if err == nil {
		t.UserCount = userCount
	}

	return t, nil
}

// GetTenantByRealm retrieves a tenant by realm name.
func (s *TenantService) GetTenantByRealm(ctx context.Context, realmName string) (*models.Tenant, error) {
	t, err := s.repo.GetByRealm(ctx, realmName)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, fmt.Errorf("tenant not found for realm %q", realmName)
	}
	return t, nil
}

// ListTenants returns paginated tenants.
func (s *TenantService) ListTenants(ctx context.Context, status string, offset, limit int) ([]*models.Tenant, int, error) {
	return s.repo.List(ctx, status, offset, limit)
}

// SuspendTenant suspends a tenant, preventing logins.
func (s *TenantService) SuspendTenant(ctx context.Context, id uuid.UUID, actorID, actorEmail, ip string) error {
	t, err := s.repo.GetByID(ctx, id)
	if err != nil || t == nil {
		return fmt.Errorf("tenant not found")
	}

	t.Status = models.TenantStatusSuspended
	if err := s.repo.Update(ctx, t); err != nil {
		return err
	}

	// Disable the Keycloak realm so existing tokens stop working
	_ = s.kc.UpdateRealm(ctx, t.RealmName, keycloak.RealmRepresentation{
		Realm:   t.RealmName,
		Enabled: false,
	})

	s.auditSvc.Log(ctx, audit.LogEntry{
		ActorID: actorID, ActorEmail: actorEmail,
		ActorRole:    string(models.RoleSuperAdmin),
		Action:       audit.ActionSuspendTenant,
		ResourceType: "tenant", ResourceID: id.String(),
		IPAddress: ip,
	})
	return nil
}

// EnableTenant re-activates a suspended tenant.
func (s *TenantService) EnableTenant(ctx context.Context, id uuid.UUID, actorID, actorEmail, ip string) error {
	t, err := s.repo.GetByID(ctx, id)
	if err != nil || t == nil {
		return fmt.Errorf("tenant not found")
	}

	t.Status = models.TenantStatusActive
	if err := s.repo.Update(ctx, t); err != nil {
		return err
	}

	_ = s.kc.UpdateRealm(ctx, t.RealmName, keycloak.RealmRepresentation{
		Realm:   t.RealmName,
		Enabled: true,
	})

	s.auditSvc.Log(ctx, audit.LogEntry{
		ActorID: actorID, ActorEmail: actorEmail,
		ActorRole:    string(models.RoleSuperAdmin),
		Action:       audit.ActionEnableTenant,
		ResourceType: "tenant", ResourceID: id.String(),
		IPAddress: ip,
	})
	return nil
}

// DeleteTenant soft-deletes the tenant record and removes the Keycloak realm.
func (s *TenantService) DeleteTenant(ctx context.Context, id uuid.UUID, actorID, actorEmail, ip string) error {
	t, err := s.repo.GetByID(ctx, id)
	if err != nil || t == nil {
		return fmt.Errorf("tenant not found")
	}

	// Delete Keycloak realm first
	if err := s.kc.DeleteRealm(ctx, t.RealmName); err != nil && !keycloak.IsNotFound(err) {
		return fmt.Errorf("deleting Keycloak realm: %w", err)
	}

	if err := s.repo.SoftDelete(ctx, id); err != nil {
		return fmt.Errorf("soft-deleting tenant: %w", err)
	}

	s.auditSvc.Log(ctx, audit.LogEntry{
		ActorID: actorID, ActorEmail: actorEmail,
		ActorRole:    string(models.RoleSuperAdmin),
		Action:       audit.ActionDeleteTenant,
		ResourceType: "tenant", ResourceID: id.String(),
		IPAddress: ip,
	})
	return nil
}

// ── helpers ─────────────────────────────────────────────────────────────────

// sanitiseRealmName converts a display name to a valid Keycloak realm identifier.
func sanitiseRealmName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	// Replace spaces and special chars with hyphens
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else if r == ' ' || r == '_' {
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

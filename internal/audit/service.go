// internal/audit/service.go
// Audit log service.
// Provides a thin, non-blocking wrapper around the AuditRepository so that
// calling code can fire audit events without worrying about whether the
// database write succeeds.
package audit

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/yourdomain/saas-iam/internal/models"
	"github.com/yourdomain/saas-iam/internal/repository"
	"github.com/yourdomain/saas-iam/pkg/logger"
)

// Service handles audit log recording.
type Service struct {
	repo *repository.AuditRepository
	log  *logger.Logger
}

// NewService creates a new audit Service.
func NewService(repo *repository.AuditRepository, log *logger.Logger) *Service {
	return &Service{repo: repo, log: log}
}

// Log records an audit event.  Failures are logged but never propagated to
// the caller so that a DB issue never causes a business operation to fail.
func (s *Service) Log(ctx context.Context, entry LogEntry) {
	al := &models.AuditLog{
		ID:           uuid.New().String(),
		TenantID:     entry.TenantID,
		ActorID:      entry.ActorID,
		ActorEmail:   entry.ActorEmail,
		ActorRole:    entry.ActorRole,
		Action:       entry.Action,
		ResourceType: entry.ResourceType,
		ResourceID:   entry.ResourceID,
		Details:      entry.Details,
		IPAddress:    entry.IPAddress,
		UserAgent:    entry.UserAgent,
		Status:       entry.Status,
		CreatedAt:    time.Now(),
	}
	if al.Status == "" {
		al.Status = "success"
	}

	// Write asynchronously so the HTTP handler is not blocked.
	go func() {
		// Use a background context so the write outlives the request.
		if err := s.repo.Create(context.Background(), al); err != nil {
			s.log.Error("failed to write audit log",
				logger.Field("action", entry.Action),
				logger.Err(err),
			)
		}
	}()
}

// List returns paginated audit log entries.
func (s *Service) List(ctx context.Context, params repository.AuditListParams) ([]*models.AuditLog, int, error) {
	return s.repo.List(ctx, params)
}

// LogEntry is the input to Service.Log – callers fill in only the fields
// relevant to their action.
type LogEntry struct {
	TenantID     string
	ActorID      string
	ActorEmail   string
	ActorRole    string
	Action       string         // e.g. "CREATE_USER", "DELETE_REALM"
	ResourceType string         // e.g. "user", "group", "tenant"
	ResourceID   string         // ID of the affected resource
	Details      map[string]any // arbitrary action-specific payload
	IPAddress    string
	UserAgent    string
	Status       string // "success" | "failure" (default: "success")
}

// ── Pre-defined action constants ─────────────────────────────────────────────
// Using constants ensures consistency and makes logs searchable.

const (
	ActionLogin          = "LOGIN"
	ActionLogout         = "LOGOUT"
	ActionRefreshToken   = "REFRESH_TOKEN"
	ActionCreateTenant   = "CREATE_TENANT"
	ActionUpdateTenant   = "UPDATE_TENANT"
	ActionDeleteTenant   = "DELETE_TENANT"
	ActionSuspendTenant  = "SUSPEND_TENANT"
	ActionEnableTenant   = "ENABLE_TENANT"
	ActionCreateUser     = "CREATE_USER"
	ActionUpdateUser     = "UPDATE_USER"
	ActionDeleteUser     = "DELETE_USER"
	ActionEnableUser     = "ENABLE_USER"
	ActionDisableUser    = "DISABLE_USER"
	ActionResetPassword  = "RESET_PASSWORD"
	ActionCreateGroup    = "CREATE_GROUP"
	ActionUpdateGroup    = "UPDATE_GROUP"
	ActionDeleteGroup    = "DELETE_GROUP"
	ActionAddUserGroup   = "ADD_USER_TO_GROUP"
	ActionRemoveUserGroup = "REMOVE_USER_FROM_GROUP"
	ActionCreateRole     = "CREATE_ROLE"
	ActionDeleteRole     = "DELETE_ROLE"
	ActionAssignRole     = "ASSIGN_ROLE"
	ActionRemoveRole     = "REMOVE_ROLE"
	ActionTerminateSession = "TERMINATE_SESSION"
	ActionUpdateProfile  = "UPDATE_PROFILE"
)

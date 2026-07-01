// internal/repository/audit_repository.go
// PostgreSQL-backed Audit Log repository.
// All writes are fire-and-forget from the caller's perspective – audit
// failures must never block the primary request flow.
package repository

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yourdomain/saas-iam/internal/models"
	"github.com/yourdomain/saas-iam/pkg/logger"
)

// AuditRepository handles persistence of audit log entries.
type AuditRepository struct {
	pool *pgxpool.Pool
	log  *logger.Logger
}

// NewAuditRepository creates a new AuditRepository.
func NewAuditRepository(pool *pgxpool.Pool, log *logger.Logger) *AuditRepository {
	return &AuditRepository{pool: pool, log: log}
}

// Create inserts an audit log entry.
func (r *AuditRepository) Create(ctx context.Context, entry *models.AuditLog) error {
	query := `
		INSERT INTO audit_logs
			(id, tenant_id, actor_id, actor_email, actor_role, action, resource_type,
			 resource_id, details, ip_address, user_agent, status, created_at)
		VALUES
			($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12, $13)`

	var tenantID *uuid.UUID
	if entry.TenantID != "" {
		id, err := uuid.Parse(entry.TenantID)
		if err == nil {
			tenantID = &id
		}
	}

	detailsJSON := marshalDetails(entry.Details)

	_, err := r.pool.Exec(ctx, query,
		entry.ID, tenantID, entry.ActorID, entry.ActorEmail, entry.ActorRole,
		entry.Action, entry.ResourceType, entry.ResourceID,
		detailsJSON, entry.IPAddress, entry.UserAgent,
		entry.Status, entry.CreatedAt,
	)
	return err
}

// List retrieves audit log entries with optional filters.
func (r *AuditRepository) List(ctx context.Context, params AuditListParams) ([]*models.AuditLog, int, error) {
	whereClause := "WHERE 1=1"
	args := []any{}
	argIdx := 1

	if params.TenantID != "" {
		whereClause += fmt.Sprintf(" AND tenant_id = $%d", argIdx)
		args = append(args, params.TenantID)
		argIdx++
	}
	if params.ActorID != "" {
		whereClause += fmt.Sprintf(" AND actor_id = $%d", argIdx)
		args = append(args, params.ActorID)
		argIdx++
	}
	if params.Action != "" {
		whereClause += fmt.Sprintf(" AND action = $%d", argIdx)
		args = append(args, params.Action)
		argIdx++
	}

	countQuery := "SELECT COUNT(*) FROM audit_logs " + whereClause
	var total int
	if err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting audit logs: %w", err)
	}

	listArgs := append(args, params.Limit, params.Offset)
	listQuery := fmt.Sprintf(`
		SELECT id, COALESCE(tenant_id::text,''), actor_id, actor_email, actor_role,
		       action, resource_type, COALESCE(resource_id,''),
		       details, COALESCE(ip_address,''), COALESCE(user_agent,''),
		       status, created_at
		FROM audit_logs %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, whereClause, argIdx, argIdx+1)

	rows, err := r.pool.Query(ctx, listQuery, listArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("listing audit logs: %w", err)
	}
	defer rows.Close()

	var entries []*models.AuditLog
	for rows.Next() {
		var e models.AuditLog
		var detailsJSON []byte
		err := rows.Scan(
			&e.ID, &e.TenantID, &e.ActorID, &e.ActorEmail, &e.ActorRole,
			&e.Action, &e.ResourceType, &e.ResourceID,
			&detailsJSON, &e.IPAddress, &e.UserAgent,
			&e.Status, &e.CreatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scanning audit log row: %w", err)
		}
		if len(detailsJSON) > 0 {
			_ = json.Unmarshal(detailsJSON, &e.Details)
		}
		entries = append(entries, &e)
	}
	return entries, total, rows.Err()
}

// AuditListParams are the optional filters for listing audit logs.
type AuditListParams struct {
	TenantID string
	ActorID  string
	Action   string
	Limit    int
	Offset   int
}

// marshalDetails encodes audit details as a JSON string for the Postgres
// JSONB column.  Returns "{}" on error so the row is never rejected.
func marshalDetails(details map[string]any) string {
	if len(details) == 0 {
		return "{}"
	}
	b, err := json.Marshal(details)
	if err != nil {
		return "{}"
	}
	return string(b)
}

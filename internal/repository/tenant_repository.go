// internal/repository/tenant_repository.go
// PostgreSQL-backed Tenant repository.
// Handles all tenant persistence operations using the pgx/v5 pool.
package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yourdomain/saas-iam/internal/models"
	"github.com/yourdomain/saas-iam/pkg/logger"
)

// TenantRepository provides database operations for tenants.
type TenantRepository struct {
	pool *pgxpool.Pool
	log  *logger.Logger
}

// NewTenantRepository creates a new TenantRepository.
func NewTenantRepository(pool *pgxpool.Pool, log *logger.Logger) *TenantRepository {
	return &TenantRepository{pool: pool, log: log}
}

// Create inserts a new tenant record.
func (r *TenantRepository) Create(ctx context.Context, t *models.Tenant) error {
	settingsJSON, err := json.Marshal(t.Settings)
	if err != nil {
		return fmt.Errorf("marshalling settings: %w", err)
	}

	query := `
		INSERT INTO tenants (id, name, realm_name, domain, status, plan, settings, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err = r.pool.Exec(ctx, query,
		t.ID, t.Name, t.RealmName, t.Domain, t.Status, t.Plan,
		settingsJSON, t.CreatedAt, t.UpdatedAt,
	)
	return err
}

// GetByID retrieves a tenant by its UUID.
func (r *TenantRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error) {
	query := `
		SELECT id, name, realm_name, domain, status, plan, settings, created_at, updated_at, deleted_at
		FROM tenants WHERE id = $1 AND deleted_at IS NULL`

	row := r.pool.QueryRow(ctx, query, id)
	return scanTenant(row)
}

// GetByRealm retrieves a tenant by its Keycloak realm name.
func (r *TenantRepository) GetByRealm(ctx context.Context, realmName string) (*models.Tenant, error) {
	query := `
		SELECT id, name, realm_name, domain, status, plan, settings, created_at, updated_at, deleted_at
		FROM tenants WHERE realm_name = $1 AND deleted_at IS NULL`

	row := r.pool.QueryRow(ctx, query, realmName)
	return scanTenant(row)
}

// GetByDomain retrieves a tenant by its custom domain.
func (r *TenantRepository) GetByDomain(ctx context.Context, domain string) (*models.Tenant, error) {
	query := `
		SELECT id, name, realm_name, domain, status, plan, settings, created_at, updated_at, deleted_at
		FROM tenants WHERE domain = $1 AND deleted_at IS NULL`

	row := r.pool.QueryRow(ctx, query, domain)
	return scanTenant(row)
}

// List returns paginated tenants, optionally filtered by status.
func (r *TenantRepository) List(ctx context.Context, status string, offset, limit int) ([]*models.Tenant, int, error) {
	var rows pgx.Rows
	var err error
	var countQuery, listQuery string

	if status != "" {
		countQuery = `SELECT COUNT(*) FROM tenants WHERE status = $1 AND deleted_at IS NULL`
		listQuery = `SELECT id, name, realm_name, domain, status, plan, settings, created_at, updated_at, deleted_at
			FROM tenants WHERE status = $1 AND deleted_at IS NULL ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	} else {
		countQuery = `SELECT COUNT(*) FROM tenants WHERE deleted_at IS NULL`
		listQuery = `SELECT id, name, realm_name, domain, status, plan, settings, created_at, updated_at, deleted_at
			FROM tenants WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT $1 OFFSET $2`
	}

	// Count total
	var total int
	if status != "" {
		err = r.pool.QueryRow(ctx, countQuery, status).Scan(&total)
	} else {
		err = r.pool.QueryRow(ctx, countQuery).Scan(&total)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("counting tenants: %w", err)
	}

	// Fetch page
	if status != "" {
		rows, err = r.pool.Query(ctx, listQuery, status, limit, offset)
	} else {
		rows, err = r.pool.Query(ctx, listQuery, limit, offset)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("listing tenants: %w", err)
	}
	defer rows.Close()

	var tenants []*models.Tenant
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, 0, err
		}
		tenants = append(tenants, t)
	}
	return tenants, total, rows.Err()
}

// Update updates mutable tenant fields.
func (r *TenantRepository) Update(ctx context.Context, t *models.Tenant) error {
	settingsJSON, err := json.Marshal(t.Settings)
	if err != nil {
		return fmt.Errorf("marshalling settings: %w", err)
	}

	query := `
		UPDATE tenants
		SET name = $2, domain = $3, status = $4, plan = $5, settings = $6
		WHERE id = $1 AND deleted_at IS NULL`

	_, err = r.pool.Exec(ctx, query,
		t.ID, t.Name, t.Domain, t.Status, t.Plan, settingsJSON,
	)
	return err
}

// SoftDelete marks a tenant as deleted without removing the row.
func (r *TenantRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	_, err := r.pool.Exec(ctx,
		`UPDATE tenants SET deleted_at = $2, status = 'deleted' WHERE id = $1`,
		id, now,
	)
	return err
}

// ── Row scanner ──────────────────────────────────────────────────────────────

// scanTenant scans a single row into a *models.Tenant.
// Works with both pgx.Row and pgx.Rows via the pgx.Scanner interface.
func scanTenant(row interface {
	Scan(dest ...any) error
}) (*models.Tenant, error) {
	var t models.Tenant
	var settingsJSON []byte

	err := row.Scan(
		&t.ID, &t.Name, &t.RealmName, &t.Domain, &t.Status, &t.Plan,
		&settingsJSON, &t.CreatedAt, &t.UpdatedAt, &t.DeletedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil // not found
		}
		return nil, fmt.Errorf("scanning tenant row: %w", err)
	}

	if len(settingsJSON) > 0 {
		if err := json.Unmarshal(settingsJSON, &t.Settings); err != nil {
			return nil, fmt.Errorf("unmarshalling settings: %w", err)
		}
	}
	return &t, nil
}

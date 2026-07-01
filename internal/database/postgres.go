// internal/database/postgres.go
// PostgreSQL connection pool initialisation and migration runner.
// Uses pgx/v5 (the best-in-class Go Postgres driver) with a pgxpool
// connection pool for concurrency-safe access.
package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPostgres opens a pgxpool connection pool to PostgreSQL.
// It pings the database to verify connectivity before returning.
func NewPostgres(dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing postgres DSN: %w", err)
	}

	// Tuned pool settings for a typical SaaS backend.
	cfg.MaxConns = 25
	cfg.MinConns = 5
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 10 * time.Minute
	cfg.HealthCheckPeriod = 1 * time.Minute

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("creating postgres pool: %w", err)
	}

	// Verify the connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging postgres: %w", err)
	}

	return pool, nil
}

// RunMigrations executes the embedded DDL statements that create
// application tables if they do not already exist.  This is intentionally
// simple (no versioned migration library) to keep the binary self-contained.
// For complex schema changes use a tool such as golang-migrate.
func RunMigrations(pool *pgxpool.Pool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// All DDL is idempotent (IF NOT EXISTS / OR REPLACE).
	_, err := pool.Exec(ctx, schema)
	return err
}

// schema contains the full DDL for the application database.
// Each table has an explanatory comment so DBAs can understand the purpose
// without reading Go source code.
const schema = `
-- ──────────────────────────────────────────────────────────────────────────────
-- TENANTS
-- One row per customer organisation.  Mirrors the corresponding Keycloak Realm.
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tenants (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          TEXT        NOT NULL,                -- human-friendly display name
    realm_name    TEXT        NOT NULL UNIQUE,         -- Keycloak realm identifier
    domain        TEXT        UNIQUE,                  -- optional custom domain / subdomain
    status        TEXT        NOT NULL DEFAULT 'active', -- active | suspended | deleted
    plan          TEXT        NOT NULL DEFAULT 'free', -- free | starter | pro | enterprise
    settings      JSONB       NOT NULL DEFAULT '{}',   -- arbitrary tenant-level config blob
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at    TIMESTAMPTZ                          -- soft-delete marker
);

-- ──────────────────────────────────────────────────────────────────────────────
-- AUDIT LOGS
-- Immutable, append-only log of every privileged action taken on the platform.
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_logs (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID        REFERENCES tenants(id) ON DELETE SET NULL,
    actor_id      TEXT        NOT NULL,               -- Keycloak user-id of the actor
    actor_email   TEXT        NOT NULL,
    actor_role    TEXT        NOT NULL,               -- super_admin | realm_admin | end_user
    action        TEXT        NOT NULL,               -- e.g. CREATE_USER, DELETE_REALM …
    resource_type TEXT        NOT NULL,               -- user | group | role | tenant | session
    resource_id   TEXT,                               -- ID of the affected resource
    details       JSONB       NOT NULL DEFAULT '{}',  -- action-specific payload
    ip_address    TEXT,
    user_agent    TEXT,
    status        TEXT        NOT NULL DEFAULT 'success', -- success | failure
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_id  ON audit_logs (tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_id   ON audit_logs (actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action      ON audit_logs (action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at  ON audit_logs (created_at DESC);

-- ──────────────────────────────────────────────────────────────────────────────
-- AUTO-UPDATE updated_at
-- ──────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$ BEGIN
    CREATE TRIGGER tenants_set_updated_at
        BEFORE UPDATE ON tenants
        FOR EACH ROW EXECUTE FUNCTION set_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
`

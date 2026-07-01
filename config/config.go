// config/config.go
// Application-wide configuration loaded from environment variables (.env
// file in development, real env vars in production).  All external service
// coordinates live here so that individual packages never read os.Getenv
// directly.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Config holds all runtime configuration for the SaaS IAM application.
type Config struct {
	// ── Server ──────────────────────────────────────────────────────────
	Port       string
	Env        string        // "development" | "staging" | "production"
	BaseDomain string        // e.g. "saas.example.com" – used for tenant subdomain detection
	LogLevel   string        // "debug" | "info" | "warn" | "error"
	JWTSecret  string        // HMAC secret used by our own short-lived session tokens (optional)
	SessionTTL time.Duration // how long a Redis session lives

	// ── Database ────────────────────────────────────────────────────────
	DatabaseURL string // postgres://user:pass@host:5432/dbname?sslmode=disable

	// ── Redis ───────────────────────────────────────────────────────────
	RedisURL string // redis://localhost:6379/0

	// ── Keycloak ────────────────────────────────────────────────────────
	KeycloakURL          string // e.g. http://localhost:8080
	KeycloakAdminUser    string // master-realm admin username
	KeycloakAdminPass    string // master-realm admin password
	KeycloakMasterRealm  string // usually "master"
	KeycloakClientID     string // client id used by the backend
	KeycloakClientSecret string // client secret (confidential client)

	// ── Rate limiting ───────────────────────────────────────────────────
	RateLimitRequests int           // requests per window
	RateLimitWindow   time.Duration // sliding window duration

	// ── CORS ────────────────────────────────────────────────────────────
	AllowedOrigins []string

	// ── Audit log ───────────────────────────────────────────────────────
	AuditEnabled bool
}

// Load reads the .env file (if present) then populates Config from the
// environment.  An error is returned only when a required variable is
// missing or malformed.
func Load() (*Config, error) {
	// Load .env file in non-production environments – failures are silent
	// because the file may not exist in CI / production.
	if env := os.Getenv("ENV"); env != "production" {
		_ = godotenv.Load(".env")
	}

	cfg := &Config{}

	// ── Required fields ─────────────────────────────────────────────────
	required := []struct {
		key  string
		dest *string
	}{
		{"DATABASE_URL", &cfg.DatabaseURL},
		{"KEYCLOAK_URL", &cfg.KeycloakURL},
		{"KEYCLOAK_ADMIN_USER", &cfg.KeycloakAdminUser},
		{"KEYCLOAK_ADMIN_PASS", &cfg.KeycloakAdminPass},
		{"KEYCLOAK_CLIENT_ID", &cfg.KeycloakClientID},
		{"KEYCLOAK_CLIENT_SECRET", &cfg.KeycloakClientSecret},
	}

	var missing []string
	for _, r := range required {
		v := os.Getenv(r.key)
		if v == "" {
			missing = append(missing, r.key)
			continue
		}
		*r.dest = v
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}

	// ── Optional fields with defaults ───────────────────────────────────
	cfg.Port = getEnvOrDefault("PORT", "8080")
	cfg.Env = getEnvOrDefault("ENV", "development")
	cfg.BaseDomain = getEnvOrDefault("BASE_DOMAIN", "localhost")
	cfg.LogLevel = getEnvOrDefault("LOG_LEVEL", "info")
	cfg.JWTSecret = getEnvOrDefault("JWT_SECRET", "change-me-in-production")
	cfg.RedisURL = getEnvOrDefault("REDIS_URL", "redis://localhost:6379/0")
	cfg.KeycloakMasterRealm = getEnvOrDefault("KEYCLOAK_MASTER_REALM", "master")

	// Session TTL (default 8 h)
	ttlStr := getEnvOrDefault("SESSION_TTL", "8h")
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid SESSION_TTL %q: %w", ttlStr, err)
	}
	cfg.SessionTTL = ttl

	// Rate limiting
	cfg.RateLimitRequests = getEnvInt("RATE_LIMIT_REQUESTS", 100)
	rlWindow, err := time.ParseDuration(getEnvOrDefault("RATE_LIMIT_WINDOW", "1m"))
	if err != nil {
		return nil, fmt.Errorf("invalid RATE_LIMIT_WINDOW: %w", err)
	}
	cfg.RateLimitWindow = rlWindow

	// CORS – comma-separated list
	originsRaw := getEnvOrDefault("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8080")
	for _, o := range strings.Split(originsRaw, ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			cfg.AllowedOrigins = append(cfg.AllowedOrigins, o)
		}
	}

	cfg.AuditEnabled = getEnvBool("AUDIT_ENABLED", true)

	return cfg, nil
}

// ── helpers ─────────────────────────────────────────────────────────────────

func getEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func getEnvBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return def
}

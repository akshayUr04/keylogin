// internal/middleware/middleware.go
// Middleware factory and configuration.
// All middleware is constructed here and returned as standard
// func(http.Handler) http.Handler adapters, compatible with gorilla/mux.
package middleware

import (
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/cors"
	"github.com/yourdomain/saas-iam/config"
	"github.com/yourdomain/saas-iam/internal/audit"
	"github.com/yourdomain/saas-iam/internal/auth"
	"github.com/yourdomain/saas-iam/internal/tenant"
	"github.com/yourdomain/saas-iam/pkg/apierror"
	"github.com/yourdomain/saas-iam/pkg/logger"
	"golang.org/x/time/rate"
)

// Config holds the dependencies needed to construct middleware.
type Config struct {
	JWTVerifier    *auth.JWTVerifier
	TenantResolver *tenant.CompositeResolver
	AuditService   *audit.Service
	Logger         *logger.Logger
	Config         *config.Config
}

// Middleware provides all HTTP middleware constructors.
type Middleware struct {
	cfg Config
}

// New creates a new Middleware factory.
func New(cfg Config) *Middleware {
	return &Middleware{cfg: cfg}
}

// ── Request ID ───────────────────────────────────────────────────────────────

// RequestID attaches a unique request ID to every request context and
// response header (X-Request-ID).  If the client provides X-Request-ID,
// that value is re-used (useful for distributed tracing).
func (m *Middleware) RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = uuid.New().String()
		}
		ctx := auth.WithRequestID(r.Context(), id)
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ── Structured logging ───────────────────────────────────────────────────────

// Logger logs incoming requests and their outcomes with structured fields.
func (m *Middleware) Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rw, r)

		m.cfg.Logger.Info("http request",
			logger.Field("method", r.Method),
			logger.Field("path", r.URL.Path),
			logger.Field("remote_addr", r.RemoteAddr),
			logger.Field("request_id", auth.RequestIDFromContext(r.Context())),
			logger.Int("status", rw.status),
			logger.Field("duration", time.Since(start).String()),
		)
	})
}

// responseWriter is a wrapper that captures the status code.
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// ── Panic recovery ───────────────────────────────────────────────────────────

// Recovery catches panics in handlers, logs a stack trace, and returns a
// 500 Internal Server Error to the client.
func (m *Middleware) Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				m.cfg.Logger.Error("panic recovered",
					logger.Field("panic", toString(rec)),
					logger.Field("stack", string(debug.Stack())),
					logger.Field("request_id", auth.RequestIDFromContext(r.Context())),
				)
				apierror.Write(w, apierror.Internal("an unexpected error occurred"))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return "unknown panic"
}

// ── CORS ─────────────────────────────────────────────────────────────────────

// CORS returns a handler that adds CORS headers to responses.
// Only origins in config.AllowedOrigins are permitted.
func (m *Middleware) CORS() func(http.Handler) http.Handler {
	c := cors.New(cors.Options{
		AllowedOrigins:   m.cfg.Config.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-Request-ID", "X-Tenant-Realm"},
		ExposedHeaders:   []string{"X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           86400,
	})
	return c.Handler
}

// ── Rate limiting ────────────────────────────────────────────────────────────

// RateLimiter returns a per-IP token-bucket rate limiter.
// Each unique IP gets its own limiter; limiters are NOT cleaned up in this
// simple implementation – for production consider using a Redis-backed
// distributed rate limiter.
func (m *Middleware) RateLimiter(next http.Handler) http.Handler {
	type entry struct {
		limiter  *rate.Limiter
		lastSeen time.Time
	}

	limiters := make(map[string]*entry)
	// How many requests per second?
	rps := rate.Limit(float64(m.cfg.Config.RateLimitRequests) / m.cfg.Config.RateLimitWindow.Seconds())
	burst := m.cfg.Config.RateLimitRequests / 5 // allow small burst

	var mu sync.RWMutex
	// Clean up stale entries every minute
	go func() {
		for range time.Tick(time.Minute) {
			mu.Lock()
			for ip, e := range limiters {
				if time.Since(e.lastSeen) > 3*time.Minute {
					delete(limiters, ip)
				}
			}
			mu.Unlock()
		}
	}()

	getOrCreate := func(ip string) *rate.Limiter {
		mu.Lock()
		defer mu.Unlock()
		if e, ok := limiters[ip]; ok {
			e.lastSeen = time.Now()
			return e.limiter
		}
		lim := rate.NewLimiter(rps, burst)
		limiters[ip] = &entry{limiter: lim, lastSeen: time.Now()}
		return lim
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		if !getOrCreate(ip).Allow() {
			apierror.Write(w, apierror.RateLimited())
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ── Authentication ───────────────────────────────────────────────────────────

// Authenticate validates the Bearer token or session cookie on the request
// and attaches the parsed Claims to the context.
// Returns 401 if no valid token is present.
func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract realm for multi-tenant JWT validation
		realm := m.cfg.TenantResolver.Resolve(r)
		if realm == "" {
			realm = m.cfg.Config.KeycloakMasterRealm
		}

		// Extract Bearer token from Authorization header
		rawToken := extractBearerToken(r)
		if rawToken == "" {
			apierror.Write(w, apierror.Unauthorized("missing or invalid Authorization header"))
			return
		}

		claims, err := m.cfg.JWTVerifier.Verify(r.Context(), realm, rawToken)
		if err != nil {
			m.cfg.Logger.Debug("JWT verification failed",
				logger.Field("realm", realm),
				logger.Err(err),
			)
			apierror.Write(w, apierror.Unauthorized("invalid or expired token"))
			return
		}

		ctx := auth.WithClaims(r.Context(), claims)
		ctx = auth.WithRealm(ctx, realm)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ── RBAC ─────────────────────────────────────────────────────────────────────

// RequireRoles checks that the authenticated user has AT LEAST ONE of the
// specified Keycloak realm roles.  Must be applied AFTER Authenticate.
func (m *Middleware) RequireRoles(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := auth.ClaimsFromContext(r.Context())
			if claims == nil {
				apierror.Write(w, apierror.Unauthorized("unauthenticated"))
				return
			}

			for _, required := range roles {
				if claims.HasRole(required) {
					next.ServeHTTP(w, r)
					return
				}
			}

			apierror.Write(w, apierror.Forbidden("insufficient role permissions"))
		})
	}
}

// RequireSuperAdmin restricts the endpoint to super-admin users.
func (m *Middleware) RequireSuperAdmin(next http.Handler) http.Handler {
	return m.RequireRoles("super_admin")(next)
}

// RequireRealmAdmin restricts to realm admins (also allows super_admin).
func (m *Middleware) RequireRealmAdmin(next http.Handler) http.Handler {
	return m.RequireRoles("realm_admin", "super_admin")(next)
}

// ── Tenant resolution ────────────────────────────────────────────────────────

// TenantResolution resolves the tenant realm and attaches it to the context.
// Returns 400 if the tenant cannot be resolved.
func (m *Middleware) TenantResolution(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		realm := m.cfg.TenantResolver.Resolve(r)
		if realm != "" {
			ctx := auth.WithRealm(r.Context(), realm)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

// RequireTenant returns 400 if no tenant realm is resolved.
func (m *Middleware) RequireTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.RealmFromContext(r.Context()) == "" {
			apierror.Write(w, apierror.New(http.StatusBadRequest, apierror.CodeTenantNotFound,
				"could not resolve tenant – provide a valid subdomain or X-Tenant-Realm header"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// extractBearerToken parses the "Authorization: Bearer <token>" header.
func extractBearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if header == "" {
		// Also check a session cookie for browser clients
		cookie, err := r.Cookie("access_token")
		if err == nil {
			return cookie.Value
		}
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return parts[1]
}

// extractIP extracts the client IP from X-Forwarded-For or RemoteAddr.
func extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx >= 0 {
		ip = ip[:idx]
	}
	return ip
}

// IPFromRequest extracts and returns the client IP address.
func IPFromRequest(r *http.Request) string { return extractIP(r) }



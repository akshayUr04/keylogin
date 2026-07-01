// cmd/server/main.go
// Entry point for the Multi-Tenant SaaS IAM application.
// Initialises configuration, database, Redis, Keycloak client,
// all service/repository layers and starts the HTTP server with
// graceful shutdown support.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yourdomain/saas-iam/config"
	"github.com/yourdomain/saas-iam/internal/audit"
	"github.com/yourdomain/saas-iam/internal/auth"
	"github.com/yourdomain/saas-iam/internal/database"
	"github.com/yourdomain/saas-iam/internal/handlers"
	"github.com/yourdomain/saas-iam/internal/keycloak"
	"github.com/yourdomain/saas-iam/internal/middleware"
	"github.com/yourdomain/saas-iam/internal/repository"
	"github.com/yourdomain/saas-iam/internal/routes"
	"github.com/yourdomain/saas-iam/internal/services"
	"github.com/yourdomain/saas-iam/internal/tenant"
	"github.com/yourdomain/saas-iam/pkg/logger"
)

func main() {
	// ------------------------------------------------------------------
	// 1. Load application configuration from .env / environment variables
	// ------------------------------------------------------------------
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// ------------------------------------------------------------------
	// 2. Initialise structured logger (Zap)
	// ------------------------------------------------------------------
	log, err := logger.New(cfg.LogLevel, cfg.Env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialise logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Sync() //nolint:errcheck

	log.Info("Starting SaaS IAM server",
		logger.Field("env", cfg.Env),
		logger.Field("port", cfg.Port),
	)

	// ------------------------------------------------------------------
	// 3. Connect to PostgreSQL
	// ------------------------------------------------------------------
	db, err := database.NewPostgres(cfg.DatabaseURL)
	if err != nil {
		log.Fatal("failed to connect to PostgreSQL", logger.Err(err))
	}
	defer db.Close()

	// Run migrations (idempotent)
	if err := database.RunMigrations(db); err != nil {
		log.Fatal("failed to run database migrations", logger.Err(err))
	}

	// ------------------------------------------------------------------
	// 4. Connect to Redis (session / token cache)
	// ------------------------------------------------------------------
	redisClient, err := database.NewRedis(cfg.RedisURL)
	if err != nil {
		log.Fatal("failed to connect to Redis", logger.Err(err))
	}
	defer redisClient.Close()

	// ------------------------------------------------------------------
	// 5. Build the Keycloak Admin API client
	// ------------------------------------------------------------------
	kcClient := keycloak.NewClient(keycloak.Config{
		BaseURL:      cfg.KeycloakURL,
		AdminUser:    cfg.KeycloakAdminUser,
		AdminPass:    cfg.KeycloakAdminPass,
		MasterRealm:  cfg.KeycloakMasterRealm,
		ClientID:     cfg.KeycloakClientID,
		ClientSecret: cfg.KeycloakClientSecret,
	}, log)

	// ------------------------------------------------------------------
	// 6. Initialise JWT verifier (validates against Keycloak JWKS endpoint)
	// ------------------------------------------------------------------
	jwtVerifier := auth.NewJWTVerifier(cfg.KeycloakURL, cfg.KeycloakMasterRealm, log)

	// ------------------------------------------------------------------
	// 7. Build Tenant Resolver (subdomain → realm mapping)
	// ------------------------------------------------------------------
	tenantResolver := tenant.NewCompositeResolver(
		tenant.NewSubdomainResolver(cfg.BaseDomain),
		tenant.NewHeaderResolver(),
		tenant.NewQueryParamResolver(),
	)

	// ------------------------------------------------------------------
	// 8. Wire up repositories
	// ------------------------------------------------------------------
	tenantRepo := repository.NewTenantRepository(db, log)
	auditRepo := repository.NewAuditRepository(db, log)
	sessionRepo := repository.NewSessionRepository(redisClient, log)

	// ------------------------------------------------------------------
	// 9. Wire up services
	// ------------------------------------------------------------------
	auditSvc := audit.NewService(auditRepo, log)
	tenantSvc := services.NewTenantService(tenantRepo, kcClient, auditSvc, log)
	userSvc := services.NewUserService(kcClient, auditSvc, log)
	groupSvc := services.NewGroupService(kcClient, auditSvc, log)
	roleSvc := services.NewRoleService(kcClient, auditSvc, log)
	sessionSvc := services.NewSessionService(sessionRepo, kcClient, log)
	authSvc := services.NewAuthService(kcClient, sessionSvc, jwtVerifier, cfg, log)
	profileSvc := services.NewProfileService(kcClient, log)

	// ------------------------------------------------------------------
	// 10. Wire up HTTP handlers
	// ------------------------------------------------------------------
	h := handlers.New(handlers.Dependencies{
		AuthService:    authSvc,
		TenantService:  tenantSvc,
		UserService:    userSvc,
		GroupService:   groupSvc,
		RoleService:    roleSvc,
		SessionService: sessionSvc,
		ProfileService: profileSvc,
		AuditService:   auditSvc,
		Config:         cfg,
		Logger:         log,
	})

	// ------------------------------------------------------------------
	// 11. Build middleware chain
	// ------------------------------------------------------------------
	mw := middleware.New(middleware.Config{
		JWTVerifier:    jwtVerifier,
		TenantResolver: tenantResolver,
		AuditService:   auditSvc,
		Logger:         log,
		Config:         cfg,
	})

	// ------------------------------------------------------------------
	// 12. Register routes and create HTTP server
	// ------------------------------------------------------------------
	router := routes.Register(h, mw, cfg)

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// ------------------------------------------------------------------
	// 13. Start server in a goroutine; listen for OS signals for graceful
	//     shutdown.
	// ------------------------------------------------------------------
	serverErr := make(chan error, 1)
	go func() {
		log.Info("HTTP server listening", logger.Field("addr", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		log.Fatal("server error", logger.Err(err))
	case sig := <-quit:
		log.Info("received shutdown signal", logger.Field("signal", sig.String()))
	}

	// Graceful shutdown: allow up to 30 s for in-flight requests to finish.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Error("graceful shutdown failed", logger.Err(err))
		os.Exit(1)
	}

	log.Info("server stopped cleanly")
}

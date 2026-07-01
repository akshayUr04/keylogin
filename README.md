# SaaS IAM Platform

> **Production-ready, enterprise-grade Multi-Tenant Identity & Access Management platform** built with Go, Keycloak, PostgreSQL, and Redis.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Browser / API Client                          │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ HTTPS
┌───────────────────────────────▼─────────────────────────────────────┐
│                      Go Backend (SaaS IAM)                           │
│                                                                      │
│  ┌──────────┐ ┌────────────┐ ┌─────────────┐ ┌──────────────────┐  │
│  │ Auth     │ │ Tenant     │ │ User / Group│ │ Audit / Sessions │  │
│  │ Service  │ │ Service    │ │ Role Service│ │ Service          │  │
│  └────┬─────┘ └─────┬──────┘ └──────┬──────┘ └────────┬─────────┘  │
│       │             │               │                  │            │
│  ┌────▼─────────────▼───────────────▼──────────────────▼──────────┐ │
│  │                   Keycloak Admin REST Client                    │ │
│  └────────────────────────────┬────────────────────────────────────┘ │
└───────────────────────────────┼──────────────────────────────────────┘
                                │ Admin REST API
┌───────────────────────────────▼──────────────────────────────────────┐
│                         Keycloak IAM Server                           │
│                                                                       │
│   Master Realm          Tenant-A Realm       Tenant-B Realm          │
│   ┌──────────┐         ┌──────────────┐     ┌──────────────┐        │
│   │ super    │         │ realm_admin  │     │ realm_admin  │        │
│   │ admin    │         │ users/groups │     │ users/groups │        │
│   └──────────┘         │ roles/sess. │     │ roles/sess.  │        │
│                         └──────────────┘     └──────────────┘        │
└───────────────────────────────────────────────────────────────────────┘
                     │                          │
            ┌────────▼────────┐        ┌────────▼────────┐
            │   PostgreSQL    │        │      Redis       │
            │  (tenants +     │        │  (sessions +     │
            │   audit logs)   │        │   token cache)   │
            └─────────────────┘        └──────────────────┘
```

---

## Project Structure

```
saas-iam/
├── cmd/server/main.go              # Entry point – wires all dependencies
├── config/config.go                # Configuration loader (.env → struct)
├── Dockerfile                      # Multi-stage minimal container image
├── docker-compose.yml              # Full stack: app + Keycloak + PG + Redis
├── Makefile                        # Developer helpers
├── .env.example                    # Configuration template
│
├── internal/
│   ├── auth/
│   │   ├── jwt.go                  # JWKS-based JWT verifier with caching
│   │   ├── keys.go                 # RSA / EC public key parsing from JWK
│   │   └── context.go              # Typed context keys for claims / realm
│   │
│   ├── keycloak/
│   │   ├── client.go               # Admin API client (auto token refresh)
│   │   ├── realms.go               # Realm CRUD
│   │   ├── users.go                # User CRUD + role/group assignment
│   │   ├── groups.go               # Group CRUD + membership
│   │   └── roles.go                # Role CRUD
│   │
│   ├── tenant/
│   │   └── resolver.go             # Subdomain / header / query resolution
│   │
│   ├── models/
│   │   ├── tenant.go               # Tenant domain model
│   │   └── user.go                 # User, Session, AuditLog models
│   │
│   ├── database/
│   │   ├── postgres.go             # PG pool + embedded schema migrations
│   │   └── redis.go                # Redis client
│   │
│   ├── repository/
│   │   ├── tenant_repository.go    # Tenant CRUD in PostgreSQL
│   │   ├── audit_repository.go     # Append-only audit log
│   │   └── session_repository.go   # Redis-backed sessions
│   │
│   ├── audit/
│   │   └── service.go              # Non-blocking audit event recorder
│   │
│   ├── services/
│   │   ├── auth_service.go         # Login / logout / refresh / session
│   │   ├── tenant_service.go       # Tenant lifecycle (realm + DB)
│   │   ├── user_service.go         # User management
│   │   ├── group_service.go        # Group management
│   │   ├── role_service.go         # Role management
│   │   ├── session_service.go      # Session listing / termination
│   │   └── profile_service.go      # End-user self-service
│   │
│   ├── middleware/
│   │   └── middleware.go           # Auth, RBAC, CORS, rate-limit, logging
│   │
│   ├── handlers/
│   │   ├── handlers.go             # Dependency injection container
│   │   ├── auth_handler.go         # Login / logout / refresh / me
│   │   ├── tenant_handler.go       # Tenant CRUD (super admin)
│   │   ├── user_handler.go         # User CRUD (realm admin)
│   │   ├── group_handler.go        # Group CRUD (realm admin)
│   │   ├── role_handler.go         # Role CRUD (realm admin)
│   │   ├── profile_handler.go      # Profile self-service (end user)
│   │   ├── audit_handler.go        # Audit log queries
│   │   └── helpers.go              # Shared handler utilities
│   │
│   └── routes/
│       └── routes.go               # gorilla/mux route registration
│
├── pkg/
│   ├── logger/logger.go            # Zap-based structured logger
│   ├── apierror/apierror.go        # Canonical JSON error type
│   └── response/response.go        # HTTP response helpers
│
└── web/dist/
    ├── index.html                  # Login page
    ├── css/
    │   ├── global.css              # Design system tokens + base styles
    │   ├── login.css               # Login-specific styles
    │   └── dashboard.css           # Dashboard layout + components
    ├── js/
    │   ├── api.js                  # Centralised REST client
    │   ├── login.js                # Login page controller
    │   ├── dashboard-common.js     # Shared dashboard utilities
    │   ├── super-admin.js          # Super admin dashboard controller
    │   └── realm-admin.js          # Realm admin dashboard controller
    └── dashboard/
        ├── super-admin.html        # Super admin dashboard page
        └── realm-admin.html        # Realm admin dashboard page
```

---

## Quick Start

### Prerequisites
- Go 1.22+
- Docker & Docker Compose
- `make` (optional)

### 1. Clone and configure

```bash
git clone <repo-url> saas-iam
cd saas-iam
cp .env.example .env
# Edit .env with your configuration
```

### 2. Start the full stack

```bash
docker compose up -d
```

This starts:
- **Keycloak** at http://localhost:8081 (admin: `admin` / `Admin1234!`)
- **PostgreSQL** at localhost:5432
- **Redis** at localhost:6379
- **SaaS IAM app** at http://localhost:8080

### 3. Configure Keycloak client

In the Keycloak admin console (http://localhost:8081):

1. Go to **Master realm → Clients → Create client**
2. **Client ID**: `saas-iam-backend`
3. **Client authentication**: ON
4. **Direct access grants**: ON
5. **Service accounts**: ON
6. Copy the client secret and update `KEYCLOAK_CLIENT_SECRET` in `.env`

Or run the automated setup:
```bash
make keycloak-setup KEYCLOAK_URL=http://localhost:8081 KEYCLOAK_ADMIN_USER=admin KEYCLOAK_ADMIN_PASS=Admin1234!
```

### 4. Create the super admin role

In Keycloak master realm:
1. **Realm roles → Create role**: `super_admin`
2. **Users → Admin user → Role mapping**: Assign `super_admin`

### 5. Access the application

Open http://localhost:8080 → Login with your Keycloak admin credentials.

---

## API Reference

All endpoints are prefixed with `/api/v1`.

### Authentication

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/login` | Public | Login with username/password |
| POST | `/auth/logout` | Session | Logout and revoke tokens |
| POST | `/auth/refresh` | Session | Refresh access token |
| GET | `/auth/me` | Bearer | Get current user info |

### Tenant Management (Super Admin)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/tenants` | List all tenants |
| POST | `/admin/tenants` | Create tenant + Keycloak realm |
| GET | `/admin/tenants/{id}` | Get tenant details |
| DELETE | `/admin/tenants/{id}` | Delete tenant |
| POST | `/admin/tenants/{id}/suspend` | Suspend tenant |
| POST | `/admin/tenants/{id}/enable` | Re-enable tenant |
| GET | `/admin/audit-logs` | View all audit logs |

### User Management (Realm Admin)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/realms/{realm}/users` | List users |
| POST | `/realms/{realm}/users` | Create user |
| GET | `/realms/{realm}/users/{id}` | Get user |
| PUT | `/realms/{realm}/users/{id}` | Update user |
| DELETE | `/realms/{realm}/users/{id}` | Delete user |
| PUT | `/realms/{realm}/users/{id}/enabled` | Enable/disable user |
| PUT | `/realms/{realm}/users/{id}/reset-password` | Reset password |
| POST | `/realms/{realm}/users/{id}/roles` | Assign roles |
| DELETE | `/realms/{realm}/users/{id}/roles` | Remove roles |
| GET | `/realms/{realm}/users/{id}/sessions` | Get user sessions |

### Group Management (Realm Admin)

| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/realms/{realm}/groups` | List / Create |
| GET/PUT/DELETE | `/realms/{realm}/groups/{id}` | Get / Update / Delete |
| GET | `/realms/{realm}/groups/{id}/members` | List members |
| PUT/DELETE | `/realms/{realm}/groups/{groupId}/members/{userId}` | Add/Remove member |

### Role Management (Realm Admin)

| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/realms/{realm}/roles` | List / Create |
| GET/DELETE | `/realms/{realm}/roles/{name}` | Get / Delete |
| GET | `/realms/{realm}/roles/{name}/users` | Users with role |

### Profile (End User)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/profile` | Get own profile |
| PUT | `/profile` | Update profile |
| POST | `/profile/change-password` | Change password |

---

## Security Design

### JWT Verification
- All JWTs are verified **cryptographically** using Keycloak's JWKS endpoint
- JWKS is cached per realm with automatic refresh on key rotation
- Validates: signature, issuer, expiry, audience, not-before

### Tenant Isolation
- Every tenant has its own dedicated Keycloak Realm
- Service layer enforces realm-scoped operations
- Realm admins cannot access other realms (validated in `assertRealmAccess`)

### Session Management
- Sessions stored in Redis with configurable TTL
- Access tokens refreshed transparently
- Logout revokes Keycloak refresh token AND destroys local session

### Rate Limiting
- Per-IP token bucket rate limiter
- Configurable via `RATE_LIMIT_REQUESTS` and `RATE_LIMIT_WINDOW`

---

## User Roles

| Role | Realm | Capabilities |
|------|-------|-------------|
| `super_admin` | Master | Full platform control: manage tenants, realms, all users |
| `realm_admin` | Tenant | Manage users/groups/roles within their realm only |
| `end_user` | Tenant | Login, view profile, change own password |

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | ✅ | – | PostgreSQL connection string |
| `KEYCLOAK_URL` | ✅ | – | Keycloak server URL |
| `KEYCLOAK_ADMIN_USER` | ✅ | – | Master realm admin username |
| `KEYCLOAK_ADMIN_PASS` | ✅ | – | Master realm admin password |
| `KEYCLOAK_CLIENT_ID` | ✅ | – | Backend client ID |
| `KEYCLOAK_CLIENT_SECRET` | ✅ | – | Backend client secret |
| `PORT` | ❌ | `8080` | HTTP server port |
| `ENV` | ❌ | `development` | Environment mode |
| `REDIS_URL` | ❌ | redis://localhost:6379/0 | Redis connection |
| `SESSION_TTL` | ❌ | `8h` | Session lifetime |
| `LOG_LEVEL` | ❌ | `info` | debug/info/warn/error |
| `BASE_DOMAIN` | ❌ | `localhost` | Base domain for subdomain resolution |
| `ALLOWED_ORIGINS` | ❌ | localhost:8080 | Comma-separated CORS origins |

---

## Production Checklist

- [ ] Replace all `change-me-in-production` secrets
- [ ] Enable TLS on Keycloak (use `start` instead of `start-dev`)
- [ ] Set `ENV=production` for structured JSON logs
- [ ] Configure `ALLOWED_ORIGINS` to your actual domains
- [ ] Set up a reverse proxy (nginx/Caddy) with TLS termination
- [ ] Configure a proper Redis password
- [ ] Set `SESSION_TTL` appropriately for your security policy
- [ ] Enable Keycloak's brute-force protection (enabled by default in realm config)
- [ ] Set up database backups for PostgreSQL
- [ ] Review Keycloak password policy in `DefaultRealmConfig`

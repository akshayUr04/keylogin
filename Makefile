# Makefile – SaaS IAM Development Helpers

.PHONY: all build run test tidy docker-up docker-down docker-logs clean keycloak-setup

# ── Build ──────────────────────────────────────────────────
all: tidy build

tidy:
	go mod tidy

build:
	CGO_ENABLED=0 go build -o ./bin/saas-iam ./cmd/server

run: build
	./bin/saas-iam

# ── Docker ────────────────────────────────────────────────
docker-up:
	docker compose up -d --build

docker-down:
	docker compose down -v

docker-logs:
	docker compose logs -f app

docker-restart:
	docker compose restart app

# ── Keycloak client setup ─────────────────────────────────
# Creates the backend client in the master realm.
# Requires KEYCLOAK_URL and admin credentials to be set.
keycloak-setup:
	@echo "Creating saas-iam-backend client in Keycloak master realm..."
	@TOKEN=$$(curl -s -X POST "$(KEYCLOAK_URL)/realms/master/protocol/openid-connect/token" \
		-H "Content-Type: application/x-www-form-urlencoded" \
		-d "grant_type=password&client_id=admin-cli&username=$(KEYCLOAK_ADMIN_USER)&password=$(KEYCLOAK_ADMIN_PASS)" \
		| python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])") && \
	curl -s -X POST "$(KEYCLOAK_URL)/admin/realms/master/clients" \
		-H "Authorization: Bearer $$TOKEN" \
		-H "Content-Type: application/json" \
		-d '{"clientId":"saas-iam-backend","enabled":true,"clientAuthenticatorType":"client-secret","secret":"change-me-in-production","directAccessGrantsEnabled":true,"serviceAccountsEnabled":true,"standardFlowEnabled":false}' && \
	echo "Client created successfully"

# ── Development ────────────────────────────────────────────
.env:
	cp .env.example .env
	@echo ".env created – please fill in the values"

lint:
	@which golangci-lint >/dev/null 2>&1 || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run ./...

fmt:
	gofmt -w .
	goimports -w .

vet:
	go vet ./...

clean:
	rm -rf ./bin ./dist

# ── Testing ────────────────────────────────────────────────
test:
	go test -v -race -count=1 ./...

test-cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

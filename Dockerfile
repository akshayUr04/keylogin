# ── Multi-stage Dockerfile for the SaaS IAM Go application ────────────────────

# ── Stage 1: Builder ───────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

LABEL stage=builder

# Install build tools
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Cache dependency downloads before copying source
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source and build the binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -extldflags '-static'" \
    -o /saas-iam ./cmd/server

# ── Stage 2: Runtime ───────────────────────────────────────────────────────────
FROM scratch

# Copy timezone data and CA certificates from builder
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the statically-linked binary
COPY --from=builder /saas-iam /saas-iam

# The app expects the frontend to be mounted at /app/web/dist
# In Docker Compose, we bind-mount the host ./web/dist directory.
WORKDIR /app

# Expose the HTTP port
EXPOSE 8080

# Run as non-root user for security
USER 65534:65534

ENTRYPOINT ["/saas-iam"]

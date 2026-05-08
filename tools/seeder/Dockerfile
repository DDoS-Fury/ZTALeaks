# =============================================================================
# Business Database Seed - Go Application
# Project: ZTALeaks - Zero Trust Architecture for Nuclear Plant
# =============================================================================
# Multi-stage build for the database seed application.
# Stage 1: Compiles the Go binary with CGO disabled for static linking.
# Stage 2: Copies only the binary into a minimal Alpine image.
# The resulting container is ephemeral - it runs once to populate the
# database and then exits.
# =============================================================================

# -- Build stage ---------------------------------------------------------------
FROM golang:1.26-alpine AS builder

WORKDIR /app

# Copy dependency manifests first to leverage Docker layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and compile
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o seed ./cmd/seeder/main.go

# -- Runtime stage -------------------------------------------------------------
FROM alpine:3.19

# Install CA certificates for TLS connections if needed
RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /app/seed .

# Run as non-root user
RUN adduser -D -u 1001 seeduser
USER seeduser

CMD ["./seed"]
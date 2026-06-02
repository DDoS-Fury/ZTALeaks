# =============================================================================
# nftables Firewall - Dockerfile
#
# Multi-stage build:
#   Stage 1 (builder): compiles the Go log parser that converts ulogd
#                      syslogemu output to structured JSONL.
#   Stage 2 (runtime): Alpine image with nftables, ulogd, and the compiled
#                      parser binary.
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build the Go log parser
# -----------------------------------------------------------------------------
FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY infra/nftables/parser.go .

RUN go build -o nftables-parser parser.go

# -----------------------------------------------------------------------------
# Stage 2: Runtime image
# -----------------------------------------------------------------------------
FROM alpine:3.19

# Install nftables, ulogd (for kernel packet logging), and utilities
RUN apk add --no-cache \
    nftables \
    iproute2 \
    bash \
    util-linux \
    dos2unix \
    ulogd

# Copy nftables and ulogd configuration files
COPY infra/nftables/nftables.conf /etc/nftables.conf
COPY infra/nftables/ulogd.conf    /etc/ulogd.conf

# Copy the container entrypoint script
COPY infra/nftables/entrypoint.sh /entrypoint.sh

# Copy the compiled parser binary from the builder stage
COPY --from=builder /app/nftables-parser /usr/local/bin/nftables-parser

# Normalize line endings (important when building on Windows hosts) and
# make the entrypoint executable
RUN dos2unix /etc/nftables.conf /etc/ulogd.conf /entrypoint.sh \
    && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
# =============================================================================
# snort-mid - Dockerfile
#
# This Snort instance monitors TCP traffic between Envoy and the Security
# Orchestrator on port 8081 (queue 3 in the nftables IDS chain
# ids_output_extauthz). Its focus is on application-layer attacks carried in
# the plaintext ext_authz HTTP request URI: SQL injection and XSS.
#
# Multi-stage build:
#   Stage 1 (builder): compiles the Go alert parser.
#   Stage 2 (runtime): Ubuntu 24.04 with Snort 2.9 and the compiled parser.
#
# NFQUEUE integration:
#   The nftables rule "tcp dport 8081 queue num 3 bypass" in the
#   ids_output_extauthz chain (OUTPUT hook) diverts packets to this instance.
#   Snort only issues "alert" verdicts. The "bypass" keyword ensures fail-open
#   behaviour if this container crashes.
#   "-k none" disables checksum validation for Docker veth interfaces.
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build the Go alert parser
# -----------------------------------------------------------------------------
FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY infra/snort-mid/parser.go .

RUN go mod init snort-parser \
    && go get golang.org/x/time/rate \
    && go build -o snort-parser parser.go

# -----------------------------------------------------------------------------
# Stage 2: Runtime image
# -----------------------------------------------------------------------------
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        snort \
        iproute2 \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Create required directories for Snort
RUN mkdir -p /var/log/snort /etc/snort/rules

# Include the custom rules file in the default snort.conf
RUN echo "include /etc/snort/rules/mid.rules" >> /etc/snort/snort.conf

# Copy the custom Snort rules and the compiled parser binary
COPY infra/snort-mid/rules/mid.rules /etc/snort/rules/mid.rules
COPY --from=builder /app/snort-parser /usr/local/bin/snort-parser

# Create the output directory for JSONL alert files (mounted by Splunk UF)
RUN mkdir -p /var/log/ztaleaks/snort-mid

# Start the Go parser (background) and Snort (foreground, NFQUEUE mode, queue 3).
CMD bash -c " \
    touch /var/log/snort/alert \
    && mkdir -p /var/log/ztaleaks/snort-mid \
    && /usr/local/bin/snort-parser \
           /var/log/snort/alert \
           /var/log/ztaleaks/snort-mid/alert_json.txt \
           snort-mid & \
    snort -k none -c /etc/snort/snort.conf -A fast --daq nfq --daq-var queue=3"
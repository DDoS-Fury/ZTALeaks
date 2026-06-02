# =============================================================================
# snort-internal - Dockerfile
#
# This Snort instance monitors TCP traffic directed at the Envoy listener port
# (queue 2 in the nftables IDS chain ids_prerouting_tls). Its focus is on
# TLS handshake anomalies: missing mTLS certificates, legacy TLS versions,
# downgrade attacks, weak cipher suites, and volumetric SYN floods.
#
# Multi-stage build:
#   Stage 1 (builder): compiles the Go alert parser.
#   Stage 2 (runtime): Ubuntu 24.04 with Snort 2.9 and the compiled parser.
#
# NFQUEUE integration:
#   The nftables rule "tcp dport ENVOY_PORT queue num 2 bypass" in the
#   ids_prerouting_tls chain diverts packets to this instance.
#   Snort only issues "alert" verdicts (never "drop"), so traffic flows
#   through regardless. The "bypass" keyword ensures fail-open behaviour
#   if this container crashes.
#   "-k none" disables checksum validation, which is necessary on Docker
#   veth interfaces where checksum offloading makes checksums unreliable.
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build the Go alert parser
# -----------------------------------------------------------------------------
FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY infra/snort-internal/parser.go .

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

# Append the sfportscan preprocessor configuration and include the custom
# rules file into the default snort.conf
RUN echo "preprocessor sfportscan: proto { all } memcap { 10000000 } sense_level { low }" \
        >> /etc/snort/snort.conf \
    && echo "include /etc/snort/rules/internal.rules" \
        >> /etc/snort/snort.conf

# Copy the compiled parser binary from the builder stage
COPY --from=builder /app/snort-parser /usr/local/bin/snort-parser

# Create the output directory for JSONL alert files (mounted by Splunk UF)
RUN mkdir -p /var/log/ztaleaks/snort-internal

# Copy the custom Snort rules
COPY infra/snort-internal/rules/internal.rules /etc/snort/rules/internal.rules

# Substitute the Envoy port placeholder in the rules file, then start
# the Go parser (background) and Snort (foreground, NFQUEUE mode, queue 2).
CMD sed -i "s/ENV_ENVOY_PORT/${ENVOY_PORT:-8443}/g" /etc/snort/rules/internal.rules \
    && touch /var/log/snort/alert \
    && mkdir -p /var/log/ztaleaks/snort-internal \
    && /usr/local/bin/snort-parser \
           /var/log/snort/alert \
           /var/log/ztaleaks/snort-internal/alert_json.txt \
           snort-internal & \
    snort -k none -c /etc/snort/snort.conf -A fast --daq nfq --daq-var queue=2
    
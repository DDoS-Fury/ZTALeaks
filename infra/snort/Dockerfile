# =============================================================================
# snort (external) - Dockerfile
#
# This Snort instance monitors all inbound traffic on the front-net interface
# (queue 1 in the nftables IDS chain ids_prerouting). Its primary focus is
# port scanning and reconnaissance activity.
#
# Multi-stage build:
#   Stage 1 (builder): compiles the Go alert parser.
#   Stage 2 (runtime): Ubuntu 24.04 with Snort 2.9 and the compiled parser.
#
# NFQUEUE integration:
#   The nftables rule "iifname <front-iface> queue num 1 bypass" diverts
#   all inbound packets to this instance. Snort only issues "alert" verdicts
#   (never "drop"). The "bypass" keyword ensures fail-open behaviour if this
#   container crashes.
#   "-k none" disables checksum validation for Docker veth interfaces.
#   "-A fast" writes alerts to /var/log/snort/alert (consumed by parser.go).
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build the Go alert parser
# -----------------------------------------------------------------------------
FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY infra/snort/parser.go .

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

# Enable the sfportscan preprocessor and include the custom rules file
# in the default snort.conf
RUN echo "preprocessor sfportscan: proto { all } memcap { 10000000 } sense_level { low }" \
        >> /etc/snort/snort.conf \
    && echo "include /etc/snort/rules/portscan.rules" \
        >> /etc/snort/snort.conf

# Copy the custom Snort rules and the compiled parser binary
COPY infra/snort/rules/portscan.rules /etc/snort/rules/portscan.rules
COPY --from=builder /app/snort-parser /usr/local/bin/snort-parser

# Create the output directory for JSONL alert files (mounted by Splunk UF)
RUN mkdir -p /var/log/ztaleaks/snort

# Start the Go parser (background) and Snort (foreground, NFQUEUE mode, queue 1).
CMD bash -c " \
    touch /var/log/snort/alert \
    && mkdir -p /var/log/ztaleaks/snort \
    && /usr/local/bin/snort-parser \
           /var/log/snort/alert \
           /var/log/ztaleaks/snort/alert_json.txt \
           snort & \
    snort -k none -c /etc/snort/snort.conf -A fast --daq nfq --daq-var queue=1"
# Fase 1: Build parser Go
FROM golang:1.22-alpine as builder
WORKDIR /app
COPY infra/snort-mid/parser.go .
RUN go build -o snort-parser parser.go

# Fase 2: Immagine Snort base
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    snort \
    iproute2 \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/log/snort /etc/snort/rules

# Include custom rules in snort.conf
RUN echo "include /etc/snort/rules/mid.rules" >> /etc/snort/snort.conf

COPY infra/snort-mid/rules/mid.rules /etc/snort/rules/mid.rules

COPY --from=builder /app/snort-parser /usr/local/bin/snort-parser
RUN mkdir -p /var/log/ztaleaks/snort-mid

# IDS inline via NFQUEUE: il kernel devia su queue 3 il traffico TCP
# diretto a orchestrator:8081 (rule nftables 'tcp dport 8081 queue num 3
# bypass' nella chain ids_output_extauthz, hook OUTPUT). Snort verdicta
# ACCEPT (rule 'alert', niente 'drop'). Bypass = fail-open.
# -k none: necessario su veth Docker (checksum offloading).
CMD bash -c "touch /var/log/snort/alert && mkdir -p /var/log/ztaleaks/snort-mid && /usr/local/bin/snort-parser /var/log/snort/alert /var/log/ztaleaks/snort-mid/alert_json.txt snort-mid & snort -k none -c /etc/snort/snort.conf -A fast --daq nfq --daq-var queue=3"

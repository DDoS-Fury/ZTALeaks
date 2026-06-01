# Fase 1: Build parser Go
FROM golang:1.25-alpine as builder
WORKDIR /app
COPY infra/snort-internal/parser.go .
RUN go mod init snort-parser && \
    go get golang.org/x/time/rate && \
    go build -o snort-parser parser.go

# Fase 2: Immagine Snort base
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    snort \
    iproute2 \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/log/snort /etc/snort/rules

# Tweak standard snort configuration
RUN echo "preprocessor sfportscan: proto { all } memcap { 10000000 } sense_level { low }" >> /etc/snort/snort.conf && \
    echo "include /etc/snort/rules/internal.rules" >> /etc/snort/snort.conf     

COPY --from=builder /app/snort-parser /usr/local/bin/snort-parser
RUN mkdir -p /var/log/ztaleaks/snort-internal

COPY infra/snort-internal/rules/internal.rules /etc/snort/rules/internal.rules

# IDS inline via NFQUEUE: il kernel devia i pacchetti su queue 2 (rule
# nftables 'tcp dport ENVOY_PORT queue num 2 bypass' nella chain
# ids_prerouting_tls). Snort verdicta ACCEPT (rule 'alert' soltanto,
# niente 'drop'). Bypass garantisce fail-open se snort cade.
# -k none: necessario per veth Docker dove il checksum offloading
#          renderebbe inaffidabili i pacchetti.
CMD sed -i "s/ENV_ENVOY_PORT/${ENVOY_PORT:-8443}/g" /etc/snort/rules/internal.rules && \
    touch /var/log/snort/alert && mkdir -p /var/log/ztaleaks/snort-internal && \
    /usr/local/bin/snort-parser /var/log/snort/alert /var/log/ztaleaks/snort-internal/alert_json.txt snort-internal & \
    snort -k none -c /etc/snort/snort.conf -A fast --daq nfq --daq-var queue=2

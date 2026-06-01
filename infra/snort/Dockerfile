# Fase 1: Build parser Go
FROM golang:1.25-alpine as builder
WORKDIR /app
COPY infra/snort/parser.go .
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
# Enable sfportscan preprocessor and include our custom rules
RUN echo "preprocessor sfportscan: proto { all } memcap { 10000000 } sense_level { low }" >> /etc/snort/snort.conf && \
    echo "include /etc/snort/rules/portscan.rules" >> /etc/snort/snort.conf

COPY infra/snort/rules/portscan.rules /etc/snort/rules/portscan.rules

COPY --from=builder /app/snort-parser /usr/local/bin/snort-parser
RUN mkdir -p /var/log/ztaleaks/snort

# IDS inline via NFQUEUE: il kernel devia i pacchetti su queue 1 (rule
# nftables 'iifname eth0 queue num 1 bypass'). Snort ispeziona e verdicta
# sempre ACCEPT (rule 'alert', niente 'drop'): fail-open garantito da
# 'bypass' lato nftables se snort crasha.
# -k none: checksum offloading su veth Docker e' inaffidabile, evitiamo
#          drop silenziosi.
# -A fast: log alerts in /var/log/snort/alert (formato consumato da parser.go).
CMD bash -c "touch /var/log/snort/alert && mkdir -p /var/log/ztaleaks/snort && /usr/local/bin/snort-parser /var/log/snort/alert /var/log/ztaleaks/snort/alert_json.txt snort & snort -k none -c /etc/snort/snort.conf -A fast --daq nfq --daq-var queue=1"

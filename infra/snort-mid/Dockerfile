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

# Aggiunge la regola per il rilevamento di SQL Injection e XSS nel traffico HTTP
# Il preprocessor http_inspect abilita la decodifica del payload HTTP (URL-encoding, ecc.)
# necessaria per i pattern SQLi/XSS
RUN echo "preprocessor http_inspect: global iis_unicode_map /etc/snort/unicode.map 1252 compress_depth 65535 decompress_depth 65535" >> /etc/snort/snort.conf && \
    echo "preprocessor http_inspect_server: server default ports { 8081 } oversize_dir_length 500" >> /etc/snort/snort.conf && \
    echo "include /etc/snort/rules/mid.rules" >> /etc/snort/snort.conf

COPY infra/snort-mid/rules/mid.rules /etc/snort/rules/mid.rules

COPY --from=builder /app/snort-parser /usr/local/bin/snort-parser
RUN mkdir -p /var/log/ztaleaks/snort-mid

# -A fast: log alerts su /var/log/snort/alert
# -k none: disabilita verifica checksum (necessario in Docker per checksum offloading)
# -i eth0: ascolta sull'interfaccia condivisa con il firewall
CMD bash -c "touch /var/log/snort/alert && mkdir -p /var/log/ztaleaks/snort-mid && \
    /usr/local/bin/snort-parser /var/log/snort/alert /var/log/ztaleaks/snort-mid/alert_json.txt & \
    snort -k none -c /etc/snort/snort.conf -i eth0 -A fast"

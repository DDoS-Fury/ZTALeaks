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

COPY infra/snort-internal/rules/internal.rules /etc/snort/rules/internal.rules

# Avvio con sed per iniettare l'ENVOY_PORT dinamica e gestire il log bypassando buffering
CMD sed -i "s/ENV_ENVOY_PORT/${ENVOY_PORT:-8443}/g" /etc/snort/rules/internal.rules && \
    snort -k none -c /etc/snort/snort.conf -i eth0 -A fast & tail -F /var/log/snort/alert

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

# -A console: log alerts to standard output (docker logs)
# -k none: disable checksum verification (important for Docker/virtual networks where checksum offloading causes Snort to drop packets)
# -i eth0: listen on shared interface
CMD ["snort", "-k", "none", "-c", "/etc/snort/snort.conf", "-i", "eth0", "-A", "console"]

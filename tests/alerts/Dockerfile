FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    snort \
    python3 \
    python3-pip \
    python3-venv \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Virtualenv to bypass PEP 668 "externally-managed-environment".
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

COPY tests/alerts/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Rule sets of the three snort flavors; ENV_ENVOY_PORT placeholder rewritten.
COPY infra/snort/rules/          /rules/snort/
COPY infra/snort-internal/rules/ /rules/snort-internal/
COPY infra/snort-mid/rules/      /rules/snort-mid/
RUN sed -i "s/ENV_ENVOY_PORT/8443/g" /rules/snort-internal/internal.rules

COPY tests/alerts/snort-test.conf /etc/snort/snort-test.conf
COPY tests/alerts/ ./

CMD ["pytest", "-v", "--tb=short"]

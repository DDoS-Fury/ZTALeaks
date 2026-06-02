# =============================================================================
# Envoy Proxy - Dockerfile
#
# Builds the Envoy container used as the entry point (PEP) for all incoming
# HTTPS traffic. TLS certificates and the Envoy configuration are injected
# at build time from the repository root context.
# =============================================================================

FROM envoyproxy/envoy:v1.30-latest

# Copy TLS certificates for mTLS termination
COPY certs/server.crt /etc/envoy/certs/server.crt
COPY certs/server.key /etc/envoy/certs/server.key
COPY certs/ca.crt     /etc/envoy/certs/ca.crt

# Copy the main Envoy configuration file
COPY infra/envoy/envoy.yaml /etc/envoy/envoy.yaml

# Create the log directory and set ownership before dropping privileges.
# UID/GID 101 is the default envoy user inside the official image.
USER root
RUN mkdir -p /var/log/ztaleaks/envoy \
    && chown -R 101:101 /var/log/ztaleaks/envoy \
    && chown envoy:envoy /etc/envoy/certs/server.key

# Drop back to the unprivileged envoy user
USER envoy

# Start Envoy with the provided configuration at log level "info"
CMD ["/usr/local/bin/envoy", "-c", "/etc/envoy/envoy.yaml", "-l", "info"]
FROM envoyproxy/envoy:v1.30-latest


COPY certs/server.crt /etc/envoy/certs/server.crt
COPY certs/server.key /etc/envoy/certs/server.key
COPY certs/ca.crt /etc/envoy/certs/ca.crt

COPY infra/envoy/envoy.yaml /etc/envoy/envoy.yaml

USER root
RUN mkdir -p /var/log/ztaleaks/envoy && chown -R 101:101 /var/log/ztaleaks/envoy \
    && chown envoy:envoy /etc/envoy/certs/server.key
USER envoy

CMD /usr/local/bin/envoy -c /etc/envoy/envoy.yaml -l info

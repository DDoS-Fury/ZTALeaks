FROM envoyproxy/envoy:v1.30-latest

RUN apt-get update && apt-get install -y openssl && \
    mkdir -p /etc/envoy/certs && \
    openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
    -subj "/C=US/ST=CA/L=SF/O=ZTALeaks/CN=ztaleaks_envoy" \
    -keyout /etc/envoy/certs/server.key \
    -out /etc/envoy/certs/server.crt && \
    chmod 644 /etc/envoy/certs/server.key /etc/envoy/certs/server.crt

COPY envoy.yaml /etc/envoy/envoy.yaml

CMD /usr/local/bin/envoy -c /etc/envoy/envoy.yaml -l info

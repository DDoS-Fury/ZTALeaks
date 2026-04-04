FROM alpine:3.19

RUN apk add --no-cache nftables iproute2 bash util-linux dos2unix

COPY infra/nftables/nftables.conf /etc/nftables.conf
COPY infra/nftables/entrypoint.sh /entrypoint.sh
RUN dos2unix /etc/nftables.conf /entrypoint.sh && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

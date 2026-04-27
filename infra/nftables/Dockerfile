# Fase 1: Build parser Go
FROM golang:1.22-alpine as builder
WORKDIR /app
COPY infra/nftables/parser.go .
RUN go build -o nftables-parser parser.go

# Fase 2: Immagine Nftables base
FROM alpine:3.19

RUN apk add --no-cache nftables iproute2 bash util-linux dos2unix ulogd

COPY infra/nftables/nftables.conf /etc/nftables.conf
COPY infra/nftables/ulogd.conf /etc/ulogd.conf
COPY infra/nftables/entrypoint.sh /entrypoint.sh
COPY --from=builder /app/nftables-parser /usr/local/bin/nftables-parser
RUN dos2unix /etc/nftables.conf /etc/ulogd.conf /entrypoint.sh && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

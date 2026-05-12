# Fase di build
FROM golang:1.26-alpine AS builder

WORKDIR /app

ENV GOTOOLCHAIN=auto

# Copia tutto, poi tidy genera go.sum a partire dagli import effettivi.
# (go.sum non è committato perché go.mod è scarno; tidy + download lo creano
# in build con le versioni corrispondenti agli import dei sorgenti.)
COPY . .
RUN go mod tidy
RUN go mod download

# Compila l'orchestratore (intero pacchetto cmd/orchestrator)
RUN CGO_ENABLED=0 GOOS=linux go build -o orchestrator ./cmd/orchestrator

# Fase finale
FROM alpine:3.19

WORKDIR /app
RUN apk add --no-cache ca-certificates

COPY --from=builder /app/orchestrator /app/orchestrator

# Crea la directory di log per Splunk-uf forwarding
RUN mkdir -p /var/log/ztaleaks/orchestrator

EXPOSE 8081

CMD ["/app/orchestrator"]

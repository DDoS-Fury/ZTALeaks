# Fase di build
FROM golang:1.26-alpine AS builder

WORKDIR /app

# Copia moduli
COPY go.mod ./
RUN go mod download || true

# Copia sorgenti
COPY . .

# Compila l'orchestratore
RUN CGO_ENABLED=0 GOOS=linux go build -o orchestrator ./cmd/orchestrator/main.go

# Fase finale
FROM alpine:latest

WORKDIR /app

# Copia l'eseguibile compiled
COPY --from=builder /app/orchestrator .

# Esegui l'orchestratore
CMD ["./orchestrator"]

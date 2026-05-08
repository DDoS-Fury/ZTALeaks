# Fase 1: Compilazione Builder
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copia i file del modulo Go e scarica le dipendenze
COPY go.mod go.sum ./
ENV GOTOOLCHAIN=auto
RUN go get -u all || true
RUN go mod download

# Copia il codice sorgente
COPY . .

# Compilazione statica per ottenere un eseguibile standalone ultra leggero
RUN CGO_ENABLED=0 GOOS=linux go build -o identity-server ./cmd/identity

# Fase 2: Immagine Esecutiva Distroless Minimalista (Pratica Zero Trust per la minimizzazione attacchi via container escape)
FROM alpine:latest

WORKDIR /app

# Installare un utente dedicato non di root e i root CA certificates
RUN apk add --no-cache ca-certificates && adduser -D -g '' identityapp

# L'eseguibile compilato
COPY --from=builder /app/identity-server /app/identity-server

# Crea la directory di base su cui i logger JSON verranno scritti 
RUN mkdir -p /var/log/ztaleaks/identity && chown -R identityapp:identityapp /var/log/ztaleaks/identity

# Eseguire l'applicazione in modalità non privilegiata come da norme ZT
USER identityapp

# La porta del servizio
EXPOSE 8082

CMD ["/app/identity-server"]

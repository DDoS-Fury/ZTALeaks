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
RUN CGO_ENABLED=0 GOOS=linux go build -o iam-server ./cmd/iam

# Fase 2: Immagine Esecutiva Distroless Minimalista (Pratica Zero Trust per la minimizzazione attacchi via container escape)
FROM alpine:3.19

WORKDIR /app

# Installare un utente dedicato non di root e i root CA certificates
RUN apk add --no-cache ca-certificates && adduser -D -g '' iamapp

# L'eseguibile compilato
COPY --from=builder /app/iam-server /app/iam-server

# Copia i template HTML nel container runtime
COPY --from=builder /app/templates /app/templates

# Crea la directory di base su cui i logger JSON verranno scritti 
RUN mkdir -p /var/log/ztaleaks/iam && chown -R iamapp:iamapp /var/log/ztaleaks/iam

# Eseguire l'applicazione in modalità non privilegiata come da norme ZT
USER iamapp

# La porta del servizio
EXPOSE 8082

CMD ["/app/iam-server"]

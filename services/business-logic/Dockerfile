# Fase di build
FROM golang:1.22 AS builder

WORKDIR /app

# Copia i file dei moduli e scarica le dipendenze
COPY go.mod ./
RUN go mod download

# Copia il codice sorgente
COPY . .

# Compila l'applicazione staticamente
RUN CGO_ENABLED=0 GOOS=linux go build -o business-server main.go

# Fase finale (immagine minima)
FROM alpine:latest

WORKDIR /app

# Copia l'eseguibile compilato dal costruttore
COPY --from=builder /app/business-server .

# Copia i template
COPY --from=builder /app/templates /app/templates

EXPOSE $BUSINESS_LOGIC_PORT

# Esegui il binario
CMD ["./business-server"]

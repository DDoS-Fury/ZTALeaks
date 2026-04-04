FROM golang:1.26-alpine

WORKDIR /app

# Copy go mod if available
COPY tests/clients/go.mod ./
RUN go mod download || true

COPY certs/ca.crt /app/certs/
COPY certs/client.crt /app/certs/
COPY certs/client.key /app/certs/

COPY tests/clients/main.go ./

RUN go build -o test-client main.go

# Run the test client
CMD ["./test-client"]

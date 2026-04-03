FROM golang:1.26-alpine

WORKDIR /app

# Copy go mod if available
COPY go.mod ./
RUN go mod download || true

COPY main.go ./

RUN go build -o test-client main.go

# Run the test client
CMD ["./test-client"]

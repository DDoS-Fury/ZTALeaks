FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY tests/dashboard-app/main.go tests/dashboard-app/index.html ./

# Initialize go modules and build the server binary
RUN go mod init dashboard-app && \
    go build -ldflags="-w -s" -o dashboard main.go

FROM alpine:3.19

WORKDIR /app
COPY --from=builder /app/dashboard /app/index.html ./

# Run the app. Note: certificates should be volume mounted to /certs at runtime as defined in main.go
EXPOSE 8080
CMD ["./dashboard"]
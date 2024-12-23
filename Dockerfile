# Stage 1: Build the Go binary
FROM golang:1.22-alpine AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the entire project into the container
COPY .. ./

RUN go build -o auth-service ./cmd/main.go

# Stage 2: Create a minimal runtime image
FROM alpine:latest

# Set the working directory inside the container
WORKDIR /root/

# Copy the compiled binary from the builder stage
COPY --from=builder /app/auth-service .

EXPOSE 8080

CMD ["./auth-service"]
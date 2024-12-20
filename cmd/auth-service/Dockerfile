# Stage 1: Build the Go binary
FROM golang:1.21-alpine AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go.mod and go.sum from the root of the project
COPY ../../../go.mod ../../../go.sum ./

# Download all dependencies (cached if go.mod and go.sum haven't changed)
RUN go mod download

# Copy the entire project into the container
COPY ../../../ ./

# Build the Go app (auth-service) specifically
RUN go build -o auth-service ./cmd/auth-service/cmd/auth-service.go

# Stage 2: Create a minimal runtime image
FROM alpine:latest

# Set the working directory inside the container
WORKDIR /root/

# Copy the compiled binary from the builder stage
COPY --from=builder /app/auth-service .

# Expose the service's port (adjust according to your app)
EXPOSE 8080

# Command to run the executable
CMD ["./auth-service"]
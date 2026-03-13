# Stage 1: Build the Go binary
FROM golang:1.25-alpine AS builder

# Install git (needed if you have modules from git)
RUN apk add --no-cache git
RUN apk add --no-cache curl

# Set the working directory inside the container
WORKDIR /app

# Copy everything except what's in .dockerignore
COPY . .

# Build the Go binary
RUN go mod tidy
RUN go build -o server ./cmd/server/main.go

# Stage 2: Minimal runtime image
FROM alpine:latest

# Set working directory
WORKDIR /app

# Copy the compiled binary from builder
COPY --from=builder /app/server .

# Expose the port your service uses (adjust if needed)
EXPOSE 8080

# Command to run the binary
CMD ["./server", "serve"]
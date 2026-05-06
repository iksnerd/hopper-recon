# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /app

# Install projectdiscovery safe passive tools
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
RUN go install github.com/projectdiscovery/uncover/cmd/uncover@latest

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the MCP server
RUN go build -o hopper-recon main.go

# Final stage
FROM alpine:latest

WORKDIR /app

# Install dependencies for tools
RUN apk add --no-cache ca-certificates libc6-compat

# Copy binaries from builder
COPY --from=builder /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=builder /go/bin/dnsx /usr/local/bin/dnsx
COPY --from=builder /go/bin/httpx /usr/local/bin/httpx
COPY --from=builder /go/bin/tlsx /usr/local/bin/tlsx
COPY --from=builder /go/bin/uncover /usr/local/bin/uncover
COPY --from=builder /app/hopper-recon /usr/local/bin/hopper-recon

# Ensure binaries are executable
RUN chmod +x /usr/local/bin/subfinder /usr/local/bin/dnsx /usr/local/bin/httpx /usr/local/bin/tlsx /usr/local/bin/uncover /usr/local/bin/hopper-recon

# Run the MCP server
ENTRYPOINT ["hopper-recon"]

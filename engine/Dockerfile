# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /app

# Install projectdiscovery safe passive tools
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
RUN go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
RUN go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the engine — build the whole package, not main.go, so multi-file split compiles.
RUN go build -o hopper-recon .

# Final stage
FROM alpine:latest

WORKDIR /app

# Install dependencies for tools (ca-certs for HTTPS, wget for healthcheck).
RUN apk add --no-cache ca-certificates libc6-compat wget

# GeoLite2-Country.mmdb is volume-mounted at runtime (license-restricted, can't bake in).
# Pre-create the mount directory and the SQLite data dir.
RUN mkdir -p /root/.config/hopper-recon /data

# Copy binaries from builder
COPY --from=builder /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=builder /go/bin/dnsx /usr/local/bin/dnsx
COPY --from=builder /go/bin/httpx /usr/local/bin/httpx
COPY --from=builder /go/bin/tlsx /usr/local/bin/tlsx
COPY --from=builder /go/bin/cdncheck /usr/local/bin/cdncheck
COPY --from=builder /go/bin/urlfinder /usr/local/bin/urlfinder
COPY --from=builder /app/hopper-recon /usr/local/bin/hopper-recon

# Ensure binaries are executable
RUN chmod +x /usr/local/bin/subfinder /usr/local/bin/dnsx /usr/local/bin/httpx /usr/local/bin/tlsx /usr/local/bin/cdncheck /usr/local/bin/urlfinder /usr/local/bin/hopper-recon

EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD wget -qO- http://localhost:8080/healthz || exit 1

# Default to long-running HTTP server (compose path).
# AI agents wanting the stdio MCP transport invoke `docker run -i hopper-recon:latest mcp`.
ENTRYPOINT ["hopper-recon"]
CMD ["serve"]

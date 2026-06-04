# syntax=docker/dockerfile:1.7

# Build stage
FROM golang:1.26.4-alpine AS builder

WORKDIR /app

# Install projectdiscovery tools. Cache mounts keep the module download cache
# and build artifact cache on the host between runs — first build is slow,
# subsequent rebuilds skip the network entirely and reuse compiled objects.
RUN --mount=type=cache,target=/root/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest && \
    go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest && \
    go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest && \
    go install github.com/projectdiscovery/alterx/cmd/alterx@latest

# Separate layer: engine module downloads. Invalidated only when go.mod/go.sum
# change, not when source changes.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

# Copy source and build. Cache mount means incremental recompilation — only
# changed packages are recompiled.
COPY . .
RUN --mount=type=cache,target=/root/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -o hopper-recon .

# Final stage
FROM alpine:latest

WORKDIR /app

# ca-certs for outbound HTTPS, wget for the compose healthcheck. libc6-compat
# isn't needed: builder + runtime are both alpine (musl) and the Go binaries
# are static.
RUN apk add --no-cache ca-certificates wget

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
COPY --from=builder /go/bin/alterx /usr/local/bin/alterx
COPY --from=builder /app/hopper-recon /usr/local/bin/hopper-recon

# Ensure binaries are executable
RUN chmod +x /usr/local/bin/subfinder /usr/local/bin/dnsx /usr/local/bin/httpx /usr/local/bin/tlsx /usr/local/bin/cdncheck /usr/local/bin/urlfinder /usr/local/bin/alterx /usr/local/bin/hopper-recon

EXPOSE 8080
VOLUME ["/data"]

# Healthcheck is owned by docker-compose (or k8s livenessProbe in prod) so the
# stdio MCP path (`docker run -i hopper-recon mcp`) doesn't pointlessly try to
# wget :8080 in a process that never opens it.

# Default to long-running HTTP server (compose path).
# AI agents wanting the stdio MCP transport invoke `docker run -i hopper-recon:latest mcp`.
ENTRYPOINT ["hopper-recon"]
CMD ["serve"]

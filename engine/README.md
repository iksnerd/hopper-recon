# engine — hopper-recon MCP server

A Go MCP server that wraps a small set of [projectdiscovery](https://github.com/projectdiscovery) OSINT binaries plus a local MaxMind GeoIP lookup. Speaks JSON-RPC over stdio (`mcp.StdioTransport`); shipped as a single Alpine container the web app spawns per scan via `docker run --rm -i hopper-recon:latest`.

## Tools

| MCP name | Binary / library | Input | Output shape | Notes |
|---|---|---|---|---|
| `passive_subdomains` | subfinder | `{ domain }` | `{ findings: [{ host, sources[] }] }` | `-all -cs` for source attribution |
| `resolve_dns` | dnsx | `{ target }` | `{ results: jsonl[] }` | A/CNAME/NS/MX/TXT, CDN + ASN |
| `fetch_tls_cert` | tlsx | `{ target }` | `{ results: jsonl[] }` | SAN/CN/cipher/wildcard/expired/self-signed |
| `probe_http` | httpx | `{ target }` | `{ results: jsonl[] }` | Title, tech, JARM, ASN, redirect chain, 50 rps cap |
| `map_asn` | asnmap | `{ domain }` | `{ results: jsonl[] }` | ASN + CIDR ranges |
| `search_hosts` | uncover | `{ domain }` | `{ results: jsonl[] }` | Shodan/Censys/FOFA query: `ssl:"<domain>"` |
| `lookup_geoip` | oschwald/geoip2-golang | `{ ips: "1.2.3.4,5.6.7.8" }` | `{ results: [{ ip, country }] }` | Reads MaxMind GeoLite2-Country.mmdb |

`results` from the projectdiscovery tools is JSONL — one JSON object per line. The web side (`web/src/lib/scan-parser.ts`) handles parsing.

## Volume mounts (optional config)

| Host path | Container path | Used by |
|---|---|---|
| `~/.config/subfinder/provider-config.yaml` | `/root/.config/subfinder/provider-config.yaml` | `passive_subdomains` |
| `~/.config/uncover/provider-config.yaml` | `/root/.config/uncover/provider-config.yaml` | `search_hosts` |
| `~/.config/hopper-recon/GeoLite2-Country.mmdb` | `/root/.config/hopper-recon/GeoLite2-Country.mmdb` | `lookup_geoip` |

The web side (`web/src/lib/docker-mcp.ts`) detects each file and adds a `-v ...:ro` flag only when present. Missing config = the tool runs with reduced functionality but never errors.

GeoLite2 is license-restricted, so it isn't baked into the image. Sign up at <https://www.maxmind.com/en/geolite2/signup>, download `GeoLite2-Country.mmdb`, and drop it at the host path above.

## Build & run

### Local (no Docker)

```bash
go build -o hopper-recon .
./hopper-recon          # speaks MCP on stdio; ctrl-D to exit
```

The projectdiscovery binaries (`subfinder`, `dnsx`, `httpx`, `tlsx`, `asnmap`, `uncover`) need to be on `$PATH` — install via `go install github.com/projectdiscovery/<tool>/cmd/<tool>@latest`.

### Container (the way the web app calls it)

```bash
docker build -t hopper-recon:latest .
docker run --rm -i hopper-recon:latest    # MCP over stdio
```

The web app spawns this image per tool call; see `web/src/lib/docker-mcp.ts` for the handshake.

## Pre-commit checks

```bash
gofmt -w .
go vet ./...
go build ./...
go mod tidy            # after import changes
docker build -t hopper-recon:latest .   # after any Go change
```

## Adding a tool

1. Define `<Name>Input` / `<Name>Output` types and a `Handle<Name>` function in `main.go`.
2. Register with `mcp.AddTool(server, &mcp.Tool{Name, Description}, Handle<Name>)` in `main()`.
3. If a binary is required, add the `RUN go install ...` and the `COPY --from=builder ...` lines in `Dockerfile`.
4. Mirror on the web side: extend `McpTool` in `web/src/lib/docker-mcp.ts`, add to `VALID_TOOLS` in `web/src/app/api/scan/route.ts` (and `DOMAIN_ARG_TOOLS` if the input is `{domain}`), write a parser in `web/src/lib/scan-parser.ts`, surface in dashboard / history pages.
5. Rebuild the image.

## Roadmap

- Split `main.go` into `cmd/hopper-recon/main.go` + `internal/tools/{subfinder,dnsx,tlsx,httpx,asnmap,uncover,geoip}.go` once the tool count grows past ~10.
- Per-tool unit tests against canned binary output (today the tools are exercised only end-to-end through the web app).

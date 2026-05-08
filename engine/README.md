# engine — hopper-recon HTTP + MCP server

Go server that wraps a small set of [projectdiscovery](https://github.com/projectdiscovery) OSINT binaries plus a local MaxMind GeoIP lookup. Speaks two transports off the same binary:

- **HTTP** (`hopper-recon serve`, compose default) — REST API for the dashboard plus MCP at `/mcp` for AI agents that want to attach to a long-running engine. Owns SQLite at `/data/scans.db`.
- **stdio MCP** (`hopper-recon mcp`, no DB) — for one-shot AI agent invocations like `docker run --rm -i hopper-recon:latest mcp` from Claude Desktop / Cline.

## Tools

| MCP name | Binary / library | Input | Output | Notes |
|---|---|---|---|---|
| `passive_subdomains` | subfinder | `{ domain }` | `[{ host, sources[] }]` | `-all -cs` for source attribution |
| `resolve_dns` | dnsx | `{ target }` | parsed JSON record | A/AAAA/CNAME/NS/MX/TXT, CDN + ASN; merges `_dmarc.<host>` TXT into apex |
| `fetch_tls_cert` | tlsx | `{ target }` | parsed JSON record | SAN/CN/cipher/wildcard/expired/self-signed |
| `probe_http` | httpx | `{ target }` | parsed JSON record | Title, tech, JARM, ASN, redirect chain, 50 rps cap, custom `hopper-recon/0.2.0` UA |
| `check_cdn` | cdncheck | `{ target }` | `[{ ip, cdn/cloud/waf, *_name }]` | Pure offline CIDR-list lookup — bundled `sources_data.json`, no network calls beyond the DNS resolution embedded in cdncheck itself |
| `find_urls` | urlfinder | `{ domain }` | `[{ url, source }]` | Passive URL discovery via waybackarchive / commoncrawl / alienvault. Uses `-jsonl` (urlfinder's flag, not the `-json` other PD tools take) |
| `lookup_geoip` | oschwald/geoip2-golang | `{ ips: "1.2.3.4,5.6.7.8" }` | `[{ ip, country }]` | Reads MaxMind GeoLite2-Country.mmdb. Anycast IPs (Cloudflare / AWS / Google) intentionally have no country attribution and produce no entry. |

Tools previously shipped (`map_asn`, `search_hosts`) were removed in v0.2 because they require API keys to function (PDCP auth, Shodan/Censys/FOFA keys). The admission rule: tools must produce useful output for an unconfigured first-time user.

## REST endpoints (HTTP mode)

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/scan` | Run tool + persist + return — body `{ tool, target }`. One transaction per request. |
| `GET`  | `/scans?domain=&limit=` | List scans, newest first. |
| `DELETE` | `/scans/{id}` | Drop a single scan row. |
| `GET`  | `/geoip?ips=a,b,c` | Cache lookup + mmdb fallback for misses. |
| `GET`  | `/healthz` | Liveness probe. |
| `GET`  | `/readyz` | Readiness probe (pings SQLite). |
| `*`    | `/mcp` | Streamable HTTP MCP — same tool set as stdio mode. |

## Volume mounts (optional config)

| Host path | Container path | Mode | Used by |
|---|---|---|---|
| `~/.config/subfinder/` | `/root/.config/subfinder/` | rw | `passive_subdomains` (subfinder bootstraps `config.yaml` here on first run; API keys persist) |
| `~/.config/hopper-recon/GeoLite2-Country.mmdb` | `/root/.config/hopper-recon/GeoLite2-Country.mmdb` | ro | `lookup_geoip` |
| named volume `engine-data` | `/data` | rw | SQLite database |

GeoLite2 is license-restricted, so it isn't baked into the image. Sign up at <https://www.maxmind.com/en/geolite2/signup> (or use the [P3TERX mirror](https://github.com/P3TERX/GeoLite.mmdb)), download `GeoLite2-Country.mmdb`, and drop it at the host path above. Missing mmdb → `lookup_geoip` returns `[]` and the geo-globe simply doesn't render — nothing else degrades.

## Build & run

### Local (no Docker)

```bash
go build -o hopper-recon .
./hopper-recon serve --addr :8080 --db /tmp/scans.db    # HTTP server
./hopper-recon mcp                                       # stdio MCP, no DB
```

The projectdiscovery binaries (`subfinder`, `dnsx`, `httpx`, `tlsx`, `cdncheck`, `urlfinder`) need to be on `$PATH` — `go install github.com/projectdiscovery/<tool>/cmd/<tool>@latest`.

### Container (compose, what the dashboard uses)

```bash
docker compose up -d --build engine
curl http://127.0.0.1:9119/healthz       # → ok
curl http://127.0.0.1:9119/scans          # → []
```

The compose file binds `:8080` (container) to `127.0.0.1:9119` (host). The web service reaches the engine via the compose network at `engine:8080`.

### Container (stdio MCP, for one-shot AI agents)

```bash
docker run --rm -i hopper-recon:latest mcp
```

Speaks JSON-RPC over stdio. No DB, no persistence — every call is independent.

## Pre-commit checks

```bash
gofmt -w .
go vet ./...
go build ./...
go mod tidy            # after import changes
docker compose build engine    # after any Go change
```

## Adding a tool

1. Add `Run<Name>` in `tools.go` returning `[]string` (raw JSONL).
2. Add `handle<Name>` in `main.go` and register with `mcp.AddTool` in `buildMCPServer()`.
3. Add a `case "<name>":` in `runTool` in `server.go`.
4. If a new binary is required, add `RUN go install …` and `COPY --from=builder /go/bin/<bin> /usr/local/bin/<bin>` (plus chmod) in `Dockerfile`.
5. Mirror on the web side — `web/src/app/api/scan/route.ts` `VALID_TOOLS`, parser in `web/src/lib/scan-parser.ts`, dashboard + history panels.
6. `docker compose build engine && docker compose up -d --force-recreate engine`.

## File layout

| File | Responsibility |
|---|---|
| `main.go` | Entrypoint, mode dispatch (`serve` / `mcp`), MCP tool registration |
| `tools.go` | Pure recon-binary runners — JSONL in, parsed objects out |
| `db.go` | SQLite open, schema, query helpers |
| `server.go` | HTTP REST handlers + MCP-over-HTTP mount |
| `Dockerfile` | Two-stage build: golang + projectdiscovery binaries → alpine runtime |

## Roadmap

- Per-tool unit tests against canned binary output (today the tools are exercised only end-to-end through the web app).
- Once the tool count grows past ~10, split `tools.go` into `internal/tools/{subfinder,…}.go`.
- USER 1000:1000 + non-root container hardening (v0.1 prod-deploy item).

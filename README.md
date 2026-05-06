# hopper-recon

Passive security reconnaissance platform. A **Next.js 16** web frontend runs scans through a **Go MCP engine** packaged as a Docker container, results stored in SQLite (dev) or Cloudflare D1 (prod).

![Terminal aesthetic — monospace, dark, no hue](https://img.shields.io/badge/UI-terminal--aesthetic-111?style=flat-square&labelColor=080808&color=444)
![Go](https://img.shields.io/badge/Go-1.26-00ADD8?style=flat-square&logo=go&logoColor=white)
![Next.js](https://img.shields.io/badge/Next.js-16-000?style=flat-square&logo=next.js)
![Docker](https://img.shields.io/badge/engine-Docker-2496ED?style=flat-square&logo=docker&logoColor=white)

---

## Features

- **Dashboard** — run all OSINT tools in parallel against a target domain, live elapsed timers, findings triage strip, tech stack detection
- **History** — list of all scanned domains with inline stats, multi-scan timeline charts, geo-globe from IP data
- **Domain detail** — full-page per-domain view with uncapped subdomain list, cert SAN expansion, TXT records, port exposure (uncover), per-subdomain `>_ scan` links
- **EXPOSE tab** — powered by `uncover`, queries Shodan/Censys/FOFA for exposed IPs and open ports via `ssl:"<domain>"`
- **Geo globe** — IP → country via bundled MaxMind GeoLite2 (offline, no rate limit), rendered with [cobe](https://cobe.vercel.app)
- **Findings strip** — auto-triage: expired certs, missing SPF/DMARC, HTTPS→HTTP downgrades, sensitive subdomains
- **Dual DB** — SQLite for local dev (auto-migrated), Cloudflare D1 for production

---

## Architecture

```
hopper-recon/
├── engine/          # Go MCP server — runs as Docker container
│   ├── main.go      # Tool handlers + MCP registration
│   └── Dockerfile
├── web/             # Next.js 16 app
│   ├── src/app/     # App Router pages + API routes
│   ├── src/lib/     # db.ts · docker-mcp.ts · scan-parser.ts
│   └── src/components/recon/   # Domain-specific UI components
├── schema.sql       # D1 production schema
└── CLAUDE.md        # Agent + dev guide
```

The web app calls the engine over MCP via `docker run --rm -i hopper-recon:latest`. Each scan is a new container instance.

---

## Tools

| MCP name | Binary | What it does |
|---|---|---|
| `passive_subdomains` | subfinder | OSINT subdomain enumeration across 40+ sources |
| `resolve_dns` | dnsx | A/NS/MX/TXT records, CDN detection, TTL |
| `fetch_tls_cert` | tlsx | TLS cert details — CN, SANs, expiry, cipher |
| `probe_http` | httpx | HTTP probe — title, tech stack, JARM, CPE, redirects |
| `search_hosts` | uncover | Search Shodan/Censys/FOFA for exposed IPs/ports |
| `lookup_geoip` | geoip2-golang | Resolve IPs to ISO country codes from a local MaxMind GeoLite2 mmdb |

API keys for subfinder (`~/.config/subfinder/provider-config.yaml`) and uncover (`~/.config/uncover/provider-config.yaml`) are volume-mounted read-only when present.

### GeoLite2 setup

`lookup_geoip` reads a MaxMind GeoLite2-Country database mounted into the container. It's license-restricted, so you supply it yourself:

1. Sign up for a free MaxMind account: <https://www.maxmind.com/en/geolite2/signup>
2. After login → **Download Databases** (left sidebar) → grab `GeoLite2 Country` as **GeoIP2 Binary (.mmdb)**, not the CSV.
3. Extract the tarball and move the `.mmdb` into place:
   ```bash
   mkdir -p ~/.config/hopper-recon
   tar -xzf GeoLite2-Country_*.tar.gz
   mv GeoLite2-Country_*/GeoLite2-Country.mmdb ~/.config/hopper-recon/
   ```
4. Verify: `ls ~/.config/hopper-recon/GeoLite2-Country.mmdb` should print the path with a non-zero size (~6 MB).

The web side mounts that path into the container at scan time. If the file is missing, geoip lookups return empty results and the geo-globe simply doesn't render — everything else keeps working.

---

## Quick start

**Prerequisites**: Node.js 18+, Go 1.26+, Docker

```bash
# 1. Install web dependencies
cd web && npm install

# 2. Build the engine image
cd engine && docker build -t hopper-recon:latest .

# 3. Start dev server
cd web && npm run dev
# → http://localhost:3000
```

SQLite DB is created automatically at `web/data/recon.db` on first request.

---

## Development

### Pre-commit checklist

**Web (`web/`)**
```bash
npx tsc --noEmit    # must pass clean — no any, no @ts-ignore
npm run lint        # fix warnings, don't disable rules
```

**Engine (`engine/`)**
```bash
go fmt ./...
go vet ./...
go build ./...
go mod tidy         # after adding/removing imports
docker build -t hopper-recon:latest .   # after Go changes
```

### Adding a tool

1. Add handler + types in `engine/main.go`, register with `mcp.AddTool`
2. Add binary install + copy/chmod in `engine/Dockerfile`
3. Add to `McpTool` union in `web/src/lib/docker-mcp.ts`
4. Add to `VALID_TOOLS` (and `DOMAIN_ARG_TOOLS` if it takes `domain`) in `web/src/app/api/scan/route.ts`
5. Add parser in `web/src/lib/scan-parser.ts`
6. Add tab/panel in dashboard and history pages
7. Rebuild image

### Database schema changes

Edit both `web/schema.sql` (D1) and the inline `db.exec` in `web/src/lib/db.ts` (SQLite) — keep them in sync.

---

## Deployment

**Cloudflare (production)**

```bash
# Provision D1
wrangler d1 create recon-db-prod
wrangler d1 execute recon-db-prod --file=schema.sql

# Deploy
cd web && npm run build && wrangler deploy
```

The Cloudflare Sandbox executor for running the engine in production is stubbed in `web/src/lib/executor.ts` — Docker is used for local dev.

---

## Roadmap

See [TODO.md](./TODO.md) for the full list. Key open items:

- Cloudflare Sandbox executor wiring for production scans
- Auth (NextAuth — GitHub/Google OAuth), per-user scan limits
- `uncover` batch scanning against all discovered subdomains
- Engine refactor — split monolithic `main.go` into `cmd/` + `internal/tools/`

---

## License

MIT

# Changelog

All notable changes to this project will be documented in this file. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — TBD

First public OSS release. Single-tenant, self-hosted, MCP-native.

### Architecture

- **Engine owns SQLite + recon binaries; web is a thin HTTP client.** Web container no longer requires the Docker socket — runs on platforms that forbid privileged containers (Cloud Run, Fly Machines, k8s rootless).
- **MCP at `/mcp` over Streamable HTTP** plus stdio mode (`hopper-recon mcp`) for AI agents that prefer one-shot containers. Same tool surface across both transports.
- **Continuous backup via Litestream sidecars.** Default replica is a local file volume (zero config); pre-written blocks for Cloudflare R2 / AWS S3 / Azure Blob / GCS in `litestream.yml`.

### Recon tools (7)

`passive_subdomains` (subfinder) · `resolve_dns` (dnsx, with `_dmarc.<host>` merge) · `fetch_tls_cert` (tlsx) · `probe_http` (httpx, custom UA + 50 rps cap) · `check_cdn` (cdncheck, offline) · `find_urls` (urlfinder) · `lookup_geoip` (MaxMind GeoLite2, offline).

Tools needing API keys to function are intentionally absent. The bar for a shipped tool: must produce useful output for an unconfigured first-time user.

### Built-in protections

- **Restricted-suffix blocklist** for active probes against `.gov`, `.mil`, `.gouv.fr`, `.gov.uk`, `.go.jp`, `.gc.ca`, `.gov.au`. Override via `HOPPER_OVERRIDE_BLOCKLIST=true` + non-empty `HOPPER_BLOCKLIST_OVERRIDE_REASON`, audit-logged.
- **Per-target cooldown** — 60s window per `(target, tool)`; repeats return HTTP 429 with `Retry-After`.
- **Audit log table** — every `/scan` records source IP, User-Agent, tool, target, decision, reason. Operator can `tail -f` the SQLite via the volume.
- **`HOPPER_ALLOWED_DOMAINS` scope** — when set, off-scope targets return HTTP 403 (also audit-logged).
- **Operator advisory banner** in the UI when neither scope nor auth is configured. Dismissable per-browser; `useSyncExternalStore` keeps the dismissal in sync across tabs.
- **`X-Hopper-Recon: authorized-use-only`** header on every `/api/scan` response (web and engine), so reverse-proxy / CDN logs identify the tool.
- **Custom `hopper-recon/<version>` User-Agent** on `httpx` so target operators can attribute traffic and request exclusion.
- **`/config`** endpoint on engine reports scope/auth state as booleans (no env values leaked).
- **Engine binds to loopback** (`127.0.0.1:9119`) by default in compose; LAN exposure requires deliberate config change.

All gates apply equally to direct MCP callers (Claude Code / Cline / stdio agents) and the dashboard — protection lives at the engine, not the web.

### UI

- **Cyberpunk-terminal aesthetic.** Achromatic palette with terminal-phosphor green accent for affordances and live signal only. `ReconCard` / `Panel` / `PageHeader` are the only sanctioned chrome primitives.
- **Findings strip** triages all four scan results into one ranked actionable list (`[!] cert expires in 14d`, `[!] no DMARC`, `[!] public access: dev.x.com`, `[✓] SPF policy present`).
- **Per-domain history detail page** — multi-scan timeline, geo-globe from IP data, scrollable subdomain list, cert SAN expansion, redirect chains, scrub-friendly elapsed-time charts.
- **About page** at `/about` lists every recon tool and notable runtime dep with an upstream link, so credit is visible.
- **Health endpoints** — `/healthz` and `/readyz` on engine and web.

### Build / CI

- **GitHub Actions CI** (`.github/workflows/ci.yml`) — checks-only, no artifacts. Engine: `gofmt -l`, `go vet`, `go mod tidy --diff`. Web: `tsc --noEmit`, `eslint`, Vitest.
- **Smoke tests on `scan-parser.ts`** for the seven parsers (`parseHttp` / `parseDns` / `parseTls` / `parseSubdomains` / `parseCdn` / `parseUrls`).
- **Single-source `Version`** in the engine — overridable via `-ldflags "-X main.Version=…"` so future builds can stamp themselves.
- Operators build their own images locally with `docker compose up -d --build`. We do not publish to GHCR — bring back `release.yml` from git history if you ever want to.

### Documentation

- **`SECURITY.md`** with authorized-use posture, outbound footprint table, disclosure email + 3/10/30-day SLA, out-of-scope list.
- **`.env.example`** documenting every env var.
- **`CONTRIBUTING.md`** + **`CODE_OF_CONDUCT.md`** + GitHub issue / PR templates.
- **`CLAUDE.md`** — agent guide for the codebase. The repo is consciously LLM-coding-friendly.

[Unreleased]: https://github.com/iksnerd/hopper-recon/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/iksnerd/hopper-recon/releases/tag/v0.1.0

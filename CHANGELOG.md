# Changelog

All notable changes to this project will be documented in this file. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1] — 2026-05-23

### Added

- **`next build` step in CI** — web job now runs `tsc → lint → vitest → next build`, catching broken imports and bad metadata that type-check alone misses.

### Changed

- **Landing page shows all 8 tools** — capabilities grid updated from 4 to 8 entries (CDN, URLS, MUTATIONS, GEO added); copy updated to mention cdn, historical urls, and subdomain mutations; footer credits extended to include `cdncheck · urlfinder · alterx`.
- **Version strings are now dynamic** — landing page and sidebar both read `pkg.version` from `package.json` instead of a hardcoded `v0.1.0-alpha`.
- **`web/package.json` version bumped to `0.3.0`** to match engine and git tag.
- **Next.js metadata expanded** — `description` covers all 7 tools; `metadataBase`, `og:url`, `og:siteName`, Twitter card (`summary_large_image`) added; keywords expanded with `self-hosted`, `mcp-server`, `alterx`, `projectdiscovery`, `bug-bounty`.
- **README quick start** — adds `docker compose ps` health check and explicit `open http://localhost:9120` command.
- **README roadmap** — replaced stale v0.1.0 highlights with a clean v0.1→v0.3 changelog and a "Next" entry for auth; removed false v0.3.0 auth promise.
- **Screenshots refreshed** — all four PNG screenshots retaken against the running v0.3.0 stack; dashboard shot now shows an active scan with all 7 tabs visible.
- **CLAUDE.md tool list corrected** — `expand_subdomains` added; `lookup_geoip` clarified as enrichment-only (not a scan tab).

### Fixed

- **4 moderate npm vulnerabilities resolved** (`ws` / `wrangler` chain) via `npm audit fix`. Remaining 2 are `postcss` bundled inside `next@16` — no non-breaking fix available upstream.

### Documentation

- **CONTRIBUTING.md** — added third-party license note for LGPL-3 `sharp` transitive dependency.

## [0.3.0] — 2026-05-20

### Added

- **`expand_subdomains` tool** (`alterx`) — permutation-based subdomain wordlist generation from existing subdomains. Pure local transform, no network requests. Exposed as MCP tool, REST `/scan` dispatch, and dashboard MUTATIONS tab with 5000-entry cap.

## [0.2.0] — 2026-05-13

### Fixed

- **`parseDns` CDN field** — `dnsx` JSON returns `cdn: bool` + `cdn-name: string`. The parser was reading the boolean flag as the display value, so every CDN-backed domain showed `"true"` instead of the provider name (`"cloudflare"`, `"google"`, etc.). Fixed to read `first["cdn-name"]`.
- **`probe_http` missing CPE data** — `httpx` requires an explicit `-cpe` flag to populate the `cpe` array in JSON output. The flag was absent, so CPE identifiers were never returned. Added `-cpe` to `RunHttpx`.
- **DKIM false-positive** — parser regex `/v=dkim1|dkim=/` was matching `adkim=r` from DMARC records, incorrectly marking DKIM as present. Fixed to `/v=dkim1/i`.

### Added

- **`probe_http` surfaces CDN/WAF and IPv6 from httpx** — `HttpResult` now includes `cdn_name` (e.g. `"cloudflare"`), `cdn_type` (`"cdn"` / `"waf"` / `"cloud"`), `aaaa` (IPv6 addresses), and `scheme`. Dashboard and history detail HTTP panels render the CDN row when present and show IPv4 + IPv6 in a combined IPS section.
- **`InfoTooltip` component** (`components/recon/info-tooltip.tsx`) — small Lucide `Info` icon that shows a Radix tooltip on hover. `TooltipProvider` added to `app/(app)/layout.tsx`.
- **Tooltips wired on technical fields** — `DataRow` (dashboard) and `MiniTable` (history detail) accept an optional `info` prop. Tooltips cover: JARM, CPE, CNAME, ASN, CDN in the HTTP panel; TTL, CDN, ASN in the DNS panel.
- **Engine test suite** — `go test ./...` added to CI engine job; engine job previously ran only `gofmt`/`go vet`/`go mod tidy`.
- **`.gitleaks.toml`** — suppresses confirmed false-positive (`engine/README.md:20` Shodan/Censys/FOFA prose list).
- **`CODEOWNERS`** — `.github/CODEOWNERS` designates `@iksnerd` as reviewer on all PRs.

### Removed

- `spec.md` — stale v0.1 Cloudflare D1 / NextAuth.js planning artifact. Architecture no longer matches.
- `GEMINI.md` removed from git tracking (added to `.gitignore`); kept as a local dev file updated to reflect v0.2 architecture.

### Security

- Go base image bumped from `1.26-alpine` to `1.26.3-alpine`; CI `go-version` pinned to `1.26.3`. Fixes two reachable stdlib CVEs: `GO-2026-4971` (panic in `net.Dial` on NUL byte) and `GO-2026-4918` (infinite loop in HTTP/2 transport).
- Next.js bumped from `16.2.4` to `16.2.6`. Fixes high-severity DoS/XSS/SSRF chain in Server Components and middleware.

## [0.1.0] — 2026-05-09

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

[Unreleased]: https://github.com/iksnerd/hopper-recon/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/iksnerd/hopper-recon/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/iksnerd/hopper-recon/releases/tag/v0.1.0

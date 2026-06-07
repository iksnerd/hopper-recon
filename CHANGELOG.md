# Changelog

All notable changes to this project will be documented in this file. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Dashboard self-collided on the per-target cooldown** — v0.3.3 made `passive_subdomains`, `expand_subdomains`, and `resolve_mutations` share a cooldown surface because all three run subfinder internally. But the dashboard fans those tools out in one parallel scan, and the agent workflow runs discover → expand → resolve in sequence — so whichever wrote its `allowed` audit row first made the others 429 (intermittently, on a first-ever scan). The cross-tool implication fought the product's own design; removed it. The per-`(target, tool)` cooldown stays: repeating the *same* tool against the same target within 60s is still blocked.

## [0.3.4] — 2026-06-07

### Fixed

- **CI red since v0.3.3 — geoip permission error treated as fatal** — v0.3.3 made `loadGeoipReader` assign `geoipErr` on `os.Stat` failure, but `LookupGeoip` only swallowed `os.IsNotExist`. On the Linux CI runner the engine's `/root/.config` mmdb path is mode-700, so `stat` as the non-root runner returns `EACCES`, not `ENOENT`; the error propagated and the three `TestLookupGeoip` cases failed. (Green on macOS, where `/root` doesn't exist → `ENOENT`.) `os.IsPermission` is now treated the same as `os.IsNotExist`: an inaccessible mmdb means no geo data, not an error.
- **Failed tools rendered as successful empty scans** — the engine returns HTTP 200 with `status:"failed"` on tool error (so the message is readable) and the proxy forwards it as `isError`, but the dashboard only threw on `!res.ok`. A tool that errored (tlsx connect refused, httpx timeout) showed a finished tab with blank results instead of an error. The dashboard now throws on `isError` so it routes to the existing error state.
- **`parseDns` rendered `[undefined]` / `undefineds`** — `status_code` and `ttl` were read with no fallback while every sibling field coalesced; a domain with no A record produced garbage in the DNS panel. Coalesced to match the rest of the parser.

### Changed

- **CI runs only on version tags + manual dispatch** — it previously ran on every push to `main` and every PR, consuming the bulk of the Actions allowance. Day-to-day pushes now cost zero minutes; run the pre-commit checks locally (see `CONTRIBUTING.md`).
- **README refocused on what/why** — it opened with architecture before saying what the tool does. Rewritten with a value-first lede; ~100 lines of duplicated Configuration/Development/Deployment depth moved to `DEPLOY.md` / `CONTRIBUTING.md` behind a Docs section. Added the missing `resolve_mutations` tool to the tools table.

## [0.3.3] — 2026-06-04

### Fixed

- **`has_geo_db` always reported `true` when mmdb absent** — `loadGeoipReader` returned `(nil, nil)` on `os.Stat` failure (early return left `geoipErr` at zero value). Settings page showed "GeoLite2-Country.mmdb found" when no file existed. Fix: assign `geoipErr = statErr` before returning; `LookupGeoip` treats `ErrNotExist` as empty results (not an error) so lookup behavior is unchanged.
- **`ListScans` ignored `limit` when `domain` filter was set** — domain-filter query had no `LIMIT` clause; the `limit` parameter was silently discarded. History page could return unbounded rows for heavily-scanned domains.
- **`expand_subdomains` and `resolve_mutations` bypassed subfinder cooldown** — both tools call `RunSubfinder` internally but the cooldown gate only checked the outer tool name. Added bidirectional cooldown sharing: `expand_subdomains`/`resolve_mutations` block when `passive_subdomains` ran recently, and vice versa. Applied to both HTTP handler and MCP gate.
- **Theme toggle showed wrong icon / set wrong theme before hydration** — `resolvedTheme` is `undefined` before next-themes hydrates; `undefined === "dark"` evaluated false so clicking always set theme to dark. Fixed with `resolvedTheme ?? "dark"` fallback matching `defaultTheme`.
- **`FindingsStrip` header/body separator missing** — `ReconCardHeader` border-b removal left the FINDINGS header strip visually merged with the first finding row. Added `border-t border-border` to the `<ul>`.
- **`has_geo_db` guard was dead code in settings page** — field declared optional (`has_geo_db?: boolean`) but engine always emits it; `!== undefined` was permanently true. Removed guard and made type required.
- **`SidebarRail` removed accidentally** — sidebar collapse affordance (click-edge-to-collapse) was lost. Restored.
- **Settings page fetch had no `AbortController`** — state update on unmounted component on slow connections. Added cleanup.
- **`EngineConfig` type defined in three files with diverging optionality** — extracted to `web/src/lib/engine-client.ts` as single source; all consumers import from there.
- **`grid-bg` CSS class was a no-op** — background-image removed in v0.3.2 but class still applied in layout. Removed class and CSS rule.
- **`ListScans` domain query missing LIMIT** — see above.

### Added

- **CPE entries link to NVD** — each detected software version (e.g. `cpe:2.3:a:...`) is now a clickable link to `nvd.nist.gov/vuln/search` for that identifier. Renamed label from "CPE" to "KNOWN SOFTWARE".
- **DNS email security tooltips** — SPF, DMARC, and DKIM badges now include plain-English popover explanations of what each protocol does and why it matters.
- **`web/src/lib/recon-display.ts`** — shared `certDaysCls`, `certDaysLabel`, `httpStatusCls`, `httpStatusBracket` utilities replacing three independent copies across dashboard and history pages.
- **`MiniTable` in history list now supports `info` tooltips** — DNS TTL, CDN, and ASN rows show the same tooltips as the history detail page.

### Changed

- **Operator warning banner collapsed to a single slim bar** — replaced full ReconCard (title + two paragraphs) with a one-line `[UNSCOPED]` strip. Page header is now immediately visible without scrolling.
- **Findings strip messages rewritten with plain-language consequences** — "No SPF record — email spoofing risk" → "No SPF record — anyone can send email pretending to be this domain"; "No DMARC record — no enforcement policy" → "No DMARC — spoofed emails reach inboxes even with SPF configured"; etc.
- **`JARM` renamed to `TLS FINGERPRINT`** with an updated tooltip explaining when a changed fingerprint signals infrastructure change.
- **Settings "SCAN TOOLS" renamed to "WHAT EACH SCAN DOES"** with friendly labels (SUBDOMAINS, DNS, TLS CERTIFICATE…) and plain-English descriptions replacing internal tool names.
- **`RunDnsx` DMARC and DKIM queries now run concurrently** — was sequential; wall-clock time for `resolve_dns` cut roughly in half on cold connections.

### Documentation

- **`engine/server.go`** — 200-on-tool-failure response is intentional; comment added explaining why.
- **`.claude/skills/release`** — project release skill added documenting the version-bump and tag workflow.
- **Dockerfile BuildKit cache mounts** — `--mount=type=cache` added to all `go install`, `go mod download`, and `go build` steps. `web/.dockerignore` and `engine/.dockerignore` added, cutting web build context from 1.4 GB to ~2 MB.

## [0.3.2] — 2026-05-29

### Added

- **Light/dark theme toggle** — `next-themes` with `defaultTheme="dark"` and `attribute="class"`; toggle button in sidebar footer. `suppressHydrationWarning` on `<html>` prevents flash-of-wrong-theme on first load.
- **Settings page live engine status** — `/settings` now fetches `/api/config` on mount and displays VERSION, SCOPE, AUTH, COOLDOWN, and GEO DB status as live badges rather than static text. Shows "Configure in Settings →" link from operator banner.
- **Geo DB status in engine `/config` response** — `has_geo_db: boolean` added. Settings page and banner both consume it.
- **`resolve_mutations` tool** — runs `expand_subdomains` candidates through `dnsx` to confirm which subdomain mutations actually resolve. Exposed as MCP tool, REST dispatch, dashboard MUTATIONS tab button, and history detail LIVE MUTATIONS panel.
- **DKIM selector enumeration** — `RunDnsx` now batches 12 common DKIM selectors (`default`, `google`, `s1`, `selector1`, `selector2`, `resend`, etc.) and merges any found TXT records into the apex DNS result. Enables DKIM detection without knowing the domain's selector name.
- **"scan →" link on live mutation rows** — each resolved mutation in the dashboard and history detail panels links directly to a pre-filled dashboard scan for that subdomain.
- **Info callouts on mutations tabs** — brief explanations of what mutations are and why unverified candidates are unverified.

### Changed

- **Visual noise reduced** — scanlines CRT overlay removed; grid background removed; `ReconCardHeader` border-b removed (green left-rail remains the card identity marker); `border-x-0` on operator banner corrected to `border-x-0 border-t-0`.
- **Recent targets grid** — replaced fragile `nth-child` border hacks with a CSS grid (`grid-cols-2 sm:grid-cols-3 lg:grid-cols-4`).
- **Tab bar** — changed from full `border border-border` box to `border-b border-border` underline style.
- **InfoTooltip** switched from Radix `Tooltip` (hover) to `Popover` (click) — works on touch devices without a hover event.
- **`SidebarGroupLabel` and `SidebarRail` removed** from `AppSidebar` — cleaner collapsed state.

### Fixed

- **Grid-bg opacity** — reduced background grid line opacity to 30% so lines didn't overpower content (subsequently removed entirely in v0.3.3).

### Documentation

- **README screenshots refreshed** — all four PNGs retaken against the v0.3.2 UI.

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

[Unreleased]: https://github.com/iksnerd/hopper-recon/compare/v0.3.3...HEAD
[0.3.3]: https://github.com/iksnerd/hopper-recon/compare/v0.3.1...v0.3.3
[0.3.2]: https://github.com/iksnerd/hopper-recon/compare/v0.3.1...v0.3.3
[0.3.1]: https://github.com/iksnerd/hopper-recon/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/iksnerd/hopper-recon/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/iksnerd/hopper-recon/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/iksnerd/hopper-recon/releases/tag/v0.1.0

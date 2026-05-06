# Hopper Recon — TODO

## In Progress
_(none — backend complete, FE density pass complete; Recent-Targets idle state + history delete UI still TODO)_

## Follow-ups
- [ ] Engine refactor — split `engine/main.go` into `engine/cmd/hopper-recon/main.go` + `engine/internal/tools/{subfinder,dnsx,tlsx,httpx,asnmap,uncover,geoip}.go` once the tool count grows beyond ~7 (currently borderline)

---

## Done — this session (backend + FE density)

### Backend / engine wiring
- [x] `GET /api/scans/domains/[domain]` — full scan history for a single domain (timeline-ready)
- [x] `DELETE /api/scans/[id]` — wired through both SQLite and D1 adapters
- [x] 90 s Docker timeout in `docker-mcp.ts` with `settled` flag preventing double-resolve / stuck promises
- [x] Subfinder API key dir (`~/.config/subfinder`) volume-mounted read-only when present
- [x] `asnmap` tool added: Dockerfile install, `HandleAsnmap` in `engine/main.go`, `map_asn` registered, `McpTool` union + `VALID_TOOLS` updated, `parseAsn()` in `scan-parser.ts`

### Database
- [x] `http_status`, `cert_expiry`, `tech_stack` columns + indexes added to scans table
- [x] `ScanMeta` extracted in scan route from parsed results, persisted via extended `completeScan` signature
- [x] `purgeOldScans(domain, keepN=50)` called after every successful scan
- [x] **Bug fix:** SQLite migration ordering — `ALTER TABLE ADD COLUMN` now runs *before* `CREATE INDEX` so existing DBs migrate cleanly. Previously index creation aborted the whole exec batch on legacy schemas, leaving `http_status` missing and crashing every scan with `no such column` outside the route's try/catch (Next.js then returned an empty 500 body, surfacing as `Unexpected end of JSON input` on the client).

### Frontend resilience
- [x] `runTool` (dashboard) and history fetch read responses as text first and gracefully handle empty / non-JSON bodies; cryptic JSON parse error replaced with `Scan failed [500]`.
- [x] Scan route's pre-try section wrapped so DB-init failures return JSON, not empty 500 bodies.

### FE density / Palantir-style refresh
- [x] Type scale enlarged: micro 10→11, data 11→13, body 12→14, emphasis 14→16, metric 24→30 (with letter-spacing tightening)
- [x] Container width unconstrained on dashboard + history — was `max-w-5xl`, now flows full viewport with responsive padding
- [x] Form / panel padding opened up: input + button heights `h-8 → h-10`, panel `p-4 → p-5`, vertical rhythm `space-y-4 → space-y-6 sm:space-y-8`
- [x] Muted-text contrast bumped a second time — `--muted-foreground` 0.55 → 0.68, `-2` 0.70 → 0.78, `-3` 0.45 → 0.58
- [x] **`FindingsStrip` component** — triages all four scan results into a single ranked actionable list (`[!] cert expires in 14d`, `[!] no DMARC`, `[!] public access: dev.x.com`, `[✓] SPF policy present`); issues sort first, then info, then OK. Renders between summary metrics and the tab panels.
- [x] Tab labels carry inline data — `SUBDOMAINS [5]`, `DNS [2 IPs]`, `TLS [62d]`, `HTTP [200]`; while loading they show live elapsed seconds
- [x] Per-tool elapsed timer ticks every 100ms during scan; final duration captured on `ScanState.durations`

### Tooling / docs
- [x] Consolidated agent guidance into a single root `CLAUDE.md` (Next.js + Go engine sections); removed redundant `web/CLAUDE.md` + `web/AGENTS.md`. Adds explicit pre-commit checks: `tsc --noEmit`, `npm run lint`, `gofmt`, `go vet`, `go build`, `go mod tidy`.

---

## Done — earlier UI design system refresh
- [x] Typography scale defined in globals.css (`text-micro` / `text-data` / `text-body` / `text-emphasis` / `text-metric`) — replaces all ad-hoc `text-[10px]`/`text-[11px]`/`text-2xl` sizes
- [x] All hard-coded hex literals routed through CSS tokens; new `--card-hover` / `--card-inset` / `--muted-foreground-2` / `--muted-foreground-3` tokens added
- [x] Accessibility pass: bumped muted-foreground tones to AA-pass contrast on `bg-card`
- [x] Hand-rolled primitives migrated to shadcn — `<Input>`, `<Button>`, `<Table>`, `<Badge>`
- [x] Shared components extracted — `recon/panel.tsx`, `recon/data-chip.tsx`, `recon/redirect-chain.tsx`, `recon/copy-button.tsx`
- [x] Chart styling extracted to `lib/chart-style.ts` (single source for tooltip/tick/cursor/fills)
- [x] Mobile layout pass — `grid-cols-1 md:grid-cols-2` for tab content + history expanded grid; `grid-cols-2 sm:grid-cols-4` for dashboard summary; responsive padding on all pages

---

## Frontend

### Dashboard
- [x] Wire `?domain=` query param to pre-fill and auto-run scan (rescan from history now works end-to-end)
- [x] Add source breakdown chart to Subdomains tab (bar chart of crtsh / hackertarget / submd counts)
- [x] Show redirect chain `[308 → 200]` visually in HTTP tab
- [x] Show JARM hash in HTTP tab with copy button
- [x] Show NS + MX records in DNS tab
- [x] Show TXT records (SPF / DMARC / DKIM presence) in DNS tab — missing TXT = security finding (rendered as destructive ✗ pills)
- [x] Wildcard cert / expired / self-signed badges in TLS tab
- [x] CPE identifiers in HTTP tab
- [x] FindingsStrip — prioritized triage panel for security signals
- [x] Tab labels carry inline data + live elapsed time during scan
- [x] Recent Targets idle state — clickable tiles pulling from `/api/scans/domains` for one-click rescan when no scan is active
- [x] Two-column results layout at lg+ widths — FindingsStrip on left, tabs on right
- [x] Per-tool duration shown after completion — tab triggers now show `[OK 2.3s]`

### History
- [x] Source breakdown — top OSINT sources surfaced as inline pills under subdomain list
- [x] Show NS / MX / TXT in DNS panel
- [x] Show redirect chain in HTTP panel
- [x] CPE list in HTTP panel
- [x] TLS hardening pills (wildcard / expired / self-signed)
- [x] Wire `DELETE /api/scans/[id]` — `[×]` / `[delete?] [yes] [no]` inline confirm on each domain row
- [x] Relative timestamps — `date-fns` `formatDistanceToNow` ("3 days ago")
- [x] Multi-scan timeline — cert days + HTTP status trend chart (lazy-fetched on first expand)
- [x] Migrate raw Recharts to shadcn `ChartContainer`/`ChartTooltip`/`ChartTooltipContent` across all three chart instances
- [x] Replace `Badge`-based `SecPill` with bracket notation spans (design system compliance)
- [x] Domain detail page (`/history/[domain]`) — full-page layout with uncapped subdomain list, SAN display, full TXT records, FindingsStrip, stat bar, scan durations, and bigger charts; domain names in list link to it
- [x] `>_ scan` hover action on each subdomain row in detail page — pre-fills dashboard with that subdomain

---

## Backend / Engine

### API
- [x] `GET /api/scans/domains/[domain]` — full scan history for a single domain (for timeline view)
- [x] `DELETE /api/scans/[id]` — delete a scan record
- [x] Timeout handling — kill Docker container if tool exceeds N seconds (90 s hard kill)

### Database
- [x] Add indexed columns for common query fields (`json_extract` is unindexed today):
  - `http_status`, `cert_expiry`, `tech_stack` — enables server-side filtering
- [x] Purge old scans (keep latest 50 per domain, called after each scan)

### Go Engine
- [x] Subfinder API keys — mount `~/.config/subfinder/provider-config.yaml` via Docker volume
- [x] Add `asnmap` tool — map domain → ASN → CIDR ranges (pure OSINT, Tier 1)
- [x] `uncover` tool — `search_hosts` registered in engine + Dockerfile; `ssl:"<domain>"` query; config dir `~/.config/uncover/` mounted when present; parser + EXPOSE tab on dashboard; panels in history list + detail page

---

## Infrastructure

### Cloudflare (Production)
- [ ] Create D1 database: `wrangler d1 create recon-db-prod`
- [ ] Run `schema.sql` against D1
- [ ] Fill in `database_id` in `wrangler.jsonc`
- [ ] Implement Cloudflare Sandbox executor in `lib/executor.ts` (stub today)
- [ ] Push Docker image to Cloudflare Registry
- [ ] Add `SCANNER_ENV` sandbox binding to `wrangler.jsonc`
- [ ] Deploy: `npm run build && wrangler deploy`

### Litestream (Docker/VPS deployment — alternative to CF)
- [ ] Add `litestream.yml` config replicating to R2
- [ ] Create `Dockerfile` for Next.js app with Litestream sidecar
- [ ] `docker-compose.yml` for local full-stack (web + litestream)

---

## Auth & Multi-user
- [ ] Add NextAuth.js (GitHub + Google OAuth)
- [ ] Restore `users` + `targets` tables to schema
- [ ] Gate API routes behind session
- [ ] Per-user MCP secret for IDE agent authentication (`/api/mcp` route)
- [ ] Tier system (free / pro scan limits)

---

## Polish
- ~~Landing page live example~~ — dropped: running `probe_http` on every page load would exhaust Cloudflare Workers free tier CPU budget
- [ ] Empty state illustrations for history / dashboard
- [x] Replace ip-api.com geoip lookups with bundled MaxMind GeoLite2 (oschwald/geoip2-golang) — engine-side `lookup_geoip` MCP tool reads `~/.config/hopper-recon/GeoLite2-Country.mmdb` (volume-mounted, license-restricted so not baked in); web route caches results in `geoip_cache` table to avoid Docker spawn per history-page view
- [x] Mobile layout pass
- [x] Favicon + metadata (custom `>_` SVG icon, full OG/keywords metadata, title template)
- [x] Error boundary for chart crashes (`recon/chart-boundary.tsx` wraps every recharts container)
- [x] TLS certificate table truncation — fixed via `break-all` on value cells

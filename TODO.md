# Hopper Recon — TODO

## Critical path — self-hosted on k8s
The shortest road to "a company can deploy this on their Kubernetes cluster, free":

1. **v0.1.0 OSS release** — license + docs + CI + multi-arch images (weeks 1–2)
2. **v0.1.0 K8s package** — Helm chart + Kustomize + pod-security defaults (weeks 2–3)
3. **v0.3.0 Self-hosted auth** — Auth.js + audit log + scope config (weeks 3–4) — required for >5 users; smaller teams can run with `AUTH_MODE=none` behind a VPN

**v0.2.0 engine refactor is optional for this path** — current SaaS-shaped architecture deploys to k8s fine. Pursue the engine refactor separately for the "MCP-native, engine is a product on its own" narrative.

Pricing target: marginal cost on existing cluster ≈ $0/mo; standalone tiny cluster (Hetzner CX11 or Oracle Free Tier ARM) $0–5/mo. Real operational cost is upstream API quotas (Shodan/Censys), which is the customer's bill with those vendors.

---

## In Progress
_(none — UX overhaul shipped; OSS prep + engine refactor are next milestones)_

## Follow-ups
- [ ] Engine refactor — split `engine/main.go` into `engine/cmd/hopper-recon/main.go` + `engine/internal/tools/{subfinder,dnsx,tlsx,httpx,asnmap,uncover,geoip}.go` once the tool count grows beyond ~7 (currently borderline). Naturally aligns with the v0.2.0 engine refactor below.
- [ ] Empty state illustrations for history / dashboard
- [ ] **DKIM selector enumeration** — engine should query common DKIM selectors (`default`, `google`, `s1/s2`, `selector1/selector2`, `clk/clk2`, `pm`, `resend`, `k1`, `mxvault`) and merge their TXT records into the apex result. Today, parser regex `/v=dkim1|dkim=/` in `scan-parser.ts:172` is greedy and false-positives on `adkim=r` from DMARC records — coincidentally correct for setups that have DKIM, wrong for setups that don't. Tighten regex to `/v=dkim1/i` once selectors are enumerated.

---

## Done — UX overhaul (Palantir + terminal green, this session)

### Components
- [x] **`ReconCard` primitive** (`components/recon/recon-card.tsx`) — composable Palantir-style card on shadcn `Card`: header strip, terminal-green left rail, eyebrow, uppercase title, action slot, content. `tone="danger"` variant for findings with issues.
- [x] **`PageHeader` shared component** (`components/recon/page-header.tsx`) — sticky chrome with bordered, mobile-visible sidebar toggle + breadcrumb + right slot. Used on dashboard, history, history/[domain], settings.
- [x] **`Panel` refactored** to delegate to `ReconCard`; auto-splits `// LABEL [N]` into title + count action; new `contentClassName` and `action` props.
- [x] All call sites migrated — dashboard, history list + detail, settings, landing, `FindingsStrip`, `GeoGlobe`.

### Color system
- [x] `--terminal-green` (oklch 0.85/0.19/145) + `--terminal-green-dim` (0.55/0.10/145) tokens added to `globals.css`
- [x] Green applied to: `>_` prompt sigils, active tab underline + text, scanning cursor, status pills (`[DONE]`, `[SCANNING]`), success indicators (HTTP 2xx, cert >30d, SPF/DMARC ✓), card left rail, sidebar active item, logo dot, footer pulse
- [x] Cards/borders/charts/tables stay achromatic — green is signal-only

### Sidebar
- [x] Distinct lucide icons: `Radar` (dashboard), `History` (history), `SlidersHorizontal` (settings)
- [x] Sidebar text bumped from `muted-foreground` → `muted-foreground-2` (brighter)
- [x] Active item: green icon, green bold text, green left rail, bg-card-hover
- [x] Mobile sidebar visibility fixed — `PageHeader`'s `SidebarToggleButton` is a real bordered control, not a ghost icon

### Skill + memory
- [x] `frontend-design` skill rewritten — replaces "achromatic only" with scoped green-accent rule, documents the load-bearing card header pattern, points at the recon composables as the only correct primitives
- [x] Two feedback memories saved (terminal-green sanctioned; card-header pattern is load-bearing) so future sessions don't drift

---

## Strategic roadmap — OSS + SaaS

### Decisions captured (this session, 2026-05-06)

- **Open-core split**: OSS = single-tenant, self-hosted, deployable on customer infra. Cloud SaaS = multi-tenant, hosted, in a **separate private repo** (e.g. `hopper-recon-cloud`) that depends on OSS as a dependency. Same pattern as Sentry/PostHog/GitLab.
- **Engine is the canonical OSS deliverable.** Dashboard is a recommended companion. The MCP-native angle is the key differentiator — other recon tools predate MCP; positioning as "recon for AI agents" is fresh.
- **License recommendation: BSL 1.1 → Apache 2.0 after 4 years.** Best balance of community adoption + protection from cloud strip-mining. Not yet decided.
- **Engine refactor for OSS: engine owns its SQLite**, runs as long-running HTTP/MCP server. Web becomes a thin frontend; AI agents (Claude, Cline) and CLI tools can also query the engine directly.
- **SaaS architecture stays different:** engine stateless, web owns D1 (multi-tenant). The codebase already has the adapter pattern; OSS adds an `EngineDBAdapter`.
- **SSO via Clerk is a premium shortcut, not a foundation.** DNS/HTTP domain verification is still load-bearing for non-Enterprise tenants and for scanning vendor domains.
- **Don't deploy publicly without auth + scope checks.** Public unauthenticated `/api/scan` is an abuse vector; will get upstream API keys (Censys, Shodan, etc.) suspended.
- **Cloudflare path verified:** Workers Free + D1 Free covers the read-only / history side. Workers Paid ($5/mo) is the floor for running the engine on Cloudflare Containers. Cheapest non-trivial deploy = Workers Free + engine on a $0 VM (Fly.io / Hetzner / Oracle Free).
- **Self-hosted does NOT require Clerk** (Clerk is cloud-only, breaks self-hosting). OSS uses Auth.js (OIDC/SAML/email magic link, all OSS) with `AUTH_MODE=none|email|oidc|saml` env switch — `none` for "behind a VPN" simple case.

### v0.1.0 — OSS public release
- [ ] **License decision** — recommended BSL 1.1 with 4-year conversion to Apache 2.0; "Additional Use Grant" for internal/non-commercial use
- [ ] `LICENSE` at repo root
- [ ] `SECURITY.md` — responsible disclosure, contact email
- [ ] `CODE_OF_CONDUCT.md` — Contributor Covenant
- [ ] `CONTRIBUTING.md` — PR style, dev setup, commit conventions
- [ ] `README.md` rewrite — what it does, 30-second install, screenshots from new UI, "authorized use only" disclaimer, list of tools, scope/limits, k8s install in first 3 sections
- [ ] `.env.example` — every env var documented
- [ ] `CHANGELOG.md` — start at v0.1.0
- [ ] `docker-compose.yml` — engine + web + SQLite volume + provider-config volume; `docker compose up` to a working install
- [ ] `.github/workflows/ci.yml` — `tsc --noEmit`, `npm run lint`, `gofmt`, `go vet`, `go build`
- [ ] `.github/workflows/release.yml` — multi-arch image build (amd64 + arm64) → GHCR, cosign signing, syft SBOM
- [ ] `.github/ISSUE_TEMPLATE/*`, `PULL_REQUEST_TEMPLATE.md`
- [ ] CLA bot ([cla-assistant.io](https://cla-assistant.io/)) — protects ability to relicense if needed
- [ ] Trademark research on "hopper-recon" (register if going SaaS later)
- [ ] Tag v0.1.0 + GitHub release notes
- [ ] Soft launch: r/netsec, r/AskNetsec, HN Show, projectdiscovery Discord, Anthropic/MCP-aware audiences

### v0.1.0 — Kubernetes deployment package (the load-bearing piece for company adoption)
- [ ] **Helm chart** at `deploy/helm/hopper-recon/` with sane defaults (works without overrides) + `values.production.yaml` example for HA setups
- [ ] Helm repo published to GHCR Pages: `helm repo add hopper https://...`
- [ ] **Kustomize overlay** at `deploy/kustomize/` (base + dev/prod overlays) — for shops that are Kustomize-only
- [ ] **Pod Security**: `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, no privileges, no `hostPath` — passes default OPA/PSP without waiver
- [ ] **Resource defaults**: engine `100m/200Mi` request, `1/500Mi` limit; web `50m/150Mi` request, `100m/200Mi` limit
- [ ] **Probes**: `/healthz` (liveness) + `/readyz` (readiness) on both engine and web
- [ ] **Persistence**: PVC for SQLite (default 5Gi, configurable), no StatefulSet (single-replica engine v0.1)
- [ ] **NetworkPolicy template** documenting egress (subfinder OSINT providers, cert transparency, etc.) so security teams can lock it down
- [ ] **ServiceMonitor** template for Prometheus Operator (`/metrics` endpoint on engine + web)
- [ ] **Structured JSON logs** to stdout — Loki/Datadog/Splunk pickup with no extra config
- [ ] **No phone-home, no telemetry** — explicitly documented; opt-in `USAGE_TELEMETRY=true` may come later, default off forever
- [ ] **Air-gapped install guide** — how to mirror image + chart to internal registry, install offline
- [ ] **Backup example** in chart — CronJob that snapshots SQLite to S3-compatible storage
- [ ] **Upgrade docs** — schema migrations run automatically on container start; rolling updates work; document version-skew tolerance
- [ ] **Optional Postgres backend** (deferred, file the issue when someone asks) — for shops that disallow SQLite-on-PVC in prod

### v0.2.0 — Engine refactor (engine owns SQLite, MCP-native server)
- [ ] **Engine: add `serve` subcommand** for long-running HTTP/MCP mode (Streamable HTTP transport from Go MCP SDK)
- [ ] Engine: optional persistent SQLite via `--db /data/scans.db` flag (or `HOPPER_DB_PATH` env)
- [ ] Engine: keep current stdio one-shot mode for back-compat (SaaS uses it)
- [ ] Engine: new MCP query tools — `list_scans`, `list_domain_summaries`, `get_scans_by_domain`, `get_scan_by_id`, `delete_scan`, `purge_old_scans`
- [ ] Engine: schema migrations system (replace duplicated `schema.sql` + inline SQL in `db.ts` with versioned migration files)
- [ ] Engine: graceful shutdown, healthcheck endpoint, structured logs
- [ ] Web: new `lib/engine.ts` — ~30-line HTTP/MCP client (`engineClient.callTool()`, typed wrappers)
- [ ] Web: `HOPPER_DB_MODE=local|d1|engine` env switch in `db.ts`; new `EngineDBAdapter` proxies reads to engine
- [ ] Web: API route handlers swap to engine client when `HOPPER_DB_MODE=engine` — URLs and response shapes unchanged so TanStack Query keeps working
- [ ] Web: handle "engine offline" with a clear empty state in UI
- [ ] Optional per-page: upgrade to Server Components with `initialData` for first-paint wins
- [ ] `docker-compose.yml` updated — engine on `:8080`, web's `ENGINE_URL=http://engine:8080`

### v0.3.0 — Self-hosted auth, audit, scope
- [ ] **Auth.js** integration (OIDC + email magic-link providers) — OSS, no external service required
- [ ] `AUTH_MODE` env: `none` (behind VPN — show banner), `email` (magic link), `oidc`, `saml`
- [ ] First-boot admin user creation via `ADMIN_EMAIL` env
- [ ] `/admin` route — users list, audit log, settings (admin role only)
- [ ] **Audit log table** — every scan logged with user, target, ts, allowed/denied, reason. Always on, even single-user.
- [ ] Middleware on `/api/scan` writes audit row before invoking engine
- [ ] **Scope config** — `assets.yaml` or `ALLOWED_DOMAINS` env. Off-scope scans WARN by default; `STRICT_SCOPE=true` blocks.
- [ ] Hardcoded blocklist baked in: `*.gov`, `*.mil`, financial regulators, NATO domains
- [ ] Periodic re-verification (cron) for any explicitly verified domains
- [ ] Documentation: network segmentation expectations, SSO setup guides for Okta/Workspace/Auth0

### Cloud SaaS (separate private repo: `hopper-recon-cloud`)
- [ ] Repo bootstrap; imports OSS as a dependency
- [ ] **Clerk** integration with Organizations + multi-tenant model
- [ ] Clerk SSO webhook handler — auto-verify tenant's apex domain on `organizationDomain.verified` event with `verification.strategy="saml"|"enterprise_sso"` (~30 lines)
- [ ] **Domain ownership verification flow** for non-Enterprise tenants:
  - [ ] `domain_subscriptions` table (id, tenant_id, domain, status, method, token, verified_at, last_checked, revoked_at)
  - [ ] `POST /api/domains` — create subscription, return DNS + HTTP challenge instructions
  - [ ] `POST /api/domains/:id/verify` — DNS-over-HTTPS lookup of `_hopper-verify.<domain>` TXT, or `fetch()` of `https://<domain>/.well-known/hopper-verify/<token>`
  - [ ] `GET /api/domains` — list per tenant
  - [ ] Public Suffix List (`tldts`) check — refuse to "verify" `co.uk`, `github.io`, `vercel.app`, etc.
  - [ ] Periodic re-verification cron (Cloudflare Cron Trigger nightly, batch 1000 oldest, revoke after 2 failures)
- [ ] **`/api/scan` gate**: tenant_id + plan quota + verified-domain (or off-scope override + audit) + rate limit
- [ ] **Per-plan quotas** table; rate limits at edge (Cloudflare Rate Limiting) + app-layer for plan logic
- [ ] **Stripe billing** integration (own Stripe account, not Marketplace pass-through)
- [ ] **Workflows or Queues** for long-running scans (subfinder ~30s — can't tie up an HTTP request for paid customers)
- [ ] Email: Resend or Mailchannels for verification, alerts, weekly digest
- [ ] Logs + paging: Workers Tail + Logpush → R2/Datadog/BetterStack
- [ ] Marketing landing page replacing dev landing
- [ ] `/admin` super-admin view for managing tenants, abuse, usage

### Cloudflare deployment (deferred until auth lands)
- [ ] D1 database creation (was attempted, immediately deleted — clean slate)
- [ ] Apply `schema.sql` (or migrations from v0.2) to D1
- [ ] Fill in real `database_id` in `wrangler.jsonc`
- [ ] Decide engine runtime path:
  - [ ] **Path A** — Cloudflare Containers (Workers Paid required, ~$5–10/mo realistic): implement Sandbox/Container executor in `lib/executor.ts` (currently a stub), push image to Cloudflare Registry, add `SCANNER_ENV` binding
  - [ ] **Path B** — Engine on external VM (Fly.io / Hetzner / Oracle Free, ~$0–5/mo): web on Workers Free calls engine over HTTPS; new `HttpExecutor` class
- [ ] OpenNext build verification: `npx opennextjs-cloudflare build` succeeds
- [ ] Production deploy: `wrangler deploy`

### Pricing model (aspirational, OSS users free forever)
- [ ] **Free**: 1 domain, daily passive scan, 7-day history, no alerts
- [ ] **Pro $19/mo**: 10 domains, 4× daily, email alerts, 90-day history, CSV export
- [ ] **Team $79/mo**: 50 domains, hourly scans, Slack/email alerts, API key access, audit log, integrations
- [ ] **Enterprise (talk to sales, $499+/mo)**: SSO/SAML, custom retention, dedicated egress, MSA, audit log retention, priority support
- Anchor pricing higher than feels comfortable — recon tools sell to security teams; $79/mo for 50 domains is laughably cheap to that buyer.

### Project hygiene
- [ ] Decide repo structure: stay monorepo (`hopper-recon` with `engine/` + `web/`), or split into `hopper-recon` (engine + MCP — the headline OSS) + `hopper-recon-dashboard` (optional Next.js companion)
- [ ] Discord/community channel for OSS users
- [ ] Versioning convention (semver) + release process
- [ ] Sketched alternative: third executor `HttpExecutor` (point Worker at remote engine VM) — already discussed; ~50 lines

### Litestream (alternative to D1, deferred — overlaps with engine-owns-DB)
- [ ] _Likely obviated by v0.2.0 engine refactor; engine's SQLite + volume mount on customer infra removes the need for replication for self-hosted. Keep on radar only if a customer wants HA without Postgres._

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

## Polish
- ~~Landing page live example~~ — dropped: running `probe_http` on every page load would exhaust Cloudflare Workers free tier CPU budget
- [ ] Empty state illustrations for history / dashboard
- [x] Replace ip-api.com geoip lookups with bundled MaxMind GeoLite2 (oschwald/geoip2-golang) — engine-side `lookup_geoip` MCP tool reads `~/.config/hopper-recon/GeoLite2-Country.mmdb` (volume-mounted, license-restricted so not baked in); web route caches results in `geoip_cache` table to avoid Docker spawn per history-page view
- [x] Mobile layout pass
- [x] Favicon + metadata (custom `>_` SVG icon, full OG/keywords metadata, title template)
- [x] Error boundary for chart crashes (`recon/chart-boundary.tsx` wraps every recharts container)
- [x] TLS certificate table truncation — fixed via `break-all` on value cells

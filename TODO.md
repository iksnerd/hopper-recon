# Hopper Recon — TODO

## Critical path — self-hosted on k8s
The shortest road to "a company can deploy this on their Kubernetes cluster, free":

1. **v0.1.0 OSS release** — license + docs + CI checks workflow ✓ (image publishing intentionally deferred — operators build locally; bring back `release.yml` from git history if needed)
2. **v0.1.0 K8s package** — Helm chart + Kustomize + pod-security defaults — _deferred; lean compose-first shape ships first_
3. **v0.3.0 Self-hosted auth** — Auth.js + audit log + scope config (weeks 3–4) — required for >5 users; smaller teams can run with `AUTH_MODE=none` behind a VPN

**v0.2.0 engine refactor shipped** — engine owns SQLite + recon tools, web is a thin HTTP client, MCP at `/mcp` for AI agents.

Pricing target: marginal cost on existing cluster ≈ $0/mo; standalone tiny cluster (Hetzner CX11 or Oracle Free Tier ARM) $0–5/mo. Real operational cost is upstream API quotas (Shodan/Censys), which is the customer's bill with those vendors.

---

## In Progress
_(none)_

---

## Done — OSS readiness + data completeness (2026-05-13)

### OSS readiness review
- [x] **Personal info audit** — no real emails, no secrets, no credentials in any tracked file. `iksnerd@users.noreply.github.com` is GitHub's privacy noreply throughout. `docs/personal/` was already gitignored.
- [x] **`spec.md` deleted** — stale v0.1 Cloudflare D1 / NextAuth.js planning artifact; did not reflect current architecture.
- [x] **`GEMINI.md` gitignored + rewritten** — was describing v0.1 Cloudflare Pages/Sandboxes/D1 architecture with 4 tools and "frontend TODO". Now gitignored (consistent with `.gemini/`), local copy updated to v0.2 arch with all 7 tools.

### Bug fixes
- [x] **`parseDns` CDN field** — `dnsx` JSON emits `cdn: bool` + `cdn-name: string`. Parser was reading the boolean as the display value (every CDN domain showed `"true"`). Fixed to read `first["cdn-name"]`.
- [x] **`probe_http` CPE** — `httpx` needs explicit `-cpe` flag to populate CPE in JSON. Flag was missing; CPE identifiers were never returned. Added `-cpe` to `RunHttpx` in `engine/tools.go`.

### Data completeness
- [x] **`HttpResult` extended** — added `cdn_name`, `cdn_type`, `aaaa`, `scheme` fields from httpx JSON output.
- [x] **Dashboard HTTP panel** — CDN row (`cloudflare · waf`) and combined IPv4+IPv6 IPS section.
- [x] **History detail HTTP panel** — same CDN row and IPS section with both address families.

### Tooltips
- [x] **`InfoTooltip` component** (`components/recon/info-tooltip.tsx`) — Lucide `Info` icon + Radix `Tooltip`. `TooltipProvider` added to app layout.
- [x] **Tooltips on technical fields** — `DataRow` (dashboard) and `MiniTable` (history detail) extended with optional `info` prop. Covers: JARM, CPE, CNAME, ASN, CDN (HTTP panel); TTL, CDN, ASN (DNS panel).

---

## Done — engine test suite (2026-05-09)

- [x] **`engine/policy_test.go`** — 18 tests covering `Policy.Check` (14 table cases: blocklist, override, passive vs active tools, scope, trailing-dot normalisation), `inScope`, `HasScope`, `LoadPolicy` env parsing + edge cases
- [x] **`engine/db_test.go`** — 12 tests covering full SQL round-trips on `:memory:` SQLite: schema migration, boot sweep (via temp file), audit write + cooldown query, insert/complete/fail/delete scan, ScanMeta column propagation, purge, list domain filter, list limit default, geoip cache upsert + idempotency
- [x] **`engine/tools_test.go`** — 12 tests covering `RunDnsx` DMARC merge logic (5 cases: merge, no-DMARC, error-ignored, empty apex, non-JSON apex), subfinder JSONL parsing, GeoIP nil-reader + malformed IP handling, `userAgent` format
- [x] **`engine/server_test.go`** — 29 tests covering pure functions (`parseJSONLines`, `extractMeta` for both tools, `clientIP` 4 cases, `envOr`, `writeJSON`), all HTTP handlers (`handleHealth`, `handleReady`, `handleConfig`, `handleListScans`, `handleDeleteScan`, `handleRunScan` 6 cases), `MCPCtx.gate` (policy-blocked, allowed, cooldown)
- [x] **`engine/integration_test.go`** — 4 smoke tests behind `//go:build integration`; excluded from `go test ./...`; require real binaries inside the Docker image
- [x] Two minimal seam vars added to production code (zero logic change): `var execJSONL = runJSONL` in `tools.go` (7 call sites), `var toolRunner = runTool` in `server.go` (1 call site) — enable test-time injection without interface abstractions
- [x] **`handleGeoipLookup` handler tests** added to `server_test.go`: empty `ips` param, cache hit, dedup, and cache-miss-without-mmdb cases
- [x] **`go test -race`** passes clean — no data races on the test-time seam vars
- [x] **Structured JSON logs** — `slog.SetDefault(slog.NewJSONHandler(os.Stderr, nil))` in `main()`; startup + shutdown messages converted to `slog.Info` key-value pairs; `log.Fatalf` fatals still route through slog automatically
- [x] **TODO housekeeping** — all shipped v0.2.0 engine + web items ticked; stale unchecked items corrected

## Follow-ups
- [ ] Engine package split — move to `engine/cmd/hopper-recon/main.go` + `engine/internal/` sub-packages once tool count grows beyond ~10. Currently 7 tools in a single `main` package — borderline but manageable. Revisit at tool 8.
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
- [x] **License decision** — ship MIT (already in `LICENSE`). BSL 1.1 was considered for cloud strip-mining protection; rejected because (a) niche security tooling is not a hyperscaler target, (b) MIT maximises adoption which is the real v0.1 risk, (c) future SaaS-only code can land in the private `hopper-recon-cloud` repo under whatever license we want without touching OSS history.
- [x] `LICENSE` at repo root (MIT, present)
- [x] `SECURITY.md` — authorized-use posture, outbound-footprint table, built-in protections, disclosure SLA (3/10/30 days)
- [x] `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1 link, contact email
- [x] `CONTRIBUTING.md` — dev setup, pre-commit checks per side, PR conventions, recon-tool admission rule
- [x] `README.md` rewrite — authorized-use disclaimer at top, outbound-footprint, "Built-in protections" table, screenshots grid, configuration env table
- [x] `.env.example` — every env var documented + commented Litestream cloud-replica blocks
- [x] `CHANGELOG.md` (Keep a Changelog format) starting at v0.1.0
- [x] `docker-compose.yml` at repo root (engine + web + Litestream sidecars, named volumes, env_file with required: false)
- [x] `.github/workflows/ci.yml` — gofmt -l, go vet, go mod tidy --diff (engine); tsc --noEmit, eslint, vitest (web). Checks-only, no artifacts.
- [x] `.github/ISSUE_TEMPLATE/{bug_report,feature_request,config}.yml` + `PULL_REQUEST_TEMPLATE.md` with authorized-use confirmation checkboxes
- [x] `v0.1.0` git tag pushed (release pipeline removed; bring back if/when we want signed multi-arch GHCR images)
- ~~`.github/workflows/release.yml`~~ — _deleted (commit `599bd20`); operators build locally with `docker compose up --build`. Multi-arch GHCR + cosign + SBOM is in git history if we ever want it back._
- [ ] CLA bot ([cla-assistant.io](https://cla-assistant.io/)) — protects ability to relicense if needed
- [ ] Trademark research on "hopper-recon" (register if going SaaS later)
- [ ] GitHub Release page for v0.1.0 (tag exists; no Release entry yet)
- [ ] Soft launch: r/netsec, r/AskNetsec, HN Show, projectdiscovery Discord, Anthropic/MCP-aware audiences

### v0.1.0 — Abuse mitigations (must ship before public release)

These are not "nice to have" — they ship with v0.1 because they're cheap, they set the operator-relations tone, and they harden the tool against the most obvious reputational risk: a sloppy first impression where someone runs hopper-recon at scale and a target's blue team can't tell who/what hit them.

Today's outbound footprint per scan is ~5 DNS queries + 1 TLS handshake + 1 HTTP GET against the target — equivalent to one browser tab. The risk is not the current default, it's the planned "scan all discovered subdomains" feature multiplying that by 50–500.

- [x] **Custom User-Agent on httpx** — `hopper-recon/<Version> (+repo URL)` set in `engine/tools.go`. Single-sourced via `var Version` so MCP serverInfo and UA stay in lockstep.
- [x] **Hardcoded blocklist** in `engine/policy.go` — refuses active probes (`probe_http`, `fetch_tls_cert`) against `*.gov`, `*.mil`, `*.gouv.fr`, `*.gov.uk`, `*.go.jp`, `*.gc.ca`, `*.gov.au`. Returns HTTP 451. Override gated behind `HOPPER_OVERRIDE_BLOCKLIST=true` + non-empty `HOPPER_BLOCKLIST_OVERRIDE_REASON`, audit-logged. Lives at the engine — direct MCP callers hit the same gate via `MCPCtx.gate()`.
- [x] **Per-target cooldown** — 60 s window keyed on `(target, tool)` reading `audit_log` (so MCP and REST share one cooldown surface — agents can't dodge it by switching transports). Returns 429 with `Retry-After`.
- [x] **Audit log table** — schema in `engine/db.go` (`id, ts, source_ip, user_agent, tool, target, decision, reason`). Every `/scan` and gated MCP call writes one row. Operator reads via `sqlite3 /data/scans.db` against the volume.
- [x] **`HOPPER_ALLOWED_DOMAINS` scope config** — when set, off-scope targets return 403 + audit row. When unset, behaviour matches today (scan anything) and the dashboard banner nags.
- [x] **First-boot warning banner** — `OperatorWarningBanner` in `(app)/layout.tsx`. `useSyncExternalStore` for the localStorage ack so dismissal refreshes across tabs. Reads engine `/config` (booleans only).
- [x] **`X-Hopper-Recon: authorized-use-only`** header on every `/scan` response (engine + web proxy).
- [ ] `Server: hopper-recon/0.1.0` header — _minor; the X-Hopper-Recon header serves the same identification purpose._
- [ ] Audit-log viewer in `/admin` deferred to v0.3 (needs auth to expose).

### v0.1.0 — Production deployment package (lean, compose-first)

> Full plan: [`docs/v0.1.0-prod-deploy-plan.md`](docs/v0.1.0-prod-deploy-plan.md). Helm chart / Kustomize / NetworkPolicy / ServiceMonitor templates intentionally deferred — operators write those themselves to fit their existing infrastructure.

- [x] `Dockerfile` for the web app (Next.js standalone build) — `web/Dockerfile`, runs as `node` user (uid 1000)
- [x] `Dockerfile` for the engine — `engine/Dockerfile`, two-stage build, alpine runtime
- [x] `/healthz` + `/readyz` on engine
- [x] `/api/healthz` + `/api/readyz` on web
- [x] Reference `docker-compose.yml` at repo root — engine + web + Litestream sidecars; engine reads `.env` via env_file with `required: false`
- [x] Verify `docker compose up` works clean from a fresh checkout
- ~~`.github/workflows/release.yml`~~ — _deleted; operators build locally._
- [ ] `DEPLOY.md` at repo root — env vars, ports, volumes, backup recipe, upgrade recipe, auth posture ("no built-in auth in v0.1; put behind VPN/oauth2-proxy")
- [x] Structured JSON logs to stdout (engine — `log/slog` JSON handler wired in `main()`; Next default is fine for web)
- [ ] `DEPLOY.md` — env vars, ports, volumes, backup recipe, upgrade path, auth posture ("no built-in auth in v0.1; put behind VPN/oauth2-proxy")
- [ ] Helm chart, Kustomize overlays, NetworkPolicy, ServiceMonitor — _deferred; revisit if 5+ issues filed_

### v0.2.0 — Engine refactor (engine owns SQLite + tools, web is dumb client)

**Decisions baked in (this session, 2026-05-08):**
- No migration story for existing dev DBs — we're the only users, fresh start. Engine boots a new SQLite, web's `web/data/recon.db` is abandoned.
- **REST, not MCP, for the dashboard ↔ engine link.** MCP is for AI agents discovering tools; the dashboard knows the schema. Plain JSON over HTTP is simpler to debug and document.
- **Drop the SQLite path from the web entirely.** `createSqliteAdapter()` in `db.ts` is deleted, not preserved as a fallback. `HOPPER_DB_MODE` becomes `engine|d1` only.
- **Drop `docker-mcp.ts` from the web.** Web no longer spawns docker per scan — that's the architectural prize. Web → engine is plain HTTP, web container no longer needs the docker socket. Doubles the deployable platform list.
- Engine retains stdio MCP mode (default `docker run -i hopper-recon`) for AI agents (Claude Desktop, Cline, etc.) connecting directly. `hopper-recon serve` adds long-running HTTP for the dashboard.
- No migrations system in v0.2 — `CREATE TABLE IF NOT EXISTS` + `ALTER TABLE` ladder is enough for one schema. Real migrations land in v0.3 when a second deployable shape exists.
- SQLite Go driver: **`modernc.org/sqlite`** (pure Go, trivial multi-arch). Recon write volume is too low to need CGo perf.

**Engine:**
- [x] Add `serve` subcommand: long-running HTTP server on `:8080`. Default (no args) keeps current stdio MCP for AI-agent compatibility.
- [x] Open SQLite at path from `--db` flag or `HOPPER_DB_PATH` env (default `/data/scans.db`). WAL mode. Boot sweep retires stale pending rows.
- [x] REST endpoints shipped:
  - `POST /scan` — runs tool, persists row, returns final state in one transaction
  - `GET /scans?domain=&limit=` — list with domain filter + limit default 50
  - `DELETE /scans/{id}` — delete
  - `GET /geoip?ips=a,b,c` — cache check → live mmdb lookup → upsert in one call (the planned `POST /geoip` upsert-only endpoint was folded in here)
  - `GET /healthz`, `GET /readyz`, `GET /config`
- [x] MCP recon tools at `POST /mcp` (Streamable HTTP) — `buildMCPServer` shared between stdio + HTTP modes.
- [x] `engine/main.go` split into `main.go` + `tools.go` + `db.go` + `server.go`.
- [x] Graceful shutdown on SIGTERM/SIGINT with 5 s drain.
- [x] Structured JSON logs to stdout — `slog.SetDefault(slog.NewJSONHandler)` in `main()` routes all `log.*` calls through JSON; startup + shutdown messages converted to `slog.Info` key-value pairs.

**Web:**
- [x] `createSqliteAdapter()` and `better-sqlite3` deleted. `web/data/recon.db` abandoned.
- [x] `lib/docker-mcp.ts` and `lib/executor.ts` deleted.
- [x] `lib/engine-client.ts` — thin fetch wrapper around engine REST.
- [x] `lib/db.ts` — `createEngineAdapter()` is the default; D1 auto-detected via `env.DB` presence on Cloudflare. No `HOPPER_DB_MODE` env needed.
- [x] `/api/scan` route is a thin proxy: validates tool + target, calls `engineClient.runScan`, mirrors `X-Hopper-Recon` header.
- [x] All `/api/scans/*` routes and `/api/geoip` go through `engine-client.ts`.
- [x] Engine-offline empty state — dashboard and history surfaces gracefully handle fetch failures from the engine.
- [ ] Optional per-page: upgrade to Server Components with `initialData` for first-paint wins.

**Compose / docs:**
- [x] `docker-compose.yml` at repo root — engine + web + Litestream sidecars; engine on `:9119` (host-bound loopback), web on `:3000`. Web no longer needs docker socket.
- [ ] `DEPLOY.md` at repo root — env vars, ports, volumes, backup recipe, upgrade path, auth posture.

### v0.3.0 — Self-hosted auth, audit, scope

> Note: hardcoded blocklist, audit log table, and `ALLOWED_DOMAINS` scope config were promoted to v0.1.0 (see "Abuse mitigations"). v0.3 layers identity + UI on top of those primitives.

- [ ] **Auth.js** integration (OIDC + email magic-link providers) — OSS, no external service required
- [ ] `AUTH_MODE` env: `none` (behind VPN — show banner), `email` (magic link), `oidc`, `saml`
- [ ] First-boot admin user creation via `ADMIN_EMAIL` env
- [ ] `/admin` route — users list, **audit-log viewer**, settings (admin role only)
- [ ] Extend v0.1 `audit_log` table with `user_id` column; backfill `null` for pre-auth rows
- [ ] Auth middleware on `/api/scan` populates `user_id` before the existing audit-write
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

### Litestream (shipped, this session — 2026-05-08)
- [x] Litestream sidecars wired into `docker-compose.yml`: `litestream-restore` (one-shot init, idempotent) + `litestream` (long-running replicate). Engine unchanged — WAL mode in `engine/db.go` was already on.
- [x] `litestream.yml` at repo root with local file replica as default; commented R2 / S3 / Azure / GCS blocks.
- [x] `litestream-backup` named volume for the default file replica.
- [x] README "Persistence & backups" section documents the cloud swap-in flow + manual restore command.
- [x] CLAUDE.md architecture diagram + new "Persistence (Litestream)" section explain the sidecar topology for future agents.

### UI: about page, tool attribution, breadcrumbs, layout (shipped, this session — 2026-05-08)
- [x] `/about` route (`web/src/app/(app)/about/page.tsx`) — five panels: intro, recon tools, engine & runtime, web stack, data. Every entry is a clickable GitHub link with a `↗` glyph; sidebar gets an `Info`-icon `about` nav entry.
- [x] `ToolSourceLink` (`components/recon/tool-source-link.tsx`) — tiny `via TOOL ↗` link wired into the `action` slot of every tab's main result Panel on the dashboard (subfinder / dnsx / tlsx / httpx / cdncheck / urlfinder).
- [x] `urlfinder` (the missed projectdiscovery tool) added to the about page's recon-tools list.
- [x] **Breadcrumbs rewritten** to use shadcn primitives (`Breadcrumb`, `BreadcrumbList`, `BreadcrumbItem`, `BreadcrumbLink`, `BreadcrumbPage`, `BreadcrumbSeparator`) with `next/link` via `asChild`. `PageHeader` `segments` prop now accepts `string | { label, href? }`. `HOPPER-RECON` → `/dashboard`; `HISTORY` on detail routes → `/history`; leaf segments render as `BreadcrumbPage`. Was previously hand-rolled `<span>`s with zero links.
- [x] **Right-side overflow fix** — `min-w-0` on `SidebarInset` (`app/(app)/layout.tsx`), `grid-cols-[300px_minmax(0,1fr)]` + `min-w-0` on inner cols on the dashboard's results grid, `[&>*]:min-w-0` on `history/[domain]` panels grid. Without these, intrinsic content width (long URLs, recharts SVGs, JARM hashes) pushed the page past the viewport.
- [x] **Globe colors** retuned (`components/recon/geo-globe.tsx`) — `baseColor 0.07 → 0.18` so the sphere reads above `--card`; markers now `[0.40, 0.92, 0.45]` (≈ `--terminal-green`) per the green-as-signal rule; faint phosphor edge glow added; `mapBrightness 7 → 9` for legible continents. sRGB ↔ oklch token mapping written into the file as a comment.
- [x] CLAUDE.md gets a new "UI conventions" section documenting these load-bearing patterns; "Adding a tool" checklist gets a step 6 covering attribution (ToolSourceLink + about-page entry).

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

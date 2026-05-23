# Hopper Recon — agent guide

Two-part project: a Next.js 16 web app in `web/` and a Go engine in `engine/` (containerised as `hopper-recon:latest`).

## Architecture (v0.2)

The engine is a long-running HTTP server that owns SQLite at `/data/scans.db` and runs the recon binaries directly. The web app is a thin client over HTTP — it does **not** spawn Docker per scan and does **not** mount the Docker socket. A pair of Litestream sidecars handle DR.

```
host                                 docker compose
─────                                ──────────────
~/.config/subfinder/    ─── rw ───▶  engine container
~/.config/hopper-recon/ ─── ro ───▶    │
                                       │  /data/scans.db (SQLite, named volume engine-data)
                                       │  :8080 internal — REST + MCP at /mcp
                                       ▼
       127.0.0.1:9119 ◀── port-bind ── exposed to host (loopback only)
                                       ▲           ▲
                                       │           │  reads /data, writes WAL → replica
                                       │           │
                                       │           litestream sidecar (replicate)
                                       │           litestream-restore (one-shot init)
                                       │              ↓
                                       │           litestream-backup volume (default)
                                       │           or S3 / R2 / Azure / GCS (configured)
                                       │
                                       │  HTTP (REST)
                       web container ──┘
                       :9120 → host
```

The host binds engine port `9119` (off the well-known 8080) for AI clients (Claude Code, Cline, etc.) to connect to MCP at `http://127.0.0.1:9119/mcp`.

The engine has two modes:
- `hopper-recon serve` — long-running HTTP server (compose default)
- `hopper-recon mcp` (or `hopper-recon` no args) — stdio MCP transport for AI agents that prefer one-shot containers

## Persistence (Litestream)

Two sidecars in `docker-compose.yml` replicate `/data/scans.db` continuously:

- `litestream-restore` — one-shot init with `depends_on: condition: service_completed_successfully` on the engine. Runs `litestream restore -if-replica-exists -if-db-not-exists`, so it's idempotent: a no-op when the local DB is already there or when no replica is configured.
- `litestream` — long-running sidecar that reads the WAL via the shared `engine-data` volume and streams frames to the replica. The engine doesn't know it exists; WAL mode (already on in `engine/db.go`) is all it needs.

`litestream.yml` at the repo root is the single source of truth for replica config. The default is a `file` replica into the `litestream-backup` named volume — works with zero credentials so `docker compose up` is self-contained for dev. Cloud replica blocks (R2, S3, Azure Blob, GCS) are pre-written and commented; uncomment one and supply matching env vars in a `.env` next to compose. Both sidecars load that `.env` (`required: false`, so its absence is fine).

When changing replica targets, only edit `litestream.yml` — the compose file does not need to change.

## Next.js (web/)

This is **not** the Next.js you know — version 16 has breaking changes from prior majors. Before writing code in `web/`, read the relevant guide in `web/node_modules/next/dist/docs/`. Heed deprecation notices.

**Run before declaring work done:**

- `npx tsc --noEmit` — type-check (must pass clean; do not silence with `any` or `@ts-ignore`)
- `npm run lint` — eslint (fix warnings rather than disabling rules)

For multi-file refactors, run both. For a single small edit, lint alone is fine. If a dependency changes, run `npm install` and commit `package-lock.json`.

No Prettier config exists — match the surrounding file's style (indentation, quote style, trailing commas) rather than reformatting unrelated code.

`web/src/lib/engine-client.ts` is the only place the web reads from / writes to the engine. `web/src/lib/db.ts` keeps an `EngineDBAdapter` (default) and a `D1Adapter` (Cloudflare auto-detect) — there is no longer a SQLite path on the web side.

## Go engine (engine/)

**Run before declaring work done:**

- `gofmt -w .` (or `go fmt ./...`) — canonical formatting; never commit unformatted Go
- `go vet ./...` — catches shadowed vars, lock copies
- `go build ./...` — must compile clean
- `go test ./...` — full unit test suite; must pass with zero external deps (no Docker, no network, no binaries)
- `go mod tidy` — after adding/removing imports; commit the resulting `go.mod` and `go.sum`

Use `go doc <pkg>` / `go doc <pkg>.<Symbol>` to inspect external API shapes before guessing — the MCP SDK and projectdiscovery tools have surprising signatures.

The engine runs inside Docker. After Go changes, rebuild the image: `docker compose build engine` (or `cd engine && docker build -t hopper-recon:latest .`).

**Logging:** the engine uses `log/slog` with a JSON handler (set in `main()` via `slog.SetDefault`). Add new log lines with `slog.Info` / `slog.Warn` / `slog.Error` and key-value pairs, not `log.Printf` format strings.

**Test suite** (`engine/*_test.go`, all `package main`):
- `policy_test.go` — `Policy.Check`, `inScope`, `LoadPolicy`
- `db_test.go` — full SQL round-trips on `:memory:` SQLite; helper `newTestDB(t)` available
- `tools_test.go` — subprocess output stubbed via `var execJSONL = runJSONL` (swap in tests via `withExecJSONL`)
- `server_test.go` — HTTP handlers via `httptest`; tool dispatch stubbed via `var toolRunner = runTool` (swap via `withToolRunner`); policy helpers `plainPolicy()` / `scopedPolicy(domains...)` available
- `integration_test.go` — `//go:build integration`; requires real binaries inside Docker; run with `go test -tags integration ./...`

File layout:
- `engine/main.go` — entrypoint, mode dispatch, MCP tool registration
- `engine/tools.go` — pure recon-binary runners (subfinder/dnsx/tlsx/httpx/cdncheck/urlfinder/geoip). dnsx queries both `-a` and `-aaaa` so IPv6-prominent hosts contribute to geo lookups. urlfinder takes `-jsonl` (its own flag), not the `-json` other PD tools accept.
- `engine/db.go` — SQLite open + queries (WAL mode — load-bearing for Litestream)
- `engine/server.go` — HTTP REST handlers + `/mcp` mount

## Adding a tool

1. Add a `Run<Name>` function in `engine/tools.go` that returns `[]string` (raw JSONL lines).
2. Add a thin `handle<Name>` in `engine/main.go` for MCP, plus the `mcp.AddTool` call in `buildMCPServer()`.
3. Add a `case "<name>":` in `runTool` in `engine/server.go` so REST `/scan` can dispatch it.
4. If a binary is required, add the `RUN go install …` and `COPY --from=builder /go/bin/<bin> /usr/local/bin/<bin>` lines in `engine/Dockerfile` (and the chmod line).
5. Add tests in `engine/tools_test.go`: use `withExecJSONL` to stub subprocess output and test JSONL parsing + any merge logic. Add handler tests in `engine/server_test.go` for the new `runTool` dispatch case. Run `go test ./...` clean before moving on.
6. On the web side, add the tool name to `VALID_TOOLS` in `web/src/app/api/scan/route.ts`, write a parser in `web/src/lib/scan-parser.ts` (consume the flat parsed-object array — no JSONL re-parsing), and surface a tab/panel on dashboard + history pages.
7. Surface attribution: attach a `ToolSourceLink` to the tool's main result Panel on the dashboard (passes the link into the Panel's `action` slot), and add an entry to `RECON_TOOLS` in `web/src/app/(app)/about/page.tsx` so the `/about` credits page lists it.
8. Rebuild the image (`docker compose build engine`) and recreate the container (`docker compose up -d --force-recreate engine`).

## Tool admission policy

Tools that **require** auth to function are rejected — `asnmap` (PDCP API key) and `uncover` (Shodan/Censys/FOFA keys) were removed in v0.2. `subfinder` runs without keys (degraded source coverage) so it stays. The bar for new tools: must produce useful output for an unconfigured first-time user; auth keys can be optional enrichment but never required.

Currently in: `passive_subdomains`, `resolve_dns`, `fetch_tls_cert`, `probe_http`, `check_cdn`, `find_urls`, `expand_subdomains` (7 scan tools) + `lookup_geoip` (enrichment-only — called on demand for IP→country, not a scan tab). Before adding another scan tool, run `<binary> -h | grep -i 'auth\|api.key\|token'`; if the help mentions any of those terms, the tool fails admission unless the key is genuinely optional.

## UI conventions (web/)

A few patterns are load-bearing — breaking them creates regressions that show up only at narrow viewports, on detail routes, or after a restart.

- **Breadcrumbs.** `PageHeader` (`components/recon/page-header.tsx`) wraps shadcn's `Breadcrumb` primitives. The `segments` prop accepts plain strings (rendered inert) or `{ label, href }` objects (rendered as `next/link` via `BreadcrumbLink asChild`). Always pass an `href` on non-leaf segments so users can navigate back; the last segment is auto-rendered as `BreadcrumbPage` regardless of href. The leading `HOPPER-RECON` always links to `/dashboard`.
- **Tool source links.** Each per-tool result Panel exposes its upstream binary via `ToolSourceLink` (`components/recon/tool-source-link.tsx`) in the panel's `action` slot — renders as `via subfinder ↗`. New tools should attach one to their main result panel; same component is reusable on history detail panels.
- **Layout overflow.** The main column needs `min-w-0` and any grid holding tables / charts / long URLs needs `minmax(0, 1fr)` columns or `[&>*]:min-w-0` on the container. Without these, intrinsic content width pushes the page past the viewport on the right. Three load-bearing spots: `app/(app)/layout.tsx` (SidebarInset), `app/(app)/dashboard/page.tsx` (results grid), `app/(app)/history/[domain]/page.tsx` (panels grid). When adding a page with tables or recharts, audit for the same — the shadcn block demos don't expose the issue because their content is aspect-ratio boxes.
- **Credits page.** `/about` (`app/(app)/about/page.tsx`) lists tools and notable libraries grouped: `RECON_TOOLS` / `ENGINE` / `WEB` / `DATA`. New recon tools and notable runtime deps should land here with their GitHub link.

## General

- TODO.md at the project root is the source of truth for outstanding work.
- The dashboard reaches the engine over HTTP (`ENGINE_URL`, default `http://127.0.0.1:9119` for `npm run dev`, `http://engine:8080` inside compose).
- Schema lives in `engine/db.go` (canonical). `web/schema.sql` mirrors it for the Cloudflare D1 path; keep them in sync when changing columns.
- `web/data/recon.db` from v0.1 is abandoned — engine owns the DB now.
- WAL mode in `engine/db.go` is required by Litestream — don't switch to `journal_mode=DELETE` or `MEMORY` without removing the litestream services from compose.

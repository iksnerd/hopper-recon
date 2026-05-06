# Hopper Recon — agent guide

Two-part project: a Next.js 16 web app in `web/` and a Go MCP engine in `engine/` (containerised as `hopper-recon:latest`).

## Next.js (web/)

This is **not** the Next.js you know — version 16 has breaking changes from prior majors. Before writing code in `web/`, read the relevant guide in `web/node_modules/next/dist/docs/`. Heed deprecation notices.

**Run before declaring work done:**

- `npx tsc --noEmit` — type-check (must pass clean; do not silence with `any` or `@ts-ignore`)
- `npm run lint` — eslint (fix warnings rather than disabling rules)

For multi-file refactors, run both. For a single small edit, lint alone is fine. If a dependency changes, run `npm install` and commit `package-lock.json`.

No Prettier config exists — match the surrounding file's style (indentation, quote style, trailing commas) rather than reformatting unrelated code.

## Go engine (engine/)

**Run before declaring work done:**

- `gofmt -w .` (or `go fmt ./...`) — canonical formatting; never commit unformatted Go
- `go vet ./...` — catches shadowed vars, printf misuse, lock copies
- `go build ./...` — must compile clean
- `go mod tidy` — after adding/removing imports; commit the resulting `go.mod` and `go.sum`

Use `go doc <pkg>` / `go doc <pkg>.<Symbol>` to inspect external API shapes before guessing — the MCP SDK and projectdiscovery tools have surprising signatures.

The engine binary runs inside Docker. After Go changes, rebuild the image: `cd engine && docker build -t hopper-recon:latest .`

## General

- The web app calls the engine over MCP via `docker run --rm -i hopper-recon:latest`. Changes to the Go tool list (e.g. adding `asnmap`) require updating both sides: `engine/main.go` (handler + registration) and `web/src/lib/docker-mcp.ts` (`McpTool` union) plus the scan route's `VALID_TOOLS`.
- SQLite is the local-dev database (`web/data/recon.db`). Cloudflare D1 is the production target. Schema lives in two places — `web/schema.sql` (for D1) and inline in `web/src/lib/db.ts` (for SQLite); keep them in sync.
- `TODO.md` at the project root is the source of truth for outstanding work.

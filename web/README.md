# web — Next.js 16 dashboard

Thin HTTP client over the engine. The engine owns SQLite + the recon
binaries; this is just rendering. See the root [`README.md`](../README.md)
for what the project does and the root [`CLAUDE.md`](../CLAUDE.md) for the
agent-facing guide.

## Run

In compose (preferred — engine + Litestream sidecars come along for the ride):

```bash
cd .. && docker compose up -d --build
# Dashboard at http://localhost:9120
```

Outside compose, against a host-bound engine:

```bash
docker compose up -d engine        # engine on 127.0.0.1:9119
npm install
npm run dev                        # http://localhost:9120
```

`ENGINE_URL` defaults to `http://127.0.0.1:9119` for local dev and is set
to `http://engine:8080` in compose via the compose file.

### Without an engine (mock data)

For UI work you usually don't want Docker, the recon binaries, or to put real
traffic on the internet:

```bash
npm run dev:mock                   # Next on :9120 + mock engine on :9119
```

`mocks/engine.mjs` speaks the same REST surface as `engine/server.go`, so
nothing in `src/` knows the difference — the app talks to it over real HTTP and
every code path stays production-shaped. It refuses to start under
`NODE_ENV=production`, and `mocks/` is excluded from the Docker build context,
so it cannot reach a deployed image.

| | |
|---|---|
| 8 fixture domains | `cloudflare.com`, `example.com`, `github.com`, `iana.org`, `linear.app`, `vercel.com`, … |
| any other target | synthesised deterministically from the name |
| `huge.test` | ~23.5k subdomains, for testing `HostList` and list perf |
| `MOCK_FAIL=probe_http,find_urls` | force per-tool failures to exercise error states |
| `MOCK_LATENCY_MS=0` | remove the fake latency (default 400ms, so loading states are visible) |

Fixtures in `mocks/fixtures/` are **real captured engine output**, deduped to
the newest row per (domain, tool) and capped at 500 entries each to keep the
repo small — so counts read lower than a real scan of the same domain, and the
category distribution is flatter than the real long tail. Don't calibrate
distribution-sensitive UI (the subdomain category chart) against mock data.

**Adding a scan tool means updating the mock too** — a `case` in `synthesise()`
and an entry in its `TOOLS` array. `src/lib/__tests__/mock-engine.test.ts`
fails the build if you forget. Match the engine's real output shape, not the
upstream binary's: the engine normalises some fields (subfinder's `source`
string becomes a `sources` array; httpx `cpe` entries are objects, not strings).
Capture a real row and copy its shape rather than guessing.

## Pre-commit

```bash
npx tsc --noEmit
npm run lint
npm test
```

## Layout pointers

- `src/app/` — App Router pages + API routes (proxies to engine)
- `src/lib/engine-client.ts` — the only place the web reads from / writes to the engine
- `src/lib/db.ts` — `EngineDBAdapter` (default) + `D1Adapter` (Cloudflare detect)
- `src/lib/scan-parser.ts` — turns engine results into the dashboard's view types
- `src/components/recon/` — `ReconCard`, `Panel`, `PageHeader`, `OperatorWarningBanner`, etc.

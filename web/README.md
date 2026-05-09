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

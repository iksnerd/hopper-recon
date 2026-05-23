# Deployment guide

Self-hosted hopper-recon runs as two containers (engine + web) plus two Litestream sidecars. The reference stack is `docker compose` on a single VM, but the primitives translate cleanly to any container runtime.

> **Auth posture:** hopper-recon ships with **no built-in authentication**. Put it behind a VPN, Tailscale, Cloudflare Access, or `oauth2-proxy` before exposing it to any network you don't control. Auth is on the roadmap; the operator advisory banner in the UI will remind you when neither scope nor auth is configured.

---

## Quick start (dev / evaluation)

```bash
git clone https://github.com/iksnerd/hopper-recon
cd hopper-recon

# Optional: drop in a GeoLite2 mmdb so the geo-globe renders
mkdir -p ~/.config/hopper-recon
curl -L https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb \
     -o ~/.config/hopper-recon/GeoLite2-Country.mmdb

docker compose up -d --build

# Dashboard → http://localhost:9120
# Engine REST + MCP → http://127.0.0.1:9119  (loopback only)
```

---

## Environment variables

Copy `.env.example` to `.env` next to `docker-compose.yml`. The compose file loads it via `env_file` with `required: false` — an absent `.env` is fine in dev.

| Variable | Default | Secret? | Purpose |
|---|---|---|---|
| `HOPPER_ADDR` | `:8080` | no | Engine HTTP listen address inside the container |
| `HOPPER_DB_PATH` | `/data/scans.db` | no | SQLite path inside the engine container |
| `ENGINE_URL` | `http://127.0.0.1:9119` (dev) / `http://engine:8080` (compose) | no | Where the web container reaches the engine |
| `HOPPER_ALLOWED_DOMAINS` | _(unset)_ | no | Comma-separated apex list. Off-scope targets return 403. Unset = scan anything (advisory banner shown). |
| `HOPPER_OVERRIDE_BLOCKLIST` | _(unset)_ | no | Set `true` (with `HOPPER_BLOCKLIST_OVERRIDE_REASON`) to allow `.gov`/`.mil` probes. Audit-logged. |
| `HOPPER_BLOCKLIST_OVERRIDE_REASON` | _(unset)_ | no | Free-text reason recorded in `audit_log`. Both vars must be non-empty to take effect. |
| `LITESTREAM_BUCKET` | _(unset)_ | no | S3 / R2 bucket name for cloud WAL replication |
| `LITESTREAM_ACCESS_KEY_ID` | _(unset)_ | **yes** | S3 / R2 access key |
| `LITESTREAM_SECRET_ACCESS_KEY` | _(unset)_ | **yes** | S3 / R2 secret key |
| `R2_ACCOUNT_ID` | _(unset)_ | no | Cloudflare account ID (R2 only) |
| `AWS_REGION` | _(unset)_ | no | AWS region (S3 only) |
| `AZURE_STORAGE_ACCOUNT` | _(unset)_ | no | Azure storage account name |
| `AZURE_STORAGE_KEY` | _(unset)_ | **yes** | Azure storage key |

---

## Ports

| Port | Bound to | Purpose |
|---|---|---|
| `9120` | `0.0.0.0` | Web dashboard (Next.js) |
| `9119` | `127.0.0.1` | Engine REST API + MCP (loopback only) |
| `8080` | internal only | Engine inside the compose network |

The engine is intentionally loopback-only on the host. To expose the MCP endpoint to remote AI clients, put a reverse proxy in front with TLS + authentication.

---

## Volumes

| Name | Contents | Persistence required? |
|---|---|---|
| `engine-data` | `/data/scans.db` — SQLite database | **Yes** — loss = loss of all scan history |
| `litestream-backup` | Local WAL replica (default) | Recommended — provides local point-in-time recovery |

The engine container also mounts two host directories read-only:

| Host path | Mount | Purpose |
|---|---|---|
| `~/.config/subfinder/` | `/root/.config/subfinder` (rw) | Subfinder API keys (optional enrichment) |
| `~/.config/hopper-recon/` | `/root/.config/hopper-recon` (ro) | `GeoLite2-Country.mmdb` (optional) |

---

## Resource expectations

| State | RAM | CPU |
|---|---|---|
| Idle | ~250 MiB | ~100m |
| During scan | ~700 MiB peak | ~1 vCPU |

A Hetzner CX11 (2 vCPU, 2 GB RAM, €3.79/mo) or equivalent is sufficient for a single operator.

---

## Production topology (single VM)

```
internet
  │
  ▼
nginx / Caddy  (TLS termination, optional oauth2-proxy / Cloudflare Access)
  │
  ▼
web :9120      (Next.js dashboard)
  │  HTTP
  ▼
engine :8080   (Go REST + MCP — compose network only)
  │
  ├── /data/scans.db  (named volume)
  └── Litestream sidecars  ──▶  S3 / R2 / Azure / GCS  (optional)
```

### Caddy example

```caddyfile
recon.example.com {
    reverse_proxy localhost:9120
}
```

Add authentication before this if the host is internet-facing.

---

## Persistence & backups (Litestream)

The compose stack includes two Litestream sidecars that continuously replicate `/data/scans.db`:

- `litestream-restore` — runs once at startup. If a replica exists and the local DB is missing (fresh disk), it pulls the latest snapshot back. Otherwise a no-op.
- `litestream` — long-running sidecar streaming WAL frames to the replica.

**Default (dev / zero config):** WAL frames replicate to the `litestream-backup` named volume on the same host. Recovery from accidental `docker volume rm`: restore from the backup volume. Not real DR (same disk).

**Cloud DR:** Open `litestream.yml`, comment out the `type: file` block, uncomment one of the cloud blocks (R2, S3, Azure, GCS), then add the matching keys to `.env`:

```bash
# .env — Cloudflare R2 example
LITESTREAM_BUCKET=hopper-recon-scans
LITESTREAM_ACCESS_KEY_ID=...
LITESTREAM_SECRET_ACCESS_KEY=...
R2_ACCOUNT_ID=...
```

`docker compose up -d` — both sidecars pick up the env file automatically.

**Manual backup:**

```bash
sqlite3 /data/scans.db ".backup /backup/scans-$(date +%F).db"
# Or via docker exec:
docker exec hopper-recon-engine-1 sqlite3 /data/scans.db ".backup /tmp/scans-backup.db"
docker cp hopper-recon-engine-1:/tmp/scans-backup.db ./scans-backup.db
```

**Restore from Litestream on a new host:**

```bash
docker run --rm \
  -v hopper-recon_engine-data:/data \
  -v ./litestream.yml:/etc/litestream.yml:ro \
  --env-file .env \
  litestream/litestream:0.3.13 restore /data/scans.db
```

---

## Upgrade

```bash
git pull
docker compose build
docker compose up -d
```

Schema migrations run automatically on engine boot (`CREATE TABLE IF NOT EXISTS` + `ALTER TABLE` ladder in `engine/db.go`). No manual migration steps required for patch and minor upgrades. Breaking schema changes will be called out in the CHANGELOG.

---

## Kubernetes

Derive a Deployment from `docker-compose.yml` to fit your existing patterns. Key translation notes:

- Engine + Litestream share a volume → use a single Pod with two containers sharing an `emptyDir` or `PersistentVolumeClaim`.
- `HOPPER_ALLOWED_DOMAINS` → `ConfigMap`; `LITESTREAM_ACCESS_KEY_ID` / `SECRET` → `Secret`.
- Engine loopback bind (`:9119`) doesn't apply inside a Pod — containers in the same Pod communicate via `localhost` already; remove the port-bind restriction.
- Web → engine: `ENGINE_URL=http://localhost:8080` (same Pod) or `http://engine-svc:8080` (separate Pod + Service).

See [`docs/v0.1.0-prod-deploy-plan.md`](docs/v0.1.0-prod-deploy-plan.md) for the rationale behind not shipping a Helm chart.

---

## Security hardening checklist

- [ ] Put web behind a reverse proxy with TLS
- [ ] Add authentication (oauth2-proxy, Cloudflare Access, Tailscale) before exposing to any non-local network
- [ ] Set `HOPPER_ALLOWED_DOMAINS` to restrict scanning to authorized targets
- [ ] Point Litestream at a cloud replica for real DR
- [ ] Rotate subfinder API keys if shared across environments
- [ ] Review `audit_log` periodically: `sqlite3 /data/scans.db 'SELECT * FROM audit_log ORDER BY ts DESC LIMIT 50'`

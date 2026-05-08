import type { D1Database } from "@cloudflare/workers-types"
import { engineClient } from "./engine-client"

export interface ScanRow {
  id: string
  domain: string
  tool: string
  status: "pending" | "completed" | "failed"
  results_json: string | null
  error: string | null
  started_at: string
  completed_at: string | null
  http_status: number | null
  cert_expiry: string | null
  tech_stack: string | null
}

export interface ScanMeta {
  http_status?: number
  cert_expiry?: string
  tech_stack?: string
}

export interface GeoipRow {
  ip: string
  country: string
}

// Reads-only adapter. Writes go through the engine's transactional /scan
// endpoint (see engineClient.runScan), so insertScan/completeScan/failScan
// aren't part of the surface — they were only needed when the web owned the
// scan lifecycle. Kept here for the D1 path until the SaaS engine refactor
// lands.
export interface DbAdapter {
  deleteScan(id: string): Promise<void>
  sweepStaleScans(olderThanMinutes?: number): Promise<void>
  getRecentScans(limit?: number): Promise<ScanRow[]>
  getScansByDomain(domain: string): Promise<ScanRow[]>
  getCachedGeoip(ips: string[]): Promise<GeoipRow[]>
}

// ── Engine (self-hosted, default) ─────────────────────────────────────────────

function createEngineAdapter(): DbAdapter {
  return {
    deleteScan: (id) => engineClient.deleteScan(id),
    // Engine sweeps on boot; the dashboard's per-page sweep is now a no-op.
    sweepStaleScans: () => Promise.resolve(),
    getRecentScans: (limit = 50) => engineClient.listScans(undefined, limit),
    getScansByDomain: (domain) => engineClient.listScans(domain),
    getCachedGeoip: (ips) => engineClient.geoipLookup(ips),
  }
}

// ── D1 (Cloudflare) ───────────────────────────────────────────────────────────

function createD1Adapter(d1: D1Database): DbAdapter {
  return {
    deleteScan: (id) =>
      d1.prepare("DELETE FROM scans WHERE id=?").bind(id).run().then(() => undefined),

    sweepStaleScans: (olderThanMinutes = 2) =>
      d1.prepare(
        "UPDATE scans SET status='failed', error='scan interrupted', completed_at=CURRENT_TIMESTAMP WHERE status='pending' AND started_at < datetime('now', ?)"
      ).bind(`-${olderThanMinutes} minutes`).run().then(() => undefined),

    getRecentScans: async (limit = 50) => {
      const { results } = await d1.prepare("SELECT * FROM scans ORDER BY started_at DESC LIMIT ?")
        .bind(limit).all<ScanRow>()
      return results
    },

    getScansByDomain: async (domain) => {
      const { results } = await d1.prepare("SELECT * FROM scans WHERE domain=? ORDER BY started_at DESC")
        .bind(domain).all<ScanRow>()
      return results
    },

    getCachedGeoip: async (ips) => {
      if (ips.length === 0) return []
      const placeholders = ips.map(() => "?").join(",")
      const { results } = await d1.prepare(`SELECT ip, country FROM geoip_cache WHERE ip IN (${placeholders})`)
        .bind(...ips).all<GeoipRow>()
      return results
    },
  }
}

// ── Factory — D1 when running on Cloudflare, otherwise the engine ────────────

export async function getDb(): Promise<DbAdapter> {
  try {
    const { getCloudflareContext } = await import("@opennextjs/cloudflare")
    const { env } = await getCloudflareContext()
    if (env.DB) return createD1Adapter(env.DB as unknown as D1Database)
  } catch {
    // Not on Cloudflare — fall through to engine.
  }
  return createEngineAdapter()
}

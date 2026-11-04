// Thin HTTP client for the long-running engine. Replaces the docker-spawn
// executor — web no longer needs the docker socket.
//
// ENGINE_URL is set explicitly in docker-compose.yml to http://engine:8080
// (compose-network DNS). When unset (e.g. `npm run dev` against the
// host-exposed engine), it falls back to http://127.0.0.1:9119, the loopback
// port the compose engine binds for local MCP/dashboard clients.
import type { GeoipRow, ScanRow } from "./db"

export interface EngineConfig {
  version: string
  has_scope: boolean
  has_auth: boolean
  cooldown_s: number
  has_geo_db: boolean
  /**
   * subfinder source coverage. Each group is absent when the engine could not
   * look it up — absent means unknown, never "none". Names only, no keys.
   */
  subfinder_sources_total?: number
  subfinder_sources_keyless?: number
  subfinder_sources_key_required?: number
  subfinder_sources_optional_key?: number
  /** keyless + optional-key + key-required sources that have a key */
  subfinder_sources_active?: number
  subfinder_providers_configured?: string[]
}

const baseUrl = (process.env.ENGINE_URL ?? "http://127.0.0.1:9119").replace(/\/$/, "")

interface ScanRunResponse {
  id: string
  tool: string
  target: string
  status: "completed" | "failed"
  results?: unknown[]
  error?: string
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${baseUrl}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    cache: "no-store",
  })
  const text = await res.text()
  if (!res.ok) {
    throw new Error(`engine ${res.status}: ${text || res.statusText}`)
  }
  return text ? (JSON.parse(text) as T) : (undefined as T)
}

export const engineClient = {
  runScan: (tool: string, target: string) =>
    call<ScanRunResponse>("/scan", { method: "POST", body: JSON.stringify({ tool, target }) }),

  listScans: (domain?: string, limit?: number) => {
    const qs = new URLSearchParams()
    if (domain) qs.set("domain", domain)
    if (limit) qs.set("limit", String(limit))
    const suffix = qs.toString() ? `?${qs}` : ""
    return call<ScanRow[]>(`/scans${suffix}`)
  },

  deleteScan: (id: string) =>
    call<void>(`/scans/${encodeURIComponent(id)}`, { method: "DELETE" }),

  geoipLookup: (ips: string[]) => {
    if (ips.length === 0) return Promise.resolve<GeoipRow[]>([])
    const qs = encodeURIComponent(ips.join(","))
    return call<GeoipRow[]>(`/geoip?ips=${qs}`)
  },
}

export type { ScanRunResponse }

// Thin HTTP client for the long-running engine. Replaces the docker-spawn
// executor — web no longer needs the docker socket.
//
// ENGINE_URL is set explicitly in docker-compose.yml to http://engine:8080
// (compose-network DNS). When unset (e.g. `npm run dev` against the
// host-exposed engine), it falls back to http://127.0.0.1:9119, the loopback
// port the compose engine binds for local MCP/dashboard clients.
import type { GeoipRow, ScanRow } from "./db"

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

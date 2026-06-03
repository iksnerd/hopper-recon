// Proxies the engine's /config endpoint. Used by the first-boot warning
// banner to decide whether to nag operators about running unauth + no-scope.
import type { EngineConfig } from "@/lib/engine-client"

const baseUrl = (process.env.ENGINE_URL ?? "http://127.0.0.1:9119").replace(/\/$/, "")

export async function GET() {
  try {
    const res = await fetch(`${baseUrl}/config`, { cache: "no-store" })
    if (!res.ok) {
      return Response.json({ error: `engine ${res.status}` }, { status: 502 })
    }
    return Response.json((await res.json()) as EngineConfig)
  } catch {
    return Response.json({ error: "engine unreachable" }, { status: 502 })
  }
}

import { getDb } from "@/lib/db"
import type { GeoipRow } from "@/lib/db"
import { getExecutor } from "@/lib/executor"

export const runtime = "nodejs"

export async function POST(req: Request) {
  const { ips } = (await req.json()) as { ips: string[] }
  if (!Array.isArray(ips) || ips.length === 0) {
    return Response.json([])
  }

  // Cap and dedupe — keeps cache lookups bounded and avoids the engine doing
  // redundant work for IPs that appear on multiple subdomains of the same scan.
  const unique = [...new Set(ips)].slice(0, 100)

  try {
    const db = await getDb()
    const cached = await db.getCachedGeoip(unique)
    const cachedSet = new Set(cached.map((r) => r.ip))
    const misses = unique.filter((ip) => !cachedSet.has(ip))

    const fresh: GeoipRow[] = []
    if (misses.length > 0) {
      const executor = await getExecutor()
      const result = await executor.run("lookup_geoip", { ips: misses.join(",") })
      const raw = result.content.map((c) => c.text).join("\n")
      // The engine returns one structured-content JSON line per call.
      try {
        const parsed = JSON.parse(raw) as { results?: GeoipRow[] }
        if (Array.isArray(parsed.results)) fresh.push(...parsed.results)
      } catch {
        // Engine returned no parseable result (mmdb missing, container failure).
        // Fall through with whatever we have from cache.
      }
      if (fresh.length > 0) await db.upsertGeoip(fresh)
    }

    return Response.json([...cached, ...fresh])
  } catch {
    return Response.json([])
  }
}

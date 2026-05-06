import { getDb } from "@/lib/db"
import type { ScanRow } from "@/lib/db"

export interface DomainSummary {
  domain: string
  lastScanned: string
  scans: Record<string, ScanRow>   // tool → latest completed row
}

export async function GET() {
  const db = await getDb()
  await db.sweepStaleScans()
  const rows = await db.getRecentScans(500)

  // Group by domain, keep latest completed scan per tool
  const domainMap = new Map<string, DomainSummary>()

  for (const row of rows) {
    if (row.status !== "completed") continue

    let entry = domainMap.get(row.domain)
    if (!entry) {
      entry = { domain: row.domain, lastScanned: row.started_at, scans: {} }
      domainMap.set(row.domain, entry)
    }

    // rows are ordered DESC by started_at — first seen = most recent
    if (!entry.scans[row.tool]) {
      entry.scans[row.tool] = row
    }

    if (row.started_at > entry.lastScanned) {
      entry.lastScanned = row.started_at
    }
  }

  const result = Array.from(domainMap.values()).sort(
    (a, b) => new Date(b.lastScanned).getTime() - new Date(a.lastScanned).getTime()
  )

  return Response.json(result)
}

import type { DomainSummary } from "@/app/api/scans/domains/route"
import type { ScanRow } from "@/lib/db"

// Build a DomainSummary from raw rows (DESC order — first seen per tool = most recent)
export function buildSummary(rows: ScanRow[], domain: string): DomainSummary {
  const scans: Record<string, ScanRow> = {}
  let lastScanned = ""
  for (const row of rows) {
    if (row.status !== "completed") continue
    if (!scans[row.tool]) scans[row.tool] = row
    if (!lastScanned || row.started_at > lastScanned) lastScanned = row.started_at
  }
  return { domain, lastScanned, scans }
}

/** The decoded `results` of one scan row, or null if it has none or they are unreadable. */
export function rowResults(row: ScanRow | null | undefined): unknown {
  if (!row?.results_json) return null
  try { return JSON.parse(row.results_json) } catch { return null }
}

/** The decoded `results` array of a tool's latest completed scan, or null if it never ran or is unreadable. */
export function toolResults(summary: DomainSummary | null, tool: string): unknown {
  return rowResults(summary?.scans[tool])
}

/**
 * The completed scan of `tool` before the latest one, or null. `rows` are newest
 * first, as the API returns them.
 */
export function previousCompleted(rows: ScanRow[], tool: string): ScanRow | null {
  return rows.filter((r) => r.status === "completed" && r.tool === tool)[1] ?? null
}

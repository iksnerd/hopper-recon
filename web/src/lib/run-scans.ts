// Runs the scans a report needs, one after another, through the dashboard's own
// /api/scan route (so the engine's policy gate and cooldown still apply).

/** Order matters only for how progress reads; the scans are independent. */
export const FULL_SCAN_TOOLS = ["resolve_dns", "fetch_tls_cert", "probe_http", "passive_subdomains", "find_domains", "find_lookalikes"] as const

export type ScanTool = (typeof FULL_SCAN_TOOLS)[number]

export interface ScanOutcome {
  tool: ScanTool
  ok: boolean
  error?: string
}

type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; body: string }) => Promise<{
  ok: boolean
  status: number
  json: () => Promise<unknown>
}>

/**
 * Scans `domain` with every tool in FULL_SCAN_TOOLS. A failing tool is recorded
 * and the rest still run, so one blocked or timed-out tool does not cost the
 * report the others. `onProgress` fires before each tool starts.
 */
export async function runFullScan(
  domain: string,
  onProgress: (tool: ScanTool, index: number, total: number) => void = () => {},
  fetchImpl: FetchLike = fetch,
): Promise<ScanOutcome[]> {
  const outcomes: ScanOutcome[] = []
  for (const [i, tool] of FULL_SCAN_TOOLS.entries()) {
    onProgress(tool, i, FULL_SCAN_TOOLS.length)
    try {
      const res = await fetchImpl("/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ tool, target: domain }),
      })
      const body = (await res.json().catch(() => ({}))) as { isError?: boolean; error?: string }
      if (res.ok && !body.isError) outcomes.push({ tool, ok: true })
      else outcomes.push({ tool, ok: false, error: body.error || `HTTP ${res.status}` })
    } catch (err) {
      outcomes.push({ tool, ok: false, error: err instanceof Error ? err.message : "request failed" })
    }
  }
  return outcomes
}

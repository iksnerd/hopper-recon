import { getDb } from "@/lib/db"
import type { ScanMeta } from "@/lib/db"
import { getExecutor } from "@/lib/executor"
import { randomUUID } from "crypto"

const VALID_TOOLS = ["passive_subdomains", "resolve_dns", "fetch_tls_cert", "probe_http", "map_asn", "search_hosts"] as const
type Tool = (typeof VALID_TOOLS)[number]

const DOMAIN_ARG_TOOLS: Tool[] = ["passive_subdomains", "map_asn", "search_hosts"]

function extractMeta(tool: Tool, parsed: unknown[]): ScanMeta {
  if (tool === "probe_http" && parsed.length) {
    const first = parsed[0] as { status_code?: number; tech?: string[] }
    return {
      http_status: first?.status_code,
      tech_stack: first?.tech?.length ? first.tech.join(",") : undefined,
    }
  }
  if (tool === "fetch_tls_cert" && parsed.length) {
    const first = parsed[0] as { not_after?: string }
    return { cert_expiry: first?.not_after }
  }
  return {}
}

export async function POST(req: Request) {
  const body = await req.json()
  const { tool, target } = body as { tool: Tool; target: string }

  if (!VALID_TOOLS.includes(tool)) {
    return Response.json({ error: "Invalid tool" }, { status: 400 })
  }
  if (!target || typeof target !== "string") {
    return Response.json({ error: "Missing target" }, { status: 400 })
  }

  const id = randomUUID()
  const arg: Record<string, string> = DOMAIN_ARG_TOOLS.includes(tool) ? { domain: target } : { target }

  try {
    const db = await getDb()
    await db.insertScan(id, target, tool)

    try {
      const executor = await getExecutor()
      const result = await executor.run(tool, arg)
      const raw = result.content.map((c) => c.text).join("\n")
      const parsed = raw.split("\n").filter(Boolean).map((l) => {
        try { return JSON.parse(l) } catch { return l }
      })

      const meta = extractMeta(tool, parsed)
      await db.completeScan(id, parsed, meta)
      await db.purgeOldScans(target)
      return Response.json({ id, tool, target, results: parsed, isError: result.isError ?? false })
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown error"
      await db.failScan(id, message).catch(() => undefined)
      return Response.json({ error: message }, { status: 500 })
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error"
    return Response.json({ error: message }, { status: 500 })
  }
}

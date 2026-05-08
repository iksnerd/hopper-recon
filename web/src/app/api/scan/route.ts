import { engineClient } from "@/lib/engine-client"

const VALID_TOOLS = [
  "passive_subdomains",
  "resolve_dns",
  "fetch_tls_cert",
  "probe_http",
  "check_cdn",
  "find_urls",
] as const
type Tool = (typeof VALID_TOOLS)[number]

export async function POST(req: Request) {
  const body = await req.json()
  const { tool, target } = body as { tool: Tool; target: string }

  if (!VALID_TOOLS.includes(tool)) {
    return Response.json({ error: "Invalid tool" }, { status: 400 })
  }
  if (!target || typeof target !== "string") {
    return Response.json({ error: "Missing target" }, { status: 400 })
  }

  try {
    const result = await engineClient.runScan(tool, target)
    return Response.json({
      id: result.id,
      tool: result.tool,
      target: result.target,
      results: result.results ?? [],
      isError: result.status === "failed",
      error: result.error,
    })
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error"
    return Response.json({ error: message }, { status: 502 })
  }
}

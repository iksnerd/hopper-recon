import { engineClient } from "@/lib/engine-client"

const VALID_TOOLS = [
  "passive_subdomains",
  "resolve_dns",
  "fetch_tls_cert",
  "probe_http",
  "check_cdn",
  "find_urls",
  "expand_subdomains",
] as const
type Tool = (typeof VALID_TOOLS)[number]

// Mirror the engine's authorized-use-only header on every proxy response so a
// reverse-proxy / CDN log identifies the tool even when the request never
// reaches the engine (validation failures, engine-unreachable 502s, etc.).
const HOPPER_HEADERS = { "X-Hopper-Recon": "authorized-use-only" } as const

export async function POST(req: Request) {
  const body = await req.json()
  const { tool, target } = body as { tool: Tool; target: string }

  if (!VALID_TOOLS.includes(tool)) {
    return Response.json({ error: "Invalid tool" }, { status: 400, headers: HOPPER_HEADERS })
  }
  if (!target || typeof target !== "string") {
    return Response.json({ error: "Missing target" }, { status: 400, headers: HOPPER_HEADERS })
  }

  try {
    const result = await engineClient.runScan(tool, target)
    return Response.json(
      {
        id: result.id,
        tool: result.tool,
        target: result.target,
        results: result.results ?? [],
        isError: result.status === "failed",
        error: result.error,
      },
      { headers: HOPPER_HEADERS },
    )
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error"
    return Response.json({ error: message }, { status: 502, headers: HOPPER_HEADERS })
  }
}

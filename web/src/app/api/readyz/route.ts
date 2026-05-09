// Readiness probe — engine is reachable.
//
// Hits the engine's own /readyz via the configured ENGINE_URL. A 200 here
// means the web can serve real requests; a 503 means orchestrators (k8s,
// compose health) should hold traffic off this replica.
const baseUrl = (process.env.ENGINE_URL ?? "http://127.0.0.1:9119").replace(/\/$/, "")

export async function GET() {
  try {
    const res = await fetch(`${baseUrl}/readyz`, { cache: "no-store" })
    if (!res.ok) {
      return new Response(`engine ${res.status}`, { status: 503 })
    }
    return new Response("ready", { status: 200, headers: { "Content-Type": "text/plain" } })
  } catch (err) {
    const msg = err instanceof Error ? err.message : "engine unreachable"
    return new Response(msg, { status: 503 })
  }
}

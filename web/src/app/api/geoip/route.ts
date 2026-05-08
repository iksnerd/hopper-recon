import { engineClient } from "@/lib/engine-client"

export const runtime = "nodejs"

export async function POST(req: Request) {
  const { ips } = (await req.json()) as { ips: string[] }
  if (!Array.isArray(ips) || ips.length === 0) {
    return Response.json([])
  }

  // Cap and dedupe — the engine also caps internally, but trimming here keeps
  // the URL bounded and avoids redundant work for IPs that appear on multiple
  // subdomains of the same scan.
  const unique = [...new Set(ips)].slice(0, 100)

  try {
    return Response.json(await engineClient.geoipLookup(unique))
  } catch {
    return Response.json([])
  }
}

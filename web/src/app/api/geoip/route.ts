export const runtime = "nodejs"

export async function POST(req: Request) {
  const { ips } = (await req.json()) as { ips: string[] }
  if (!Array.isArray(ips) || ips.length === 0) {
    return Response.json([])
  }

  // Deduplicate and cap at 100 (ip-api.com batch limit)
  const unique = [...new Set(ips)].slice(0, 100)

  try {
    const res = await fetch("http://ip-api.com/batch?fields=query,countryCode", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(unique.map((ip) => ({ query: ip }))),
    })
    if (!res.ok) return Response.json([])
    const data = (await res.json()) as Array<{ query: string; countryCode?: string }>
    return Response.json(
      data
        .filter((r) => r.countryCode && r.countryCode !== "XX")
        .map((r) => ({ ip: r.query, country: r.countryCode! }))
    )
  } catch {
    return Response.json([])
  }
}

import { getDb } from "@/lib/db"

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url)
  const domain = searchParams.get("domain")

  const db = await getDb()
  const rows = domain ? await db.getScansByDomain(domain) : await db.getRecentScans()
  return Response.json(rows)
}

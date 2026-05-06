import { getDb } from "@/lib/db"

export async function GET(_req: Request, { params }: { params: Promise<{ domain: string }> }) {
  const { domain } = await params
  const db = await getDb()
  return Response.json(await db.getScansByDomain(domain))
}

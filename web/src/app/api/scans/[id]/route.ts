import { getDb } from "@/lib/db"

export async function DELETE(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  const db = await getDb()
  await db.deleteScan(id)
  return new Response(null, { status: 204 })
}

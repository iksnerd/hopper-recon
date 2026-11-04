import { describe, it, expect } from "vitest"
import { runFullScan, FULL_SCAN_TOOLS } from "@/lib/run-scans"

const reply = (ok: boolean, status: number, body: unknown) => ({ ok, status, json: async () => body })

describe("runFullScan", () => {
  it("posts each tool for the domain, in order", async () => {
    const seen: { tool: string; target: string }[] = []
    const out = await runFullScan("example.com", undefined, async (url, init) => {
      expect(url).toBe("/api/scan")
      expect(init.method).toBe("POST")
      seen.push(JSON.parse(init.body))
      return reply(true, 200, { results: [] })
    })
    expect(seen.map((s) => s.tool)).toEqual([...FULL_SCAN_TOOLS])
    expect(seen.every((s) => s.target === "example.com")).toBe(true)
    expect(out.every((o) => o.ok)).toBe(true)
  })

  it("records a failing tool and still runs the rest", async () => {
    const out = await runFullScan("example.com", undefined, async (_u, init) => {
      const { tool } = JSON.parse(init.body)
      if (tool === "fetch_tls_cert") return reply(false, 429, { error: "cooldown: try again in 30s" })
      if (tool === "probe_http") throw new Error("network down")
      if (tool === "find_domains") return reply(true, 200, { isError: true, error: "tool failed" })
      return reply(true, 200, {})
    })
    expect(out).toHaveLength(FULL_SCAN_TOOLS.length)
    expect(out.find((o) => o.tool === "fetch_tls_cert")).toEqual({ tool: "fetch_tls_cert", ok: false, error: "cooldown: try again in 30s" })
    expect(out.find((o) => o.tool === "probe_http")).toEqual({ tool: "probe_http", ok: false, error: "network down" })
    expect(out.find((o) => o.tool === "find_domains")?.ok).toBe(false)
    expect(out.find((o) => o.tool === "resolve_dns")?.ok).toBe(true)
  })

  it("falls back to the HTTP status when the error body is not JSON", async () => {
    const out = await runFullScan("example.com", undefined, async () => ({ ok: false, status: 502, json: async () => { throw new Error("bad json") } }))
    expect(out[0]).toEqual({ tool: "resolve_dns", ok: false, error: "HTTP 502" })
  })

  it("reports progress before each tool", async () => {
    const steps: string[] = []
    await runFullScan("example.com", (tool, i, n) => steps.push(`${i + 1}/${n} ${tool}`), async () => reply(true, 200, {}))
    expect(steps[0]).toBe(`1/${FULL_SCAN_TOOLS.length} resolve_dns`)
    expect(steps).toHaveLength(FULL_SCAN_TOOLS.length)
  })
})

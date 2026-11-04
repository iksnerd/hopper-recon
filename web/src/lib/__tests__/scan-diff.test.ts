import { describe, it, expect } from "vitest"
import { parseDns } from "@/lib/scan-parser"
import { diffDns } from "@/lib/scan-diff"
import { previousCompleted } from "@/lib/domain-summary"
import type { ScanRow } from "@/lib/db"

const dns = (txt: string[], extra: Record<string, unknown> = {}) =>
  parseDns({ results: [{ host: "example.com", txt, mx: ["mx.example.com"], ns: ["ns1.example.net"], status_code: "NOERROR", ttl: 300, resolver: [], ...extra }] })!

const SPF = "v=spf1 include:_spf.example.net -all"
const BEFORE = [SPF, "v=DMARC1; p=none; rua=mailto:r@example.com;"]
const AFTER = [SPF, "v=DMARC1; p=quarantine; rua=mailto:r@example.com;"]

describe("diffDns", () => {
  it("shows the DMARC change and the finding it cleared", () => {
    const d = diffDns(dns(BEFORE), dns(AFTER))
    expect(d.changes).toEqual([{ label: "DMARC record", before: BEFORE[1], after: AFTER[1] }])
    expect(d.resolved.map((f) => f.id)).toEqual(["dmarc-none"])
    expect(d.appeared.map((f) => f.id)).toEqual(["dmarc-enforcing"])
  })

  it("reports no changes for identical scans", () => {
    expect(diffDns(dns(BEFORE), dns(BEFORE))).toEqual({ changes: [], resolved: [], appeared: [] })
  })

  it("is not fooled by a message that carries a count", () => {
    const keyed = (n: number) => dns([SPF, ...Array.from({ length: n }, () => `k=rsa; p=${"A".repeat(120)}`)])
    // DKIM count changes the record list, but the dkim-ok finding is the same one.
    const d = diffDns(keyed(1), keyed(3))
    expect(d.changes).toEqual([{ label: "DKIM keys", before: "1", after: "3" }])
    expect(d.resolved).toEqual([])
    expect(d.appeared).toEqual([])
  })

  it("flags a change in the other direction as a new finding", () => {
    const d = diffDns(dns(AFTER), dns(BEFORE))
    expect(d.appeared.map((f) => f.id)).toEqual(["dmarc-none"])
    expect(d.resolved.map((f) => f.id)).toEqual(["dmarc-enforcing"])
  })

  it("does not report findings about data only one scan carries", () => {
    const older = dns(BEFORE)
    const newer = dns(BEFORE, { caa: ["pki.goog"], mail_policy: { mta_sts: [], tls_rpt: [], bimi: [] }, spf_lookups: 12, spf_lookups_complete: true })
    const d = diffDns(older, newer)
    expect(d.appeared).toEqual([])
    expect(d.resolved).toEqual([])
    expect(d.changes).toEqual([])
  })

  it("does compare that data when both scans have it", () => {
    const mk = (caa: string[], lookups: number) => dns(BEFORE, { caa, mail_policy: { mta_sts: [], tls_rpt: [], bimi: [] }, spf_lookups: lookups, spf_lookups_complete: true })
    const d = diffDns(mk([], 12), mk(["pki.goog"], 4))
    expect(d.changes).toEqual([{ label: "CAA", before: "none", after: "pki.goog" }])
    expect(d.resolved.map((f) => f.id).sort()).toEqual(["caa-none", "spf-lookups-over"])
    expect(d.appeared.map((f) => f.id)).toEqual(["caa-ok"])
  })

  it("lists MX and NS changes", () => {
    const d = diffDns(dns(BEFORE), dns(BEFORE, { mx: ["other.example.com"], ns: ["ns2.example.net", "ns1.example.net"] }))
    expect(d.changes.map((c) => c.label)).toEqual(["Mail servers (MX)", "Name servers"])
    expect(d.changes[1].after).toBe("ns1.example.net, ns2.example.net")
  })
})

describe("previousCompleted", () => {
  const row = (id: string, tool: string, status: ScanRow["status"]) => ({ id, tool, status } as ScanRow)
  it("returns the second newest completed scan of the tool", () => {
    const rows = [row("a", "resolve_dns", "completed"), row("b", "probe_http", "completed"), row("c", "resolve_dns", "failed"), row("d", "resolve_dns", "completed")]
    expect(previousCompleted(rows, "resolve_dns")?.id).toBe("d")
  })
  it("is null with only one completed scan", () => {
    expect(previousCompleted([row("a", "resolve_dns", "completed")], "resolve_dns")).toBeNull()
  })
})

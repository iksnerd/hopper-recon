import { describe, it, expect } from "vitest"
import { assessRdap, daysUntil, daysLabel } from "@/lib/rdap"
import { parseRdap, type RdapResult } from "@/lib/scan-parser"
import { deriveFindings } from "@/components/recon/findings-strip"

const NOW = new Date("2026-11-04T12:00:00Z")
const inDays = (n: number) => new Date(NOW.getTime() + n * 86_400_000).toISOString()

const base = (over: Partial<RdapResult> = {}): RdapResult => ({
  domain: "example.com", registrar: "Example Registrar Inc.",
  registered: "2010-01-01T00:00:00Z", expires: inDays(400), last_changed: "2026-01-01T00:00:00Z",
  status: ["client transfer prohibited"], nameservers: ["ns1.example.net"], dnssec: true, server: "https://rdap.example/",
  ...over,
})

const run = (over: Partial<RdapResult> = {}) => assessRdap(base(over), NOW)
const find = (fs: ReturnType<typeof run>, re: RegExp) => fs.find((f) => re.test(f.message))

describe("daysUntil / daysLabel", () => {
  it("counts whole days and goes negative once passed", () => {
    expect(daysUntil(inDays(10), NOW)).toBe(10)
    expect(daysUntil(inDays(-3), NOW)).toBe(-3)
    expect(daysUntil(inDays(0.5), NOW)).toBe(0)
  })
  it("is null for a missing or unreadable date", () => {
    expect(daysUntil("", NOW)).toBeNull()
    expect(daysUntil(undefined, NOW)).toBeNull()
    expect(daysUntil("not a date", NOW)).toBeNull()
  })
  it("never prints a negative day count", () => {
    expect(daysLabel(412)).toBe("412d")
    expect(daysLabel(-3)).toBe("expired 3d ago")
  })
})

describe("expiry", () => {
  it("is a pass well ahead, with the date and registrar", () => {
    const f = find(run(), /Registered until/)!
    expect(f.severity).toBe("ok")
    expect(f.message).toMatch(/\(400 days\)/)
    expect(f.detail).toMatch(/Example Registrar Inc\./)
  })
  it("is a notice from 31 to 90 days and an issue at 30 or fewer", () => {
    expect(find(run({ expires: inDays(91) }), /Registered until/)!.severity).toBe("ok")
    expect(find(run({ expires: inDays(90) }), /expires in 90 days/)!.severity).toBe("info")
    expect(find(run({ expires: inDays(31) }), /expires in 31 days/)!.severity).toBe("info")
    expect(find(run({ expires: inDays(30) }), /expires in 30 days/)!.severity).toBe("issue")
    expect(find(run({ expires: inDays(1) }), /expires in 1 day$/)!.severity).toBe("issue")
  })
  it("says 'today' on the day, and 'expired' after it", () => {
    expect(find(run({ expires: inDays(0.5) }), /expires today/)!.severity).toBe("issue")
    const gone = find(run({ expires: inDays(-5) }), /expired 5 days ago/)!
    expect(gone.severity).toBe("issue")
    expect(gone.message).not.toMatch(/-/)
  })
  it("says nothing about expiry when the registry gives no date", () => {
    expect(run({ expires: "" }).some((f) => /expire|Registered until/.test(f.message))).toBe(false)
  })
})

describe("registry status", () => {
  it("flags hold, redemption and pending delete as issues", () => {
    for (const status of ["client hold", "server hold", "redemption period", "pending delete"]) {
      const f = find(run({ status: [status, "client transfer prohibited"] }), new RegExp(`status: ${status}`))
      expect(f?.severity, status).toBe("issue")
    }
  })
  it("does not flag ordinary statuses", () => {
    expect(run({ status: ["client transfer prohibited", "client update prohibited"] }).some((f) => /registry status/.test(f.message))).toBe(false)
  })
})

describe("transfer lock", () => {
  it("passes with a client or a server transfer lock", () => {
    expect(find(run({ status: ["client transfer prohibited"] }), /Transfer lock/)!.severity).toBe("ok")
    expect(find(run({ status: ["server transfer prohibited"] }), /Transfer lock/)!.severity).toBe("ok")
  })
  it("is a notice, not an issue, when the status lacks it, with the caveat that some registries do not publish it", () => {
    const f = find(run({ status: ["active"] }), /No transfer lock/)!
    expect(f.severity).toBe("info")
    expect(f.detail).toMatch(/Some registries do not publish/)
  })
  it("says nothing when no status was reported at all", () => {
    expect(run({ status: [] }).some((f) => /transfer lock/i.test(f.message))).toBe(false)
  })
})

describe("age and DNSSEC", () => {
  it("notes a registration in the last 30 days, not 31", () => {
    expect(find(run({ registered: inDays(-10) }), /registered 10 days ago/)!.severity).toBe("info")
    expect(find(run({ registered: inDays(-31) }), /was registered/)).toBeUndefined()
    expect(find(run({ registered: "" }), /was registered/)).toBeUndefined()
  })
  it("does not treat a future registration date as new", () => {
    expect(find(run({ registered: inDays(5) }), /was registered/)).toBeUndefined()
  })
  it("notes unsigned DNSSEC and is quiet when signed", () => {
    expect(find(run({ dnssec: false }), /DNSSEC is not enabled/)!.severity).toBe("info")
    expect(find(run({ dnssec: true }), /DNSSEC/)).toBeUndefined()
  })
})

describe("parseRdap", () => {
  it("reads the first record and fills missing fields", () => {
    expect(parseRdap({ results: [{ domain: "example.com", expires: "2027-01-01T00:00:00Z", dnssec: true }] })).toEqual({
      domain: "example.com", registrar: "", registered: "", expires: "2027-01-01T00:00:00Z", last_changed: "",
      status: [], nameservers: [], dnssec: true, server: "",
    })
  })
  it("is null without a record", () => {
    expect(parseRdap({ results: [] })).toBeNull()
    expect(parseRdap({ results: [{}] })).toBeNull()
    expect(parseRdap(null)).toBeNull()
  })
  it("reads dnssec as false unless it is exactly true", () => {
    expect(parseRdap({ results: [{ domain: "x.com", dnssec: "yes" }] })!.dnssec).toBe(false)
  })
})

describe("registration findings in the strip", () => {
  const derive = (rdap: RdapResult | null) => deriveFindings({ subs: null, dns: null, tls: null, http: null, rdap, now: NOW })
  it("says nothing when the registration was not looked up", () => {
    expect(derive(null)).toEqual([])
  })
  it("tags them REG and carries the explanation", () => {
    const f = derive(base({ expires: inDays(10) })).find((x) => /expires in 10 days/.test(x.message))!
    expect(f.source).toBe("REG")
    expect(f.severity).toBe("issue")
    expect(f.detail).toMatch(/auto-renew/)
  })
})

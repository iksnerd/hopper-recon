import { describe, it, expect } from "vitest"
import { deriveFindings } from "@/components/recon/findings-strip"
import { parseLookalikes } from "@/lib/scan-parser"

const run = (results: unknown[] | null) =>
  deriveFindings({ subs: null, dns: null, tls: null, http: null, lookalikes: results ? parseLookalikes({ results }) : null })

describe("lookalike findings", () => {
  it("says nothing when find_lookalikes has not run (null is unknown, not clean)", () => {
    expect(run(null)).toEqual([])
  })

  it("is an issue when a lookalike can receive mail, and names it", () => {
    const f = run([{ host: "exmple.com", kind: "omission", a: ["192.0.2.1"], mx: ["10 mail.exmple.com"] }])
    expect(f).toHaveLength(1)
    expect(f[0].severity).toBe("issue")
    expect(f[0].message).toMatch(/1 lookalike domain can receive mail: exmple\.com/)
  })

  it("is only a notice for web-only lookalikes", () => {
    const f = run([{ host: "example-login.com", kind: "keyword", a: ["192.0.2.2"] }])
    expect(f).toHaveLength(1)
    expect(f[0].severity).toBe("info")
    expect(f[0].message).toMatch(/1 lookalike domain resolves/)
  })

  it("reports both kinds separately and truncates long lists", () => {
    const mail = Array.from({ length: 5 }, (_, i) => ({ host: `m${i}.com`, kind: "omission", a: ["192.0.2.1"], mx: ["10 mx"] }))
    const f = run([...mail, { host: "w.com", kind: "keyword", a: ["192.0.2.2"] }])
    expect(f.map((x) => x.severity)).toEqual(["issue", "info"])
    expect(f[0].message).toMatch(/5 lookalike domains can receive mail: m0\.com, m1\.com, m2\.com and 2 more/)
  })

  it("is a pass only when it ran and found none", () => {
    const f = run([])
    expect(f).toHaveLength(1)
    expect(f[0].severity).toBe("ok")
  })
})

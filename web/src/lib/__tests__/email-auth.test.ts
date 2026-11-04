import { describe, it, expect } from "vitest"
import { parseEmailAuth, assessEmailAuth, assessCaa, emailBadges, suggestDmarc, dmarcEnforces, type EmailExtras } from "@/lib/email-auth"
import { parseDns } from "@/lib/scan-parser"

const KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8fcwXq7JaG6pwbT1RIQoeboUyymcjQoPU02Eblo1mdXVbdTL7WxYrMKw6uPH8u7SH7dlLKc1SgZYjQTAxfqLY9xEUJJ6YcLtNLnjYSByDvvn82jM9LknmpVsVESM48oFXDehEc1h6bB7USqk92IJJ6tUTo"

// Shape of a real scan: a hosted key without v=DKIM1 (CNAME to a mail provider),
// one with it, SPF softfail, DMARC monitor-only.
const MONITOR_ONLY = [
  "google-site-verification=abc",
  "v=spf1 include:_spf.google.com ~all",
  "v=DMARC1; p=none; rua=mailto:reports@example.com;",
  `k=rsa; t=s; p=${KEY}`,
  `v=DKIM1; k=rsa; p=${KEY}`,
  `k=rsa; t=s; p=${KEY}`,
]

const find = (txt: string[], area: string) => assessEmailAuth(parseEmailAuth(txt)).filter((f) => f.area === area)

describe("parseEmailAuth", () => {
  it("reads the policy tags from a monitor-only record", () => {
    const { dmarc, spf, dkim } = parseEmailAuth(MONITOR_ONLY)
    expect(dmarc).toMatchObject({ present: true, policy: "none", subPolicy: null, pct: 100, rua: ["mailto:reports@example.com"], adkim: "r", aspf: "r" })
    expect(spf).toMatchObject({ present: true, all: "~all", includes: ["_spf.google.com"] })
    expect(dkim.keys).toBe(3)
  })

  it("reads sp, pct, ruf and strict alignment", () => {
    const { dmarc } = parseEmailAuth(["v=DMARC1; p=Quarantine; sp=reject; pct=25; rua=mailto:a@x.com,mailto:b@x.com; ruf=mailto:f@x.com; adkim=s; aspf=S"])
    expect(dmarc).toMatchObject({ policy: "quarantine", subPolicy: "reject", pct: 25, ruf: ["mailto:f@x.com"], adkim: "s", aspf: "s" })
    expect(dmarc.rua).toEqual(["mailto:a@x.com", "mailto:b@x.com"])
  })

  it("clamps pct and falls back to 100 when it is not a number", () => {
    expect(parseEmailAuth(["v=DMARC1; p=reject; pct=250"]).dmarc.pct).toBe(100)
    expect(parseEmailAuth(["v=DMARC1; p=reject; pct=abc"]).dmarc.pct).toBe(100)
    expect(parseEmailAuth(["v=DMARC1; p=reject; pct=0"]).dmarc.pct).toBe(0)
  })

  it("treats an unknown p= value as no policy", () => {
    expect(parseEmailAuth(["v=DMARC1; p=block"]).dmarc.policy).toBeNull()
    expect(parseEmailAuth(["v=DMARC1; rua=mailto:a@x.com"]).dmarc.policy).toBeNull()
  })

  it("does not mistake a record that merely mentions DMARC for one", () => {
    expect(parseEmailAuth(["note: v=DMARC1; p=reject"]).dmarc.present).toBe(false)
    expect(parseEmailAuth(["include v=spf1 -all"]).spf.present).toBe(false)
  })

  it("flags duplicate SPF and DMARC records", () => {
    const e = parseEmailAuth(["v=spf1 -all", "v=spf1 ~all", "v=DMARC1; p=reject", "v=DMARC1; p=none"])
    expect(e.spf.multiple).toBe(true)
    expect(e.dmarc.multiple).toBe(true)
  })

  it("reads the SPF qualifier, including a bare all as +all", () => {
    expect(parseEmailAuth(["v=spf1 -all"]).spf.all).toBe("-all")
    expect(parseEmailAuth(["v=spf1 a mx ?all"]).spf.all).toBe("?all")
    expect(parseEmailAuth(["v=spf1 a all"]).spf.all).toBe("+all")
    expect(parseEmailAuth(["v=spf1 redirect=_spf.example.com"]).spf.all).toBeNull()
  })

  it("does not read 'all' inside a mechanism name as the terminator", () => {
    expect(parseEmailAuth(["v=spf1 include:mail.all.example.com -all"]).spf.all).toBe("-all")
    expect(parseEmailAuth(["v=spf1 include:small.example.com"]).spf.all).toBeNull()
  })

  it("does not count a DMARC or SPF record as a DKIM key", () => {
    expect(parseEmailAuth(["v=DMARC1; p=none; rua=mailto:x@example.com", "v=spf1 -all"]).dkim.keys).toBe(0)
  })
})

describe("assessEmailAuth", () => {
  it("calls p=none an issue, not a pass", () => {
    const [f] = find(MONITOR_ONLY, "DMARC")
    expect(f.severity).toBe("issue")
    expect(f.message).toMatch(/p=none/)
    expect(f.message).toMatch(/still delivered/)
  })

  it("does not call softfail SPF a pass", () => {
    const [f] = find(MONITOR_ONLY, "SPF")
    expect(f.severity).toBe("info")
    expect(f.message).toMatch(/softfail/)
  })

  it("passes an enforcing DMARC and a hard-fail SPF", () => {
    const txt = ["v=spf1 -all", "v=DMARC1; p=reject; rua=mailto:r@x.com"]
    expect(find(txt, "DMARC").map((f) => f.severity)).toEqual(["ok"])
    expect(find(txt, "SPF").map((f) => f.severity)).toEqual(["ok"])
  })

  it("notes a partial rollout", () => {
    const [f] = find(["v=DMARC1; p=quarantine; pct=25; rua=mailto:r@x.com"], "DMARC")
    expect(f.severity).toBe("info")
    expect(f.message).toMatch(/25%/)
  })

  it("flags missing records", () => {
    const e = assessEmailAuth(parseEmailAuth([]))
    expect(e.find((f) => f.area === "SPF")?.severity).toBe("issue")
    expect(e.find((f) => f.area === "DMARC")?.severity).toBe("issue")
    expect(e.find((f) => f.area === "DKIM")?.severity).toBe("info")
  })

  it("flags duplicate records as issues", () => {
    expect(find(["v=spf1 -all", "v=spf1 ~all"], "SPF")[0].severity).toBe("issue")
    expect(find(["v=DMARC1; p=reject", "v=DMARC1; p=none"], "DMARC")[0].severity).toBe("issue")
  })

  it("flags +all and ?all SPF", () => {
    expect(find(["v=spf1 +all"], "SPF")[0].severity).toBe("issue")
    expect(find(["v=spf1 ?all"], "SPF")[0].severity).toBe("issue")
  })

  it("reports a missing rua only when a usable DMARC record exists", () => {
    const has = (txt: string[]) => find(txt, "DMARC").some((f) => /rua/.test(f.message))
    expect(has(["v=DMARC1; p=reject"])).toBe(true)
    expect(has(["v=DMARC1; p=reject; rua=mailto:r@x.com"])).toBe(false)
    expect(has([])).toBe(false)
    expect(has(["v=DMARC1; p=bogus"])).toBe(false)
  })

  it("flags sp=none on an enforcing domain", () => {
    const f = find(["v=DMARC1; p=reject; sp=none; rua=mailto:r@x.com"], "DMARC")
    expect(f.some((x) => x.severity === "issue" && /sp=none/.test(x.message))).toBe(true)
  })

  it("words a DKIM miss as a limit of the scan, not proof of absence", () => {
    expect(find([], "DKIM")[0].message).toMatch(/common selectors/)
  })
})

describe("dmarcEnforces", () => {
  it("is false for none, missing, and pct=0", () => {
    expect(dmarcEnforces(parseEmailAuth(["v=DMARC1; p=none"]).dmarc)).toBe(false)
    expect(dmarcEnforces(parseEmailAuth([]).dmarc)).toBe(false)
    expect(dmarcEnforces(parseEmailAuth(["v=DMARC1; p=reject; pct=0"]).dmarc)).toBe(false)
  })
  it("is true for quarantine and reject", () => {
    expect(dmarcEnforces(parseEmailAuth(["v=DMARC1; p=quarantine"]).dmarc)).toBe(true)
    expect(dmarcEnforces(parseEmailAuth(["v=DMARC1; p=reject"]).dmarc)).toBe(true)
  })
})

describe("suggestDmarc", () => {
  it("moves p=none to quarantine and keeps the reporting address", () => {
    expect(suggestDmarc("example.com", parseEmailAuth(MONITOR_ONLY).dmarc))
      .toBe("v=DMARC1; p=quarantine; rua=mailto:reports@example.com;")
  })
  it("keeps strict alignment and subdomain policy, lifting sp=none too", () => {
    expect(suggestDmarc("example.com", parseEmailAuth(["v=DMARC1; p=none; sp=none; adkim=s; aspf=s; rua=mailto:r@x.com"]).dmarc))
      .toBe("v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:r@x.com; adkim=s; aspf=s;")
  })
  it("suggests a monitoring record when there is none", () => {
    expect(suggestDmarc("example.com", parseEmailAuth([]).dmarc)).toBe("v=DMARC1; p=none; rua=mailto:dmarc@example.com;")
  })
  it("drops pct so a partial rollout reaches 100", () => {
    expect(suggestDmarc("example.com", parseEmailAuth(["v=DMARC1; p=quarantine; pct=25; rua=mailto:r@x.com"]).dmarc))
      .toBe("v=DMARC1; p=quarantine; rua=mailto:r@x.com;")
  })
  it("has nothing to suggest for a full enforcing policy or for duplicates", () => {
    expect(suggestDmarc("example.com", parseEmailAuth(["v=DMARC1; p=reject"]).dmarc)).toBeNull()
    expect(suggestDmarc("example.com", parseEmailAuth(["v=DMARC1; p=none", "v=DMARC1; p=reject"]).dmarc)).toBeNull()
  })
})

describe("parseDns", () => {
  it("exposes the email analysis next to the legacy booleans", () => {
    const r = parseDns({ results: [{ host: "example.com", txt: MONITOR_ONLY, status_code: "NOERROR", ttl: 300, resolver: [] }] })
    expect(r!.securityTxt.dmarc).toBe(true)
    expect(r!.email.dmarc.policy).toBe("none")
  })
})

const SPF_OK = ["v=spf1 include:_spf.example.net -all"]
const withExtras = (txt: string[], extras: EmailExtras) => assessEmailAuth(parseEmailAuth(txt, extras))
const area = (fs: ReturnType<typeof withExtras>, a: string) => fs.filter((f) => f.area === a)

describe("SPF lookup count", () => {
  it("is an issue over the limit of 10, with 'at least' when the count is a lower bound", () => {
    const over = area(withExtras(SPF_OK, { spfLookups: { count: 12, complete: true } }), "SPF")
    expect(over.some((f) => f.severity === "issue" && /12 DNS lookups/.test(f.message))).toBe(true)
    const partial = area(withExtras(SPF_OK, { spfLookups: { count: 11, complete: false } }), "SPF")
    expect(partial.some((f) => f.severity === "issue" && /at least 11/.test(f.message))).toBe(true)
  })
  it("warns at exactly 10 and stays quiet below it", () => {
    expect(area(withExtras(SPF_OK, { spfLookups: { count: 10, complete: true } }), "SPF").some((f) => f.severity === "info" && /limit of 10/.test(f.message))).toBe(true)
    expect(area(withExtras(SPF_OK, { spfLookups: { count: 4, complete: true } }), "SPF").some((f) => /lookups/.test(f.message))).toBe(false)
  })
  it("says so when an include could not be fetched", () => {
    expect(area(withExtras(SPF_OK, { spfLookups: { count: 3, complete: false } }), "SPF").some((f) => /could not be fetched/.test(f.message))).toBe(true)
  })
  it("says nothing when the engine did not report a count (older scans)", () => {
    expect(area(withExtras(SPF_OK, {}), "SPF").some((f) => /lookups/.test(f.message))).toBe(false)
  })
  it("turns the SPF badge red and shows the count when over the limit", () => {
    const [spf] = emailBadges(parseEmailAuth(["v=spf1 -all", "v=DMARC1; p=reject"], { spfLookups: { count: 14, complete: true } }))
    expect(spf.ok).toBe(false)
    expect(spf.label).toMatch(/14 lookups/)
  })
})

describe("DKIM selector names", () => {
  const keyed = [`k=rsa; p=${KEY}`, `v=DKIM1; k=rsa; p=${KEY}`]
  it("lists the selectors when the engine reported them", () => {
    const [f] = area(withExtras(keyed, { dkimSelectors: ["google", "s1"] }), "DKIM")
    expect(f.message).toMatch(/2 DKIM public keys.*selectors: google, s1/)
  })
  it("leaves them out on older scans", () => {
    const [f] = area(withExtras(keyed, {}), "DKIM")
    expect(f.message).not.toMatch(/selectors:/)
  })
})

describe("MTA-STS and TLS-RPT", () => {
  const none = { mtaSts: [], tlsRpt: [], bimi: [] }
  it("flags a mail-receiving domain without MTA-STS", () => {
    const f = area(withExtras(SPF_OK, { mailPolicy: none, hasMx: true }), "MTA-STS")
    expect(f[0].severity).toBe("info")
  })
  it("stays quiet for a domain with no MX, or when the engine did not look", () => {
    expect(area(withExtras(SPF_OK, { mailPolicy: none, hasMx: false }), "MTA-STS")).toHaveLength(0)
    expect(area(withExtras(SPF_OK, { hasMx: true }), "MTA-STS")).toHaveLength(0)
  })
  it("asks for TLS-RPT when only MTA-STS is published", () => {
    const f = area(withExtras(SPF_OK, { mailPolicy: { ...none, mtaSts: ["v=STSv1; id=1"] }, hasMx: true }), "TLS-RPT")
    expect(f[0].message).toMatch(/no TLS-RPT/)
  })
  it("passes when both are published", () => {
    const f = withExtras(SPF_OK, { mailPolicy: { mtaSts: ["v=STSv1; id=1"], tlsRpt: ["v=TLSRPTv1; rua=mailto:r@x.com"], bimi: [] }, hasMx: true })
    expect(area(f, "MTA-STS")[0].severity).toBe("ok")
    expect(area(f, "TLS-RPT")).toHaveLength(0)
  })
})

describe("assessCaa", () => {
  it("is silent for older scans, flags none, passes with issuers", () => {
    expect(assessCaa(null)).toEqual([])
    expect(assessCaa([])[0].severity).toBe("info")
    expect(assessCaa(["pki.goog"])[0]).toMatchObject({ severity: "ok", message: expect.stringContaining("pki.goog") })
  })
})

describe("parseDns with engine email fields", () => {
  const base = { host: "example.com", txt: SPF_OK, mx: ["mx.example.com"], status_code: "NOERROR", ttl: 300, resolver: [] }
  it("maps the engine fields", () => {
    const r = parseDns({ results: [{ ...base, dkim_selectors: ["google"], spf_lookups: 11, spf_lookups_complete: false, caa: ["pki.goog"],
      mail_policy: { mta_sts: ["v=STSv1; id=1"], tls_rpt: [], bimi: [] } }] })!
    expect(r.email.dkim.selectors).toEqual(["google"])
    expect(r.email.spf.lookups).toEqual({ count: 11, complete: false })
    expect(r.email.mailPolicy).toEqual({ mtaSts: ["v=STSv1; id=1"], tlsRpt: [], bimi: [] })
    expect(r.email.hasMx).toBe(true)
    expect(r.caa).toEqual(["pki.goog"])
  })
  it("treats a scan from before these fields existed as unknown, not as missing records", () => {
    const r = parseDns({ results: [base] })!
    expect(r.email.dkim.selectors).toBeNull()
    expect(r.email.spf.lookups).toBeNull()
    expect(r.email.mailPolicy).toBeNull()
    expect(r.caa).toBeNull()
    const msgs = [...assessEmailAuth(r.email), ...assessCaa(r.caa)].map((f) => f.message).join("|")
    expect(msgs).not.toMatch(/MTA-STS|CAA|lookups/)
  })
  it("keeps spf_lookups_complete true when the engine omits it", () => {
    expect(parseDns({ results: [{ ...base, spf_lookups: 3 }] })!.email.spf.lookups).toEqual({ count: 3, complete: true })
  })
})

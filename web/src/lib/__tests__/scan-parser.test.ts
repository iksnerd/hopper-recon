import { describe, expect, it } from "vitest"
import {
  parseCdn,
  parseDns,
  parseHttp,
  parseSubdomains,
  parseTls,
  parseUrls,
} from "@/lib/scan-parser"

// Smoke tests for the parsers. Each parser does happy-path indexing on
// `results[0]` and field aliasing (e.g. `wildcard_certificate` → `wildcard`)
// — a regression here silently breaks the dashboard with no compile error.
// The fixtures below mimic real engine /scan responses (one parsed-record
// element per `results` entry).

describe("parseHttp", () => {
  it("aliases httpx fields and falls back when optional fields are missing", () => {
    const result = parseHttp({
      results: [
        {
          url: "https://example.com",
          status_code: 200,
          chain_status_codes: [301, 200],
          title: "Example Domain",
          webserver: "nginx/1.24.0",
          tech: ["nginx", "HSTS"],
          cpe: [{ cpe: "cpe:/a:nginx:nginx:1.24.0" }],
          jarm_hash: "abc123",
          asn: "AS15169 GOOGLE",
          a: ["93.184.216.34"],
        },
      ],
    })
    expect(result).not.toBeNull()
    expect(result!.url).toBe("https://example.com")
    expect(result!.status_code).toBe(200)
    expect(result!.title).toBe("Example Domain")
    expect(result!.tech).toEqual(["nginx", "HSTS"])
    expect(result!.cpe).toEqual(["cpe:/a:nginx:nginx:1.24.0"]) // unwrapped from {cpe}
    expect(result!.chain_status_codes).toEqual([301, 200])
    expect(result!.final_url).toBe("https://example.com") // falls back to url
  })

  it("returns null on empty results", () => {
    expect(parseHttp({ results: [] })).toBeNull()
  })
})

describe("parseDns", () => {
  it("derives security-txt flags + IP prefix distribution", () => {
    const result = parseDns({
      results: [
        {
          host: "example.com",
          a: ["93.184.215.14", "93.184.216.34"],
          aaaa: ["2606:2800:21f:cb07:6820:80da:af6b:8b2c"],
          ns: ["a.iana-servers.net", "b.iana-servers.net"],
          mx: [],
          txt: [
            "v=spf1 -all",
            "v=DMARC1; p=reject; rua=mailto:postmaster@example.com",
          ],
          status_code: "NOERROR",
          ttl: 300,
          resolver: ["1.1.1.1:53"],
        },
      ],
    })
    expect(result).not.toBeNull()
    expect(result!.host).toBe("example.com")
    expect(result!.securityTxt.spf).toBe(true)
    expect(result!.securityTxt.dmarc).toBe(true)
    expect(result!.securityTxt.dkim).toBe(false)
    // Both IPs share /16 prefix 93.184.x.x → single distribution bucket.
    expect(result!.ipDistribution).toEqual([{ prefix: "93.184.x.x", count: 2 }])
  })

  it("returns null on empty results", () => {
    expect(parseDns({ results: [] })).toBeNull()
  })
})

describe("parseTls", () => {
  it("aliases wildcard_certificate → wildcard and computes daysLeft", () => {
    const farFuture = new Date(Date.now() + 90 * 86_400_000).toISOString()
    const result = parseTls({
      results: [
        {
          host: "example.com",
          ip: "93.184.216.34",
          port: "443",
          tls_version: "tls13",
          cipher: "TLS_AES_256_GCM_SHA384",
          not_before: "2026-01-01T00:00:00Z",
          not_after: farFuture,
          subject_cn: "*.example.com",
          subject_an: ["example.com", "*.example.com"],
          issuer_cn: "DigiCert TLS RSA SHA256 2020 CA1",
          serial: "0a:1b:2c",
          wildcard_certificate: true,
          expired: false,
          self_signed: false,
        },
      ],
    })
    expect(result).not.toBeNull()
    expect(result!.host).toBe("example.com")
    expect(result!.wildcard).toBe(true) // aliased from wildcard_certificate
    expect(result!.expired).toBe(false)
    expect(result!.daysLeft).toBeGreaterThan(85)
    expect(result!.daysLeft).toBeLessThanOrEqual(90)
    expect(result!.subject_an).toEqual(["example.com", "*.example.com"])
  })

  it("returns null on empty results", () => {
    expect(parseTls({ results: [] })).toBeNull()
  })
})

describe("parseSubdomains", () => {
  it("counts categories + sources from SubfinderEntry shape", () => {
    const result = parseSubdomains({
      results: [
        { host: "api.example.com", sources: ["crtsh", "anubis"] },
        { host: "www.example.com", sources: ["crtsh"] },
        { host: "blog.example.com", sources: ["anubis"] },
      ],
    })
    expect(result.findings).toHaveLength(3)
    expect(result.sourceCounts).toEqual([
      { source: "crtsh", count: 2 },
      { source: "anubis", count: 2 },
    ])
    // api.* → "API / Auth", www.* → "Web", blog.* → "Marketing"
    expect(result.categories.map((c) => c.category).sort()).toEqual([
      "API / Auth",
      "Marketing",
      "Web",
    ])
  })
})

describe("parseCdn", () => {
  it("collapses cdncheck rows into typed entries and drops unattributed IPs", () => {
    const result = parseCdn({
      results: [
        { ip: "1.1.1.1", cdn: true, cdn_name: "cloudflare" },
        { ip: "8.8.8.8", cloud: true, cloud_name: "google" },
        { ip: "203.0.113.5" }, // not attributed → dropped
        { ip: "203.0.113.6", waf: true, waf_name: "imperva" },
      ],
    })
    expect(result.entries).toEqual([
      { ip: "1.1.1.1", kind: "cdn", name: "cloudflare" },
      { ip: "8.8.8.8", kind: "cloud", name: "google" },
      { ip: "203.0.113.6", kind: "waf", name: "imperva" },
    ])
  })
})

describe("parseUrls", () => {
  it("counts sources and hosts", () => {
    const result = parseUrls({
      results: [
        { url: "https://example.com/a", source: "waybackarchive" },
        { url: "https://example.com/b", source: "waybackarchive" },
        { url: "https://blog.example.com/c", source: "commoncrawl" },
        { url: "not a url", source: "alienvault" }, // host bucket skipped
      ],
    })
    expect(result.entries).toHaveLength(4)
    expect(result.sourceCounts).toEqual([
      { source: "waybackarchive", count: 2 },
      { source: "commoncrawl", count: 1 },
      { source: "alienvault", count: 1 },
    ])
    expect(result.hostCounts).toEqual([
      { host: "example.com", count: 2 },
      { host: "blog.example.com", count: 1 },
    ])
  })
})

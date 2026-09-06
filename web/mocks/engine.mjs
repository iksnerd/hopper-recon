#!/usr/bin/env node
// Mock hopper-recon engine.
//
// Speaks the same REST surface as engine/server.go so `npm run dev` works with
// no Docker, no engine, and no recon binaries. Nothing in src/ knows this
// exists: it listens on the port engine-client.ts already defaults to, so the
// app talks to it over real HTTP and every code path stays production-shaped.
//
//   node mocks/engine.mjs            # port 9119
//   PORT=9200 node mocks/engine.mjs
//
// Fixtures in mocks/fixtures/ are real engine output, captured from a live
// scan and then deduped to the newest row per (domain, tool) and capped at 500
// entries per result so the repo stays small. Counts therefore read lower than
// a real scan of the same domain.
//
// Targets not in the fixtures are synthesised, so you can type anything into
// the dashboard and get a plausible result. `huge.test` (or any target with
// HUGE_HOSTS set) generates 25,000 subdomains, which is what the unvirtualised
// list bug needed to reproduce — keep it working when touching HostList.

import { createServer } from "node:http"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { dirname, join } from "node:path"
import { randomUUID } from "node:crypto"

const here = dirname(fileURLToPath(import.meta.url))
const fixture = (name) =>
  JSON.parse(readFileSync(join(here, "fixtures", `${name}.json`), "utf8"))

const CONFIG = fixture("config")
const GEOIP = fixture("geoip")
/** Mutable so DELETE /scans/{id} and POST /scan behave like the real store. */
let SCANS = fixture("scans")

// Hard stop: this serves fabricated recon results. Shipping it in a real
// deployment would present invented subdomains and certificates as findings.
// It is already unreachable from a production build (nothing under src/ imports
// it, so next build never bundles it), and this is the belt to that braces.
if (process.env.NODE_ENV === "production") {
  console.error("mocks/engine.mjs refuses to run with NODE_ENV=production — it serves fabricated scan results.")
  process.exit(1)
}

const PORT = Number(process.env.PORT ?? 9119)
/** Fake per-tool latency so loading states are actually visible. 0 to disable. */
const LATENCY = Number(process.env.MOCK_LATENCY_MS ?? 400)
const HUGE_HOSTS = Number(process.env.HUGE_HOSTS ?? 25000)

const TOOLS = [
  "passive_subdomains", "resolve_dns", "fetch_tls_cert", "probe_http",
  "check_cdn", "find_urls", "expand_subdomains", "find_domains",
  "resolve_mutations",
]

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// ---------------------------------------------------------------- synthesis

/** Deterministic PRNG so a given target always produces the same mock data. */
function seeded(str) {
  let h = 2166136261
  for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619) }
  return () => { h = Math.imul(h ^ (h >>> 15), 2246822507); h ^= h >>> 13; return (h >>> 0) / 2 ** 32 }
}

const LABELS = [
  "api", "www", "mail", "dev", "staging", "admin", "cdn", "app", "test", "vpn",
  "git", "docs", "blog", "shop", "auth", "db", "internal", "edge", "beta", "ci",
]
const SOURCES = ["anubis", "crtsh", "hackertarget", "commoncrawl", "rapiddns", "alienvault"]

function synthSubdomains(target, rng, n) {
  const out = []
  for (let i = 0; i < n; i++) {
    const label = LABELS[Math.floor(rng() * LABELS.length)]
    const suffix = i < LABELS.length ? "" : `${Math.floor(rng() * 9999)}`
    // Shape matches the engine's normalised output: `sources` is an array, not
    // subfinder's raw `source` string. scan-parser.ts iterates it directly.
    out.push({
      host: `${label}${suffix}.${target}`,
      sources: [SOURCES[Math.floor(rng() * SOURCES.length)]],
    })
  }
  // Dedupe like subfinder does; keeps counts honest.
  const seen = new Set()
  return out.filter((e) => !seen.has(e.host) && seen.add(e.host))
}

function synthIP(rng) {
  return `${1 + Math.floor(rng() * 223)}.${Math.floor(rng() * 256)}.${Math.floor(rng() * 256)}.${1 + Math.floor(rng() * 254)}`
}

function synthesise(tool, target) {
  const rng = seeded(`${tool}:${target}`)
  const isHuge = target === "huge.test"
  switch (tool) {
    case "passive_subdomains":
      return synthSubdomains(target, rng, isHuge ? HUGE_HOSTS : 40 + Math.floor(rng() * 400))
    case "find_domains":
      return ["com", "io", "dev", "net", "org", "co", "app"]
        .map((tld) => ({ host: `${target.split(".")[0]}.${tld}`, sources: ["dnsx"] }))
    case "resolve_dns": {
      const a = [synthIP(rng), synthIP(rng)]
      return [{
        host: target, ttl: 60 + Math.floor(rng() * 300), a,
        aaaa: ["2606:4700::6810:85e5"],
        ns: [`ns1.${target}`, `ns2.${target}`],
        mx: [`10 mail.${target}`],
        txt: ["v=spf1 include:_spf.google.com -all"],
        all: [`${target}.\t300\tIN\tA\t${a[0]}`],
        status_code: "NOERROR", resolver: ["1.1.1.1:53"],
        timestamp: new Date().toISOString(),
      }]
    }
    case "fetch_tls_cert": {
      const days = Math.floor(rng() * 400) - 40 // sometimes already expired
      const notAfter = new Date(Date.now() + days * 864e5).toISOString()
      return [{
        host: target, port: "443", probe_status: true, tls_version: "tls13",
        cipher: "TLS_AES_128_GCM_SHA256",
        not_before: new Date(Date.now() - 60 * 864e5).toISOString(),
        not_after: notAfter,
        subject_cn: target, subject_an: [target, `*.${target}`],
        issuer_cn: "Mock Issuing CA", issuer_org: ["Mock CA"],
        wildcard_certificate: true, self_signed: false, expired: days < 0,
        fingerprint_hash: { sha256: "0".repeat(64) },
      }]
    }
    case "probe_http": {
      const codes = [200, 200, 200, 301, 403, 404, 500]
      return [{
        url: `https://${target}`, input: target, host: target,
        status_code: codes[Math.floor(rng() * codes.length)],
        title: `${target} — mock`, webserver: "nginx", scheme: "https",
        content_type: "text/html", content_length: 1024 + Math.floor(rng() * 40000),
        time: `${(rng() * 300).toFixed(2)}ms`, method: "GET",
        tech: ["nginx", "React"], cdn: true, cdn_name: "cloudflare", cdn_type: "waf",
        // httpx emits cpe as objects, not strings; scan-parser.ts reads `c.cpe`.
        cpe: [{ cpe: "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", product: "nginx", vendor: "nginx" }],
        final_url: `https://${target}/`, port: "443",
        path: "/", host_ip: synthIP(rng),
        a: [synthIP(rng)], jarm_hash: "27d40d40d00040d1dc42d43d00041d" + "0".repeat(33),
        timestamp: new Date().toISOString(),
      }]
    }
    case "check_cdn":
      return [{ input: target, ip: synthIP(rng), waf: true, waf_name: "cloudflare", timestamp: new Date().toISOString() }]
    case "find_urls":
      return Array.from({ length: 30 + Math.floor(rng() * 200) }, (_, i) => ({
        url: `https://${target}/${["docs", "blog", "api", "assets"][i % 4]}/page-${i}`,
        input: target, source: SOURCES[Math.floor(rng() * SOURCES.length)],
      }))
    case "expand_subdomains":
      return Array.from({ length: isHuge ? 5000 : 200 + Math.floor(rng() * 800) }, (_, i) => ({
        word: `${LABELS[i % LABELS.length]}-${i}.${target}`,
      }))
    case "resolve_mutations":
      return Array.from({ length: 5 + Math.floor(rng() * 30) }, (_, i) => ({
        host: `${LABELS[i % LABELS.length]}-${i}.${target}`, a: [synthIP(rng)],
      }))
    default:
      return []
  }
}

// ------------------------------------------------------------------ routing

function json(res, code, body) {
  const payload = JSON.stringify(body)
  res.writeHead(code, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
  })
  res.end(payload)
}

function readBody(req) {
  return new Promise((resolve) => {
    let s = ""
    req.on("data", (c) => { s += c })
    req.on("end", () => { try { resolve(JSON.parse(s || "{}")) } catch { resolve({}) } })
  })
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`)
  const path = url.pathname

  if (req.method === "GET" && path === "/healthz") return json(res, 200, { status: "ok" })
  if (req.method === "GET" && path === "/readyz") return json(res, 200, { status: "ready" })
  if (req.method === "GET" && path === "/config") return json(res, 200, CONFIG)

  if (req.method === "GET" && path === "/geoip") {
    const want = new Set((url.searchParams.get("ips") ?? "").split(",").filter(Boolean))
    const hit = GEOIP.filter((g) => want.has(g.ip))
    // Unknown IPs get a country too, otherwise the globe is always empty on
    // synthesised targets.
    const known = new Set(hit.map((g) => g.ip))
    const cc = ["US", "DE", "GB", "FR", "SG", "JP", "BR", "AU"]
    for (const ip of want) {
      if (!known.has(ip)) hit.push({ ip, country: cc[Math.floor(seeded(ip)() * cc.length)] })
    }
    return json(res, 200, hit)
  }

  if (req.method === "GET" && path === "/scans") {
    const domain = url.searchParams.get("domain")
    const limit = Number(url.searchParams.get("limit") ?? 100)
    let rows = SCANS
    if (domain) rows = rows.filter((r) => r.domain === domain)
    rows = [...rows].sort((a, b) => (b.completed_at ?? "").localeCompare(a.completed_at ?? ""))
    return json(res, 200, rows.slice(0, limit))
  }

  if (req.method === "DELETE" && path.startsWith("/scans/")) {
    const id = decodeURIComponent(path.slice("/scans/".length))
    const before = SCANS.length
    SCANS = SCANS.filter((r) => r.id !== id)
    return json(res, SCANS.length < before ? 200 : 404, {})
  }

  if (req.method === "POST" && path === "/scan") {
    const { tool, target } = await readBody(req)
    if (!TOOLS.includes(tool)) return json(res, 400, { error: `unknown tool ${tool}` })
    if (!target) return json(res, 400, { error: "target required" })
    if (LATENCY) await sleep(LATENCY + Math.random() * LATENCY)

    // MOCK_FAIL=tool1,tool2 forces those tools to error, for testing the
    // per-tool failure states without waiting for a real timeout.
    const forced = (process.env.MOCK_FAIL ?? "").split(",").filter(Boolean)
    if (forced.includes(tool)) {
      return json(res, 200, {
        id: randomUUID(), tool, target, status: "failed",
        error: `mock forced failure for ${tool}`, isError: true,
      })
    }

    const existing = SCANS.find(
      (r) => r.domain === target && r.tool === tool && r.status === "completed",
    )
    const results = existing
      ? JSON.parse(existing.results_json ?? "[]")
      : synthesise(tool, target)

    const now = new Date().toISOString()
    const row = {
      id: randomUUID(), domain: target, tool, status: "completed",
      results_json: JSON.stringify(results), error: null,
      started_at: now, completed_at: now,
      http_status: null, cert_expiry: null, tech_stack: null,
    }
    SCANS.push(row)
    return json(res, 200, { id: row.id, tool, target, status: "completed", results })
  }

  json(res, 404, { error: "not found" })
})

server.listen(PORT, "127.0.0.1", () => {
  const domains = [...new Set(SCANS.map((r) => r.domain))].sort()
  console.log(`mock engine on http://127.0.0.1:${PORT}`)
  console.log(`  ${SCANS.length} fixture rows across ${domains.length} domains: ${domains.join(", ")}`)
  console.log(`  any other target is synthesised; "huge.test" yields ${HUGE_HOSTS.toLocaleString()} subdomains`)
  console.log(`  MOCK_LATENCY_MS=${LATENCY}  MOCK_FAIL=<tool,tool> to force failures`)
})

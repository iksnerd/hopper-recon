export interface SubdomainEntry {
  host: string
  sources: string[]
}

export interface SubdomainResult {
  findings: SubdomainEntry[]
  categories: { category: string; count: number }[]
  sourceCounts: { source: string; count: number }[]
}

export interface DnsResult {
  host: string
  a: string[]
  aaaa: string[]
  ns: string[]
  mx: string[]
  txt: string[]
  cdn: string
  asn: string
  status_code: string
  ttl: number
  resolver: string[]
  ipDistribution: { prefix: string; count: number }[]
  securityTxt: { spf: boolean; dmarc: boolean; dkim: boolean }
}

export interface TlsResult {
  host: string
  ip: string
  port: string
  tls_version: string
  cipher: string
  not_before: string
  not_after: string
  subject_cn: string
  subject_an: string[]
  subject_org: string
  issuer_cn: string
  issuer_org: string[]
  serial: string
  wildcard: boolean
  expired: boolean
  self_signed: boolean
  daysLeft: number
}

export interface HttpResult {
  url: string
  final_url: string
  title: string
  webserver: string
  status_code: number
  chain_status_codes: number[]
  content_type: string
  tech: string[]
  cpe: string[]
  time: string
  content_length: number
  jarm_hash: string
  asn: string
  cname: string
  a: string[]
}

export type CdnKind = "cdn" | "cloud" | "waf"

export interface CdnEntry {
  ip: string
  kind: CdnKind
  name: string
}

export interface CdnResult {
  entries: CdnEntry[]
}

export interface UrlEntry {
  url: string
  source: string
}

export interface UrlsResult {
  entries: UrlEntry[]
  sourceCounts: { source: string; count: number }[]
  hostCounts: { host: string; count: number }[]
}

// ── Category patterns ─────────────────────────────────────────────────────────

const SUBDOMAIN_PATTERNS: [RegExp, string][] = [
  [/^(api|auth|fleet|oauth|token|id)\./i,     "API / Auth"],
  [/^(cdn|static|assets|media|img|images)\./i, "Infrastructure"],
  [/^(shop|store|checkout|pay|billing)\./i,    "Commerce"],
  [/^(support|help|docs|kb|status)\./i,        "Support"],
  [/^(blog|news|press|events|forum)\./i,       "Marketing"],
  [/^(ir|investor|careers|jobs|legal)\./i,     "Corporate"],
  [/^(dev|staging|test|sandbox|beta)\./i,      "Engineering"],
  [/^(mail|smtp|mx|vpn|remote)\./i,            "Infrastructure"],
  [/^(accounts?|login|signin|sso)\./i,         "API / Auth"],
  [/^(clerk|auth0|okta)\./i,                   "API / Auth"],
  [/^(www|web|app)\./i,                        "Web"],
]

function categorise(sub: string): string {
  for (const [pattern, label] of SUBDOMAIN_PATTERNS) {
    if (pattern.test(sub)) return label
  }
  return "Other"
}

// ── Parsers ───────────────────────────────────────────────────────────────────

export function parseSubdomains(apiResult: unknown): SubdomainResult {
  // Engine /scan returns `results: SubfinderEntry[]` directly — each entry is
  // `{ host, sources }`. Older payloads (which we no longer produce) wrapped
  // this in `[{ findings: [...] }]` or `[{ subdomains: [...] }]`, kept for
  // backwards-compatible reads of legacy DB rows.
  const raw = apiResult as {
    results: Array<SubdomainEntry | { findings?: SubdomainEntry[]; subdomains?: string[] }>
  }
  const items = raw?.results ?? []

  let findings: SubdomainEntry[] = []
  if (items.length > 0 && typeof (items[0] as SubdomainEntry).host === "string") {
    findings = items as SubdomainEntry[]
  } else {
    const first = items[0] as { findings?: SubdomainEntry[]; subdomains?: string[] } | undefined
    if (first?.findings) {
      findings = first.findings
    } else if (first?.subdomains) {
      findings = first.subdomains.map((h) => ({ host: h, sources: [] }))
    }
  }

  const categoryCounts: Record<string, number> = {}
  const sourceCounts: Record<string, number> = {}

  for (const { host, sources } of findings) {
    const cat = categorise(host)
    categoryCounts[cat] = (categoryCounts[cat] ?? 0) + 1
    for (const src of sources) {
      sourceCounts[src] = (sourceCounts[src] ?? 0) + 1
    }
  }

  return {
    findings,
    categories: Object.entries(categoryCounts)
      .map(([category, count]) => ({ category, count }))
      .sort((a, b) => b.count - a.count),
    sourceCounts: Object.entries(sourceCounts)
      .map(([source, count]) => ({ source, count }))
      .sort((a, b) => b.count - a.count),
  }
}

export function parseDns(apiResult: unknown): DnsResult | null {
  // Engine /scan returns `results: [parsedDnsRecord]` — already JSON-decoded.
  const raw = apiResult as {
    results: Array<{
      host: string; a?: string[]; aaaa?: string[]; ns?: string[]; mx?: string[]; txt?: string[]
      cdn?: string; asn?: string; status_code: string; ttl: number; resolver: string[]
    }>
  }
  const first = raw?.results?.[0]
  if (!first) return null

  const a = first.a ?? []
  const prefixCounts: Record<string, number> = {}
  for (const ip of a) {
    const parts = ip.split(".")
    const prefix = parts.slice(0, 2).join(".") + ".x.x"
    prefixCounts[prefix] = (prefixCounts[prefix] ?? 0) + 1
  }

  const txt = first.txt ?? []
  const txtJoined = txt.join(" ").toLowerCase()
  const securityTxt = {
    spf:   /v=spf1/.test(txtJoined),
    dmarc: /v=dmarc1/.test(txtJoined),
    dkim:  /v=dkim1|dkim=/.test(txtJoined),
  }

  return {
    host: first.host,
    a,
    aaaa: first.aaaa ?? [],
    ns: first.ns ?? [],
    mx: first.mx ?? [],
    txt,
    cdn: first.cdn ?? "",
    asn: first.asn ?? "",
    status_code: first.status_code,
    ttl: first.ttl,
    resolver: first.resolver ?? [],
    ipDistribution: Object.entries(prefixCounts)
      .map(([prefix, count]) => ({ prefix, count }))
      .sort((a, b) => b.count - a.count),
    securityTxt,
  }
}

export function parseTls(apiResult: unknown): TlsResult | null {
  const raw = apiResult as {
    results: Array<{
      host: string; ip: string; port: string; tls_version: string; cipher: string
      not_before: string; not_after: string; subject_cn: string; subject_an?: string[]
      subject_org?: string; issuer_cn: string; issuer_org?: string[]; serial: string
      wildcard_certificate?: boolean; expired?: boolean; self_signed?: boolean
    }>
  }
  const c = raw?.results?.[0]
  if (!c) return null

  const daysLeft = Math.ceil(
    (new Date(c.not_after).getTime() - Date.now()) / 86_400_000
  )

  return {
    host: c.host, ip: c.ip, port: c.port,
    tls_version: c.tls_version, cipher: c.cipher,
    not_before: c.not_before, not_after: c.not_after,
    subject_cn: c.subject_cn,
    subject_an: c.subject_an ?? [],
    subject_org: c.subject_org ?? "",
    issuer_cn: c.issuer_cn,
    issuer_org: c.issuer_org ?? [],
    serial: c.serial,
    wildcard: c.wildcard_certificate ?? false,
    expired: c.expired ?? false,
    self_signed: c.self_signed ?? false,
    daysLeft,
  }
}

export function parseHttp(apiResult: unknown): HttpResult | null {
  const raw = apiResult as {
    results: Array<{
      url: string; final_url?: string; title?: string; webserver?: string
      status_code: number; chain_status_codes?: number[]; content_type?: string
      tech?: string[]; cpe?: Array<{ cpe: string }>; time?: string
      content_length?: number; jarm_hash?: string; asn?: string; cname?: string; a?: string[]
    }>
  }
  const h = raw?.results?.[0]
  if (!h) return null

  return {
    url: h.url,
    final_url: h.final_url ?? h.url,
    title: h.title ?? "",
    webserver: h.webserver ?? "",
    status_code: h.status_code,
    chain_status_codes: h.chain_status_codes ?? [h.status_code],
    content_type: h.content_type ?? "",
    tech: h.tech ?? [],
    cpe: (h.cpe ?? []).map((c) => c.cpe),
    time: h.time ?? "",
    content_length: h.content_length ?? 0,
    jarm_hash: h.jarm_hash ?? "",
    asn: h.asn ?? "",
    cname: h.cname ?? "",
    a: h.a ?? [],
  }
}

// urlfinder emits historical URLs from passive sources. Each line carries a
// `url` plus an optional `source` (waybackarchive / commoncrawl / alienvault).
// The dashboard groups by host so a domain with thousands of paths stays
// scannable.
export function parseUrls(apiResult: unknown): UrlsResult {
  const raw = apiResult as { results: Array<{ url?: string; source?: string }> }
  const entries: UrlEntry[] = []
  const sourceMap: Record<string, number> = {}
  const hostMap: Record<string, number> = {}

  for (const r of raw?.results ?? []) {
    if (!r.url) continue
    const source = r.source ?? "unknown"
    entries.push({ url: r.url, source })
    sourceMap[source] = (sourceMap[source] ?? 0) + 1
    try {
      const host = new URL(r.url).hostname
      if (host) hostMap[host] = (hostMap[host] ?? 0) + 1
    } catch { /* malformed URL — skip host bucket */ }
  }

  return {
    entries,
    sourceCounts: Object.entries(sourceMap)
      .map(([source, count]) => ({ source, count }))
      .sort((a, b) => b.count - a.count),
    hostCounts: Object.entries(hostMap)
      .map(([host, count]) => ({ host, count }))
      .sort((a, b) => b.count - a.count),
  }
}

// cdncheck emits one line per attributed IP — exactly one of cdn/cloud/waf is
// true and the matching `<kind>_name` is set. Unattributed IPs produce no line
// at all (so a domain hosted on its own infra returns an empty `entries`).
export function parseCdn(apiResult: unknown): CdnResult {
  const raw = apiResult as {
    results: Array<{
      ip?: string
      cdn?: boolean; cdn_name?: string
      cloud?: boolean; cloud_name?: string
      waf?: boolean; waf_name?: string
    }>
  }
  const entries: CdnEntry[] = []
  for (const r of raw?.results ?? []) {
    if (!r.ip) continue
    let kind: CdnKind | null = null
    let name = ""
    if (r.cdn && r.cdn_name) { kind = "cdn"; name = r.cdn_name }
    else if (r.cloud && r.cloud_name) { kind = "cloud"; name = r.cloud_name }
    else if (r.waf && r.waf_name) { kind = "waf"; name = r.waf_name }
    if (kind) entries.push({ ip: r.ip, kind, name })
  }
  return { entries }
}

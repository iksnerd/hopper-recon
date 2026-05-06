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

export interface AsnEntry {
  asn: number
  org: string
  cidrs: string[]
  country: string
}

export interface AsnResult {
  entries: AsnEntry[]
}

export interface UncoverEntry {
  ip: string
  port: number
  host: string
  url: string
  source: string
}

export interface UncoverResult {
  entries: UncoverEntry[]
  portCounts: { port: string; count: number }[]
  sourceCounts: { source: string; count: number }[]
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
  const raw = apiResult as { results: Array<{ findings?: SubdomainEntry[]; subdomains?: string[] }> }
  const first = raw?.results?.[0]

  // Support both new (findings) and legacy (subdomains) format
  let findings: SubdomainEntry[] = []
  if (first?.findings) {
    findings = first.findings
  } else if (first?.subdomains) {
    findings = first.subdomains.map((h) => ({ host: h, sources: [] }))
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
  const raw = apiResult as { results: Array<{ results?: string[] }> }
  const lines = raw?.results?.[0]?.results ?? []
  if (!lines.length) return null

  const first = JSON.parse(lines[0]) as {
    host: string; a?: string[]; ns?: string[]; mx?: string[]; txt?: string[]
    cdn?: string; asn?: string; status_code: string; ttl: number; resolver: string[]
  }

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
  const raw = apiResult as { results: Array<{ results?: string[] }> }
  const lines = raw?.results?.[0]?.results ?? []
  if (!lines.length) return null

  const c = JSON.parse(lines[0]) as {
    host: string; ip: string; port: string; tls_version: string; cipher: string
    not_before: string; not_after: string; subject_cn: string; subject_an?: string[]
    subject_org?: string; issuer_cn: string; issuer_org?: string[]; serial: string
    wildcard_certificate?: boolean; expired?: boolean; self_signed?: boolean
  }

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

export function parseUncover(apiResult: unknown): UncoverResult {
  const raw = apiResult as { results: Array<{ results?: string[] }> }
  const lines = raw?.results?.[0]?.results ?? []

  const entries: UncoverEntry[] = []
  const portMap: Record<string, number> = {}
  const sourceMap: Record<string, number> = {}

  for (const line of lines) {
    try {
      const r = JSON.parse(line) as { ip?: string; port?: number; host?: string; url?: string; source?: string }
      if (!r.ip) continue
      entries.push({ ip: r.ip, port: r.port ?? 0, host: r.host ?? "", url: r.url ?? "", source: r.source ?? "" })
      const p = String(r.port ?? "?")
      portMap[p] = (portMap[p] ?? 0) + 1
      const s = r.source ?? "unknown"
      sourceMap[s] = (sourceMap[s] ?? 0) + 1
    } catch { /* skip malformed lines */ }
  }

  return {
    entries,
    portCounts: Object.entries(portMap).map(([port, count]) => ({ port, count })).sort((a, b) => b.count - a.count),
    sourceCounts: Object.entries(sourceMap).map(([source, count]) => ({ source, count })).sort((a, b) => b.count - a.count),
  }
}

export function parseAsn(apiResult: unknown): AsnResult {
  const raw = apiResult as { results: Array<{ results?: string[] }> }
  const lines = raw?.results?.[0]?.results ?? []

  const entries: AsnEntry[] = []
  for (const line of lines) {
    try {
      const r = JSON.parse(line) as {
        as_number?: number; as_name?: string; as_country?: string; as_range?: string[]
      }
      if (r.as_number) {
        entries.push({
          asn: r.as_number,
          org: r.as_name ?? "",
          cidrs: r.as_range ?? [],
          country: r.as_country ?? "",
        })
      }
    } catch { /* skip malformed lines */ }
  }

  return { entries }
}

export function parseHttp(apiResult: unknown): HttpResult | null {
  const raw = apiResult as { results: Array<{ results?: string[] }> }
  const lines = raw?.results?.[0]?.results ?? []
  if (!lines.length) return null

  const h = JSON.parse(lines[0]) as {
    url: string; final_url?: string; title?: string; webserver?: string
    status_code: number; chain_status_codes?: number[]; content_type?: string
    tech?: string[]; cpe?: Array<{ cpe: string }>; time?: string
    content_length?: number; jarm_hash?: string; asn?: string; cname?: string; a?: string[]
  }

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

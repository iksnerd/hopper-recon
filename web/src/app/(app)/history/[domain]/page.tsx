"use client"

import * as React from "react"
import Link from "next/link"
import { useRouter, useParams } from "next/navigation"
import { SidebarTrigger } from "@/components/ui/sidebar"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table"
import {
  BarChart, Bar, LineChart, Line, XAxis, YAxis, Cell,
} from "recharts"
import {
  ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig,
} from "@/components/ui/chart"
import {
  parseSubdomains, parseDns, parseTls, parseHttp, parseUncover,
  type SubdomainResult, type DnsResult, type TlsResult, type HttpResult, type UncoverResult,
} from "@/lib/scan-parser"
import type { DomainSummary } from "@/app/api/scans/domains/route"
import type { ScanRow } from "@/lib/db"
import { formatDistanceToNow } from "date-fns"
import { CHART_FILLS, CHART_CURSOR, CHART_TICK_SM } from "@/lib/chart-style"
import { Panel } from "@/components/recon/panel"
import { DataChip } from "@/components/recon/data-chip"
import { RedirectChain } from "@/components/recon/redirect-chain"
import { ChartBoundary } from "@/components/recon/chart-boundary"
import { FindingsStrip } from "@/components/recon/findings-strip"
import { GeoGlobe } from "@/components/recon/geo-globe"

// Build a DomainSummary from raw rows (DESC order — first seen per tool = most recent)
function buildSummary(rows: ScanRow[], domain: string): DomainSummary {
  const scans: Record<string, ScanRow> = {}
  let lastScanned = ""
  for (const row of rows) {
    if (row.status !== "completed") continue
    if (!scans[row.tool]) scans[row.tool] = row
    if (!lastScanned || row.started_at > lastScanned) lastScanned = row.started_at
  }
  return { domain, lastScanned: lastScanned || new Date().toISOString(), scans }
}

function buildTimeline(rows: ScanRow[]) {
  const buckets = new Map<number, { certDays: number | null; httpStatus: number | null; ts: number }>()
  for (const row of rows) {
    if (row.status !== "completed") continue
    const ts = Date.parse(row.started_at)
    const key = Math.floor(ts / 300_000)
    if (!buckets.has(key)) buckets.set(key, { certDays: null, httpStatus: null, ts })
    const entry = buckets.get(key)!
    if (row.tool === "fetch_tls_cert" && row.cert_expiry) {
      entry.certDays = Math.floor((new Date(row.cert_expiry).getTime() - ts) / 86_400_000)
    }
    if (row.tool === "probe_http" && row.http_status != null) {
      entry.httpStatus = row.http_status
    }
  }
  return Array.from(buckets.entries())
    .sort(([a], [b]) => a - b)
    .map(([, v]) => ({
      label: new Date(v.ts).toLocaleDateString(undefined, { month: "short", day: "numeric" }),
      certDays: v.certDays,
      httpStatus: v.httpStatus,
    }))
}

function certDaysCls(days: number) {
  if (days < 14) return "text-destructive"
  if (days < 30) return "text-muted-foreground-2"
  return "text-primary"
}

function httpStatusCls(code: number) {
  if (code < 300) return "text-primary"
  if (code < 400) return "text-muted-foreground-2"
  return "text-destructive"
}

function elapsed(started: string, completed: string | null) {
  if (!completed) return "—"
  const ms = new Date(completed).getTime() - new Date(started).getTime()
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`
}

// Chart configs at module level
const SUB_CAT_CONFIG = { count: { label: "Count" } } satisfies ChartConfig
const IP_DIST_CONFIG = { count: { label: "IPs" } } satisfies ChartConfig
const TIMELINE_CONFIG = {
  certDays:   { label: "cert days",   color: CHART_FILLS[0] },
  httpStatus: { label: "HTTP status", color: CHART_FILLS[1] },
} satisfies ChartConfig

export default function DomainDetailPage() {
  const params = useParams()
  const domain = decodeURIComponent(params.domain as string)
  const router = useRouter()
  const [rows, setRows] = React.useState<ScanRow[] | null>(null)

  React.useEffect(() => {
    fetch(`/api/scans/domains/${encodeURIComponent(domain)}`)
      .then(async (r) => {
        const text = await r.text()
        if (!r.ok || !text) return []
        return JSON.parse(text) as ScanRow[]
      })
      .then(setRows)
      .catch(() => setRows([]))
  }, [domain])

  const summary = rows ? buildSummary(rows, domain) : null
  const timeline = rows ? buildTimeline(rows) : null
  const showTimeline = timeline !== null && timeline.length >= 2

  const get = (tool: string) => {
    const row = summary?.scans[tool]
    if (!row?.results_json) return null
    try { return JSON.parse(row.results_json) } catch { return null }
  }

  const subRaw     = summary ? get("passive_subdomains") : null
  const dnsRaw     = summary ? get("resolve_dns")        : null
  const tlsRaw     = summary ? get("fetch_tls_cert")     : null
  const httpRaw    = summary ? get("probe_http")         : null
  const uncoverRaw = summary ? get("search_hosts")       : null

  const subdomains: SubdomainResult | null = subRaw     ? parseSubdomains({ results: subRaw })  : null
  const dns:        DnsResult | null       = dnsRaw     ? parseDns({ results: dnsRaw })         : null
  const tls:        TlsResult | null       = tlsRaw     ? parseTls({ results: tlsRaw })         : null
  const http:       HttpResult | null      = httpRaw    ? parseHttp({ results: httpRaw })       : null
  const uncover:    UncoverResult | null   = uncoverRaw ? parseUncover({ results: uncoverRaw }) : null

  const [geoCountries, setGeoCountries] = React.useState<{ code: string; count: number }[]>([])

  const ipKey = dns?.a?.join(",") ?? ""

  React.useEffect(() => {
    if (!ipKey) return
    const ips = ipKey.split(",").filter(Boolean)
    fetch("/api/geoip", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ips }),
    })
      .then(async (r) => r.ok ? r.json() as Promise<{ ip: string; country: string }[]> : [])
      .then((results) => {
        if (!results.length) return
        const counts: Record<string, number> = {}
        for (const { country } of results) {
          counts[country] = (counts[country] ?? 0) + 1
        }
        setGeoCountries(Object.entries(counts).map(([code, count]) => ({ code, count })))
      })
      .catch(() => {})
  }, [ipKey])

  return (
    <div className="min-h-screen font-mono text-foreground scanlines">
      <header className="border-b border-border px-4 py-3 flex items-center gap-3">
        <SidebarTrigger className="size-6 text-muted-foreground hover:text-foreground hover:bg-card-hover rounded-none transition-colors duration-100" />
        <Link href="/history" className="text-muted hover:text-foreground transition-colors duration-100">/</Link>
        <Link href="/history" className="text-body text-muted-foreground hover:text-foreground transition-colors duration-100">history</Link>
        <span className="text-muted">/</span>
        <span className="text-body text-foreground truncate">{domain}</span>
        <div className="ml-auto flex items-center gap-2 shrink-0">
          {summary && (
            <span className="text-micro text-muted-foreground-3 hidden sm:inline">
              {formatDistanceToNow(new Date(summary.lastScanned), { addSuffix: true })}
            </span>
          )}
          <Button
            variant="outline"
            onClick={() => router.push(`/dashboard?domain=${encodeURIComponent(domain)}`)}
            className="rounded-none border-border bg-transparent text-muted-foreground hover:text-foreground hover:bg-card-hover shadow-none ring-0 focus-visible:ring-0 h-auto py-0.5 px-2 text-micro font-mono"
          >
            &gt;_ rescan
          </Button>
        </div>
      </header>

      <div className="px-4 sm:px-8 lg:px-12 py-6 space-y-5 max-w-7xl mx-auto">

        {/* Loading */}
        {rows === null && (
          <div className="border border-border bg-card p-6 text-body text-muted-foreground flex items-center gap-2">
            <span className="cursor-blink">█</span> loading {domain}...
          </div>
        )}

        {/* Not found */}
        {rows?.length === 0 && (
          <div className="border border-border bg-card p-8 flex flex-col items-center gap-3 text-center">
            <div className="text-micro text-muted-foreground">{"// NO DATA"}</div>
            <p className="text-body text-muted-foreground-3">no completed scans found for {domain}</p>
            <Link href="/history" className="text-body text-muted-foreground hover:text-foreground border border-border px-4 py-1.5 transition-colors duration-100 mt-2">
              ← back to history
            </Link>
          </div>
        )}

        {summary && (
          <>
            {/* Stat bar */}
            <div className="border border-border bg-card px-4 py-3 flex flex-wrap items-center gap-x-8 gap-y-2">
              <div className="text-micro uppercase text-muted-foreground tracking-widest shrink-0">{"// "}{domain}</div>
              <div className="flex flex-wrap items-center gap-x-8 gap-y-2 ml-auto">
                {subdomains && <StatChip label="SUBS"  value={subdomains.findings.length.toString()} />}
                {dns         && <StatChip label="IPS"   value={dns.a.length.toString()} />}
                {tls         && <StatChip label="CERT"  value={`${tls.daysLeft}d`} cls={certDaysCls(tls.daysLeft)} />}
                {http        && <StatChip label="HTTP"  value={`[${http.status_code}]`} cls={httpStatusCls(http.status_code)} />}
              </div>
            </div>

            {/* Scan durations */}
            {Object.keys(summary.scans).length > 0 && (
              <div className="flex flex-wrap gap-x-5 gap-y-1 text-micro text-muted-foreground px-1">
                {Object.entries(summary.scans).map(([tool, row]) => (
                  <span key={tool}>
                    {tool.replace(/_/g, " ")}
                    <span className="text-muted-foreground-3 ml-1">{elapsed(row.started_at, row.completed_at)}</span>
                  </span>
                ))}
              </div>
            )}

            {/* Findings strip */}
            <FindingsStrip subs={subdomains} dns={dns} tls={tls} http={http} />

            {/* Geo globe */}
            {geoCountries.length > 0 && <GeoGlobe countries={geoCountries} />}

            {/* Main panels */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">

              {/* Subdomains */}
              {subdomains && (
                <Panel label={`// SUBDOMAINS [${subdomains.findings.length}]`} variant="inset" className="p-4">
                  {subdomains.categories.length > 0 && (
                    <ChartBoundary label="detail-sub-cat">
                      <ChartContainer config={SUB_CAT_CONFIG} className="h-[180px] w-full aspect-auto mb-3">
                        <BarChart data={subdomains.categories} layout="vertical" margin={{ left: 8 }}>
                          <XAxis type="number" hide />
                          <YAxis type="category" dataKey="category" width={110} tick={CHART_TICK_SM} />
                          <ChartTooltip
                            cursor={CHART_CURSOR}
                            content={<ChartTooltipContent className="rounded-none shadow-none" hideLabel />}
                          />
                          <Bar dataKey="count" radius={0}>
                            {subdomains.categories.map((_, i) => (
                              <Cell key={i} fill={CHART_FILLS[Math.min(i, CHART_FILLS.length - 1)]} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ChartContainer>
                    </ChartBoundary>
                  )}
                  <div className="space-y-px">
                    {subdomains.findings.map(({ host, sources }) => (
                      <div key={host} className="group text-data px-1 py-0.5 flex items-center gap-2 hover:bg-card-hover transition-colors duration-100">
                        <span className="text-muted-foreground-2 group-hover:text-foreground truncate flex-1 transition-colors duration-100">{host}</span>
                        <span className="text-muted-foreground-3 shrink-0 text-micro hidden group-hover:inline">{sources.join(", ")}</span>
                        <Link
                          href={`/dashboard?domain=${encodeURIComponent(host)}`}
                          className="shrink-0 text-micro text-muted-foreground-3 hover:text-foreground opacity-0 group-hover:opacity-100 transition-opacity duration-100 border border-border px-1.5 py-px"
                        >
                          &gt;_ scan
                        </Link>
                      </div>
                    ))}
                  </div>
                  {subdomains.sourceCounts.length > 0 && (
                    <div className="mt-3 pt-3 border-t border-border flex flex-wrap gap-1">
                      {subdomains.sourceCounts.map(({ source, count }) => (
                        <DataChip key={source} className="px-1.5">{source} {count}</DataChip>
                      ))}
                    </div>
                  )}
                </Panel>
              )}

              {/* HTTP */}
              {http && (
                <Panel label="// HTTP" variant="inset" className="p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <RedirectChain codes={http.chain_status_codes} />
                  </div>
                  <MiniTable rows={[
                    { label: "SERVER", value: http.webserver || "—" },
                    { label: "TIME",   value: http.time },
                    { label: "TITLE",  value: http.title || "—" },
                    { label: "TYPE",   value: http.content_type },
                    ...(http.cname     ? [{ label: "CNAME", value: http.cname }]     : []),
                    ...(http.asn       ? [{ label: "ASN",   value: http.asn }]       : []),
                    ...(http.jarm_hash ? [{ label: "JARM",  value: http.jarm_hash }] : []),
                  ]} />
                  {http.tech.length > 0 && (
                    <div className="mt-4 pt-3 border-t border-border">
                      <div className="text-micro text-muted-foreground mb-2">TECH STACK</div>
                      <div className="flex flex-wrap gap-1">
                        {http.tech.map((t) => (
                          <DataChip key={t} className="px-1.5 text-muted-foreground">{t}</DataChip>
                        ))}
                      </div>
                    </div>
                  )}
                  {http.cpe.length > 0 && (
                    <div className="mt-3 pt-3 border-t border-border">
                      <div className="text-micro text-muted-foreground mb-2">CPE [{http.cpe.length}]</div>
                      <div className="flex flex-wrap gap-1">
                        {http.cpe.map((c) => (
                          <DataChip key={c} className="px-1.5 text-data">{c}</DataChip>
                        ))}
                      </div>
                    </div>
                  )}
                </Panel>
              )}

              {/* DNS */}
              {dns && (
                <Panel label="// DNS" variant="inset" className="p-4">
                  {dns.ipDistribution.length > 1 && (
                    <ChartBoundary label="detail-ip">
                      <ChartContainer config={IP_DIST_CONFIG} className="h-[120px] w-full aspect-auto mb-3">
                        <BarChart data={dns.ipDistribution}>
                          <XAxis dataKey="prefix" tick={CHART_TICK_SM} />
                          <YAxis allowDecimals={false} tick={CHART_TICK_SM} />
                          <ChartTooltip
                            cursor={CHART_CURSOR}
                            content={<ChartTooltipContent className="rounded-none shadow-none" hideLabel />}
                          />
                          <Bar dataKey="count" radius={0}>
                            {dns.ipDistribution.map((_, i) => (
                              <Cell key={i} fill={CHART_FILLS[Math.min(i, CHART_FILLS.length - 1)]} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ChartContainer>
                    </ChartBoundary>
                  )}
                  <MiniTable rows={[
                    { label: "STATUS", value: `[${dns.status_code}]` },
                    { label: "TTL",    value: `${dns.ttl}s` },
                    ...(dns.cdn ? [{ label: "CDN", value: dns.cdn }] : []),
                    ...(dns.asn ? [{ label: "ASN", value: dns.asn }] : []),
                  ]} />
                  {dns.a.length  > 0 && <RecordRow label="A"  items={dns.a} />}
                  {dns.ns.length > 0 && <RecordRow label="NS" items={dns.ns} />}
                  {dns.mx.length > 0 && <RecordRow label="MX" items={dns.mx} />}
                  {dns.txt.length > 0 && (
                    <div className="mt-3 pt-3 border-t border-border">
                      <div className="text-micro text-muted-foreground mb-2">TXT RECORDS</div>
                      <div className="space-y-1">
                        {dns.txt.map((t, i) => (
                          <div key={i} className="text-data text-muted-foreground-3 break-all">{t}</div>
                        ))}
                      </div>
                    </div>
                  )}
                  <div className="mt-3 pt-3 border-t border-border">
                    <div className="text-micro text-muted-foreground mb-2">EMAIL SECURITY</div>
                    <div className="flex flex-wrap gap-1">
                      <SecPill label="SPF"   on={dns.securityTxt.spf} />
                      <SecPill label="DMARC" on={dns.securityTxt.dmarc} />
                      <SecPill label="DKIM"  on={dns.securityTxt.dkim} />
                    </div>
                  </div>
                </Panel>
              )}

              {/* TLS */}
              {tls && (
                <Panel label="// TLS CERTIFICATE" variant="inset" className="p-4">
                  <CertBar tls={tls} />
                  {(tls.wildcard || tls.expired || tls.self_signed) && (
                    <div className="flex flex-wrap gap-1 mb-3">
                      {tls.wildcard    && <SecPill label="WILDCARD"    on />}
                      {tls.expired     && <SecPill label="EXPIRED"     danger />}
                      {tls.self_signed && <SecPill label="SELF-SIGNED" danger />}
                    </div>
                  )}
                  <MiniTable rows={[
                    { label: "SUBJECT", value: tls.subject_cn },
                    { label: "ISSUER",  value: `${tls.issuer_cn} · ${tls.issuer_org[0] ?? ""}` },
                    { label: "VERSION", value: tls.tls_version.toUpperCase() },
                    { label: "CIPHER",  value: tls.cipher },
                  ]} />
                  {tls.subject_an.length > 0 && (
                    <div className="mt-4 pt-3 border-t border-border">
                      <div className="text-micro text-muted-foreground mb-2">SAN [{tls.subject_an.length}]</div>
                      <div className="flex flex-wrap gap-1">
                        {tls.subject_an.map((s) => (
                          <DataChip key={s} className="px-1.5 text-muted-foreground">{s}</DataChip>
                        ))}
                      </div>
                    </div>
                  )}
                </Panel>
              )}
            </div>

            {/* Uncover */}
            {uncover && uncover.entries.length > 0 && (
              <Panel label={`// EXPOSED HOSTS [${uncover.entries.length}]`} variant="inset" className="p-4 lg:col-span-2">
                <div className="flex flex-wrap gap-1 mb-3">
                  {uncover.sourceCounts.map(({ source, count }) => (
                    <DataChip key={source} className="px-1.5">{source} {count}</DataChip>
                  ))}
                  {uncover.portCounts.map(({ port, count }) => (
                    <DataChip key={port} className="px-1.5 text-muted-foreground">:{port} ×{count}</DataChip>
                  ))}
                </div>
                <div className="space-y-px">
                  {uncover.entries.map((e, i) => (
                    <div key={i} className="flex items-center gap-3 px-1 py-0.5 hover:bg-card transition-colors duration-100">
                      <span className="font-mono text-data text-foreground tabular-nums w-[100px] shrink-0">{e.ip}</span>
                      <span className="font-mono text-data text-muted-foreground-2 tabular-nums w-[48px] shrink-0">{e.port}</span>
                      <span className="font-mono text-data text-muted-foreground-3 truncate flex-1">{e.host || e.url}</span>
                      <DataChip className="shrink-0 text-muted-foreground-3">{e.source}</DataChip>
                    </div>
                  ))}
                </div>
              </Panel>
            )}

            {/* Scan history timeline */}
            {showTimeline && (
              <Panel label={`// SCAN HISTORY [${timeline.length} sessions]`} className="p-4">
                <ChartBoundary label="detail-timeline">
                  <ChartContainer config={TIMELINE_CONFIG} className="h-[200px] w-full aspect-auto">
                    <LineChart data={timeline} margin={{ top: 4, right: 16, bottom: 0, left: 0 }}>
                      <XAxis dataKey="label" tick={CHART_TICK_SM} />
                      <YAxis yAxisId="cert" tick={CHART_TICK_SM} allowDecimals={false} />
                      <YAxis yAxisId="http" orientation="right" tick={CHART_TICK_SM} allowDecimals={false} />
                      <ChartTooltip
                        cursor={CHART_CURSOR}
                        content={<ChartTooltipContent className="rounded-none shadow-none" indicator="line" />}
                      />
                      <Line yAxisId="cert" type="monotone" dataKey="certDays"   name="cert days"   stroke={CHART_FILLS[0]} dot={false} strokeWidth={1.5} />
                      <Line yAxisId="http" type="monotone" dataKey="httpStatus" name="HTTP status" stroke={CHART_FILLS[1]} dot={false} strokeWidth={1.5} />
                    </LineChart>
                  </ChartContainer>
                </ChartBoundary>
              </Panel>
            )}
          </>
        )}
      </div>
    </div>
  )
}

function StatChip({ label, value, cls = "text-primary" }: { label: string; value: string; cls?: string }) {
  return (
    <div className="text-center min-w-[48px]">
      <div className="text-micro text-muted-foreground tracking-widest">{label}</div>
      <div className={`text-emphasis font-bold tabular-nums ${cls}`}>{value}</div>
    </div>
  )
}

function CertBar({ tls }: { tls: TlsResult }) {
  const totalDays = (new Date(tls.not_after).getTime() - new Date(tls.not_before).getTime()) / 86_400_000
  const pct = Math.min(100, Math.max(0, ((totalDays - tls.daysLeft) / totalDays) * 100))
  return (
    <div className="mb-4">
      <div className="flex justify-between text-micro text-muted-foreground mb-1">
        <span>{new Date(tls.not_before).toLocaleDateString()}</span>
        <span>{new Date(tls.not_after).toLocaleDateString()}</span>
      </div>
      <div className="h-1 bg-card-hover">
        <div className="h-full bg-foreground" style={{ width: `${pct}%` }} />
      </div>
      <p className={`text-body font-bold mt-2 ${certDaysCls(tls.daysLeft)}`}>{tls.daysLeft}d remaining</p>
    </div>
  )
}

function MiniTable({ rows }: { rows: { label: string; value: string }[] }) {
  return (
    <Table className="text-data mt-2">
      <TableBody>
        {rows.map(({ label, value }) => (
          <TableRow key={label} className="border-b border-card-hover hover:bg-transparent">
            <TableCell className="p-0 py-1 pr-4 text-muted-foreground whitespace-nowrap align-top w-[80px]">{label}</TableCell>
            <TableCell className="p-0 py-1 text-muted-foreground-2 whitespace-normal break-all">{value}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

function RecordRow({ label, items }: { label: string; items: string[] }) {
  return (
    <div className="mt-2 flex items-baseline gap-3">
      <span className="text-micro text-muted-foreground shrink-0 w-10">{label}</span>
      <div className="flex flex-wrap gap-1">
        {items.map((v) => (
          <DataChip key={v} className="px-1.5 text-muted-foreground">{v}</DataChip>
        ))}
      </div>
    </div>
  )
}

function SecPill({ label, on, danger }: { label: string; on?: boolean; danger?: boolean }) {
  const cls = danger ? "text-destructive" : on ? "text-primary" : "text-destructive"
  const glyph = danger ? "!" : on ? "✓" : "✗"
  return (
    <span className={`font-mono text-micro border border-border bg-card-inset px-1.5 py-0.5 ${cls}`}>
      {glyph} {label}
    </span>
  )
}
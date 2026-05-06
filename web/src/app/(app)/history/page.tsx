"use client"

import * as React from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { queryKeys } from "@/lib/query-keys"
import { Input } from "@/components/ui/input"
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
import { PageHeader } from "@/components/recon/page-header"
import { DataChip } from "@/components/recon/data-chip"
import { RedirectChain } from "@/components/recon/redirect-chain"
import { ChartBoundary } from "@/components/recon/chart-boundary"
import { GeoGlobe } from "@/components/recon/geo-globe"

function certDaysCls(days: number) {
  if (days < 14) return "text-destructive"
  if (days < 30) return "text-muted-foreground-2"
  return "text-terminal-green"
}

function httpStatusCls(code: number) {
  if (code < 300) return "text-terminal-green"
  if (code < 400) return "text-muted-foreground-2"
  return "text-destructive"
}

function elapsed(started: string, completed: string | null) {
  if (!completed) return "—"
  const ms = new Date(completed).getTime() - new Date(started).getTime()
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`
}

function relativeTime(dateStr: string): string {
  return formatDistanceToNow(new Date(dateStr), { addSuffix: true })
}

interface TimelinePoint {
  label: string
  certDays: number | null
  httpStatus: number | null
}

function buildTimeline(rows: ScanRow[]): TimelinePoint[] {
  const buckets = new Map<number, { certDays: number | null; httpStatus: number | null; ts: number }>()
  for (const row of rows) {
    if (row.status !== "completed") continue
    const ts = Date.parse(row.started_at)
    const key = Math.floor(ts / 300_000) // 5-min buckets group one scan session
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

interface ParsedDomain {
  summary: DomainSummary
  subdomains: SubdomainResult | null
  dns: DnsResult | null
  tls: TlsResult | null
  http: HttpResult | null
  uncover: UncoverResult | null
}

function parseDomain(summary: DomainSummary): ParsedDomain {
  const get = (tool: string) => {
    const row = summary.scans[tool]
    if (!row?.results_json) return null
    try {
      return JSON.parse(row.results_json)
    } catch { return null }
  }

  const subRaw     = get("passive_subdomains")
  const dnsRaw     = get("resolve_dns")
  const tlsRaw     = get("fetch_tls_cert")
  const httpRaw    = get("probe_http")
  const uncoverRaw = get("search_hosts")

  return {
    summary,
    subdomains: subRaw     ? parseSubdomains({ results: subRaw })  : null,
    dns:        dnsRaw     ? parseDns({ results: dnsRaw })         : null,
    tls:        tlsRaw     ? parseTls({ results: tlsRaw })         : null,
    http:       httpRaw    ? parseHttp({ results: httpRaw })       : null,
    uncover:    uncoverRaw ? parseUncover({ results: uncoverRaw }) : null,
  }
}

export default function HistoryPage() {
  const router = useRouter()
  const [expanded, setExpanded] = React.useState<Set<string>>(new Set())
  const [filter, setFilter] = React.useState("")

  const { data: rawDomains, isPending: domainsPending } = useQuery({
    queryKey: queryKeys.domains(),
    queryFn: async (): Promise<DomainSummary[]> => {
      const r = await fetch("/api/scans/domains")
      const text = await r.text()
      if (!r.ok || !text) throw new Error(`history fetch failed [${r.status}]`)
      return JSON.parse(text) as DomainSummary[]
    },
  })
  const domains = rawDomains?.map(parseDomain) ?? null

  function toggle(domain: string) {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(domain)) { next.delete(domain) } else { next.add(domain) }
      return next
    })
  }

  const filtered = domains?.filter((d) =>
    !filter || d.summary.domain.includes(filter)
  )

  const [geoCountries, setGeoCountries] = React.useState<{ code: string; count: number }[]>([])

  const ipKey = domains?.map((d) => d.dns?.a?.join(",") ?? "").join("|") ?? ""

  React.useEffect(() => {
    if (!ipKey) return
    const ips = (domains ?? []).flatMap((d) => d.dns?.a ?? []).filter(Boolean)
    if (!ips.length) return
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
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ipKey])

  return (
    <div className="min-h-screen font-mono text-foreground scanlines">
      <PageHeader
        segments={["HISTORY"]}
        right={
          domains != null && (
            <span className="font-mono text-micro tracking-widest uppercase text-muted-foreground-2 border border-border bg-card-inset px-2 py-1">
              [{domains.length} DOMAIN{domains.length === 1 ? "" : "S"}]
            </span>
          )
        }
      />

      <div className="px-4 sm:px-8 lg:px-12 py-6 sm:py-8 space-y-4">
        {/* Filter */}
        <div className="border border-border bg-card px-4 py-2 flex items-center gap-2">
          <span className="text-terminal-green text-emphasis select-none shrink-0 font-bold">&gt;_</span>
          <Input
            type="text"
            placeholder="filter domains..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="flex-1 border-0 bg-transparent rounded-none shadow-none h-6 px-0 text-body text-foreground placeholder:text-muted-foreground-3 focus-visible:ring-0 focus-visible:border-0 font-mono"
          />
          {filter && (
            <Button
              variant="ghost"
              onClick={() => setFilter("")}
              className="rounded-none bg-transparent text-muted-foreground hover:text-foreground hover:bg-transparent shadow-none ring-0 focus-visible:ring-0 active:translate-y-0 h-auto p-0 text-body font-mono"
            >
              [clear]
            </Button>
          )}
        </div>

        {/* Geo globe — shown once data loaded and at least one country resolved */}
        {geoCountries.length > 0 && <GeoGlobe countries={geoCountries} />}

        {/* Loading */}
        {domainsPending && (
          <div className="border border-border bg-card p-6 text-body text-muted-foreground flex items-center gap-2">
            <span className="cursor-blink">█</span> loading...
          </div>
        )}

        {/* Empty */}
        {domains?.length === 0 && (
          <div className="border border-border bg-card p-8 flex flex-col items-center gap-3 text-center">
            <div className="text-micro text-muted-foreground">{"// NO SCANS YET"}</div>
            <p className="text-body text-muted-foreground-3">run a scan from the dashboard to populate history</p>
            <Link href="/dashboard" className="text-body text-terminal-green hover:text-background hover:bg-terminal-green border border-terminal-green/40 bg-card-inset px-4 py-1.5 transition-colors duration-100 mt-2 tracking-widest uppercase font-bold">
              &gt;_ GO TO DASHBOARD
            </Link>
          </div>
        )}

        {/* Domain cards */}
        {filtered?.map((d) => (
          <DomainCard
            key={d.summary.domain}
            data={d}
            open={expanded.has(d.summary.domain)}
            onToggle={() => toggle(d.summary.domain)}
            onRescan={() => router.push(`/dashboard?domain=${encodeURIComponent(d.summary.domain)}`)}
          />
        ))}

        {filtered?.length === 0 && filter && (
          <div className="border border-border bg-card px-4 py-6 text-body text-muted-foreground text-center">
            no results for &ldquo;{filter}&rdquo;
          </div>
        )}
      </div>
    </div>
  )
}

function DomainCard({ data, open, onToggle, onRescan }: {
  data: ParsedDomain
  open: boolean
  onToggle: () => void
  onRescan: () => void
}) {
  const { summary, subdomains, dns, tls, http, uncover } = data
  const queryClient = useQueryClient()
  const [confirming, setConfirming] = React.useState(false)

  const { data: timelineRows } = useQuery({
    queryKey: queryKeys.domainRows(summary.domain),
    queryFn: async (): Promise<ScanRow[]> => {
      const r = await fetch(`/api/scans/domains/${encodeURIComponent(summary.domain)}`)
      const text = await r.text()
      if (!r.ok || !text) return []
      return JSON.parse(text) as ScanRow[]
    },
    enabled: open,
  })

  const deleteMutation = useMutation({
    mutationFn: async () => {
      await Promise.allSettled(
        Object.values(summary.scans).map((row) =>
          fetch(`/api/scans/${row.id}`, { method: "DELETE" })
        )
      )
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.domains() })
      queryClient.removeQueries({ queryKey: queryKeys.domainRows(summary.domain) })
    },
  })

  function handleDelete(e: React.MouseEvent) {
    e.stopPropagation()
    deleteMutation.mutate()
  }

  const timeline = timelineRows ? buildTimeline(timelineRows) : null
  const showTimeline = timeline !== null && timeline.length >= 2

  return (
    <div className="border border-border bg-card">
      {/* Row header — clickable expand */}
      <div
        className={`relative px-3 sm:px-4 py-3 flex items-center gap-2 sm:gap-4 cursor-pointer hover:bg-card-hover transition-colors duration-100 select-none before:absolute before:left-0 before:top-2 before:bottom-2 before:w-[2px] ${open ? "before:bg-terminal-green/70" : "before:bg-foreground/20"}`}
        onClick={onToggle}
        aria-expanded={open}
      >
        <span className="text-muted-foreground text-body w-3 shrink-0 transition-transform duration-100" aria-hidden>
          {open ? "▾" : "▸"}
        </span>
        <Link
          href={`/history/${encodeURIComponent(summary.domain)}`}
          onClick={(e) => e.stopPropagation()}
          className="text-foreground text-emphasis font-bold flex-1 truncate hover:text-primary transition-colors duration-100 tracking-tight"
        >
          {summary.domain}
        </Link>

        {/* Mini stat strip */}
        <div className="hidden md:flex items-center gap-0 text-body divide-x divide-border">
          {subdomains && <Stat label="SUBS" value={subdomains.findings.length.toString()} />}
          {dns && <Stat label="IPS" value={dns.a.length.toString()} />}
          {tls && <Stat label="CERT" value={`${tls.daysLeft}d`} cls={certDaysCls(tls.daysLeft)} />}
          {http && <Stat label="HTTP" value={`[${http.status_code}]`} cls={httpStatusCls(http.status_code)} />}
        </div>
        {http?.tech && http.tech.length > 0 && (
          <div className="hidden lg:flex gap-1 max-w-[200px] overflow-hidden">
            {http.tech.slice(0, 3).map((t) => (
              <DataChip key={t} className="px-1.5 text-muted-foreground-3">{t}</DataChip>
            ))}
          </div>
        )}

        <span className="text-muted-foreground-3 text-micro tracking-widest uppercase shrink-0 hidden sm:inline">
          {relativeTime(summary.lastScanned)}
        </span>

        {/* Action cluster */}
        <div className="flex items-center border-l border-border pl-2 sm:pl-3 ml-1 gap-1 shrink-0" onClick={(e) => e.stopPropagation()}>
          <Button
            variant="outline"
            onClick={(e) => { e.stopPropagation(); onRescan() }}
            className="rounded-none border-border bg-transparent text-muted-foreground hover:text-foreground hover:bg-card-inset shadow-none ring-0 focus-visible:ring-0 active:translate-y-0 h-7 py-0 px-2.5 text-micro tracking-widest uppercase font-mono"
          >
            &gt;_ RESCAN
          </Button>

          {confirming ? (
            <>
              <span className="text-micro text-muted-foreground tracking-widest uppercase px-1">DELETE?</span>
              <Button
                variant="ghost"
                onClick={handleDelete}
                disabled={deleteMutation.isPending}
                className="rounded-none bg-transparent text-destructive hover:text-destructive hover:bg-card-inset shadow-none ring-0 focus-visible:ring-0 h-7 py-0 px-2 text-micro tracking-widest uppercase font-mono"
              >
                [YES]
              </Button>
              <Button
                variant="ghost"
                onClick={() => setConfirming(false)}
                className="rounded-none bg-transparent text-muted-foreground hover:text-foreground hover:bg-card-inset shadow-none ring-0 focus-visible:ring-0 h-7 py-0 px-2 text-micro tracking-widest uppercase font-mono"
              >
                [NO]
              </Button>
            </>
          ) : (
            <Button
              variant="ghost"
              onClick={() => setConfirming(true)}
              className="rounded-none bg-transparent text-muted-foreground-3 hover:text-destructive hover:bg-card-inset shadow-none ring-0 focus-visible:ring-0 h-7 w-7 p-0 text-body font-mono shrink-0"
              aria-label="delete"
            >
              ×
            </Button>
          )}
        </div>
      </div>

      {/* Expanded detail */}
      {open && (
        <div className="border-t border-border p-4 space-y-4">
          {/* Durations row */}
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-micro text-muted-foreground">
            {Object.entries(summary.scans).map(([tool, row]) => (
              <span key={tool}>
                {tool.replace(/_/g, " ")}
                <span className="text-muted-foreground-3 ml-1">{elapsed(row.started_at, row.completed_at)}</span>
              </span>
            ))}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Subdomains */}
            {subdomains && (
              <DetailPanel label={"// SUBDOMAINS [" + subdomains.findings.length + "]"}>
                {subdomains.categories.length > 0 && (
                  <ChartBoundary label="hist-cat">
                    <ChartContainer config={SUB_CAT_CONFIG} className="h-[160px] w-full aspect-auto">
                      <BarChart data={subdomains.categories} layout="vertical" margin={{ left: 8 }}>
                        <XAxis type="number" hide />
                        <YAxis type="category" dataKey="category" width={100} tick={CHART_TICK_SM} />
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
                <div className="mt-2 space-y-px max-h-[100px] overflow-y-auto">
                  {subdomains.findings.map(({ host, sources }) => (
                    <div key={host} className="text-data text-muted-foreground-2 hover:text-foreground px-1 py-0.5 truncate flex items-center justify-between transition-colors duration-100">
                      <span className="truncate">{host}</span>
                      <span className="text-muted-foreground-3 shrink-0 ml-2 truncate max-w-[40%]">{sources.join(", ")}</span>
                    </div>
                  ))}
                </div>
                {subdomains.sourceCounts.length > 0 && (
                  <div className="mt-2 pt-2 border-t border-border flex flex-wrap gap-1">
                    {subdomains.sourceCounts.slice(0, 5).map(({ source, count }) => (
                      <DataChip key={source} className="px-1.5">{source} {count}</DataChip>
                    ))}
                  </div>
                )}
              </DetailPanel>
            )}

            {/* DNS */}
            {dns && (
              <DetailPanel label={"// DNS"}>
                {dns.ipDistribution.length > 1 && (
                  <ChartBoundary label="hist-ip">
                    <ChartContainer config={IP_DIST_CONFIG} className="h-[100px] w-full aspect-auto">
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
                {dns.a.length > 0 && <RecordRow label="A" items={dns.a} />}
                {dns.ns.length > 0 && <RecordRow label="NS" items={dns.ns} />}
                {dns.mx.length > 0 && <RecordRow label="MX" items={dns.mx} />}
                {(dns.txt.length > 0 || !dns.securityTxt.spf) && (
                  <div className="mt-3 pt-2 border-t border-border">
                    <div className="text-micro text-muted-foreground mb-1.5">EMAIL SECURITY</div>
                    <div className="flex flex-wrap gap-1">
                      <SecPill label="SPF"   on={dns.securityTxt.spf} />
                      <SecPill label="DMARC" on={dns.securityTxt.dmarc} />
                      <SecPill label="DKIM"  on={dns.securityTxt.dkim} />
                    </div>
                  </div>
                )}
              </DetailPanel>
            )}

            {/* TLS */}
            {tls && (
              <DetailPanel label={"// TLS CERTIFICATE"}>
                <CertBar tls={tls} />
                {(tls.wildcard || tls.expired || tls.self_signed) && (
                  <div className="flex flex-wrap gap-1 mb-2">
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
              </DetailPanel>
            )}

            {/* HTTP */}
            {http && (
              <DetailPanel label={"// HTTP"}>
                <div className="flex items-center gap-2 mb-2">
                  <RedirectChain codes={http.chain_status_codes} />
                </div>
                <MiniTable rows={[
                  { label: "SERVER", value: http.webserver || "—" },
                  { label: "TIME",   value: http.time },
                  { label: "TITLE",  value: http.title || "—" },
                  { label: "TYPE",   value: http.content_type },
                  ...(http.cname ? [{ label: "CNAME", value: http.cname }] : []),
                  ...(http.asn ? [{ label: "ASN", value: http.asn }] : []),
                  ...(http.jarm_hash ? [{ label: "JARM", value: http.jarm_hash }] : []),
                ]} />
                {http.tech.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-3">
                    {http.tech.map((t) => (
                      <DataChip key={t} className="px-1.5 text-muted-foreground">{t}</DataChip>
                    ))}
                  </div>
                )}
                {http.cpe.length > 0 && (
                  <div className="mt-2 pt-2 border-t border-border">
                    <div className="text-micro text-muted-foreground mb-1.5">CPE [{http.cpe.length}]</div>
                    <div className="flex flex-wrap gap-1">
                      {http.cpe.map((c) => (
                        <DataChip key={c} className="px-1.5 text-data">{c}</DataChip>
                      ))}
                    </div>
                  </div>
                )}
              </DetailPanel>
            )}
            {/* Uncover */}
            {uncover && uncover.entries.length > 0 && (
              <DetailPanel label={`// EXPOSED HOSTS [${uncover.entries.length}]`} className="md:col-span-2">
                <div className="flex flex-wrap gap-1 mb-2">
                  {uncover.sourceCounts.map(({ source, count }) => (
                    <DataChip key={source} className="px-1.5">{source} {count}</DataChip>
                  ))}
                </div>
                <div className="space-y-px max-h-[120px] overflow-y-auto">
                  {uncover.entries.map((e, i) => (
                    <div key={i} className="flex items-center gap-3 px-1 py-0.5 hover:bg-card transition-colors duration-100">
                      <span className="font-mono text-data text-foreground tabular-nums w-[90px] shrink-0">{e.ip}</span>
                      <span className="font-mono text-data text-muted-foreground-2 tabular-nums w-[40px] shrink-0">{e.port}</span>
                      <span className="font-mono text-data text-muted-foreground-3 truncate flex-1">{e.host || e.url}</span>
                    </div>
                  ))}
                </div>
              </DetailPanel>
            )}
          </div>

          {/* Scan history timeline — only when 2+ scan sessions exist */}
          {showTimeline && (
            <Panel label={`// SCAN HISTORY [${timeline.length} sessions]`} variant="inset" contentClassName="p-3">
              <ChartBoundary label="timeline">
                <ChartContainer config={TIMELINE_CONFIG} className="h-[160px] w-full aspect-auto">
                  <LineChart data={timeline} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
                    <XAxis dataKey="label" tick={CHART_TICK_SM} />
                    <YAxis yAxisId="cert" tick={CHART_TICK_SM} allowDecimals={false} />
                    <YAxis yAxisId="http" orientation="right" tick={CHART_TICK_SM} allowDecimals={false} />
                    <ChartTooltip
                      cursor={CHART_CURSOR}
                      content={<ChartTooltipContent className="rounded-none shadow-none" indicator="line" />}
                    />
                    <Line
                      yAxisId="cert"
                      type="monotone"
                      dataKey="certDays"
                      name="cert days"
                      stroke={CHART_FILLS[0]}
                      dot={false}
                      strokeWidth={1.5}
                    />
                    <Line
                      yAxisId="http"
                      type="monotone"
                      dataKey="httpStatus"
                      name="HTTP status"
                      stroke={CHART_FILLS[1]}
                      dot={false}
                      strokeWidth={1.5}
                    />
                  </LineChart>
                </ChartContainer>
              </ChartBoundary>
            </Panel>
          )}
        </div>
      )}
    </div>
  )
}

// Chart configs — defined at module level to avoid recreation on every render
const SUB_CAT_CONFIG = { count: { label: "Count" } } satisfies ChartConfig
const IP_DIST_CONFIG = { count: { label: "IPs" } } satisfies ChartConfig
const TIMELINE_CONFIG = {
  certDays:   { label: "cert days",   color: CHART_FILLS[0] },
  httpStatus: { label: "HTTP status", color: CHART_FILLS[1] },
} satisfies ChartConfig

function CertBar({ tls }: { tls: TlsResult }) {
  const totalDays = (new Date(tls.not_after).getTime() - new Date(tls.not_before).getTime()) / 86_400_000
  const pct = Math.min(100, Math.max(0, ((totalDays - tls.daysLeft) / totalDays) * 100))
  return (
    <div className="mb-3">
      <div className="flex justify-between text-micro text-muted-foreground mb-1">
        <span>{new Date(tls.not_before).toLocaleDateString()}</span>
        <span>{new Date(tls.not_after).toLocaleDateString()}</span>
      </div>
      <div className="h-1 bg-card-hover">
        <div className="h-full bg-foreground" style={{ width: `${pct}%` }} />
      </div>
      <p className={`text-body font-bold mt-1.5 ${certDaysCls(tls.daysLeft)}`}>{tls.daysLeft}d remaining</p>
    </div>
  )
}

function MiniTable({ rows }: { rows: { label: string; value: string }[] }) {
  return (
    <Table className="text-data mt-2">
      <TableBody>
        {rows.map(({ label, value }) => (
          <TableRow key={label} className="border-b border-card-hover hover:bg-transparent">
            <TableCell className="p-0 py-1 pr-3 text-muted-foreground whitespace-nowrap align-top">{label}</TableCell>
            <TableCell className="p-0 py-1 text-muted-foreground-2 text-right whitespace-normal break-all max-w-[160px]">{value}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

function Stat({ label, value, cls = "text-foreground" }: { label: string; value: string; cls?: string }) {
  return (
    <div className="px-3 text-center first:pl-0 last:pr-0">
      <div className="text-micro text-muted-foreground tracking-widest uppercase">{label}</div>
      <div className={`text-body font-bold tabular-nums leading-tight ${cls}`}>{value}</div>
    </div>
  )
}

function DetailPanel({ label, children, className }: { label: string; children: React.ReactNode; className?: string }) {
  return <Panel label={label} variant="inset" contentClassName="p-3" className={className}>{children}</Panel>
}

function RecordRow({ label, items }: { label: string; items: string[] }) {
  return (
    <div className="mt-2 flex items-baseline gap-2">
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
  const cls = danger ? "text-destructive" : on ? "text-terminal-green" : "text-destructive"
  const glyph = danger ? "!" : on ? "✓" : "✗"
  return (
    <span className={`font-mono text-micro border border-border bg-card-inset px-1.5 py-0.5 ${cls}`}>
      {glyph} {label}
    </span>
  )
}

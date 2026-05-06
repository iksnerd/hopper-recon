"use client"

import * as React from "react"
import { useSearchParams } from "next/navigation"
import { SidebarTrigger } from "@/components/ui/sidebar"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from "recharts"
import {
  parseSubdomains, parseDns, parseTls, parseHttp, parseUncover,
  type SubdomainResult, type DnsResult, type TlsResult, type HttpResult, type UncoverResult,
} from "@/lib/scan-parser"
import { TOOLTIP_STYLE, CHART_FILLS, CHART_TICK, CHART_TICK_SM, CHART_CURSOR } from "@/lib/chart-style"
import { Panel } from "@/components/recon/panel"
import { DataChip } from "@/components/recon/data-chip"
import { RedirectChain } from "@/components/recon/redirect-chain"
import { CopyButton } from "@/components/recon/copy-button"
import { CopyableText } from "@/components/ui/copyable-text"
import { ChartBoundary } from "@/components/recon/chart-boundary"
import { FindingsStrip } from "@/components/recon/findings-strip"
import { Badge } from "@/components/ui/badge"
import type { DomainSummary } from "@/app/api/scans/domains/route"

const TOOLS = [
  { id: "passive_subdomains", label: "SUBDOMAINS" },
  { id: "resolve_dns",        label: "DNS" },
  { id: "fetch_tls_cert",     label: "TLS" },
  { id: "probe_http",         label: "HTTP" },
  { id: "search_hosts",       label: "EXPOSE" },
] as const

type ToolId = (typeof TOOLS)[number]["id"]
type ToolState = "idle" | "loading" | "done" | "error"

interface ScanState {
  target: string
  states: Record<ToolId, ToolState>
  startedAt: Record<ToolId, number | null>
  durations: Partial<Record<ToolId, number>>
  subdomains: SubdomainResult | null
  dns: DnsResult | null
  tls: TlsResult | null
  http: HttpResult | null
  uncover: UncoverResult | null
  errors: Partial<Record<ToolId, string>>
}

const EMPTY_STATES: Record<ToolId, ToolState> = {
  passive_subdomains: "loading",
  resolve_dns: "loading",
  fetch_tls_cert: "loading",
  probe_http: "loading",
  search_hosts: "loading",
}

function tabSuffix(scan: ScanState, id: ToolId, elapsedTick: number): string {
  const state = scan.states[id]
  if (state === "loading") {
    const t = scan.startedAt[id]
    if (t == null) return ""
    const secs = Math.max(0, (elapsedTick - t) / 1000)
    return ` ${secs.toFixed(1)}s`
  }
  if (state === "error") return ""
  // done — show inline data
  if (id === "passive_subdomains" && scan.subdomains) return ` [${scan.subdomains.findings.length}]`
  if (id === "resolve_dns"        && scan.dns)        return ` [${scan.dns.a.length} IP${scan.dns.a.length === 1 ? "" : "s"}]`
  if (id === "fetch_tls_cert"     && scan.tls)        return ` [${scan.tls.daysLeft}d]`
  if (id === "probe_http"         && scan.http)       return ` [${scan.http.status_code}]`
  if (id === "search_hosts"       && scan.uncover)    return ` [${scan.uncover.entries.length}]`
  return ""
}

async function runTool(tool: ToolId, target: string) {
  const res = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tool, target }),
  })
  const text = await res.text()
  let data: { error?: string } | null = null
  try { data = text ? JSON.parse(text) : null } catch { /* non-JSON body */ }
  if (!res.ok) {
    throw new Error(data?.error ?? `Scan failed [${res.status}]`)
  }
  return data
}

function certDaysLabel(days: number): { label: string; cls: string } {
  if (days < 14) return { label: `${days}d`, cls: "text-destructive" }
  if (days < 30) return { label: `${days}d`, cls: "text-muted-foreground-2" }
  return { label: `${days}d`, cls: "text-primary" }
}

function httpStatusBracket(code: number): { label: string; cls: string } {
  if (code < 300) return { label: `[${code}]`, cls: "text-primary" }
  if (code < 400) return { label: `[${code}]`, cls: "text-muted-foreground-2" }
  return { label: `[${code}]`, cls: "text-destructive" }
}

export default function DashboardPage() {
  return (
    <React.Suspense fallback={null}>
      <DashboardInner />
    </React.Suspense>
  )
}

function DashboardInner() {
  const searchParams = useSearchParams()
  const initialDomain = searchParams.get("domain") ?? ""
  const [domain, setDomain] = React.useState(initialDomain)
  const [scan, setScan] = React.useState<ScanState | null>(null)
  const autoRanRef = React.useRef(false)
  const [now, setNow] = React.useState(() => Date.now())
  const [recentDomains, setRecentDomains] = React.useState<DomainSummary[] | null>(null)

  async function startScan(targetOverride?: string) {
    const target = (targetOverride ?? domain).trim()
    if (!target) return

    const t0 = Date.now()
    const initial: ScanState = {
      target,
      states: { ...EMPTY_STATES },
      startedAt: { passive_subdomains: t0, resolve_dns: t0, fetch_tls_cert: t0, probe_http: t0, search_hosts: t0 },
      durations: {},
      subdomains: null, dns: null, tls: null, http: null, uncover: null, errors: {},
    }
    setScan(initial)

    const jobs: Array<[ToolId, Promise<unknown>]> = TOOLS.map(({ id }) => [id, runTool(id, target)])

    for (const [tool, promise] of jobs) {
      promise
        .then((data) => {
          setScan((prev) => {
            if (!prev) return prev
            const start = prev.startedAt[tool] ?? Date.now()
            const dur = Date.now() - start
            return {
              ...prev,
              states: { ...prev.states, [tool]: "done" },
              durations: { ...prev.durations, [tool]: dur },
              ...(tool === "passive_subdomains" ? { subdomains: parseSubdomains(data) } : {}),
              ...(tool === "resolve_dns"        ? { dns: parseDns(data) }               : {}),
              ...(tool === "fetch_tls_cert"     ? { tls: parseTls(data) }               : {}),
              ...(tool === "probe_http"         ? { http: parseHttp(data) }             : {}),
              ...(tool === "search_hosts"       ? { uncover: parseUncover(data) }       : {}),
            }
          })
        })
        .catch((err: Error) => {
          setScan((prev) => {
            if (!prev) return prev
            const start = prev.startedAt[tool] ?? Date.now()
            return {
              ...prev,
              states: { ...prev.states, [tool]: "error" },
              durations: { ...prev.durations, [tool]: Date.now() - start },
              errors: { ...prev.errors, [tool]: err.message },
            }
          })
        })
    }
  }

  const allDone = scan && Object.values(scan.states).every((s) => s === "done" || s === "error")
  const anyLoading = scan && Object.values(scan.states).some((s) => s === "loading")

  // Tick ~10× per second while a tool is loading so elapsed-time labels feel live.
  React.useEffect(() => {
    if (!anyLoading) return
    const id = setInterval(() => setNow(Date.now()), 100)
    return () => clearInterval(id)
  }, [anyLoading])

  React.useEffect(() => {
    if (autoRanRef.current) return
    if (initialDomain && !scan) {
      autoRanRef.current = true
      // defer to next tick so we don't synchronously setState during mount effect
      const t = setTimeout(() => { void startScan(initialDomain) }, 0)
      return () => clearTimeout(t)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialDomain])

  React.useEffect(() => {
    fetch("/api/scans/domains")
      .then(async (r) => {
        const text = await r.text()
        if (!r.ok || !text) return []
        return JSON.parse(text) as DomainSummary[]
      })
      .then(setRecentDomains)
      .catch(() => setRecentDomains([]))
  }, [])

  return (
    <div className="min-h-screen font-mono text-foreground scanlines">
      {/* Header */}
      <header className="sticky top-0 z-10 bg-background border-b border-border px-4 py-3 flex items-center gap-3">
        <SidebarTrigger className="size-6 text-muted-foreground hover:text-foreground hover:bg-card-hover rounded-none transition-colors duration-100" />
        <span className="text-muted">/</span>
        <span className="text-body text-foreground">dashboard</span>
        {scan && (
          <>
            <span className="text-muted">/</span>
            <span className="text-body text-muted-foreground-2">{scan.target}</span>
          </>
        )}
      </header>

      <div className="px-4 sm:px-8 lg:px-12 py-6 sm:py-8 space-y-6 sm:space-y-8">
        {/* Scan form */}
        <div className="border border-border bg-card p-5">
          <div className="text-micro uppercase text-muted-foreground mb-3">{"// TARGET"}</div>
          <div className="flex gap-3 items-center">
            <span className="text-muted-foreground text-emphasis select-none shrink-0">&gt;_</span>
            <Input
              placeholder="example.com"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && startScan()}
              className="flex-1 font-mono bg-transparent border-border rounded-none shadow-none text-foreground placeholder:text-muted-foreground-3 focus-visible:ring-0 focus-visible:border-muted-foreground h-10 text-emphasis"
            />
            <Button
              variant="outline"
              onClick={() => startScan()}
              disabled={!domain.trim() || (!!scan && !allDone)}
              className="rounded-none border-border bg-transparent text-foreground hover:text-primary hover:bg-card-hover shadow-none ring-0 focus-visible:ring-0 active:translate-y-0 h-10 px-5 text-emphasis font-mono shrink-0 disabled:opacity-30"
            >
              {scan && !allDone
                ? <span className="cursor-blink inline-block w-[1ch]">█</span>
                : "execute"}
            </Button>
          </div>
        </div>

        {!scan && recentDomains !== null && recentDomains.length > 0 && (
          <div className="border border-border bg-card p-5">
            <div className="text-micro uppercase text-muted-foreground mb-3">{"// RECENT TARGETS"}</div>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-px bg-secondary">
              {recentDomains.slice(0, 8).map((d) => (
                <RecentTargetTile
                  key={d.domain}
                  summary={d}
                  onScan={() => { setDomain(d.domain); void startScan(d.domain) }}
                />
              ))}
            </div>
          </div>
        )}

        {scan && (
          <>
            {/* Summary strip */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-px bg-secondary">
              <MetricCell
                label="SUBDOMAINS"
                value={scan.subdomains ? scan.subdomains.findings.length.toString() : "—"}
                sub="via subfinder"
                loading={scan.states.passive_subdomains === "loading"}
              />
              <MetricCell
                label="A RECORDS"
                value={scan.dns ? scan.dns.a.length.toString() : "—"}
                sub={scan.dns ? `ttl ${scan.dns.ttl}s` : "resolving"}
                loading={scan.states.resolve_dns === "loading"}
              />
              <MetricCell
                label="CERT EXPIRY"
                value={scan.tls ? certDaysLabel(scan.tls.daysLeft).label : "—"}
                valueClass={scan.tls ? certDaysLabel(scan.tls.daysLeft).cls : ""}
                sub={scan.tls ? new Date(scan.tls.not_after).toLocaleDateString() : "fetching"}
                loading={scan.states.fetch_tls_cert === "loading"}
              />
              <MetricCell
                label="HTTP"
                value={scan.http ? httpStatusBracket(scan.http.status_code).label : "—"}
                valueClass={scan.http ? httpStatusBracket(scan.http.status_code).cls : ""}
                sub={scan.http?.webserver ?? "probing"}
                loading={scan.states.probe_http === "loading"}
              />
            </div>

            {/* Results: two-column at lg (findings left, tabs right) */}
            <div className="lg:grid lg:grid-cols-[300px_1fr] lg:gap-6 lg:items-start">
              <div>
                {(scan.subdomains || scan.dns || scan.tls || scan.http) && (
                  <FindingsStrip
                    subs={scan.subdomains}
                    dns={scan.dns}
                    tls={scan.tls}
                    http={scan.http}
                  />
                )}
              </div>

              <div>
            {/* Results tabs */}
            <Tabs defaultValue="passive_subdomains">
              <TabsList className="bg-transparent border-b border-border rounded-none w-full justify-start h-auto p-0 gap-0 overflow-x-auto">
                {TOOLS.map(({ id, label }) => (
                  <TabsTrigger
                    key={id}
                    value={id}
                    className="font-mono text-micro text-muted-foreground rounded-none border-b-2 border-transparent px-5 py-3 data-[state=active]:text-foreground data-[state=active]:border-foreground data-[state=active]:bg-transparent hover:text-muted-foreground-2 transition-colors duration-100 gap-2 shadow-none whitespace-nowrap"
                  >
                    <span>{label}<span className="tabular-nums">{tabSuffix(scan, id, now)}</span></span>
                    {scan.states[id] === "loading" && <span className="cursor-blink text-muted-foreground-3">▮</span>}
                    {scan.states[id] === "error"   && <span className="text-destructive text-micro">[ERR]</span>}
                    {scan.states[id] === "done"    && <span className="text-muted-foreground text-micro">[OK{scan.durations[id] != null ? ` ${(scan.durations[id]! / 1000).toFixed(1)}s` : ""}]</span>}
                  </TabsTrigger>
                ))}
              </TabsList>

              {/* Subdomains */}
              <TabsContent value="passive_subdomains" className="pt-4 mt-0">
                <ToolPanel state={scan.states.passive_subdomains} error={scan.errors.passive_subdomains}>
                  {scan.subdomains && (
                    <div className="space-y-4">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <Panel label={"// BY CATEGORY"}>
                          {scan.subdomains.categories.length > 0 ? (
                            <ChartBoundary label="categories"><ResponsiveContainer width="100%" height={200}>
                              <BarChart data={scan.subdomains.categories} layout="vertical" margin={{ left: 16 }}>
                                <XAxis type="number" hide />
                                <YAxis
                                  type="category"
                                  dataKey="category"
                                  width={110}
                                  tick={CHART_TICK}
                                />
                                <Tooltip cursor={CHART_CURSOR} contentStyle={TOOLTIP_STYLE} />
                                <Bar dataKey="count" radius={0}>
                                  {scan.subdomains.categories.map((_, i) => (
                                    <Cell key={i} fill={CHART_FILLS[Math.min(i, CHART_FILLS.length - 1)]} />
                                  ))}
                                </Bar>
                              </BarChart>
                            </ResponsiveContainer></ChartBoundary>
                          ) : (
                            <p className="text-body text-muted-foreground py-6">no categorized subdomains</p>
                          )}
                        </Panel>
                        <Panel label={"// BY SOURCE"}>
                          {scan.subdomains.sourceCounts.length > 0 ? (
                            <ChartBoundary label="sources"><ResponsiveContainer width="100%" height={200}>
                              <BarChart data={scan.subdomains.sourceCounts} layout="vertical" margin={{ left: 16 }}>
                                <XAxis type="number" hide />
                                <YAxis
                                  type="category"
                                  dataKey="source"
                                  width={110}
                                  tick={CHART_TICK}
                                />
                                <Tooltip cursor={CHART_CURSOR} contentStyle={TOOLTIP_STYLE} />
                                <Bar dataKey="count" radius={0}>
                                  {scan.subdomains.sourceCounts.map((_, i) => (
                                    <Cell key={i} fill={CHART_FILLS[Math.min(i, CHART_FILLS.length - 1)]} />
                                  ))}
                                </Bar>
                              </BarChart>
                            </ResponsiveContainer></ChartBoundary>
                          ) : (
                            <p className="text-body text-muted-foreground py-6">no source data — legacy scan format</p>
                          )}
                        </Panel>
                      </div>
                      <Panel label={`// ALL SUBDOMAINS [${scan.subdomains.findings.length}]`}>
                        {scan.subdomains.findings.length === 0 ? (
                          <p className="text-body text-muted-foreground py-6">no subdomains found — api keys may expand coverage</p>
                        ) : (
                          <div className="space-y-1 max-h-[280px] overflow-y-auto">
                            {scan.subdomains.findings.map(({ host }) => (
                              <CopyableText
                                key={host}
                                text={host}
                                className="text-sm"
                              />
                            ))}
                          </div>
                        )}
                      </Panel>
                    </div>
                  )}
                </ToolPanel>
              </TabsContent>

              {/* DNS */}
              <TabsContent value="resolve_dns" className="pt-4 mt-0">
                <ToolPanel state={scan.states.resolve_dns} error={scan.errors.resolve_dns}>
                  {scan.dns && (
                  <>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <Panel label={"// IP DISTRIBUTION"}>
                        <ChartBoundary label="ip-dist"><ResponsiveContainer width="100%" height={200}>
                          <BarChart data={scan.dns.ipDistribution}>
                            <XAxis dataKey="prefix" tick={CHART_TICK_SM} />
                            <YAxis allowDecimals={false} tick={CHART_TICK} />
                            <Tooltip cursor={CHART_CURSOR} contentStyle={TOOLTIP_STYLE} />
                            <Bar dataKey="count" radius={0}>
                              {scan.dns.ipDistribution.map((_, i) => (
                                <Cell key={i} fill={CHART_FILLS[Math.min(i, CHART_FILLS.length - 1)]} />
                              ))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer></ChartBoundary>
                      </Panel>
                      <Panel label={"// RECORDS"}>
                        <Table className="text-body">
                          <TableBody>
                            <DataRow label="STATUS" value={`[${scan.dns.status_code}]`} />
                            <DataRow label="TTL" value={`${scan.dns.ttl}s`} />
                            <DataRow label="RESOLVERS" value={scan.dns.resolver.join(", ")} mono />
                            {scan.dns.cdn && <DataRow label="CDN" value={scan.dns.cdn} />}
                            {scan.dns.asn && <DataRow label="ASN" value={scan.dns.asn} mono />}
                            <ChipsRow label="A RECORDS" items={scan.dns.a} />
                            {scan.dns.ns.length > 0 && <ChipsRow label="NS" items={scan.dns.ns} />}
                            {scan.dns.mx.length > 0 && <ChipsRow label="MX" items={scan.dns.mx} />}
                          </TableBody>
                        </Table>
                      </Panel>
                    </div>

                    <Panel label={"// EMAIL SECURITY (TXT)"} className="mt-4">
                      <div className="flex flex-wrap gap-2">
                        <SecurityTxtBadge label="SPF"   present={scan.dns.securityTxt.spf} />
                        <SecurityTxtBadge label="DMARC" present={scan.dns.securityTxt.dmarc} />
                        <SecurityTxtBadge label="DKIM"  present={scan.dns.securityTxt.dkim} />
                      </div>
                      {scan.dns.txt.length > 0 ? (
                        <div className="mt-3 space-y-1 max-h-[140px] overflow-y-auto">
                          {scan.dns.txt.map((t, i) => (
                            <CopyableText key={i} text={t} variant="code" className="text-xs" />
                          ))}
                        </div>
                      ) : (
                        <p className="text-body text-muted-foreground-3 mt-3">no TXT records — email spoofing protection missing</p>
                      )}
                    </Panel>
                  </>
                  )}
                </ToolPanel>
              </TabsContent>

              {/* TLS */}
              <TabsContent value="fetch_tls_cert" className="pt-4 mt-0">
                <ToolPanel state={scan.states.fetch_tls_cert} error={scan.errors.fetch_tls_cert}>
                  {scan.tls && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <Panel label={"// VALIDITY WINDOW"}>
                        <CertValidityBar tls={scan.tls} />
                      </Panel>
                      <Panel label={"// CERTIFICATE"}>
                        {(scan.tls.wildcard || scan.tls.expired || scan.tls.self_signed) && (
                          <div className="flex flex-wrap gap-2 mb-3">
                            <TlsHardeningBadge label="WILDCARD" flag={scan.tls.wildcard} />
                            <TlsHardeningBadge label="EXPIRED" flag={scan.tls.expired} danger />
                            <TlsHardeningBadge label="SELF-SIGNED" flag={scan.tls.self_signed} danger />
                          </div>
                        )}
                        <Table className="text-body">
                          <TableBody>
                            <DataRow label="SUBJECT CN" value={scan.tls.subject_cn} mono />
                            <DataRow label="ISSUER" value={`${scan.tls.issuer_cn} (${scan.tls.issuer_org[0] ?? ""})`} />
                            <DataRow label="TLS" value={scan.tls.tls_version.toUpperCase()} />
                            <DataRow label="CIPHER" value={scan.tls.cipher} mono />
                            {scan.tls.serial && <DataRow label="SERIAL" value={scan.tls.serial} mono />}
                            <ChipsRow label="SANS" items={scan.tls.subject_an} />
                          </TableBody>
                        </Table>
                      </Panel>
                    </div>
                  )}
                </ToolPanel>
              </TabsContent>

              {/* HTTP */}
              <TabsContent value="probe_http" className="pt-4 mt-0">
                <ToolPanel state={scan.states.probe_http} error={scan.errors.probe_http}>
                  {scan.http && (
                    <Panel label={"// HTTP PROBE"}>
                      <div className="flex items-center gap-3 mb-3">
                        <RedirectChain codes={scan.http.chain_status_codes} />
                        <span className="text-body text-muted-foreground truncate flex-1">{scan.http.final_url || scan.http.url}</span>
                      </div>
                      <Table className="text-body mb-3">
                        <TableBody>
                          <DataRow label="SERVER" value={scan.http.webserver || "—"} />
                          <DataRow label="RESPONSE TIME" value={scan.http.time} mono />
                          <DataRow label="TITLE" value={scan.http.title || "—"} />
                          <DataRow label="CONTENT LENGTH" value={`${scan.http.content_length} bytes`} />
                          <DataRow label="CONTENT TYPE" value={scan.http.content_type || "—"} />
                          {scan.http.cname && <DataRow label="CNAME" value={scan.http.cname} mono />}
                          {scan.http.asn && <DataRow label="ASN" value={scan.http.asn} mono />}
                          {scan.http.jarm_hash && (
                            <TableRow className="border-b border-card-hover hover:bg-transparent">
                              <TableCell className="p-0 py-1.5 pr-4 text-muted-foreground align-top whitespace-nowrap">JARM</TableCell>
                              <TableCell className="p-0 py-1.5 text-right">
                                <div className="flex items-center gap-2 justify-end">
                                  <span className="font-mono text-data text-muted-foreground-2 truncate max-w-[140px] sm:max-w-[280px]">{scan.http.jarm_hash}</span>
                                  <CopyButton value={scan.http.jarm_hash} />
                                </div>
                              </TableCell>
                            </TableRow>
                          )}
                        </TableBody>
                      </Table>
                      <div className="border-t border-border pt-3">
                        <div className="text-micro text-muted-foreground mb-2">TECHNOLOGIES</div>
                        <div className="flex flex-wrap gap-1">
                          {scan.http.tech.length > 0
                            ? scan.http.tech.map((t) => <DataChip key={t}>{t}</DataChip>)
                            : <span className="text-body text-muted-foreground-3">none detected</span>}
                        </div>
                      </div>
                      {scan.http.cpe.length > 0 && (
                        <div className="border-t border-border pt-3 mt-3">
                          <div className="text-micro text-muted-foreground mb-2">CPE [{scan.http.cpe.length}]</div>
                          <div className="flex flex-wrap gap-1">
                            {scan.http.cpe.map((c) => <DataChip key={c} className="text-data">{c}</DataChip>)}
                          </div>
                        </div>
                      )}
                      {scan.http.a.length > 0 && (
                        <div className="border-t border-border pt-3 mt-3">
                          <div className="text-micro text-muted-foreground mb-2">IPS [{scan.http.a.length}]</div>
                          <div className="flex flex-wrap gap-1">
                            {scan.http.a.map((ip) => <DataChip key={ip}>{ip}</DataChip>)}
                          </div>
                        </div>
                      )}
                    </Panel>
                  )}
                </ToolPanel>
              </TabsContent>
              {/* Expose / Uncover */}
              <TabsContent value="search_hosts" className="pt-4 mt-0">
                <ToolPanel state={scan.states.search_hosts} error={scan.errors.search_hosts}>
                  {scan.uncover && (
                    <div className="space-y-4">
                      {scan.uncover.entries.length === 0 ? (
                        <Panel label="// EXPOSED HOSTS">
                          <p className="text-body text-muted-foreground py-6">no results — add API keys to <span className="font-mono">~/.config/uncover/provider-config.yaml</span> for broader coverage</p>
                        </Panel>
                      ) : (
                        <>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <Panel label="// OPEN PORTS">
                              <ChartBoundary label="ports">
                                <ResponsiveContainer width="100%" height={200}>
                                  <BarChart data={scan.uncover.portCounts} layout="vertical" margin={{ left: 8 }}>
                                    <XAxis type="number" hide />
                                    <YAxis type="category" dataKey="port" width={50} tick={CHART_TICK} />
                                    <Tooltip cursor={CHART_CURSOR} contentStyle={TOOLTIP_STYLE} />
                                    <Bar dataKey="count" radius={0}>
                                      {scan.uncover.portCounts.map((_, i) => (
                                        <Cell key={i} fill={CHART_FILLS[Math.min(i, CHART_FILLS.length - 1)]} />
                                      ))}
                                    </Bar>
                                  </BarChart>
                                </ResponsiveContainer>
                              </ChartBoundary>
                            </Panel>
                            <Panel label="// SOURCES">
                              <div className="flex flex-wrap gap-1 pt-1">
                                {scan.uncover.sourceCounts.map(({ source, count }) => (
                                  <DataChip key={source}>{source} {count}</DataChip>
                                ))}
                              </div>
                            </Panel>
                          </div>
                          <Panel label={`// HOSTS [${scan.uncover.entries.length}]`}>
                            <div className="space-y-px max-h-[320px] overflow-y-auto">
                              {scan.uncover.entries.map((e, i) => (
                                <div key={i} className="flex items-center gap-3 px-1 py-1 hover:bg-card-hover transition-colors duration-100">
                                  <span className="font-mono text-data text-foreground tabular-nums w-[100px] shrink-0">{e.ip}</span>
                                  <span className="font-mono text-data text-muted-foreground-2 tabular-nums w-[48px] shrink-0">{e.port}</span>
                                  <span className="font-mono text-data text-muted-foreground-3 truncate flex-1">{e.host || e.url}</span>
                                  <DataChip className="shrink-0">{e.source}</DataChip>
                                </div>
                              ))}
                            </div>
                          </Panel>
                        </>
                      )}
                    </div>
                  )}
                </ToolPanel>
              </TabsContent>
            </Tabs>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

function ToolPanel({ state, error, children }: {
  state: ToolState
  error?: string
  children: React.ReactNode
}) {
  if (state === "loading") {
    return (
      <div className="flex items-center gap-2 h-32 px-2 text-muted-foreground text-body">
        <span className="cursor-blink">█</span>
        <span>scanning...</span>
      </div>
    )
  }
  if (state === "error") {
    return (
      <div className="border border-destructive bg-card p-4 text-body text-destructive">
        <span className="text-muted-foreground mr-2">[ERR]</span>{error ?? "scan failed"}
      </div>
    )
  }
  return <>{children}</>
}

function MetricCell({ label, value, sub, loading, valueClass }: {
  label: string; value: string; sub: string; loading?: boolean; valueClass?: string
}) {
  return (
    <div className="bg-card p-4">
      <div className="text-micro text-muted-foreground mb-2">{label}</div>
      {loading
        ? <div className="text-metric text-muted-foreground-3 cursor-blink">█</div>
        : <div className={`text-metric tabular-nums ${valueClass ?? "text-primary"}`}>{value}</div>}
      <div className="text-body text-muted-foreground-3 mt-1">{sub}</div>
    </div>
  )
}

function CertValidityBar({ tls }: { tls: NonNullable<ScanState["tls"]> }) {
  const totalDays = (new Date(tls.not_after).getTime() - new Date(tls.not_before).getTime()) / 86_400_000
  const pct = Math.min(100, Math.max(0, ((totalDays - tls.daysLeft) / totalDays) * 100))
  const { label, cls } = certDaysLabel(tls.daysLeft)
  return (
    <div className="space-y-3">
      <div className="flex justify-between text-body text-muted-foreground">
        <span>{new Date(tls.not_before).toLocaleDateString()}</span>
        <span>{new Date(tls.not_after).toLocaleDateString()}</span>
      </div>
      <div className="h-1 bg-card-hover overflow-hidden">
        <div className="h-full bg-foreground transition-all duration-300" style={{ width: `${pct}%` }} />
      </div>
      <p className={`text-emphasis font-bold ${cls}`}>{label} remaining</p>
    </div>
  )
}

function DataRow({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <TableRow className="border-b border-card-hover hover:bg-transparent">
      <TableCell className="p-0 py-1.5 pr-4 text-muted-foreground align-top whitespace-nowrap">{label}</TableCell>
      <TableCell className={`p-0 py-1.5 text-right text-foreground whitespace-normal break-all ${mono ? "font-mono" : ""}`}>{value}</TableCell>
    </TableRow>
  )
}

function ChipsRow({ label, items }: { label: string; items: string[] }) {
  return (
    <TableRow className="border-b border-card-hover hover:bg-transparent">
      <TableCell className="p-0 py-1.5 pr-4 text-muted-foreground align-top whitespace-nowrap">{label}</TableCell>
      <TableCell className="p-0 py-1.5 text-right">
        <div className="flex flex-wrap gap-1 justify-end">
          {items.map((v) => <DataChip key={v}>{v}</DataChip>)}
        </div>
      </TableCell>
    </TableRow>
  )
}

function SecurityTxtBadge({ label, present }: { label: string; present: boolean }) {
  return (
    <Badge
      variant="outline"
      className={`rounded-none h-auto py-0.5 px-2 text-micro font-mono font-normal border-border ${present ? "bg-card-inset text-primary" : "bg-card-inset text-destructive"}`}
    >
      {present ? "✓" : "✗"} {label}
    </Badge>
  )
}

function TlsHardeningBadge({ label, flag, danger }: { label: string; flag: boolean; danger?: boolean }) {
  if (!flag) return null
  return (
    <Badge
      variant="outline"
      className={`rounded-none h-auto py-0.5 px-2 text-micro font-mono font-normal border-border bg-card-inset ${danger ? "text-destructive" : "text-muted-foreground-2"}`}
    >
      {label}
    </Badge>
  )
}

function RecentTargetTile({ summary, onScan }: { summary: DomainSummary; onScan: () => void }) {
  const httpRow = summary.scans.probe_http
  const tlsRow = summary.scans.fetch_tls_cert
  // useState initializer runs once at mount — avoids impure Date.now() in render
  const [mountTime] = React.useState(() => Date.now())
  const certDays = tlsRow?.cert_expiry
    ? Math.floor((new Date(tlsRow.cert_expiry).getTime() - mountTime) / 86_400_000)
    : null

  return (
    <button
      onClick={onScan}
      className="bg-card p-3 text-left hover:bg-card-hover transition-colors duration-100 group w-full"
    >
      <div className="text-body text-foreground group-hover:text-primary truncate font-mono">{summary.domain}</div>
      <div className="flex items-center gap-3 mt-1.5 flex-wrap">
        {httpRow?.http_status != null && (
          <span className={`text-micro tabular-nums ${httpStatusBracket(httpRow.http_status).cls}`}>
            {httpStatusBracket(httpRow.http_status).label}
          </span>
        )}
        {certDays != null && (
          <span className={`text-micro tabular-nums ${certDaysLabel(certDays).cls}`}>
            cert {certDays}d
          </span>
        )}
      </div>
    </button>
  )
}

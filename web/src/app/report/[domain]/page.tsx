"use client"

// Printable security report for one domain. Lives outside the (app) route
// group so it renders without the sidebar. "Save as PDF" uses the browser's
// print dialog; the page is styled for A4 paper in light colours regardless of
// the dashboard theme.

import * as React from "react"
import Link from "next/link"
import { useParams } from "next/navigation"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { queryKeys } from "@/lib/query-keys"
import type { ScanRow } from "@/lib/db"
import { buildSummary, previousCompleted, rowResults, toolResults } from "@/lib/domain-summary"
import { parseDns, parseTls, parseHttp, parseSubdomains, parseDomains, type DnsResult, type TlsResult, type HttpResult } from "@/lib/scan-parser"
import { diffDns, type DnsDiff } from "@/lib/scan-diff"
import { runFullScan, type ScanOutcome } from "@/lib/run-scans"
import { dmarcEnforces, suggestDmarc, type EmailAuth } from "@/lib/email-auth"
import { deriveFindings, type Finding } from "@/components/recon/findings-strip"
import { certDaysLabel } from "@/lib/recon-display"

const SEVERITY_ORDER = { issue: 0, info: 1, ok: 2 } as const
const SEVERITY_LABEL = { issue: "ISSUE", info: "NOTICE", ok: "OK" } as const
const SEVERITY_CLS = {
  issue: "border-red-700 text-red-800 bg-red-50",
  info: "border-amber-600 text-amber-800 bg-amber-50",
  ok: "border-green-700 text-green-800 bg-green-50",
} as const

const SCAN_TOOLS: { tool: string; what: string }[] = [
  { tool: "resolve_dns", what: "DNS records, including SPF, DMARC and a short list of DKIM selectors" },
  { tool: "fetch_tls_cert", what: "TLS certificate" },
  { tool: "probe_http", what: "HTTP response" },
  { tool: "passive_subdomains", what: "Subdomains from public sources" },
  { tool: "find_domains", what: "Sibling domains: the same name under other top-level domains" },
]

function fmt(ts: string | undefined) {
  return ts ? new Date(ts).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "—"
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mt-8">
      <h2 className="text-base font-semibold border-b border-neutral-300 pb-1 mb-3 break-after-avoid-page">{title}</h2>
      {children}
    </section>
  )
}

function Code({ children }: { children: React.ReactNode }) {
  return <code className="block font-mono text-xs bg-neutral-100 border border-neutral-300 px-2 py-1.5 break-all whitespace-pre-wrap">{children}</code>
}

function Pill({ severity }: { severity: Finding["severity"] }) {
  return <span className={`inline-block border px-1.5 py-0.5 text-[10px] font-semibold tracking-wider ${SEVERITY_CLS[severity]}`}>{SEVERITY_LABEL[severity]}</span>
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <tr className="align-top">
      <th scope="row" className="text-left font-medium text-neutral-600 pr-4 py-1 w-40 whitespace-nowrap">{label}</th>
      <td className="py-1 break-words">{children}</td>
    </tr>
  )
}

function ChangesSection({ diff, since }: { diff: DnsDiff; since: string }) {
  const empty = diff.changes.length === 0 && diff.resolved.length === 0 && diff.appeared.length === 0
  return (
    <Section title={`Changes since the previous scan (${since})`}>
      {empty ? (
        <p className="text-neutral-700">No change in DNS or email records.</p>
      ) : (
        <div className="space-y-3">
          {diff.changes.map((c) => (
            <div key={c.label} className="break-inside-avoid">
              <div className="text-xs font-semibold text-neutral-600 mb-1">{c.label}</div>
              <Code>{`− ${c.before}\n+ ${c.after}`}</Code>
            </div>
          ))}
          {diff.resolved.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-neutral-600 mb-1">No longer reported</div>
              <ul className="list-disc pl-5 space-y-0.5">{diff.resolved.map((f) => <li key={f.id}>{f.message}</li>)}</ul>
            </div>
          )}
          {diff.appeared.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-neutral-600 mb-1">Newly reported</div>
              <ul className="list-disc pl-5 space-y-0.5">{diff.appeared.map((f) => <li key={f.id}>{f.message}</li>)}</ul>
            </div>
          )}
        </div>
      )}
    </Section>
  )
}

function FullScan({ domain }: { domain: string }) {
  const queryClient = useQueryClient()
  const [running, setRunning] = React.useState(false)
  const [step, setStep] = React.useState("")
  const [failed, setFailed] = React.useState<ScanOutcome[]>([])

  async function start() {
    setRunning(true)
    setFailed([])
    const outcomes = await runFullScan(domain, (tool, i, n) => setStep(`${i + 1}/${n} ${tool}`))
    await queryClient.invalidateQueries({ queryKey: queryKeys.domainRows(domain) })
    setFailed(outcomes.filter((o) => !o.ok))
    setRunning(false)
    setStep("")
  }

  return (
    <div className="text-sm">
      <button
        type="button"
        onClick={start}
        disabled={running}
        className="border border-neutral-400 bg-white px-3 py-1 hover:bg-neutral-100 disabled:opacity-50"
      >
        {running ? `Scanning ${step}…` : "Run full scan"}
      </button>
      <span className="ml-3 text-xs text-neutral-600">
        Sends DNS, TLS and HTTP requests to {domain} and queries public sources. Takes up to a minute.
      </span>
      {failed.length > 0 && (
        <ul className="mt-2 text-xs text-red-800">
          {failed.map((f) => <li key={f.tool}>{f.tool} failed: {f.error}</li>)}
        </ul>
      )}
    </div>
  )
}

function EmailSection({ domain, email }: { domain: string; email: EmailAuth }) {
  const { spf, dmarc, dkim } = email
  const suggestion = suggestDmarc(domain, dmarc)
  return (
    <Section title="Email authentication">
      <p className="text-sm text-neutral-700 mb-3">
        Three DNS records decide whether mail that claims to be from {domain} is trusted. SPF lists the servers allowed to send it, DKIM
        signs each message, and DMARC says what receivers do with mail that fails both and where to send reports.
      </p>
      <table className="w-full text-sm">
        <tbody>
          <Row label="SPF record">{spf.present ? <Code>{spf.record}</Code> : "None published"}</Row>
          {spf.present && <Row label="SPF ends in">{spf.all ?? "no terminating all"}{spf.all === "~all" ? " (softfail: unlisted senders are marked suspicious, not rejected)" : spf.all === "-all" ? " (hard fail)" : ""}</Row>}
          {spf.includes.length > 0 && <Row label="SPF authorises">{spf.includes.join(", ")}</Row>}
          {spf.lookups && <Row label="SPF DNS lookups">{`${spf.lookups.complete ? "" : "at least "}${spf.lookups.count} of 10 allowed${spf.lookups.count > 10 ? " (over the limit: SPF fails for every message)" : ""}`}</Row>}
          <Row label="DMARC record">{dmarc.present ? <Code>{dmarc.record}</Code> : "None published"}</Row>
          {dmarc.present && (
            <>
              <Row label="Policy (p)">{dmarc.policy ?? "missing or invalid"}{dmarc.policy === "none" ? " (monitor only: failing mail is still delivered)" : ""}</Row>
              <Row label="Subdomains (sp)">{dmarc.subPolicy ?? `not set, subdomains follow p=${dmarc.policy ?? "?"}`}</Row>
              <Row label="Applies to (pct)">{dmarc.pct}% of failing mail</Row>
              <Row label="Reports (rua)">{dmarc.rua.length ? dmarc.rua.join(", ") : "none requested"}</Row>
              <Row label="Alignment">{`DKIM ${dmarc.adkim === "s" ? "strict" : "relaxed"}, SPF ${dmarc.aspf === "s" ? "strict" : "relaxed"}`}</Row>
            </>
          )}
          <Row label="DKIM keys">{dkim.keys} found at common selectors{dkim.selectors && dkim.selectors.length > 0 ? ` (${dkim.selectors.join(", ")})` : ""}</Row>
          {email.mailPolicy && (
            <>
              <Row label="MTA-STS">{email.mailPolicy.mtaSts[0] ? <Code>{email.mailPolicy.mtaSts[0]}</Code> : "none published"}</Row>
              <Row label="TLS-RPT">{email.mailPolicy.tlsRpt[0] ? <Code>{email.mailPolicy.tlsRpt[0]}</Code> : "none published"}</Row>
              <Row label="BIMI">{email.mailPolicy.bimi[0] ? <Code>{email.mailPolicy.bimi[0]}</Code> : "none published"}</Row>
            </>
          )}
        </tbody>
      </table>

      {suggestion && (
        <div className="mt-5 break-inside-avoid">
          <h3 className="text-sm font-semibold mb-1">Suggested change</h3>
          <p className="text-sm text-neutral-700 mb-2">
            Edit the existing TXT record for <span className="font-mono">_dmarc.{domain}</span>. Do not add a second one: two DMARC records
            make receivers ignore both.
          </p>
          <div className="text-xs font-semibold text-neutral-600 mb-1">Publish</div>
          <Code>{suggestion}</Code>
          {dmarc.present && (
            <>
              <div className="text-xs font-semibold text-neutral-600 mt-2 mb-1">Roll back to</div>
              <Code>{dmarc.record}</Code>
            </>
          )}
          <p className="text-sm text-neutral-700 mt-3">
            Before enforcing, read the aggregate reports sent to the rua address and confirm every legitimate sender (the mail provider,
            billing, ticketing, marketing tools) passes SPF or DKIM aligned with {domain}. Mail from a sender that is missed will go to
            spam. When reports stay clean, move to p=reject, and tighten SPF to -all.
          </p>
        </div>
      )}
    </Section>
  )
}

export default function ReportPage() {
  const params = useParams()
  const domain = decodeURIComponent(params.domain as string)

  const { data: rows, isPending } = useQuery({
    queryKey: queryKeys.domainRows(domain),
    queryFn: async (): Promise<ScanRow[]> => {
      const r = await fetch(`/api/scans/domains/${encodeURIComponent(domain)}`)
      const text = await r.text()
      if (!r.ok || !text) return []
      return JSON.parse(text) as ScanRow[]
    },
  })

  React.useEffect(() => {
    // The browser uses the page title as the default PDF file name.
    const previous = document.title
    document.title = `${domain} security report`
    return () => { document.title = previous }
  }, [domain])

  const summary = rows?.length ? buildSummary(rows, domain) : null
  const dnsRaw = toolResults(summary, "resolve_dns")
  const tlsRaw = toolResults(summary, "fetch_tls_cert")
  const httpRaw = toolResults(summary, "probe_http")
  const subRaw = toolResults(summary, "passive_subdomains")
  const dns: DnsResult | null = dnsRaw ? parseDns({ results: dnsRaw }) : null
  const tls: TlsResult | null = tlsRaw ? parseTls({ results: tlsRaw }) : null
  const http: HttpResult | null = httpRaw ? parseHttp({ results: httpRaw }) : null
  const subs = subRaw ? parseSubdomains({ results: subRaw }) : null
  const domainsRaw = toolResults(summary, "find_domains")
  const siblings = domainsRaw ? parseDomains({ results: domainsRaw }).findings.filter((d) => d.host !== domain) : null

  const prevDnsRow = rows ? previousCompleted(rows, "resolve_dns") : null
  const prevDnsRaw = rowResults(prevDnsRow)
  const prevDns: DnsResult | null = prevDnsRaw ? parseDns({ results: prevDnsRaw }) : null
  const diff = dns && prevDns ? diffDns(prevDns, dns) : null

  const findings = deriveFindings({ subs, dns, tls, http })
    .map((f, i) => ({ f, i }))
    .sort((a, b) => SEVERITY_ORDER[a.f.severity] - SEVERITY_ORDER[b.f.severity] || a.i - b.i)
    .map(({ f }) => f)
  const count = (s: Finding["severity"]) => findings.filter((f) => f.severity === s).length
  const spoofable = dns ? !dmarcEnforces(dns.email.dmarc) : false

  return (
    <div
      className="mx-auto max-w-3xl px-6 py-8 bg-white text-neutral-900 text-sm leading-relaxed min-h-screen"
      style={{ fontFamily: "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif" }}
    >
      <style>{`
        @page { size: A4; margin: 14mm; }
        :root { color-scheme: light !important; }
        html, body { background: #fff !important; color: #111 !important; }
        @media print {
          .no-print, nextjs-portal { display: none !important; }
        }
      `}</style>

      <div className="no-print flex items-center justify-between gap-3 mb-6 border border-neutral-300 bg-neutral-50 px-3 py-2">
        <Link href={`/history/${encodeURIComponent(domain)}`} className="text-sm text-neutral-700 underline">← back to {domain}</Link>
        <button
          type="button"
          onClick={() => window.print()}
          className="border border-neutral-900 bg-neutral-900 text-white px-3 py-1 text-sm hover:bg-neutral-700"
        >
          Save as PDF
        </button>
      </div>

      <div className="no-print mb-6"><FullScan domain={domain} /></div>

      {isPending && <p className="text-neutral-600">Loading {domain}…</p>}
      {rows?.length === 0 && <p className="text-neutral-600">No completed scans for {domain}. Run a scan from the dashboard first.</p>}

      {summary && (
        <>
          <header>
            <div className="text-xs uppercase tracking-widest text-neutral-500">Security report</div>
            <h1 className="text-2xl font-semibold font-mono break-all">{domain}</h1>
            <p className="text-neutral-600 mt-1">Scans from {fmt(summary.lastScanned)} · generated {fmt(new Date().toISOString())} by hopper-recon</p>
          </header>

          <Section title="Summary">
            {dns && (
              <p className={`border px-3 py-2 mb-3 ${spoofable ? "border-red-700 bg-red-50 text-red-900" : "border-green-700 bg-green-50 text-green-900"}`}>
                {spoofable
                  ? `Mail that forges ${domain} is not blocked. DMARC is ${dns.email.dmarc.present ? `p=${dns.email.dmarc.policy ?? "invalid"}` : "missing"}, so receivers deliver messages that fail SPF and DKIM.`
                  : `DMARC enforces p=${dns.email.dmarc.policy}: receivers are told to act on mail that forges ${domain}.`}
              </p>
            )}
            <p className="text-neutral-700">
              {count("issue")} issue{count("issue") === 1 ? "" : "s"}, {count("info")} notice{count("info") === 1 ? "" : "s"}, {count("ok")} passing.
            </p>
            <ul className="mt-3 space-y-3">
              {findings.map((f, i) => (
                <li key={i} className="break-inside-avoid">
                  <div className="flex items-start gap-2">
                    <Pill severity={f.severity} />
                    <div>
                      <div><span className="text-neutral-500 text-xs mr-1">{f.source}</span>{f.message}</div>
                      {f.detail && <div className="text-neutral-600 text-xs mt-0.5">{f.detail}</div>}
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          </Section>

          {diff && prevDnsRow && <ChangesSection diff={diff} since={fmt(prevDnsRow.started_at)} />}

          {dns && <EmailSection domain={domain} email={dns.email} />}

          {dns && (
            <Section title="DNS and hosting">
              <table className="w-full text-sm"><tbody>
                <Row label="Addresses">{[...dns.a, ...dns.aaaa].join(", ") || "none"}</Row>
                <Row label="CDN or WAF">{dns.cdn || "none detected"}</Row>
                <Row label="Name servers">{dns.ns.join(", ") || "none"}</Row>
                <Row label="Mail servers (MX)">{dns.mx.join(", ") || "none"}</Row>
                {dns.caa && <Row label="CAA (certificate issuers)">{dns.caa.join(", ") || "none: any certificate authority may issue"}</Row>}
                {subs && <Row label="Subdomains found">{subs.findings.length}</Row>}
              </tbody></table>
            </Section>
          )}

          {(tls || http) && (
            <Section title="Web endpoint">
              <table className="w-full text-sm"><tbody>
                {tls && <Row label="Certificate">{tls.expired ? "expired" : `valid, ${certDaysLabel(tls.daysLeft).label} left`}, issued by {tls.issuer_cn || "unknown"} ({tls.tls_version})</Row>}
                {http && <Row label="HTTP response">{http.status_code}{http.final_url ? ` at ${http.final_url}` : ""}{http.webserver ? `, server ${http.webserver}` : ""}</Row>}
              </tbody></table>
            </Section>
          )}

          {siblings && (
            <Section title="Sibling domains">
              <p className="text-sm text-neutral-700 mb-2">
                {siblings.length === 0
                  ? `No other top-level domain was found with the name of ${domain}.`
                  : `${siblings.length} other top-level domain${siblings.length === 1 ? "" : "s"} resolve with the same name. They are not necessarily yours: look for ones you do not recognise, which could be used for lookalike phishing.`}
              </p>
              {siblings.length > 0 && (
                <p className="font-mono text-xs break-words">
                  {siblings.slice(0, 40).map((d) => d.host).join("  ")}
                  {siblings.length > 40 ? `  … and ${siblings.length - 40} more` : ""}
                </p>
              )}
            </Section>
          )}

          <Section title="What was scanned">
            <table className="w-full text-sm"><tbody>
              {SCAN_TOOLS.map(({ tool, what }) => {
                const row = summary.scans[tool]
                return <Row key={tool} label={tool}>{row ? `${fmt(row.started_at)}: ${what}` : "not run"}</Row>
              })}
            </tbody></table>
            <p className="text-xs text-neutral-600 mt-3">
              This is an outside-in check of public DNS and HTTPS only. DKIM is probed at a short list of common selectors, so a sender that
              uses another selector does not appear here. It cannot tell whether a particular message was sent by a compromised mailbox: that
              passes DMARC and needs the message headers and the sending account&apos;s logs.
            </p>
          </Section>
        </>
      )}
    </div>
  )
}

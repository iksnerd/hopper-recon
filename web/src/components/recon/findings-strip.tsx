import * as React from "react"
import { assessCaa, assessEmailAuth } from "@/lib/email-auth"
import type { SubdomainResult, DnsResult, TlsResult, HttpResult, LookalikesResult, RdapResult } from "@/lib/scan-parser"
import { assessRdap } from "@/lib/rdap"
import {
  ReconCard,
  ReconCardHeader,
  ReconCardHeaderText,
  ReconCardTitle,
  ReconCardAction,
} from "@/components/recon/recon-card"

type Severity = "issue" | "ok" | "info"

export interface Finding {
  severity: Severity
  source: "TLS" | "DNS" | "HTTP" | "SUBS" | "REG"
  message: string
  /** Longer explanation; the report shows it, the strip does not. */
  detail?: string
}

const SENSITIVE_SUB = /^(dev|staging|test|sandbox|beta|admin|internal|jenkins|ci|stg|qa|preview)\./i

export function deriveFindings({ subs, dns, tls, http, lookalikes = null, rdap = null, now }: {
  subs: SubdomainResult | null
  dns: DnsResult | null
  tls: TlsResult | null
  http: HttpResult | null
  /** Only present once find_lookalikes has run; null means it has not, which says nothing. */
  lookalikes?: LookalikesResult | null
  /** Registration record; null means it was not looked up, which says nothing. */
  rdap?: RdapResult | null
  /** For tests; defaults to the current time. */
  now?: Date
}): Finding[] {
  const out: Finding[] = []

  if (tls) {
    if (tls.expired) {
      out.push({ severity: "issue", source: "TLS", message: "Certificate is EXPIRED" })
    } else if (tls.daysLeft <= 14) {
      out.push({ severity: "issue", source: "TLS", message: `Certificate expires in ${tls.daysLeft}d` })
    } else if (tls.daysLeft <= 30) {
      out.push({ severity: "info", source: "TLS", message: `Certificate renews in ${tls.daysLeft}d` })
    } else {
      out.push({ severity: "ok", source: "TLS", message: `Certificate valid for ${tls.daysLeft}d` })
    }
    if (tls.self_signed) {
      out.push({ severity: "issue", source: "TLS", message: "Self-signed certificate" })
    }
  }

  if (dns) {
    for (const f of [...assessEmailAuth(dns.email), ...assessCaa(dns.caa)]) {
      out.push({ severity: f.severity, source: "DNS", message: f.message, detail: f.detail })
    }
  }

  if (rdap) {
    for (const f of assessRdap(rdap, now)) out.push({ severity: f.severity, source: "REG", message: f.message, detail: f.detail })
  }

  if (lookalikes) {
    const { entries, withMail } = lookalikes
    const names = (xs: { host: string }[]) => xs.slice(0, 3).map((e) => e.host).join(", ") + (xs.length > 3 ? ` and ${xs.length - 3} more` : "")
    if (withMail > 0) {
      out.push({
        severity: "issue", source: "DNS",
        message: `${withMail} lookalike domain${withMail === 1 ? "" : "s"} can receive mail: ${names(entries.filter((e) => e.mx.length > 0))}`,
        detail: "These registered domains differ from yours by a typo, a look-alike character or a phishing word, and they publish MX records, so they can send and receive mail. Check who registered them. If they are not yours, they are a phishing risk: consider a takedown request or blocking them in your mail gateway.",
      })
    }
    const web = entries.length - withMail
    if (web > 0) {
      out.push({
        severity: "info", source: "DNS",
        message: `${web} lookalike domain${web === 1 ? "" : "s"} resolve${web === 1 ? "s" : ""}: ${names(entries.filter((e) => e.mx.length === 0))}`,
        detail: "These registered domains look like yours but have no MX record. They can still host a phishing page. Check whether they are yours.",
      })
    }
    if (entries.length === 0) {
      out.push({
        severity: "ok", source: "DNS", message: "No registered lookalikes found under the same suffix",
        detail: "Typos, look-alike characters and phishing words were tried under the same top-level suffix. Other suffixes are covered by sibling-domain discovery, and this does not cover look-alike characters outside ASCII.",
      })
    }
  }

  if (http) {
    const codes = http.chain_status_codes
    if (codes.length > 1) {
      const firstHasHttps = (http.url ?? "").startsWith("https")
      const finalHasHttps = (http.final_url ?? "").startsWith("https")
      if (firstHasHttps && !finalHasHttps) {
        out.push({ severity: "issue", source: "HTTP", message: "Insecure redirect — HTTPS visitors are sent to plain HTTP, exposing traffic" })
      }
    }
    if (http.status_code >= 500) {
      out.push({ severity: "issue", source: "HTTP", message: `Server error ${http.status_code} — origin is returning an error to all visitors` })
    }
  }

  if (subs) {
    const exposed = subs.findings.filter((f) => SENSITIVE_SUB.test(f.host)).slice(0, 3)
    for (const e of exposed) {
      out.push({ severity: "issue", source: "SUBS", message: `Public access: ${e.host}` })
    }
  }

  // Issues first, then info, then ok — in stable insertion order within each tier.
  const order: Record<Severity, number> = { issue: 0, info: 1, ok: 2 }
  return out.sort((a, b) => order[a.severity] - order[b.severity])
}

export function FindingsStrip(props: {
  subs: SubdomainResult | null
  dns: DnsResult | null
  tls: TlsResult | null
  http: HttpResult | null
  lookalikes?: LookalikesResult | null
  rdap?: RdapResult | null
}) {
  const findings = React.useMemo(() => deriveFindings(props), [props])
  if (findings.length === 0) return null

  const issueCount = findings.filter((f) => f.severity === "issue").length
  const okCount = findings.filter((f) => f.severity === "ok").length

  return (
    <ReconCard tone={issueCount > 0 ? "danger" : "neutral"}>
      <ReconCardHeader className="gap-2">
        <ReconCardHeaderText className="flex-row items-baseline gap-2 min-w-0">
          <span className="text-muted-foreground-3 font-bold tracking-widest shrink-0" aria-hidden>{"//"}</span>
          <ReconCardTitle className="shrink-0">FINDINGS</ReconCardTitle>
        </ReconCardHeaderText>
        <ReconCardAction className="text-micro flex-wrap justify-end">
          {issueCount > 0 && <span className="text-destructive font-bold whitespace-nowrap">{issueCount} ISSUE{issueCount === 1 ? "" : "S"}</span>}
          {issueCount > 0 && okCount > 0 && <span className="text-muted-foreground-3">·</span>}
          {okCount > 0 && <span className="text-terminal-green-dim whitespace-nowrap">{okCount} OK</span>}
        </ReconCardAction>
      </ReconCardHeader>
      <ul className="divide-y divide-border/30 border-t border-border">
        {findings.map((f, i) => (
          <FindingRow key={i} finding={f} />
        ))}
      </ul>
    </ReconCard>
  )
}

function FindingRow({ finding }: { finding: Finding }) {
  const glyph = finding.severity === "issue" ? "[!]" : finding.severity === "ok" ? "[✓]" : "[·]"
  const cls =
    finding.severity === "issue" ? "text-destructive"
    : finding.severity === "ok" ? "text-foreground"
    : "text-muted-foreground-2"

  return (
    <li className="flex items-center gap-3 px-4 py-2 text-body hover:bg-card-hover transition-colors duration-100">
      <span className={`${cls} font-bold tabular-nums shrink-0`}>{glyph}</span>
      <span className="flex-1 truncate text-foreground">{finding.message}</span>
      <span className="text-micro text-muted-foreground tracking-widest shrink-0">[{finding.source}]</span>
    </li>
  )
}

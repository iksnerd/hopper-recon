import * as React from "react"
import type { SubdomainResult, DnsResult, TlsResult, HttpResult } from "@/lib/scan-parser"
import {
  ReconCard,
  ReconCardHeader,
  ReconCardHeaderText,
  ReconCardTitle,
  ReconCardAction,
} from "@/components/recon/recon-card"

type Severity = "issue" | "ok" | "info"

interface Finding {
  severity: Severity
  source: "TLS" | "DNS" | "HTTP" | "SUBS"
  message: string
}

const SENSITIVE_SUB = /^(dev|staging|test|sandbox|beta|admin|internal|jenkins|ci|stg|qa|preview)\./i

function deriveFindings({ subs, dns, tls, http }: {
  subs: SubdomainResult | null
  dns: DnsResult | null
  tls: TlsResult | null
  http: HttpResult | null
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
    const sec = dns.securityTxt
    if (!sec.spf)   out.push({ severity: "issue", source: "DNS", message: "No SPF record — email spoofing risk" })
    else            out.push({ severity: "ok",    source: "DNS", message: "SPF policy present" })
    if (!sec.dmarc) out.push({ severity: "issue", source: "DNS", message: "No DMARC record — no enforcement policy" })
    if (!sec.dkim)  out.push({ severity: "info",  source: "DNS", message: "No DKIM signature found" })
  }

  if (http) {
    const codes = http.chain_status_codes
    if (codes.length > 1) {
      const firstHasHttps = (http.url ?? "").startsWith("https")
      const finalHasHttps = (http.final_url ?? "").startsWith("https")
      if (firstHasHttps && !finalHasHttps) {
        out.push({ severity: "issue", source: "HTTP", message: "HTTPS → HTTP downgrade in redirect chain" })
      }
    }
    if (http.status_code >= 500) {
      out.push({ severity: "issue", source: "HTTP", message: `Origin returns ${http.status_code}` })
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
      <ul className="divide-y divide-card-hover">
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

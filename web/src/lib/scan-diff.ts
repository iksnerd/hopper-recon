// Compares two DNS scans of the same domain, so a record change (for example
// tightening DMARC) can be checked against the scan taken before it.

import type { DnsResult } from "@/lib/scan-parser"
import { assessCaa, assessEmailAuth, type EmailFinding } from "@/lib/email-auth"

export interface DnsChange {
  label: string
  before: string
  after: string
}

export interface DnsDiff {
  /** Record values that differ. */
  changes: DnsChange[]
  /** Findings present before and gone now. */
  resolved: EmailFinding[]
  /** Findings present now and not before. */
  appeared: EmailFinding[]
}

const list = (xs: string[]) => [...new Set(xs)].sort().join(", ") || "none"
const text = (s: string) => s || "none"

// Findings that depend on data an older engine did not report. When either scan
// lacks it, the finding says nothing about a change, so it is left out.
const NEEDS: { prefix: string; known: (d: DnsResult) => boolean }[] = [
  { prefix: "spf-lookups-", known: (d) => d.email.spf.lookups !== null },
  { prefix: "mta-sts-", known: (d) => d.email.mailPolicy !== null },
  { prefix: "tls-rpt-", known: (d) => d.email.mailPolicy !== null },
  { prefix: "caa-", known: (d) => d.caa !== null },
]

function comparable(f: EmailFinding, prev: DnsResult, curr: DnsResult): boolean {
  const need = NEEDS.find((n) => f.id.startsWith(n.prefix))
  return !need || (need.known(prev) && need.known(curr))
}

export function diffDns(prev: DnsResult, curr: DnsResult): DnsDiff {
  const changes: DnsChange[] = []
  const check = (label: string, before: string, after: string) => {
    if (before !== after) changes.push({ label, before, after })
  }
  check("SPF record", text(prev.email.spf.record), text(curr.email.spf.record))
  check("DMARC record", text(prev.email.dmarc.record), text(curr.email.dmarc.record))
  check("DKIM keys", String(prev.email.dkim.keys), String(curr.email.dkim.keys))
  check("Mail servers (MX)", list(prev.mx), list(curr.mx))
  check("Name servers", list(prev.ns), list(curr.ns))
  const [pm, cm] = [prev.email.mailPolicy, curr.email.mailPolicy]
  if (pm && cm) {
    check("MTA-STS", list(pm.mtaSts), list(cm.mtaSts))
    check("TLS-RPT", list(pm.tlsRpt), list(cm.tlsRpt))
    check("BIMI", list(pm.bimi), list(cm.bimi))
  }
  if (prev.caa && curr.caa) check("CAA", list(prev.caa), list(curr.caa))

  const all = (d: DnsResult) => [...assessEmailAuth(d.email), ...assessCaa(d.caa)].filter((f) => comparable(f, prev, curr))
  const [before, after] = [all(prev), all(curr)]
  const beforeIds = new Set(before.map((f) => f.id))
  const afterIds = new Set(after.map((f) => f.id))
  return {
    changes,
    resolved: before.filter((f) => !afterIds.has(f.id)),
    appeared: after.filter((f) => !beforeIds.has(f.id)),
  }
}

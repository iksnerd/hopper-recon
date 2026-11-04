// Findings from a domain's registry registration (RDAP): expiry, registry status,
// transfer lock, age and DNSSEC. Pure, with `now` injectable, so the date logic
// is testable.

import type { RdapResult } from "@/lib/scan-parser"

export type RdapSeverity = "issue" | "info" | "ok"

export interface RdapFinding {
  severity: RdapSeverity
  message: string
  detail: string
}

const DAY_MS = 86_400_000

/** Whole days from `now` until `iso` (negative once passed), or null when the date is missing or unreadable. */
export function daysUntil(iso: string | undefined, now: Date): number | null {
  if (!iso) return null
  const t = Date.parse(iso)
  return Number.isNaN(t) ? null : Math.floor((t - now.getTime()) / DAY_MS)
}

const plural = (n: number) => (n === 1 ? "day" : "days")

/** "412d", or "expired 3d ago" past the date, never "-3d" (same rule as certificate days). */
export function daysLabel(days: number): string {
  return days < 0 ? `expired ${-days}d ago` : `${days}d`
}

// Registry statuses that mean the domain is, or is about to be, out of service.
const TROUBLE: Record<string, string> = {
  "client hold": "The registrar has put the domain on hold, so it may stop resolving.",
  "server hold": "The registry has put the domain on hold, so it may stop resolving.",
  "redemption period": "The domain has expired and is in the redemption period: it can still be restored, at a fee, but it is not resolving normally.",
  "pending delete": "The domain is queued for deletion and will become available for anyone to register.",
}

export function assessRdap(r: RdapResult, now: Date = new Date()): RdapFinding[] {
  const out: RdapFinding[] = []

  const left = daysUntil(r.expires, now)
  if (left !== null) {
    if (left < 0) {
      out.push({
        severity: "issue",
        message: `Domain registration expired ${-left} ${plural(-left)} ago`,
        detail: "The registration is past its expiry date. Registries usually allow a short grace period in which it can be renewed; after that the domain can be dropped and registered by anyone, who would then control its web and mail.",
      })
    } else if (left <= 90) {
      out.push({
        severity: left <= 30 ? "issue" : "info",
        message: left === 0 ? "Domain registration expires today" : `Domain registration expires in ${left} ${plural(left)}`,
        detail: "An expired domain can be registered by anyone once the grace period ends, taking over its web and mail. Renew it, and turn on auto-renew at the registrar.",
      })
    } else {
      out.push({
        severity: "ok",
        message: `Registered until ${r.expires.slice(0, 10)} (${left} days)`,
        detail: r.registrar ? `Registrar: ${r.registrar}.` : "The registry reports the registration as current.",
      })
    }
  }

  for (const status of r.status) {
    const why = TROUBLE[status]
    if (why) out.push({ severity: "issue", message: `Domain registry status: ${status}`, detail: why })
  }

  if (r.status.length > 0) {
    if (r.status.some((s) => s.includes("transfer prohibited"))) {
      out.push({
        severity: "ok",
        message: "Transfer lock is on",
        detail: "The domain cannot be moved to another registrar until the lock is removed, which limits what an attacker with registrar-account access, or a social-engineered transfer, can do.",
      })
    } else {
      out.push({
        severity: "info",
        message: "No transfer lock in the registry status",
        detail: "Without a transfer lock the domain can be moved to another registrar by anyone who gets into the registrar account or talks support into it. Some registries do not publish this status, so check at the registrar before acting.",
      })
    }
  }

  const registeredAt = Date.parse(r.registered)
  if (!Number.isNaN(registeredAt)) {
    const since = Math.floor((now.getTime() - registeredAt) / DAY_MS)
    if (since >= 0 && since <= 30) {
      out.push({
        severity: "info",
        message: `Domain was registered ${since} ${plural(since)} ago`,
        detail: "A newly registered domain has no history. That is expected for a new project; for a domain you did not just register, check who did.",
      })
    }
  }

  if (!r.dnssec) {
    out.push({
      severity: "info",
      message: "DNSSEC is not enabled",
      detail: "DNSSEC signs the domain's DNS records so resolvers can detect forged answers. It is not a defence against mail spoofing, which SPF, DKIM and DMARC cover.",
    })
  }

  return out
}

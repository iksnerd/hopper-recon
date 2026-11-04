import * as React from "react"
import type { DnsDiff } from "@/lib/scan-diff"
import type { EmailFinding } from "@/lib/email-auth"
import { Panel } from "@/components/recon/panel"

const GLYPH = { issue: "[!]", info: "[·]", ok: "[✓]" } as const
const CLS = { issue: "text-destructive", info: "text-muted-foreground", ok: "text-terminal-green" } as const

function FindingLine({ f, prefix }: { f: EmailFinding; prefix: string }) {
  return (
    <li className="flex gap-2 text-body">
      <span className={`shrink-0 ${CLS[f.severity]}`}>{GLYPH[f.severity]}</span>
      <span><span className="text-muted-foreground">{prefix}</span> {f.message}</span>
    </li>
  )
}

/** What changed in a domain's DNS and email records between two scans. */
export function ScanChanges({ diff, since }: { diff: DnsDiff; since: string }) {
  const empty = diff.changes.length === 0 && diff.resolved.length === 0 && diff.appeared.length === 0
  return (
    <Panel label="// CHANGES SINCE PREVIOUS SCAN" action={<span className="text-micro text-muted-foreground-3">{since}</span>}>
      {empty ? (
        <p className="text-body text-muted-foreground">No change in DNS or email records.</p>
      ) : (
        <div className="space-y-3">
          {diff.changes.length > 0 && (
            <ul className="space-y-2">
              {diff.changes.map((c) => (
                <li key={c.label} className="text-body">
                  <div className="text-muted-foreground text-micro uppercase tracking-widest">{c.label}</div>
                  <div className="font-mono break-all"><span className="text-destructive">− {c.before}</span></div>
                  <div className="font-mono break-all"><span className="text-terminal-green">+ {c.after}</span></div>
                </li>
              ))}
            </ul>
          )}
          {(diff.resolved.length > 0 || diff.appeared.length > 0) && (
            <ul className="space-y-1">
              {diff.resolved.map((f) => <FindingLine key={`r-${f.id}`} f={f} prefix="gone:" />)}
              {diff.appeared.map((f) => <FindingLine key={`a-${f.id}`} f={f} prefix="new:" />)}
            </ul>
          )}
        </div>
      )}
    </Panel>
  )
}

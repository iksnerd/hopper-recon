import * as React from "react"
import Link from "next/link"
import type { LookalikeEntry } from "@/lib/scan-parser"

// Rendered cap: registered lookalikes are rare, so this is a guard, not a pager.
const MAX_ROWS = 200

/**
 * Lookalike domains with how each differs and whether it can handle mail. Not
 * HostList, whose per-row `meta` appears only on hover: for lookalikes "can
 * send mail" is the reason to look at a row at all, so it is always visible.
 */
export function LookalikeList({ entries }: { entries: LookalikeEntry[] }) {
  const shown = entries.slice(0, MAX_ROWS)
  return (
    <div className="max-h-[480px] overflow-y-auto">
      <ul className="divide-y divide-border">
        {shown.map((e) => (
          <li key={e.host} className="group flex items-center gap-2 px-2 py-1">
            <span className="font-mono text-data text-foreground truncate flex-1 min-w-0 select-all">{e.host}</span>
            {e.mx.length > 0 && (
              <span
                title={`MX: ${e.mx.join(", ")}`}
                className="shrink-0 font-mono text-micro text-destructive border border-destructive/50 px-1.5 py-px"
              >
                MAIL
              </span>
            )}
            <span className="shrink-0 font-mono text-micro text-muted-foreground-3">{e.kind}</span>
            <Link
              href={`/dashboard?domain=${encodeURIComponent(e.host)}`}
              className="shrink-0 font-mono text-micro text-muted-foreground-3 hover:text-terminal-green opacity-0 group-hover:opacity-100 transition-opacity duration-100 border border-border px-1.5 py-px"
            >
              &gt;_ scan
            </Link>
          </li>
        ))}
      </ul>
      {entries.length > MAX_ROWS && (
        <p className="text-micro text-muted-foreground-3 px-2 py-1">… and {entries.length - MAX_ROWS} more</p>
      )}
    </div>
  )
}

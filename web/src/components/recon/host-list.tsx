"use client"

import * as React from "react"
import Link from "next/link"
import { Check } from "lucide-react"
import { Input } from "@/components/ui/input"
import { cn } from "@/lib/utils"

export interface HostRow {
  /** Stable React key. */
  key: string
  /** Primary text. Also what the filter matches and what a click copies. */
  text: string
  /** Right-aligned detail, revealed on hover (source list, resolved IP, …). */
  meta?: string
  /** When set, the row gets a `>_ scan` link pointing here. */
  href?: string
}

/**
 * Scrollable list of hosts / URLs with a filter and a render cap.
 *
 * A passive scan of a large domain returns tens of thousands of rows
 * (example.com yields ~25k subdomains). Rendering them all locks the tab hard
 * enough that navigating away times out, so this caps the DOM at `pageSize`
 * rows and grows on demand. The filter is not a nicety: a 25k-row list with no
 * search is unusable even when it renders instantly.
 *
 * Copy state lives here rather than per row — one `copiedKey` for the whole
 * list instead of a hook trio per row.
 */
export function HostList({
  rows,
  pageSize = 200,
  maxHeight = "max-h-[280px]",
  filterPlaceholder = "filter…",
  filterThreshold = 25,
  className,
}: {
  rows: HostRow[]
  pageSize?: number
  maxHeight?: string
  filterPlaceholder?: string
  /** Below this many rows the filter is hidden as clutter. */
  filterThreshold?: number
  className?: string
}) {
  const [query, setQuery] = React.useState("")
  const [shown, setShown] = React.useState(pageSize)
  const [copiedKey, setCopiedKey] = React.useState<string | null>(null)
  const deferredQuery = React.useDeferredValue(query)

  const filtered = React.useMemo(() => {
    const q = deferredQuery.trim().toLowerCase()
    if (!q) return rows
    return rows.filter((r) => r.text.toLowerCase().includes(q))
  }, [rows, deferredQuery])

  // A new query should start from the top of the result set rather than carry
  // over a "show more" depth from the previous one. Adjusted during render
  // (React's documented pattern for deriving state from a changed input) since
  // the eslint config rules out setState inside an effect.
  const [shownFor, setShownFor] = React.useState(deferredQuery)
  if (shownFor !== deferredQuery) {
    setShownFor(deferredQuery)
    setShown(pageSize)
  }

  const visible = filtered.slice(0, shown)
  const remaining = filtered.length - visible.length

  async function copy(row: HostRow) {
    try {
      await navigator.clipboard.writeText(row.text)
      setCopiedKey(row.key)
      setTimeout(() => setCopiedKey((k) => (k === row.key ? null : k)), 1200)
    } catch {
      // Clipboard is unavailable over plain HTTP on a non-localhost origin.
      // Nothing useful to do; the text is selectable either way.
    }
  }

  return (
    <div className={cn("space-y-2", className)}>
      {rows.length > filterThreshold && (
        <div className="flex items-center gap-2 border border-border bg-card-inset px-2">
          <span className="font-mono text-micro text-terminal-green select-none shrink-0" aria-hidden>
            &gt;_
          </span>
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={filterPlaceholder}
            aria-label="filter results"
            className="flex-1 font-mono text-data bg-transparent border-0 rounded-none shadow-none h-7 px-0 placeholder:text-muted-foreground-3 focus-visible:ring-0 focus-visible:border-0"
          />
          {query && (
            <button
              type="button"
              onClick={() => setQuery("")}
              className="font-mono text-micro text-muted-foreground-3 hover:text-foreground shrink-0"
            >
              clear
            </button>
          )}
        </div>
      )}

      <div className={cn("space-y-px overflow-y-auto bg-card-inset", maxHeight)}>
        {visible.map((row) => (
          <div
            key={row.key}
            className="group flex items-center gap-2 px-2 py-0.5 hover:bg-card-hover transition-colors duration-100"
          >
            <button
              type="button"
              onClick={() => void copy(row)}
              title="copy"
              className="font-mono text-data text-muted-foreground-2 group-hover:text-foreground truncate flex-1 text-left transition-colors duration-100 cursor-pointer"
            >
              {row.text}
            </button>
            {copiedKey === row.key && (
              <Check className="size-3 text-terminal-green shrink-0" aria-label="copied" />
            )}
            {row.meta && (
              <span className="font-mono text-micro text-muted-foreground-3 shrink-0 hidden group-hover:inline">
                {row.meta}
              </span>
            )}
            {row.href && (
              <Link
                href={row.href}
                className="shrink-0 font-mono text-micro text-muted-foreground-3 hover:text-terminal-green opacity-0 group-hover:opacity-100 transition-opacity duration-100 border border-border px-1.5 py-px"
              >
                &gt;_ scan
              </Link>
            )}
          </div>
        ))}

        {filtered.length === 0 && (
          <p className="font-mono text-body text-muted-foreground-3 px-2 py-3">
            no rows match &quot;{deferredQuery.trim()}&quot;
          </p>
        )}
      </div>

      {(remaining > 0 || filtered.length !== rows.length) && (
        <div className="flex items-center justify-between font-mono text-micro text-muted-foreground-3">
          <span className="tabular-nums">
            showing {visible.length.toLocaleString()} of {filtered.length.toLocaleString()}
            {filtered.length !== rows.length && ` (filtered from ${rows.length.toLocaleString()})`}
          </span>
          {remaining > 0 && (
            <button
              type="button"
              onClick={() => setShown((s) => s + pageSize)}
              className="border border-border bg-card-inset px-2 py-0.5 uppercase tracking-widest hover:text-terminal-green hover:border-terminal-green/40 transition-colors duration-100"
            >
              show {Math.min(remaining, pageSize).toLocaleString()} more
            </button>
          )}
        </div>
      )}
    </div>
  )
}

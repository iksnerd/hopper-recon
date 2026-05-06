"use client"

import * as React from "react"
import { useSidebar } from "@/components/ui/sidebar"
import { PanelLeftIcon } from "lucide-react"

/**
 * Sticky page header with sidebar trigger, breadcrumb, and optional right slot.
 * Used on dashboard, history, settings, and detail pages — keeps the chrome
 * consistent so navigation feels predictable.
 */
export function PageHeader({
  segments,
  right,
}: {
  segments: (string | undefined | null)[]
  right?: React.ReactNode
}) {
  return (
    <header className="sticky top-0 z-10 bg-background border-b border-border">
      <div className="px-3 sm:px-4 py-2.5 flex items-center gap-2 sm:gap-3">
        <SidebarToggleButton />
        <Breadcrumb segments={segments} />
        {right && <div className="ml-auto flex items-center gap-2 shrink-0">{right}</div>}
      </div>
    </header>
  )
}

function SidebarToggleButton() {
  const { toggleSidebar, isMobile, openMobile, open } = useSidebar()
  const expanded = isMobile ? openMobile : open
  return (
    <button
      type="button"
      onClick={toggleSidebar}
      aria-label="toggle navigation"
      aria-expanded={expanded}
      className="h-8 w-8 flex items-center justify-center text-foreground hover:text-terminal-green hover:bg-card-hover border border-border bg-card-inset rounded-none transition-colors duration-100 shrink-0"
    >
      <PanelLeftIcon className="size-4" />
    </button>
  )
}

export function Breadcrumb({ segments }: { segments: (string | undefined | null)[] }) {
  const visible = segments.filter(Boolean) as string[]
  return (
    <nav aria-label="breadcrumb" className="flex items-center gap-2 min-w-0">
      <span className="text-micro tracking-widest uppercase text-muted-foreground-3">HOPPER-RECON</span>
      {visible.map((seg, i) => {
        const last = i === visible.length - 1
        return (
          <React.Fragment key={i}>
            <span className="text-muted-foreground-3 select-none" aria-hidden>/</span>
            <span
              className={
                last
                  ? "text-body text-foreground font-bold uppercase tracking-wide truncate"
                  : "text-body text-muted-foreground uppercase tracking-wide"
              }
            >
              {seg}
            </span>
          </React.Fragment>
        )
      })}
    </nav>
  )
}

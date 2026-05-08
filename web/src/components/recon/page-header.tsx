"use client"

import * as React from "react"
import Link from "next/link"
import { useSidebar } from "@/components/ui/sidebar"
import { PanelLeftIcon } from "lucide-react"
import {
  Breadcrumb as ShadBreadcrumb,
  BreadcrumbList,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"

/**
 * Sticky page header with sidebar trigger, breadcrumb, and optional right slot.
 * Used on dashboard, history, settings, and detail pages — keeps the chrome
 * consistent so navigation feels predictable.
 *
 * Segments accept either a plain string (rendered as inert text) or an object
 * `{ label, href }` (rendered as a clickable link). The last segment is always
 * rendered as the current-page indicator regardless of href.
 */
export type BreadcrumbSegment = string | { label: string; href?: string }

export function PageHeader({
  segments,
  right,
}: {
  segments: (BreadcrumbSegment | undefined | null)[]
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

function normalize(
  segments: (BreadcrumbSegment | undefined | null)[],
): { label: string; href?: string }[] {
  return segments
    .filter((s): s is BreadcrumbSegment => Boolean(s))
    .map((s) => (typeof s === "string" ? { label: s } : s))
}

export function Breadcrumb({
  segments,
}: {
  segments: (BreadcrumbSegment | undefined | null)[]
}) {
  const items = normalize(segments)
  return (
    <ShadBreadcrumb className="min-w-0">
      <BreadcrumbList className="gap-2 flex-nowrap min-w-0">
        <BreadcrumbItem>
          <BreadcrumbLink
            asChild
            className="font-mono text-micro tracking-widest uppercase text-muted-foreground-3 hover:text-terminal-green transition-colors"
          >
            <Link href="/dashboard">HOPPER-RECON</Link>
          </BreadcrumbLink>
        </BreadcrumbItem>

        {items.map((item, i) => {
          const last = i === items.length - 1
          return (
            <React.Fragment key={`${i}-${item.label}`}>
              <BreadcrumbSeparator className="text-muted-foreground-3 [&>svg]:hidden">
                <span aria-hidden>/</span>
              </BreadcrumbSeparator>
              <BreadcrumbItem className="min-w-0">
                {last ? (
                  <BreadcrumbPage className="font-mono text-body text-foreground font-bold uppercase tracking-wide truncate">
                    {item.label}
                  </BreadcrumbPage>
                ) : item.href ? (
                  <BreadcrumbLink
                    asChild
                    className="font-mono text-body text-muted-foreground uppercase tracking-wide hover:text-terminal-green transition-colors"
                  >
                    <Link href={item.href}>{item.label}</Link>
                  </BreadcrumbLink>
                ) : (
                  <span className="font-mono text-body text-muted-foreground uppercase tracking-wide">
                    {item.label}
                  </span>
                )}
              </BreadcrumbItem>
            </React.Fragment>
          )
        })}
      </BreadcrumbList>
    </ShadBreadcrumb>
  )
}

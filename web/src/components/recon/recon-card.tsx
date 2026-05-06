import * as React from "react"
import { cn } from "@/lib/utils"

/**
 * Palantir-style data card. Header strip, accent rail, action slot.
 * Composable — caller assembles header pieces. Pair with Panel for the
 * single-label shorthand.
 */

interface ReconCardProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: "default" | "inset" | "outline"
  tone?: "neutral" | "danger"
}

export function ReconCard({
  className,
  variant = "default",
  tone = "neutral",
  ...props
}: ReconCardProps) {
  return (
    <div
      data-slot="recon-card"
      data-tone={tone}
      className={cn(
        "border rounded-none flex flex-col",
        tone === "danger" ? "border-destructive/60" : "border-border",
        variant === "default" && "bg-card",
        variant === "inset" && "bg-card-inset",
        variant === "outline" && "bg-transparent",
        className,
      )}
      {...props}
    />
  )
}

interface ReconCardHeaderProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Hide the left accent rail. Default shows it. */
  flush?: boolean
}

export function ReconCardHeader({ className, flush, ...props }: ReconCardHeaderProps) {
  return (
    <div
      data-slot="recon-card-header"
      className={cn(
        "relative flex items-center gap-3 border-b border-border min-h-[40px] px-4 py-2",
        !flush && "before:absolute before:left-0 before:top-2 before:bottom-2 before:w-[2px] before:bg-terminal-green/70",
        className,
      )}
      {...props}
    />
  )
}

export function ReconCardHeaderText({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      data-slot="recon-card-header-text"
      className={cn("flex flex-col min-w-0 flex-1", className)}
      {...props}
    />
  )
}

export function ReconCardEyebrow({
  className,
  ...props
}: React.HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      data-slot="recon-card-eyebrow"
      className={cn(
        "text-micro uppercase text-muted-foreground-3 leading-none",
        className,
      )}
      {...props}
    />
  )
}

export function ReconCardTitle({
  className,
  ...props
}: React.HTMLAttributes<HTMLHeadingElement>) {
  return (
    <h3
      data-slot="recon-card-title"
      className={cn(
        "text-body uppercase tracking-widest font-bold text-foreground leading-tight truncate",
        className,
      )}
      {...props}
    />
  )
}

export function ReconCardAction({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      data-slot="recon-card-action"
      className={cn(
        "flex items-center gap-2 text-micro text-muted-foreground tabular-nums shrink-0",
        className,
      )}
      {...props}
    />
  )
}

export function ReconCardContent({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      data-slot="recon-card-content"
      className={cn("p-4 flex-1", className)}
      {...props}
    />
  )
}

export function ReconCardFooter({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      data-slot="recon-card-footer"
      className={cn(
        "border-t border-border px-4 py-2 text-micro text-muted-foreground flex items-center gap-3",
        className,
      )}
      {...props}
    />
  )
}

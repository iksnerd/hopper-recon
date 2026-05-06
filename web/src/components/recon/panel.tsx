import * as React from "react"
import { cn } from "@/lib/utils"
import {
  ReconCard,
  ReconCardHeader,
  ReconCardHeaderText,
  ReconCardTitle,
  ReconCardAction,
  ReconCardContent,
} from "@/components/recon/recon-card"

interface PanelProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Either `// LABEL` or `// LABEL [count]`. */
  label: string
  /** Right-aligned header content (button, status, extra count). */
  action?: React.ReactNode
  variant?: "default" | "inset"
  /** Override default content padding (e.g. `"p-3"`, `"p-0"`). */
  contentClassName?: string
}

/**
 * Splits `// LABEL [N]` into `("LABEL", "[N]")` so the count rides in the action slot.
 */
function splitLabel(label: string): { title: string; count: string | null } {
  const stripped = label.replace(/^\/\/\s*/, "")
  const m = /^(.*?)\s*\[(.*?)\]\s*$/.exec(stripped)
  if (m) return { title: m[1].trim(), count: `[${m[2]}]` }
  return { title: stripped.trim(), count: null }
}

export function Panel({
  label,
  action,
  variant = "default",
  className,
  contentClassName,
  children,
  ...props
}: PanelProps) {
  const { title, count } = splitLabel(label)
  return (
    <ReconCard
      data-slot="recon-panel"
      variant={variant}
      className={className}
      {...props}
    >
      <ReconCardHeader>
        <ReconCardHeaderText className="flex-row items-baseline gap-2">
          <span className="text-muted-foreground-3 font-bold tracking-widest" aria-hidden>{"//"}</span>
          <ReconCardTitle>{title}</ReconCardTitle>
        </ReconCardHeaderText>
        {(count || action) && (
          <ReconCardAction>
            {count && <span className="text-foreground tabular-nums">{count}</span>}
            {action}
          </ReconCardAction>
        )}
      </ReconCardHeader>
      <ReconCardContent className={cn(contentClassName)}>
        {children}
      </ReconCardContent>
    </ReconCard>
  )
}

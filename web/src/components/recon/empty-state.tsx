import * as React from "react"
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty"
import { cn } from "@/lib/utils"

/**
 * The `empty` primitive in the terminal style: square, solid border, mono
 * `// TITLE` caption. `children` is the next-step action (a link or button).
 */
export function EmptyState({
  title,
  description,
  children,
  className,
}: {
  title: string
  description: React.ReactNode
  children?: React.ReactNode
  className?: string
}) {
  return (
    <Empty className={cn("rounded-none border border-border bg-card p-8 font-mono", className)}>
      <EmptyHeader>
        <EmptyTitle className="text-micro uppercase tracking-widest text-muted-foreground">{"// "}{title}</EmptyTitle>
        <EmptyDescription className="text-body text-muted-foreground-3">{description}</EmptyDescription>
      </EmptyHeader>
      {children && <EmptyContent>{children}</EmptyContent>}
    </Empty>
  )
}

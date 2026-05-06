import * as React from "react"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

type DataChipProps = React.ComponentProps<typeof Badge>

export function DataChip({ className, children, ...props }: DataChipProps) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "rounded-none h-auto py-0.5 px-2 text-data font-normal bg-card-inset border-border text-muted-foreground-2 hover:bg-card-hover",
        className,
      )}
      {...props}
    >
      {children}
    </Badge>
  )
}

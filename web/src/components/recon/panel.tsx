import * as React from "react"
import { cn } from "@/lib/utils"

interface PanelProps extends React.HTMLAttributes<HTMLDivElement> {
  label: string
  variant?: "default" | "inset"
}

export function Panel({ label, variant = "default", className, children, ...props }: PanelProps) {
  return (
    <div
      data-slot="recon-panel"
      className={cn(
        "border border-border p-4",
        variant === "inset" ? "bg-card-inset" : "bg-card",
        className,
      )}
      {...props}
    >
      <div className="text-micro uppercase text-muted-foreground mb-3">{label}</div>
      {children}
    </div>
  )
}

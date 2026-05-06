"use client"

import * as React from "react"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

export function CopyButton({ value, label = "copy", className }: { value: string; label?: string; className?: string }) {
  const [copied, setCopied] = React.useState(false)

  async function onClick() {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1000)
    } catch {
      // clipboard API unavailable; ignore
    }
  }

  return (
    <Button
      variant="ghost"
      onClick={onClick}
      className={cn(
        "rounded-none bg-transparent text-muted-foreground hover:text-foreground hover:bg-transparent shadow-none ring-0 focus-visible:ring-0 active:translate-y-0 h-auto p-0 text-micro font-mono",
        className,
      )}
    >
      [{copied ? "copied" : label}]
    </Button>
  )
}

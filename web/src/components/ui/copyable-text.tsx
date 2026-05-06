"use client"

import * as React from "react"
import { Check, Copy } from "lucide-react"
import { cn } from "@/lib/utils"

interface CopyableTextProps extends React.HTMLAttributes<HTMLDivElement> {
  text: string
  label?: string
  variant?: "default" | "code"
}

function CopyableText({
  text,
  label,
  variant = "default",
  className,
  ...props
}: CopyableTextProps) {
  const [copied, setCopied] = React.useState(false)
  const [showToast, setShowToast] = React.useState(false)
  const [pulsing, setPulsing] = React.useState(false)

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setShowToast(true)
      setPulsing(true)

      setTimeout(() => setCopied(false), 2000)
      setTimeout(() => setShowToast(false), 3000)
      setTimeout(() => setPulsing(false), 600)
    } catch (err) {
      console.error("Failed to copy:", err)
    }
  }

  return (
    <>
      <style>{`
        @keyframes pulse-flash {
          0% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.7); }
          50% { box-shadow: 0 0 0 8px rgba(34, 197, 94, 0); }
          100% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0); }
        }
        .pulse-copy { animation: pulse-flash 0.6s ease-out; }
      `}</style>

      <div
        className={cn(
          "group relative flex items-center gap-2 rounded-lg border border-border bg-background p-3 transition-colors hover:bg-muted",
          pulsing && "pulse-copy",
          className
        )}
        {...props}
      >
        {label && <span className="text-xs font-medium text-muted-foreground">{label}</span>}
        <pre className={cn(
          "flex-1 overflow-x-auto",
          variant === "code" && "font-mono text-sm text-foreground"
        )}>
          <code>{text}</code>
        </pre>
        <button
          onClick={handleCopy}
          className="ml-auto shrink-0 rounded-md p-2 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          title={copied ? "Copied!" : "Copy to clipboard"}
        >
          {copied ? (
            <Check className="size-4 text-green-500" />
          ) : (
            <Copy className="size-4" />
          )}
        </button>
      </div>

      {showToast && (
        <div className="fixed bottom-4 right-4 animate-in fade-in slide-in-from-bottom-2 duration-300 bg-green-900/90 text-green-100 px-4 py-2 rounded-lg text-sm border border-green-700 pointer-events-none">
          ✓ Copied to clipboard
        </div>
      )}
    </>
  )
}

export { CopyableText }
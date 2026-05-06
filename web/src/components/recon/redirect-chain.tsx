import { cn } from "@/lib/utils"

function statusCls(code: number) {
  if (code < 300) return "text-primary"
  if (code < 400) return "text-muted-foreground-2"
  return "text-destructive"
}

export function RedirectChain({ codes, className }: { codes: number[]; className?: string }) {
  if (!codes.length) return null
  return (
    <span className={cn("font-mono text-data inline-flex items-center gap-1", className)}>
      <span className="text-muted">[</span>
      {codes.map((c, i) => (
        <span key={i} className="inline-flex items-center gap-1">
          <span className={statusCls(c)}>{c}</span>
          {i < codes.length - 1 && <span className="text-muted-foreground-3">→</span>}
        </span>
      ))}
      <span className="text-muted">]</span>
    </span>
  )
}

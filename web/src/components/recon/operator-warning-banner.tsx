"use client"

import * as React from "react"
import Link from "next/link"
import { X } from "lucide-react"
import { cn } from "@/lib/utils"
import type { EngineConfig } from "@/lib/engine-client"

const ACK_KEY = "hopper-recon:operator-warning-ack-v1"

// useSyncExternalStore lets us subscribe to localStorage cleanly on the
// client without tripping the react-hooks/set-state-in-effect rule. Per-
// browser ack is fine for a single-tenant tool: each operator dismisses
// once on each device they use; clearing storage or moving browsers
// reappears the banner, which is the correct nudge.
function subscribeAck(notify: () => void) {
  window.addEventListener("storage", notify)
  return () => window.removeEventListener("storage", notify)
}
const getAckClient = () => window.localStorage.getItem(ACK_KEY) === "1"
const getAckServer = () => false

function useAck(): [boolean, () => void] {
  const ack = React.useSyncExternalStore(subscribeAck, getAckClient, getAckServer)
  const dismiss = React.useCallback(() => {
    window.localStorage.setItem(ACK_KEY, "1")
    // Same-tab subscribers don't see the native `storage` event, so fire
    // a synthetic one to refresh other component instances.
    window.dispatchEvent(new StorageEvent("storage", { key: ACK_KEY }))
  }, [])
  return [ack, dismiss]
}

/**
 * First-boot warning shown when the engine is running with neither a scope
 * filter (HOPPER_ALLOWED_DOMAINS) nor authentication. Dismissable; the ack
 * persists in localStorage so the banner doesn't nag forever, but reappears
 * if the operator clears storage or moves to a new browser.
 */
export function OperatorWarningBanner({ className }: { className?: string }) {
  const [config, setConfig] = React.useState<EngineConfig | null>(null)
  const [acked, dismiss] = useAck()

  React.useEffect(() => {
    let cancelled = false
    fetch("/api/config", { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : null))
      .then((data: EngineConfig | null) => {
        if (!cancelled) setConfig(data)
      })
      .catch(() => {
        // Engine offline — leave config null so the banner stays hidden;
        // there's a separate "engine offline" empty state for that case.
      })
    return () => {
      cancelled = true
    }
  }, [])

  if (!config) return null
  if (config.has_scope || config.has_auth) return null
  if (acked) return null

  return (
    <div
      role="alert"
      className={cn(
        "flex items-center gap-2 sm:gap-3 px-3 sm:px-4 py-2 border-b border-border bg-card text-micro font-mono",
        className,
      )}
    >
      <span className="text-destructive font-bold tracking-widest shrink-0">[ UNSCOPED ]</span>
      <span className="text-muted-foreground flex-1 min-w-0 truncate">
        No scope filter or auth — anyone can scan any domain.{" "}
        <Link
          href="/settings"
          className="text-foreground hover:text-terminal-green underline underline-offset-2 transition-colors"
        >
          See Settings for how to lock this down →
        </Link>
      </span>
      <button
        type="button"
        onClick={dismiss}
        aria-label="Dismiss advisory"
        className="shrink-0 text-muted-foreground-3 hover:text-foreground transition-colors"
      >
        <X className="size-3.5" />
      </button>
    </div>
  )
}

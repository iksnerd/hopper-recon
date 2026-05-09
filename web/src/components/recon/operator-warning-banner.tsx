"use client"

import * as React from "react"
import { X } from "lucide-react"
import {
  ReconCard,
  ReconCardHeader,
  ReconCardHeaderText,
  ReconCardEyebrow,
  ReconCardTitle,
  ReconCardAction,
  ReconCardContent,
} from "@/components/recon/recon-card"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

interface EngineConfig {
  version: string
  has_scope: boolean
  has_auth: boolean
  cooldown_s: number
}

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
    <ReconCard tone="danger" className={cn("rounded-none border-l-0 border-r-0 border-t-0", className)}>
      <ReconCardHeader>
        <ReconCardHeaderText>
          <ReconCardEyebrow className="text-destructive">[ AUTHORIZED-USE-ONLY ]</ReconCardEyebrow>
          <ReconCardTitle>Operator advisory — no scope filter, no authentication</ReconCardTitle>
        </ReconCardHeaderText>
        <ReconCardAction>
          <Button type="button" variant="ghost" size="sm" aria-label="Dismiss advisory" onClick={dismiss}>
            <X className="size-4" />
            <span className="text-micro">[ack]</span>
          </Button>
        </ReconCardAction>
      </ReconCardHeader>
      <ReconCardContent className="text-data text-muted-foreground space-y-2">
        <p>
          This engine is running with <span className="text-foreground">no scope filter</span> and{" "}
          <span className="text-foreground">no authentication</span>. Anyone reaching this UI or the engine
          on <code className="text-foreground">/mcp</code> can scan any domain you point them at.
        </p>
        <p>
          Operate only against assets you own or have written authorization to test. To narrow scope,
          set <code className="text-foreground">HOPPER_ALLOWED_DOMAINS</code> on the engine
          (comma-separated apex list) and restart. Engine version{" "}
          <span className="text-foreground tabular-nums">{config.version}</span>.
        </p>
      </ReconCardContent>
    </ReconCard>
  )
}

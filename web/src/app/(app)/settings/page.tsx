"use client"

import * as React from "react"
import { Panel } from "@/components/recon/panel"
import { PageHeader } from "@/components/recon/page-header"
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table"
import { CopyButton } from "@/components/recon/copy-button"
import type { EngineConfig } from "@/lib/engine-client"

function StatusBadge({ ok, okLabel, failLabel }: { ok: boolean; okLabel: string; failLabel: string }) {
  return (
    <span className={ok ? "text-terminal-green" : "text-destructive"}>
      {ok ? okLabel : failLabel}
    </span>
  )
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <TableRow className="border-none hover:bg-transparent">
      <TableCell className="p-0 py-1.5 pr-6 text-muted-foreground tracking-widest uppercase whitespace-nowrap w-40 align-top">{label}</TableCell>
      <TableCell className="p-0 py-1.5 text-foreground whitespace-normal">{children}</TableCell>
    </TableRow>
  )
}

/**
 * One configurable knob: the env line to set, and where to put it.
 *
 * The engine reads its policy once at boot (`LoadPolicy` in engine/policy.go),
 * so there is deliberately no in-app editing — a write endpoint would be
 * unauthenticated today and the things it would edit are the abuse guardrails
 * (scope filter, gov/mil blocklist). Operator-controlled via .env is the point,
 * not a limitation. This panel exists so the page tells you exactly what to
 * change instead of naming a variable and leaving you to grep for it.
 */
function EnvSetting({
  env,
  what,
  applies = "engine",
}: {
  env: string
  what: React.ReactNode
  applies?: "engine" | "web"
}) {
  return (
    <div className="py-2 first:pt-0 last:pb-0 border-b border-border last:border-b-0">
      <p className="text-body text-muted-foreground-2">{what}</p>
      <div className="mt-1.5 flex items-start gap-2">
        {/* whitespace-pre-line so a two-line snippet renders as two lines;
            without it HTML collapses the newline and it reads as one var. */}
        <code className="flex-1 min-w-0 break-all whitespace-pre-line bg-card-inset border border-border px-2 py-1 text-data text-terminal-green">
          {env}
        </code>
        <CopyButton value={env} className="mt-1 shrink-0" />
      </div>
      <p className="mt-1 text-micro text-muted-foreground-3">
        add to <span className="text-muted-foreground">./.env</span> next to docker-compose.yml, then{" "}
        <span className="text-muted-foreground">docker compose up -d --force-recreate {applies}</span>
      </p>
    </div>
  )
}

export default function SettingsPage() {
  const [config, setConfig] = React.useState<EngineConfig | null>(null)
  const [err, setErr] = React.useState(false)

  React.useEffect(() => {
    const ac = new AbortController()
    fetch("/api/config", { cache: "no-store", signal: ac.signal })
      .then((r) => r.ok ? r.json() : Promise.reject())
      .then((d: EngineConfig) => setConfig(d))
      .catch((e: unknown) => { if ((e as Error)?.name !== "AbortError") setErr(true) })
    return () => ac.abort()
  }, [])

  return (
    <div className="min-h-screen font-mono text-foreground">
      <PageHeader segments={[{ label: "SETTINGS", href: "/settings" }]} />

      <div className="mx-auto max-w-5xl px-3 sm:px-6 py-4 sm:py-6 space-y-4">

        {/* Live engine status */}
        <Panel label="// ENGINE STATUS">
          {err ? (
            <p className="text-body text-destructive">engine unreachable — is the container running?</p>
          ) : !config ? (
            <p className="text-body text-muted-foreground-3">loading…</p>
          ) : (
            <Table className="text-body">
              <TableBody>
                <Row label="VERSION">{config.version}</Row>
                <Row label="SCOPE">
                  <StatusBadge ok={config.has_scope} okLabel="enforced" failLabel="open — any domain scannable" />
                  {!config.has_scope && (
                    <span className="text-muted-foreground-3 ml-2">set HOPPER_ALLOWED_DOMAINS on the engine</span>
                  )}
                </Row>
                <Row label="AUTH">
                  <StatusBadge ok={config.has_auth} okLabel="enabled" failLabel="disabled — anyone can scan" />
                </Row>
                <Row label="COOLDOWN">{config.cooldown_s}s between scans per target</Row>
                <Row label="GEO DB">
                  <StatusBadge
                    ok={config.has_geo_db}
                    okLabel="loaded — GeoLite2-Country.mmdb found"
                    failLabel="missing — geo lookups return no data"
                  />
                  {!config.has_geo_db && (
                    <span className="block text-muted-foreground-3 mt-0.5">
                      place GeoLite2-Country.mmdb at ~/.config/hopper-recon/ and restart
                    </span>
                  )}
                </Row>
              </TableBody>
            </Table>
          )}
        </Panel>

        {/* How to change the things above */}
        <Panel label="// CONFIGURE">
          <p className="text-body text-muted-foreground-3 mb-3">
            The engine reads its policy once at startup, so these are set as environment
            variables rather than edited here — the scope filter and blocklist are abuse
            guardrails, and an in-app control would be unauthenticated until auth lands.
          </p>
          <EnvSetting
            env="HOPPER_ALLOWED_DOMAINS=example.com,example.org"
            what={
              config?.has_scope
                ? "Scope is enforced. Change the list of apex domains the engine will scan; anything else returns 403 and an audit row."
                : "Restrict the engine to specific apex domains. Anything else returns 403 and an audit row. Currently unset, so any domain is scannable."
            }
          />
          <EnvSetting
            env={"HOPPER_OVERRIDE_BLOCKLIST=true\nHOPPER_BLOCKLIST_OVERRIDE_REASON=Engagement #1234, authorization on file"}
            what="Allow probing *.gov / *.mil / *.gouv.fr / *.gov.uk / *.go.jp / *.gc.ca / *.gov.au, which are refused by default. Both lines are required — a missing reason leaves protection on — and every override is recorded in audit_log."
          />
          <div className="pt-2 mt-1 border-t border-border space-y-1">
            <p className="text-micro text-muted-foreground-3">
              <span className="text-muted-foreground">COOLDOWN</span> is a compile-time constant
              (<span className="text-muted-foreground">cooldownSeconds</span> in engine/server.go),
              not an environment variable — changing it needs a rebuild.
            </p>
            <p className="text-micro text-muted-foreground-3">
              <span className="text-muted-foreground">AUTH</span> is not implemented yet. Put the
              dashboard behind a VPN, Tailscale, or Cloudflare Access; see DEPLOY.md.
            </p>
            <p className="text-micro text-muted-foreground-3">
              <span className="text-muted-foreground">GEO DB</span> is a file, not a variable —
              place GeoLite2-Country.mmdb in ~/.config/hopper-recon/ on the host.
            </p>
          </div>
        </Panel>

        {/* Scan tools */}
        <Panel label="// WHAT EACH SCAN DOES">
          <Table className="text-body">
            <TableBody>
              <Row label="SUBDOMAINS">Finds all subdomains (e.g. api.example.com, staging.example.com) using public OSINT sources — no requests to the target.</Row>
              <Row label="DNS">Resolves the domain to its IP addresses and reads DNS records (A, NS, MX, TXT). Also checks for SPF, DMARC, and DKIM email-security records.</Row>
              <Row label="TLS CERTIFICATE">Reads the public TLS certificate — who issued it, when it expires, which domains it covers, and what cipher the server uses.</Row>
              <Row label="HTTP">Makes one HTTP request to detect the server software, page title, tech stack, and response time. Identifies itself with a hopper-recon User-Agent.</Row>
              <Row label="CDN / WAF">Checks which CDN, cloud provider, or Web Application Firewall is in front of each resolved IP — e.g. Cloudflare, AWS, Fastly.</Row>
              <Row label="HISTORICAL URLS">Pulls URLs crawled by the Wayback Machine and AlienVault. Shows what paths and files have been publicly indexed — no requests to the target.</Row>
              <Row label="SUBDOMAIN MUTATIONS">Generates likely subdomain variants (dev-api, staging-api, api2…) by permuting known subdomains. These are unverified guesses — use DNS Verify to confirm which are live.</Row>
              <Row label="DNS VERIFY (MUTATIONS)">Takes the mutation candidates and checks each one in DNS. Returns only the ones with a real A record — i.e. subdomains that actually exist.</Row>
              <Row label="GEO LOOKUP">Maps IP addresses to countries using a local MaxMind database. Used automatically when displaying the globe on the history page.</Row>
            </TableBody>
          </Table>
        </Panel>

        {/* API keys */}
        <Panel label="// API KEYS" variant="inset">
          <p className="text-body text-muted-foreground-2">
            subfinder reads keys from{" "}
            <span className="text-terminal-green">~/.config/subfinder/provider-config.yaml</span>{" "}
            inside the engine container. Mount a host config volume to persist keys across restarts.
            Keys are optional — subfinder runs with degraded source coverage without them.
          </p>
        </Panel>

        {/* MCP / HTTP */}
        <Panel label="// TRANSPORT">
          <Table className="text-body">
            <TableBody>
              <Row label="HTTP">engine at port 9119 (loopback) · REST + /mcp over HTTP</Row>
              <Row label="MCP STDIO">hopper-recon mcp — stdio transport for one-shot agent containers</Row>
              <Row label="WEB">Next.js at port 9120 (or npm run dev for local iteration)</Row>
            </TableBody>
          </Table>
        </Panel>

      </div>
    </div>
  )
}

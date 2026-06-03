"use client"

import * as React from "react"
import { Panel } from "@/components/recon/panel"
import { PageHeader } from "@/components/recon/page-header"
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table"
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

"use client"

import * as React from "react"
import { Panel } from "@/components/recon/panel"
import { PageHeader } from "@/components/recon/page-header"
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table"

interface EngineConfig {
  version: string
  has_scope: boolean
  has_auth: boolean
  cooldown_s: number
  has_geo_db?: boolean
}

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
    fetch("/api/config", { cache: "no-store" })
      .then((r) => r.ok ? r.json() : Promise.reject())
      .then((d: EngineConfig) => setConfig(d))
      .catch(() => setErr(true))
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
                {config.has_geo_db !== undefined && (
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
                )}
              </TableBody>
            </Table>
          )}
        </Panel>

        {/* Scan tools */}
        <Panel label="// SCAN TOOLS">
          <Table className="text-body">
            <TableBody>
              <Row label="passive_subdomains">subfinder · osint passive enumeration</Row>
              <Row label="resolve_dns">dnsx · A / AAAA / NS / MX / TXT records + email security check</Row>
              <Row label="fetch_tls_cert">tlsx · certificate chain, expiry, cipher, SANs</Row>
              <Row label="probe_http">httpx · HTTP probe — status, server, tech stack, JARM, CPE</Row>
              <Row label="check_cdn">cdncheck · CDN / WAF / cloud attribution per resolved IP</Row>
              <Row label="find_urls">urlfinder · historical URLs from Wayback Machine + AlienVault</Row>
              <Row label="expand_subdomains">alterx · permutation-based subdomain mutation candidates</Row>
              <Row label="resolve_mutations">dnsx (on-demand) · DNS-verify mutation candidates from alterx</Row>
              <Row label="lookup_geoip">MaxMind GeoLite2 · IP → country (enrichment, not a scan tab)</Row>
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

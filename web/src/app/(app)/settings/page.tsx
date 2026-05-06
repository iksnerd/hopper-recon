"use client"

import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table"
import { Panel } from "@/components/recon/panel"
import { PageHeader } from "@/components/recon/page-header"

const SETTINGS = [
  {
    section: "// MCP SERVER",
    rows: [
      { label: "TRANSPORT", value: "stdio", editable: false },
      { label: "ENGINE", value: "docker · hopper-recon:latest", editable: false },
      { label: "RATE LIMIT", value: "50 rps (httpx)", editable: false },
    ],
  },
  {
    section: "// SCAN DEFAULTS",
    rows: [
      { label: "TOOLS", value: "passive_subdomains · resolve_dns · fetch_tls_cert · probe_http", editable: false },
      { label: "TIER", value: "1 + 2 (osint + standard browser-like)", editable: false },
      { label: "TIMEOUT", value: "30s per tool", editable: false },
    ],
  },
]

export default function SettingsPage() {
  return (
    <div className="min-h-screen font-mono text-foreground scanlines">
      <PageHeader segments={["SETTINGS"]} />

      <div className="mx-auto max-w-5xl px-3 sm:px-6 py-4 sm:py-6 space-y-4">
        {SETTINGS.map(({ section, rows }) => (
          <Panel key={section} label={section}>
            <Table className="text-body">
              <TableBody>
                {rows.map(({ label, value }) => (
                  <TableRow key={label} className="border-b border-card-hover hover:bg-transparent">
                    <TableCell className="p-0 py-1.5 pr-6 text-muted-foreground tracking-widest uppercase whitespace-nowrap w-40 align-top">{label}</TableCell>
                    <TableCell className="p-0 py-1.5 text-foreground whitespace-normal">{value}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Panel>
        ))}

        <Panel label="// API KEYS" variant="inset">
          <p className="text-body text-muted-foreground-2">
            subfinder reads keys from <span className="text-terminal-green">~/.config/subfinder/provider-config.yaml</span> inside the docker container.
            mount a config volume to persist api keys across restarts.
          </p>
        </Panel>
      </div>
    </div>
  )
}

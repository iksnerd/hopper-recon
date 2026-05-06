"use client"

import { SidebarTrigger } from "@/components/ui/sidebar"
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table"

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
      <header className="sticky top-0 z-10 bg-background border-b border-border px-4 py-3 flex items-center gap-3">
        <SidebarTrigger className="size-6 text-muted-foreground hover:text-foreground hover:bg-card-hover rounded-none transition-colors duration-100" />
        <span className="text-muted">/</span>
        <span className="text-body text-foreground">settings</span>
      </header>

      <div className="mx-auto max-w-5xl px-3 sm:px-6 py-4 sm:py-6 space-y-4">
        {SETTINGS.map(({ section, rows }) => (
          <div key={section} className="border border-border bg-card p-4">
            <div className="text-micro text-muted-foreground mb-3">{section}</div>
            <Table className="text-body">
              <TableBody>
                {rows.map(({ label, value }) => (
                  <TableRow key={label} className="border-b border-card-hover hover:bg-transparent">
                    <TableCell className="p-0 py-1.5 pr-6 text-muted-foreground whitespace-nowrap w-36">{label}</TableCell>
                    <TableCell className="p-0 py-1.5 text-muted-foreground-2 whitespace-normal">{value}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ))}

        <div className="border border-border bg-card-inset p-4">
          <div className="text-micro text-muted-foreground mb-2">{"// API KEYS"}</div>
          <p className="text-body text-muted-foreground-3">
            subfinder reads keys from <span className="text-muted-foreground">~/.config/subfinder/provider-config.yaml</span> inside the docker container.
            mount a config volume to persist api keys across restarts.
          </p>
        </div>
      </div>
    </div>
  )
}

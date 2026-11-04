import * as React from "react"
import type { RdapResult } from "@/lib/scan-parser"
import { daysLabel, daysUntil } from "@/lib/rdap"
import { Panel } from "@/components/recon/panel"
import { DataChip } from "@/components/recon/data-chip"
import { ToolSourceLink } from "@/components/recon/tool-source-link"
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table"

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <TableRow className="border-b border-card-hover hover:bg-transparent">
      <TableCell className="p-0 py-1.5 pr-4 text-muted-foreground tracking-widest uppercase whitespace-nowrap align-top">{label}</TableCell>
      <TableCell className="p-0 py-1.5 text-foreground break-words">{children}</TableCell>
    </TableRow>
  )
}

// ISO date, not a locale format: the same text on every machine, so a pasted
// screenshot or a report reads the same everywhere.
const day = (iso: string) => (iso ? iso.slice(0, 10) : "—")

/** A domain's registration as its registry reports it (RDAP): registrar, dates, status flags, name servers and DNSSEC. */
export function RegistrationPanel({ rdap, variant = "default" }: { rdap: RdapResult; variant?: "default" | "inset" }) {
  const left = daysUntil(rdap.expires, new Date())
  return (
    <Panel
      label="// REGISTRATION"
      variant={variant}
      action={<ToolSourceLink name="rdap" url="https://about.rdap.org/" />}
    >
      <Table className="text-body">
        <TableBody>
          <Row label="REGISTRAR">{rdap.registrar || "—"}</Row>
          <Row label="REGISTERED">{day(rdap.registered)}</Row>
          <Row label="EXPIRES">
            {day(rdap.expires)}
            {left !== null && (
              <span className={`ml-2 text-micro ${left <= 30 ? "text-destructive" : "text-muted-foreground-3"}`}>[{daysLabel(left)}]</span>
            )}
          </Row>
          <Row label="STATUS">
            {rdap.status.length === 0 ? (
              "—"
            ) : (
              <span className="flex flex-wrap gap-1">
                {rdap.status.map((s) => <DataChip key={s}>{s}</DataChip>)}
              </span>
            )}
          </Row>
          <Row label="NAMESERVERS">{rdap.nameservers.length > 0 ? rdap.nameservers.join(", ") : "—"}</Row>
          <Row label="DNSSEC">
            <span className={`text-micro ${rdap.dnssec ? "text-terminal-green" : "text-muted-foreground-3"}`}>
              {rdap.dnssec ? "[SIGNED]" : "[UNSIGNED]"}
            </span>
          </Row>
        </TableBody>
      </Table>
    </Panel>
  )
}

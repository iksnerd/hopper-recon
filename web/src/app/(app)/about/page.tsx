import { Panel } from "@/components/recon/panel"
import { PageHeader } from "@/components/recon/page-header"
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table"

type Credit = {
  name: string
  url: string
  note: string
}

const RECON_TOOLS: Credit[] = [
  { name: "subfinder",     url: "https://github.com/projectdiscovery/subfinder", note: "passive subdomain enumeration across 40+ osint sources" },
  { name: "dnsx",          url: "https://github.com/projectdiscovery/dnsx",      note: "fast multi-resolver dns toolkit (a / cname / ns / mx / txt)" },
  { name: "httpx",         url: "https://github.com/projectdiscovery/httpx",     note: "http probe — title, tech stack, jarm, redirect chain" },
  { name: "tlsx",          url: "https://github.com/projectdiscovery/tlsx",      note: "tls cert details — sans, expiry, cipher, weak / wildcard / expired flags" },
  { name: "cdncheck",      url: "https://github.com/projectdiscovery/cdncheck",  note: "detect cdn / waf / cloud provider for an ip or host" },
  { name: "urlfinder",     url: "https://github.com/projectdiscovery/urlfinder", note: "passive historical url discovery from web archives + osint sources" },
  { name: "geoip2-golang", url: "https://github.com/oschwald/geoip2-golang",     note: "maxmind geolite2 mmdb reader (offline ip → country)" },
]

const ENGINE: Credit[] = [
  { name: "litestream",                  url: "https://github.com/benbjohnson/litestream",         note: "continuous sqlite wal replication to s3 / r2 / azure / gcs" },
  { name: "modernc.org/sqlite",          url: "https://gitlab.com/cznic/sqlite",                   note: "pure-go sqlite driver — no cgo, trivial multi-arch" },
  { name: "modelcontextprotocol/go-sdk", url: "https://github.com/modelcontextprotocol/go-sdk",    note: "official go sdk for mcp — powers /mcp endpoint and stdio transport" },
]

const WEB: Credit[] = [
  { name: "next.js",                url: "https://github.com/vercel/next.js",      note: "react framework — app router, server components" },
  { name: "shadcn/ui",              url: "https://github.com/shadcn-ui/ui",        note: "component primitives on top of radix + tailwind" },
  { name: "@tanstack/react-query",  url: "https://github.com/TanStack/query",      note: "server-state caching for /api/scans/* fetches" },
  { name: "recharts",               url: "https://github.com/recharts/recharts",   note: "history timeline + multi-scan trend charts" },
  { name: "cobe",                   url: "https://github.com/shuding/cobe",        note: "webgl globe — geo distribution of scanned ips" },
  { name: "date-fns",               url: "https://github.com/date-fns/date-fns",   note: "relative timestamps in history list" },
  { name: "lucide",                 url: "https://github.com/lucide-icons/lucide", note: "icon set — sidebar + ui glyphs" },
]

const DATA: Credit[] = [
  { name: "MaxMind GeoLite2", url: "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data", note: "free ip → country database — bundled at runtime, license requires attribution" },
]

function CreditRow({ name, url, note }: Credit) {
  return (
    <TableRow className="border-b border-card-hover hover:bg-transparent">
      <TableCell className="p-0 py-1.5 pr-6 whitespace-nowrap w-56 align-top">
        <a
          href={url}
          target="_blank"
          rel="noopener noreferrer"
          className="group inline-flex items-baseline gap-1.5 text-terminal-green-dim transition-colors hover:text-terminal-green"
        >
          <span>{name}</span>
          <span aria-hidden className="text-muted-foreground-3 transition-colors group-hover:text-terminal-green">↗</span>
        </a>
      </TableCell>
      <TableCell className="p-0 py-1.5 whitespace-normal text-muted-foreground-2">{note}</TableCell>
    </TableRow>
  )
}

function CreditTable({ rows }: { rows: Credit[] }) {
  return (
    <Table className="text-body">
      <TableBody>
        {rows.map((c) => <CreditRow key={c.name} {...c} />)}
      </TableBody>
    </Table>
  )
}

export default function AboutPage() {
  return (
    <div className="min-h-screen font-mono text-foreground scanlines">
      <PageHeader segments={["ABOUT"]} />

      <div className="mx-auto max-w-5xl px-3 sm:px-6 py-4 sm:py-6 space-y-4">
        <Panel label="// HOPPER-RECON" variant="inset">
          <p className="text-body text-muted-foreground-2">
            self-hosted, mcp-native security reconnaissance dashboard. a go engine wraps the
            {" "}
            <a
              href="https://github.com/projectdiscovery"
              target="_blank"
              rel="noopener noreferrer"
              className="text-terminal-green-dim transition-colors hover:text-terminal-green"
            >
              projectdiscovery
            </a>
            {" "}
            osint toolchain plus a bundled maxmind geoip reader, and owns its own sqlite; a next.js client renders the results. ai agents (claude / cline) attach over mcp at <span className="text-terminal-green">/mcp</span>.
          </p>
          <p className="mt-3 text-body text-muted-foreground-2">
            source:&nbsp;
            <a
              href="https://github.com/iksnerd/hopper-recon"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-baseline gap-1 text-terminal-green-dim transition-colors hover:text-terminal-green"
            >
              <span>github.com/iksnerd/hopper-recon</span>
              <span aria-hidden>↗</span>
            </a>
          </p>
        </Panel>

        <Panel label="// RECON TOOLS">
          <CreditTable rows={RECON_TOOLS} />
        </Panel>

        <Panel label="// ENGINE & RUNTIME">
          <CreditTable rows={ENGINE} />
        </Panel>

        <Panel label="// WEB">
          <CreditTable rows={WEB} />
        </Panel>

        <Panel label="// DATA">
          <CreditTable rows={DATA} />
        </Panel>

        <Panel label="// LICENSE" variant="inset">
          <p className="text-body text-muted-foreground-2">
            hopper-recon ships under the mit license. each component above is distributed under its own upstream license — follow the links for terms.
          </p>
        </Panel>
      </div>
    </div>
  )
}

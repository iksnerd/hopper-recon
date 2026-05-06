import Link from "next/link"

const CAPABILITIES = [
  { label: "SUBDOMAINS", tool: "passive_subdomains", desc: "osint enumeration via subfinder" },
  { label: "DNS",        tool: "resolve_dns",        desc: "live resolution via dnsx" },
  { label: "TLS",        tool: "fetch_tls_cert",     desc: "cert · cn · sans · expiry via tlsx" },
  { label: "HTTP",       tool: "probe_http",         desc: "stack detection via httpx @ 50 rps" },
]

export default function Home() {
  return (
    <div className="min-h-screen font-mono text-foreground scanlines flex flex-col">
      <header className="border-b border-border px-6 py-3 flex items-center justify-between">
        <span className="text-micro uppercase text-muted-foreground">hopper-recon</span>
        <span className="text-micro text-muted">v0.1.0-alpha</span>
      </header>

      <main className="flex-1 flex items-center justify-center px-3 sm:px-6 py-8 sm:py-16">
        <div className="w-full max-w-2xl space-y-4">

          {/* Boot block */}
          <div className="border border-border bg-card-inset p-4 sm:p-6">
            <div className="text-micro text-muted-foreground-3 mb-5">{"// SYSTEM INIT"}</div>
            <h1 className="text-3xl sm:text-5xl font-bold text-primary tracking-tight mb-4">
              hopper-recon
            </h1>
            <p className="text-emphasis text-muted-foreground-2 leading-relaxed max-w-md">
              agent-first attack surface reconnaissance. passive, non-invasive,
              consumed by ai agents via mcp. maps subdomains, dns, tls, and http
              without touching target infrastructure.
            </p>
            <div className="mt-8 flex items-center gap-3">
              <Link
                href="/dashboard"
                className="text-emphasis text-foreground hover:text-primary hover:bg-card-hover px-5 py-2 border border-border transition-colors duration-100"
              >
                &gt;_ enter dashboard
              </Link>
              <span className="text-body text-muted-foreground-3">no account required</span>
            </div>
          </div>

          {/* Capabilities grid */}
          <div className="grid grid-cols-2 sm:grid-cols-2 gap-px bg-secondary">
            {CAPABILITIES.map(({ label, tool, desc }) => (
              <div key={tool} className="bg-card p-4">
                <div className="text-micro text-muted-foreground mb-1">{label}</div>
                <div className="text-body text-muted-foreground-2">{desc}</div>
              </div>
            ))}
          </div>

          {/* Live probe example (from MCP — anthropic.com) */}
          <div className="border border-border bg-card-inset p-4">
            <div className="text-micro text-muted-foreground mb-3">
              {"// LIVE EXAMPLE"} &mdash; probe_http(anthropic.com)
            </div>
            <table className="w-full border-collapse text-body">
              <tbody>
                {([
                  ["TARGET",   "anthropic.com"],
                  ["STATUS",   "[302 → www.anthropic.com]"],
                  ["SERVER",   "cloudflare"],
                  ["IP",       "160.79.104.10"],
                  ["TIME",     "45ms"],
                  ["TECH",     "Cloudflare · HTTP/3 · AWS S3 · Sanity.io"],
                ] as const).map(([k, v]) => (
                  <tr key={k} className="border-b border-card-hover">
                    <td className="py-1.5 pr-6 text-muted-foreground whitespace-nowrap">{k}</td>
                    <td className="py-1.5 text-muted-foreground-2">{v}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

        </div>
      </main>

      <footer className="border-t border-border px-6 py-3 flex items-center justify-between">
        <span className="text-micro text-muted">tier 1 + tier 2 tools only — strictly non-invasive</span>
        <span className="text-micro text-muted">powered by subfinder · dnsx · tlsx · httpx</span>
      </footer>
    </div>
  )
}

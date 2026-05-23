import Link from "next/link"
import { Panel } from "@/components/recon/panel"
import pkg from "../../package.json"

const CAPABILITIES = [
  { label: "SUBDOMAINS", tool: "passive_subdomains", desc: "osint enumeration via subfinder" },
  { label: "DNS",        tool: "resolve_dns",        desc: "a/aaaa/cname/mx/txt records via dnsx" },
  { label: "TLS",        tool: "fetch_tls_cert",     desc: "cert · cn · sans · expiry via tlsx" },
  { label: "HTTP",       tool: "probe_http",         desc: "stack detection via httpx @ 50 rps" },
  { label: "CDN",        tool: "check_cdn",          desc: "cdn / cloud / waf attribution via cdncheck" },
  { label: "URLS",       tool: "find_urls",          desc: "historical urls via wayback / commoncrawl" },
  { label: "MUTATIONS",  tool: "expand_subdomains",  desc: "permutation wordlists via alterx" },
  { label: "GEO",        tool: "lookup_geoip",       desc: "ip → country via maxmind geolite2" },
]

export default function Home() {
  return (
    <div className="min-h-screen font-mono text-foreground scanlines flex flex-col">
      <header className="border-b border-border px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="size-2 bg-terminal-green" aria-hidden />
          <span className="text-micro uppercase text-foreground tracking-widest font-bold">hopper-recon</span>
        </div>
        <span className="text-micro tracking-widest uppercase text-muted-foreground-3">v{pkg.version}</span>
      </header>

      <main className="flex-1 flex items-center justify-center px-3 sm:px-6 py-8 sm:py-16">
        <div className="w-full max-w-2xl space-y-5">

          {/* Boot block */}
          <div className="border border-border bg-card-inset p-4 sm:p-6 relative before:absolute before:left-0 before:top-6 before:bottom-6 before:w-[2px] before:bg-terminal-green/70">
            <div className="text-micro text-muted-foreground-3 mb-5 tracking-widest uppercase font-bold">{"// SYSTEM INIT"}</div>
            <h1 className="text-3xl sm:text-5xl font-bold text-foreground tracking-tight mb-4">
              hopper-recon<span className="text-terminal-green cursor-blink">_</span>
            </h1>
            <p className="text-emphasis text-muted-foreground-2 leading-relaxed max-w-md">
              agent-first attack surface reconnaissance. passive, non-invasive,
              consumed by ai agents via mcp. maps subdomains, dns, tls, http,
              cdn, historical urls, and subdomain mutations without touching
              target infrastructure.
            </p>
            <div className="mt-8 flex items-center gap-3">
              <Link
                href="/dashboard"
                className="text-emphasis text-terminal-green hover:text-background hover:bg-terminal-green px-5 py-2 border border-terminal-green/40 bg-card-inset transition-colors duration-100 tracking-widest uppercase font-bold"
              >
                &gt;_ ENTER DASHBOARD
              </Link>
              <span className="text-body text-muted-foreground-3">no account required</span>
            </div>
          </div>

          {/* Capabilities grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-px bg-border border border-border">
            {CAPABILITIES.map(({ label, tool, desc }) => (
              <div key={tool} className="bg-card p-4 hover:bg-card-hover transition-colors duration-100">
                <div className="text-micro text-muted-foreground mb-1 tracking-widest uppercase font-bold">{label}</div>
                <div className="text-body text-muted-foreground-2">{desc}</div>
              </div>
            ))}
          </div>

          {/* Live probe example (from MCP — anthropic.com) */}
          <Panel label="// LIVE EXAMPLE" variant="inset" action={<span className="text-muted-foreground-3 normal-case tracking-normal">probe_http(anthropic.com)</span>}>
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
                    <td className="py-1.5 pr-6 text-muted-foreground tracking-widest uppercase whitespace-nowrap">{k}</td>
                    <td className="py-1.5 text-foreground">{v}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Panel>

        </div>
      </main>

      <footer className="border-t border-border px-6 py-3 flex items-center justify-between">
        <span className="text-micro tracking-widest uppercase text-muted-foreground-3">tier 1 + tier 2 tools only — strictly non-invasive</span>
        <span className="text-micro tracking-widest uppercase text-muted-foreground-3">powered by subfinder · dnsx · tlsx · httpx · cdncheck · urlfinder · alterx</span>
      </footer>
    </div>
  )
}

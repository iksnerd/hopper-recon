package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// MCP input/output types — kept narrow so the schemas auto-generated from
// jsonschema tags stay friendly for the AI clients calling them.

type subfinderInput struct {
	Domain string `json:"domain" jsonschema:"The domain to perform passive reconnaissance on (e.g., example.com)"`
}
type subfinderOutput struct {
	Findings []SubfinderEntry `json:"findings" jsonschema:"Subdomains found, each with the OSINT sources that discovered it"`
	Error    string           `json:"error,omitempty" jsonschema:"Any error message encountered during the scan"`
}

type targetInput struct {
	Target string `json:"target" jsonschema:"The domain or subdomain to act on"`
}
type linesOutput struct {
	Results []string `json:"results" jsonschema:"One JSON-encoded record per line of tool output"`
	Error   string   `json:"error,omitempty" jsonschema:"Any error message encountered during the scan"`
}

type geoipInput struct {
	Ips string `json:"ips" jsonschema:"Comma-separated list of IPv4/IPv6 addresses to look up (e.g., 8.8.8.8,1.1.1.1)"`
}
type geoipOutput struct {
	Results []GeoipEntry `json:"results" jsonschema:"One entry per resolvable IP. Empty Country means no match in the local mmdb (or the mmdb file is missing)."`
	Error   string       `json:"error,omitempty" jsonschema:"Any error message encountered during lookup"`
}

func handleSubfinder(ctx context.Context, _ *mcp.CallToolRequest, in subfinderInput) (*mcp.CallToolResult, subfinderOutput, error) {
	findings, err := RunSubfinder(ctx, in.Domain)
	if err != nil {
		return nil, subfinderOutput{Error: err.Error()}, nil
	}
	return nil, subfinderOutput{Findings: findings}, nil
}

func handleDnsx(ctx context.Context, _ *mcp.CallToolRequest, in targetInput) (*mcp.CallToolResult, linesOutput, error) {
	res, err := RunDnsx(ctx, in.Target)
	if err != nil {
		return nil, linesOutput{Error: err.Error()}, nil
	}
	return nil, linesOutput{Results: res}, nil
}

func handleTlsx(ctx context.Context, _ *mcp.CallToolRequest, in targetInput) (*mcp.CallToolResult, linesOutput, error) {
	res, err := RunTlsx(ctx, in.Target)
	if err != nil {
		return nil, linesOutput{Error: err.Error()}, nil
	}
	return nil, linesOutput{Results: res}, nil
}

func handleHttpx(ctx context.Context, _ *mcp.CallToolRequest, in targetInput) (*mcp.CallToolResult, linesOutput, error) {
	res, err := RunHttpx(ctx, in.Target)
	if err != nil {
		return nil, linesOutput{Error: err.Error()}, nil
	}
	return nil, linesOutput{Results: res}, nil
}

func handleCdncheck(ctx context.Context, _ *mcp.CallToolRequest, in targetInput) (*mcp.CallToolResult, linesOutput, error) {
	res, err := RunCdncheck(ctx, in.Target)
	if err != nil {
		return nil, linesOutput{Error: err.Error()}, nil
	}
	return nil, linesOutput{Results: res}, nil
}

type urlfinderInput struct {
	Domain string `json:"domain" jsonschema:"The domain to gather historical URLs for (e.g., example.com)"`
}

func handleUrlfinder(ctx context.Context, _ *mcp.CallToolRequest, in urlfinderInput) (*mcp.CallToolResult, linesOutput, error) {
	res, err := RunUrlfinder(ctx, in.Domain)
	if err != nil {
		return nil, linesOutput{Error: err.Error()}, nil
	}
	return nil, linesOutput{Results: res}, nil
}

func handleLookupGeoip(_ context.Context, _ *mcp.CallToolRequest, in geoipInput) (*mcp.CallToolResult, geoipOutput, error) {
	ips := strings.Split(in.Ips, ",")
	res, err := LookupGeoip(ips)
	if err != nil {
		return nil, geoipOutput{Error: err.Error()}, nil
	}
	return nil, geoipOutput{Results: res}, nil
}

// buildMCPServer registers all tool handlers on a fresh server. Both the
// stdio mode and the HTTP /mcp mount call this — same surface, two transports.
func buildMCPServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "hopper-recon-engine",
		Version: "v0.2.0",
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "passive_subdomains",
		Description: "Perform strictly passive reconnaissance to find subdomains using OSINT (subfinder).",
	}, handleSubfinder)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "resolve_dns",
		Description: "Safely resolve a domain to verify if it is live using standard DNS queries (dnsx).",
	}, handleDnsx)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "fetch_tls_cert",
		Description: "Safely connect to a server to grab its public SSL/TLS certificate, CN, and SANs without sending payloads (tlsx).",
	}, handleTlsx)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "probe_http",
		Description: "Probe a target domain to detect HTTP servers, extract titles, and technology stack. Identifies itself with a hopper-recon User-Agent. Rate-limited to 50 req/s (httpx).",
	}, handleHttpx)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "check_cdn",
		Description: "Attribute the IPs behind a domain to their CDN, cloud, or WAF provider using bundled CIDR lists (cdncheck). Pure offline lookup — no requests reach the target.",
	}, handleCdncheck)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "find_urls",
		Description: "Gather historical URLs for a domain from passive sources (waybackarchive, commoncrawl, alienvault). No requests to the target (urlfinder).",
	}, handleUrlfinder)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "lookup_geoip",
		Description: "Resolve IP addresses to ISO 3166-1 alpha-2 country codes using a bundled MaxMind GeoLite2-Country database. Pure offline, no external network calls.",
	}, handleLookupGeoip)

	return server
}

func runStdioMCP() error {
	log.Println("Hopper Recon engine: stdio MCP mode")
	return buildMCPServer().Run(context.Background(), &mcp.StdioTransport{})
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: hopper-recon [serve [-addr :8080] [-db /data/scans.db]]")
	fmt.Fprintln(os.Stderr, "  no args:  stdio MCP server (for AI agents via `docker run -i`)")
	fmt.Fprintln(os.Stderr, "  serve:    long-running HTTP server (REST + MCP at /mcp) for the dashboard")
}

func main() {
	if len(os.Args) < 2 {
		if err := runStdioMCP(); err != nil {
			log.Fatalf("stdio: %v", err)
		}
		return
	}

	switch os.Args[1] {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		addr := fs.String("addr", envOr("HOPPER_ADDR", ":8080"), "HTTP listen address")
		dbPath := fs.String("db", envOr("HOPPER_DB_PATH", "/data/scans.db"), "SQLite database path")
		_ = fs.Parse(os.Args[2:])
		if err := runHTTPServer(*addr, *dbPath); err != nil {
			log.Fatalf("serve: %v", err)
		}
	case "mcp", "stdio":
		if err := runStdioMCP(); err != nil {
			log.Fatalf("stdio: %v", err)
		}
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- Subfinder ---
type SubfinderInput struct {
	Domain string `json:"domain" jsonschema:"The domain to perform passive reconnaissance on (e.g., example.com)"`
}

type SubfinderEntry struct {
	Host    string   `json:"host"`
	Sources []string `json:"sources"`
}

type SubfinderOutput struct {
	Findings []SubfinderEntry `json:"findings" jsonschema:"Subdomains found, each with the OSINT sources that discovered it"`
	Error    string           `json:"error,omitempty" jsonschema:"Any error message encountered during the scan"`
}

// --- DNSX ---
type DnsxInput struct {
	Target string `json:"target" jsonschema:"The domain or subdomain to resolve (e.g., api.example.com)"`
}

type DnsxOutput struct {
	Results []string `json:"results" jsonschema:"The JSON output from dnsx containing resolved records"`
	Error   string   `json:"error,omitempty" jsonschema:"Any error message encountered during the scan"`
}

// --- TLSX ---
type TlsxInput struct {
	Target string `json:"target" jsonschema:"The domain or IP to fetch TLS certificate details for"`
}

type TlsxOutput struct {
	Results []string `json:"results" jsonschema:"The JSON output from tlsx containing SANs, CN, and cert details"`
	Error   string   `json:"error,omitempty" jsonschema:"Any error message encountered during the scan"`
}

// --- HTTPX ---
type HttpxInput struct {
	Target string `json:"target" jsonschema:"The target domain or IP to probe (e.g., api.example.com)"`
}

type HttpxOutput struct {
	Results []string `json:"results" jsonschema:"The JSON output from httpx containing status, title, tech, etc."`
	Error   string   `json:"error,omitempty" jsonschema:"Any error message encountered during the scan"`
}

// --- ASNMAP ---
type AsnmapInput struct {
	Domain string `json:"domain" jsonschema:"The domain to map to ASN and CIDR ranges (e.g., example.com)"`
}

type AsnmapOutput struct {
	Results []string `json:"results" jsonschema:"The JSON output from asnmap containing ASN and CIDR range entries"`
	Error   string   `json:"error,omitempty" jsonschema:"Any error message encountered during the scan"`
}

// --- UNCOVER ---
type UncoverInput struct {
	Domain string `json:"domain" jsonschema:"The domain to search for exposed hosts across internet scan databases (e.g., example.com)"`
}

type UncoverOutput struct {
	Results []string `json:"results" jsonschema:"The JSON output from uncover containing exposed IPs, ports, and source engines"`
	Error   string   `json:"error,omitempty" jsonschema:"Any error message encountered during the scan"`
}

func HandleSubfinder(ctx context.Context, req *mcp.CallToolRequest, input SubfinderInput) (*mcp.CallToolResult, SubfinderOutput, error) {
	// -oJ outputs JSONL, -cs collects source attribution per subdomain
	cmd := exec.CommandContext(ctx, "subfinder", "-d", input.Domain, "-silent", "-all", "-oJ", "-cs")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, SubfinderOutput{Error: fmt.Sprintf("failed to run subfinder: %v", err)}, nil
	}

	var findings []SubfinderEntry
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		var entry SubfinderEntry
		if jsonErr := json.Unmarshal([]byte(line), &entry); jsonErr == nil && entry.Host != "" {
			findings = append(findings, entry)
		}
	}

	return nil, SubfinderOutput{Findings: findings}, nil
}

func HandleDnsx(ctx context.Context, req *mcp.CallToolRequest, input DnsxInput) (*mcp.CallToolResult, DnsxOutput, error) {
	// -ns/-mx/-txt/-cdn/-asn add nameserver, mail, TXT records, CDN and ASN info
	cmd := exec.CommandContext(ctx, "dnsx", "-silent", "-a", "-cname", "-ns", "-mx", "-txt", "-cdn", "-asn", "-json")
	cmd.Stdin = strings.NewReader(input.Target + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, DnsxOutput{
			Error: fmt.Sprintf("failed to run dnsx: %v", err),
		}, nil
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var results []string
	for _, l := range lines {
		if l != "" {
			results = append(results, l)
		}
	}

	return nil, DnsxOutput{
		Results: results,
	}, nil
}

func HandleTlsx(ctx context.Context, req *mcp.CallToolRequest, input TlsxInput) (*mcp.CallToolResult, TlsxOutput, error) {
	// -san/-cn are redundant (already in JSON output); -so/-tv/-cipher/-wc/-expired/-self-signed add org, tls version, cipher, wildcard and misconfiguration checks
	cmd := exec.CommandContext(ctx, "tlsx", "-u", input.Target, "-so", "-tv", "-cipher", "-wc", "-expired", "-self-signed", "-silent", "-json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, TlsxOutput{
			Error: fmt.Sprintf("failed to run tlsx: %v", err),
		}, nil
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var results []string
	for _, l := range lines {
		if l != "" {
			results = append(results, l)
		}
	}

	return nil, TlsxOutput{
		Results: results,
	}, nil
}

func HandleHttpx(ctx context.Context, req *mcp.CallToolRequest, input HttpxInput) (*mcp.CallToolResult, HttpxOutput, error) {
	// -fr follows redirects; -jarm adds TLS fingerprint; -asn/-cname add network info; -location/-chain-status-codes show redirect chain
	cmd := exec.CommandContext(ctx, "httpx", "-u", input.Target, "-silent", "-json", "-title", "-td", "-sc", "-fr", "-location", "-jarm", "-asn", "-cname", "-rt", "-rl", "50")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, HttpxOutput{
			Error: fmt.Sprintf("failed to run httpx: %v", err),
		}, nil
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var results []string
	for _, l := range lines {
		if l != "" {
			results = append(results, l)
		}
	}

	return nil, HttpxOutput{
		Results: results,
	}, nil
}

func HandleAsnmap(ctx context.Context, req *mcp.CallToolRequest, input AsnmapInput) (*mcp.CallToolResult, AsnmapOutput, error) {
	cmd := exec.CommandContext(ctx, "asnmap", "-d", input.Domain, "-json", "-silent")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, AsnmapOutput{Error: fmt.Sprintf("failed to run asnmap: %v", err)}, nil
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var results []string
	for _, l := range lines {
		if l != "" {
			results = append(results, l)
		}
	}

	return nil, AsnmapOutput{Results: results}, nil
}

func HandleUncover(ctx context.Context, req *mcp.CallToolRequest, input UncoverInput) (*mcp.CallToolResult, UncoverOutput, error) {
	query := fmt.Sprintf("ssl:\"%s\"", input.Domain)
	cmd := exec.CommandContext(ctx, "uncover", "-q", query, "-json", "-silent", "-timeout", "30")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, UncoverOutput{Error: fmt.Sprintf("failed to run uncover: %v", err)}, nil
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var results []string
	for _, l := range lines {
		if l != "" {
			results = append(results, l)
		}
	}
	return nil, UncoverOutput{Results: results}, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "hopper-recon-engine",
		Version: "v0.1.0",
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "passive_subdomains",
		Description: "Perform strictly passive reconnaissance to find subdomains using OSINT (subfinder).",
	}, HandleSubfinder)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "resolve_dns",
		Description: "Safely resolve a domain to verify if it is live using standard DNS queries (dnsx).",
	}, HandleDnsx)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "fetch_tls_cert",
		Description: "Safely connect to a server to grab its public SSL/TLS certificate, CN, and SANs without sending payloads (tlsx).",
	}, HandleTlsx)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "probe_http",
		Description: "Safely probe a target domain to detect active HTTP servers, extract titles, and technology stack, strictly rate-limited to 50 requests per second (httpx).",
	}, HandleHttpx)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "map_asn",
		Description: "Map a domain to its ASN and associated CIDR ranges using passive OSINT (asnmap).",
	}, HandleAsnmap)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "search_hosts",
		Description: "Search internet scan databases (Shodan, Censys, FOFA) for exposed IPs and open ports associated with a domain using SSL certificate queries (uncover).",
	}, HandleUncover)

	log.Println("Hopper Recon MCP Server starting on stdio...")
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

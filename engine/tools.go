package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

// Version is single-sourced here so MCP server metadata (main.go) and the
// outbound httpx User-Agent (below) agree at build time. Override at link
// time with `-ldflags "-X main.Version=v0.3.0"` for tagged releases.
var Version = "v0.3.0"

const geoipDbPath = "/root/.config/hopper-recon/GeoLite2-Country.mmdb"

func userAgent() string {
	return "hopper-recon/" + Version + " (+https://github.com/iksnerd/hopper-recon)"
}

var (
	geoipOnce   sync.Once
	geoipReader *geoip2.Reader
	geoipErr    error
)

// loadGeoipReader opens the bundled MaxMind GeoLite2-Country.mmdb once. If the
// file is missing the reader stays nil; callers must handle that as "no result".
func loadGeoipReader() (*geoip2.Reader, error) {
	geoipOnce.Do(func() {
		if _, statErr := os.Stat(geoipDbPath); statErr != nil {
			return
		}
		geoipReader, geoipErr = geoip2.Open(geoipDbPath)
	})
	return geoipReader, geoipErr
}

// execJSONL is the subprocess executor used by all Run* functions. Tests swap
// it to return canned JSONL without spawning real binaries.
var execJSONL = runJSONL

// runJSONL executes a command and returns each non-empty stdout line as a
// separate string. stderr is captured separately and only surfaced on a
// non-zero exit — keeping warning noise (deprecation notices, retry chatter)
// out of the JSONL parse path.
func runJSONL(ctx context.Context, name string, args []string, stdin string) ([]string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s: %w (%s)", name, err, strings.TrimSpace(stderr.String()))
	}
	var results []string
	for l := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if l != "" {
			results = append(results, l)
		}
	}
	return results, nil
}

// SubfinderEntry is a single subdomain discovery with its OSINT sources.
type SubfinderEntry struct {
	Host    string   `json:"host"`
	Sources []string `json:"sources"`
}

// RunSubfinder performs strictly passive subdomain enumeration via OSINT.
func RunSubfinder(ctx context.Context, domain string) ([]SubfinderEntry, error) {
	out, err := execJSONL(ctx, "subfinder",
		[]string{"-d", domain, "-silent", "-all", "-oJ", "-cs"}, "")
	if err != nil {
		return nil, err
	}
	var findings []SubfinderEntry
	for _, line := range out {
		var entry SubfinderEntry
		if json.Unmarshal([]byte(line), &entry) == nil && entry.Host != "" {
			findings = append(findings, entry)
		}
	}
	return findings, nil
}

// dkimSelectors is the ordered list of common DKIM selector names queried during
// DNS resolution. Each is tried as <selector>._domainkey.<domain>. Any found
// TXT records are merged into the apex result so the parser sees v=DKIM1 at the
// same level as SPF/DMARC — without requiring the caller to know the selector.
var dkimSelectors = []string{
	"default", "google", "s1", "s2", "selector1", "selector2",
	"clk", "clk2", "pm", "resend", "k1", "mxvault",
}

// mergeTxtLines extracts the "txt" array from each JSONL line and appends
// non-empty entries to dst.
func mergeTxtLines(dst []any, lines []string) []any {
	for _, l := range lines {
		var rec map[string]any
		if json.Unmarshal([]byte(l), &rec) != nil {
			continue
		}
		if txts, ok := rec["txt"].([]any); ok {
			dst = append(dst, txts...)
		}
	}
	return dst
}

// RunDnsx resolves a domain and merges _dmarc.<domain> TXT records and common
// DKIM selector TXT records into the apex result so the parser can detect
// DMARC and DKIM presence without knowing which selector the domain uses.
func RunDnsx(ctx context.Context, target string) ([]string, error) {
	results, err := execJSONL(ctx, "dnsx",
		[]string{"-silent", "-a", "-aaaa", "-cname", "-ns", "-mx", "-txt", "-cdn", "-asn", "-json"},
		target+"\n")
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return results, nil
	}

	var apex map[string]any
	if json.Unmarshal([]byte(results[0]), &apex) != nil {
		return results, nil
	}
	existing, _ := apex["txt"].([]any)

	// Merge _dmarc TXT records.
	dmarcLines, _ := execJSONL(ctx, "dnsx", []string{"-silent", "-txt", "-json"}, "_dmarc."+target+"\n")
	existing = mergeTxtLines(existing, dmarcLines)

	// Merge DKIM selector TXT records (one batch, all selectors via stdin).
	var dkimSB strings.Builder
	for _, sel := range dkimSelectors {
		fmt.Fprintf(&dkimSB, "%s._domainkey.%s\n", sel, target)
	}
	dkimLines, _ := execJSONL(ctx, "dnsx", []string{"-silent", "-txt", "-json"}, dkimSB.String())
	existing = mergeTxtLines(existing, dkimLines)

	apex["txt"] = existing
	if merged, mergeErr := json.Marshal(apex); mergeErr == nil {
		results[0] = string(merged)
	}
	return results, nil
}

// RunTlsx fetches the public TLS certificate plus hardening signals.
func RunTlsx(ctx context.Context, target string) ([]string, error) {
	return execJSONL(ctx, "tlsx",
		[]string{"-u", target, "-so", "-tv", "-cipher", "-wc", "-expired", "-self-signed", "-silent", "-json"},
		"")
}

// RunCdncheck attributes the IPs behind a target to a CDN / cloud / WAF
// provider using cdncheck's bundled CIDR lists. Pure offline lookup once the
// IPs are resolved — no requests reach the target operator.
func RunCdncheck(ctx context.Context, target string) ([]string, error) {
	return execJSONL(ctx, "cdncheck",
		[]string{"-i", target, "-resp", "-jsonl", "-silent"},
		"")
}

// RunUrlfinder gathers historical URLs for a domain from passive sources
// (waybackarchive, commoncrawl, alienvault). No requests to the target.
// Uses -jsonl (urlfinder's flag) rather than the -json other PD tools take.
func RunUrlfinder(ctx context.Context, domain string) ([]string, error) {
	return execJSONL(ctx, "urlfinder",
		[]string{"-d", domain, "-all", "-silent", "-jsonl"},
		"")
}

// RunHttpx probes a target for HTTP services. The custom User-Agent identifies
// the scan to target operators so they can attribute / request exclusion.
func RunHttpx(ctx context.Context, target string) ([]string, error) {
	return execJSONL(ctx, "httpx",
		[]string{
			"-u", target, "-silent", "-json",
			"-title", "-td", "-cpe", "-sc", "-fr", "-location", "-jarm",
			"-asn", "-cname", "-rt", "-rl", "50",
			"-H", "User-Agent: " + userAgent(),
		},
		"")
}

// AlterxEntry is a single subdomain mutation candidate from alterx.
type AlterxEntry struct {
	Word string `json:"word"`
}

// RunAlterx generates subdomain permutation candidates. It first collects
// known subdomains via subfinder (read: no network contact with the target),
// then pipes them into alterx to produce mutations. Returns an empty slice —
// never an error — when subfinder finds nothing (nothing to mutate).
func RunAlterx(ctx context.Context, domain string) ([]AlterxEntry, error) {
	subs, err := RunSubfinder(ctx, domain)
	if err != nil {
		return nil, err
	}
	if len(subs) == 0 {
		return nil, nil
	}
	// Cap input at 200 subs — alterx extrapolates patterns from a sample;
	// piping all subs for large domains (10k+) burns most of the timeout budget.
	const maxInput = 200
	if len(subs) > maxInput {
		subs = subs[:maxInput]
	}
	var sb strings.Builder
	for _, s := range subs {
		sb.WriteString(s.Host)
		sb.WriteByte('\n')
	}
	// alterx outputs one candidate per line (plain text, no -json flag).
	// Cap at 5000 so large inputs don't flood memory or the UI.
	lines, err := execJSONL(ctx, "alterx", []string{"-silent", "-limit", "5000"}, sb.String())
	if err != nil {
		return nil, err
	}
	var findings []AlterxEntry
	for _, line := range lines {
		if line != "" {
			findings = append(findings, AlterxEntry{Word: line})
		}
	}
	return findings, nil
}

// RunResolveMutations generates subdomain mutation candidates (via RunAlterx)
// and pipes them through dnsx to find which ones actually resolve. Only
// candidates with an A record are returned. Results share the same JSON shape
// as RunDnsx but cover only A records — no DMARC/DKIM enrichment.
func RunResolveMutations(ctx context.Context, domain string) ([]string, error) {
	candidates, err := RunAlterx(ctx, domain)
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	var sb strings.Builder
	for _, c := range candidates {
		sb.WriteString(c.Word)
		sb.WriteByte('\n')
	}
	return execJSONL(ctx, "dnsx", []string{"-silent", "-a", "-json"}, sb.String())
}

// GeoipEntry pairs an IP with its ISO 3166-1 alpha-2 country code.
type GeoipEntry struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
}

// LookupGeoip resolves the given IPs to country codes from the local mmdb.
// Missing mmdb or unresolvable IPs simply produce no entry — never an error.
func LookupGeoip(ips []string) ([]GeoipEntry, error) {
	reader, err := loadGeoipReader()
	if err != nil {
		return nil, err
	}
	results := []GeoipEntry{}
	if reader == nil {
		return results, nil
	}
	for _, raw := range ips {
		ip := strings.TrimSpace(raw)
		if ip == "" {
			continue
		}
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		record, lookupErr := reader.Country(parsed)
		if lookupErr != nil || record.Country.IsoCode == "" {
			continue
		}
		results = append(results, GeoipEntry{IP: ip, Country: record.Country.IsoCode})
	}
	return results, nil
}

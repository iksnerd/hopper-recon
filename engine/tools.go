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
var Version = "v0.2.0"

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

// RunDnsx resolves a domain and merges _dmarc.<domain> TXT records into the
// apex result so the parser can detect DMARC presence at the same level as SPF.
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

	dmarcLines, dmarcErr := execJSONL(ctx, "dnsx",
		[]string{"-silent", "-txt", "-json"},
		"_dmarc."+target+"\n")
	if dmarcErr != nil || len(dmarcLines) == 0 {
		return results, nil
	}

	var apex map[string]any
	if json.Unmarshal([]byte(results[0]), &apex) != nil {
		return results, nil
	}
	existing, _ := apex["txt"].([]any)
	for _, dl := range dmarcLines {
		var dmarc map[string]any
		if json.Unmarshal([]byte(dl), &dmarc) != nil {
			continue
		}
		if dt, ok := dmarc["txt"].([]any); ok {
			existing = append(existing, dt...)
		}
	}
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

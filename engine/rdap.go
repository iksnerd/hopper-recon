package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// RdapResult is what a domain's registry says about its registration. Only
// registration facts are kept (registrar, dates, status, name servers,
// DNSSEC): RDAP can also carry contact details, which are deliberately not read.
type RdapResult struct {
	Domain      string   `json:"domain"`
	Registrar   string   `json:"registrar,omitempty"`
	Registered  string   `json:"registered,omitempty"`
	Expires     string   `json:"expires,omitempty"`
	LastChanged string   `json:"last_changed,omitempty"`
	Status      []string `json:"status"`
	Nameservers []string `json:"nameservers"`
	DNSSEC      bool     `json:"dnssec"`
	Server      string   `json:"server"`
}

// rdapBootstrapURL is IANA's registry of which RDAP server answers for which
// TLD (RFC 9224). Asking it, then the registry's own server, means the domain
// name goes only to IANA and the registry, not to a third-party redirector.
var rdapBootstrapURL = "https://data.iana.org/rdap/dns.json"

var rdapHTTP = &http.Client{Timeout: 15 * time.Second}

const (
	rdapMaxBody      = 2 << 20
	rdapBootstrapTTL = 24 * time.Hour
)

var rdapBootstrap struct {
	mu      sync.Mutex
	fetched time.Time
	byTLD   map[string][]string
}

func resetRdapBootstrap() {
	rdapBootstrap.mu.Lock()
	defer rdapBootstrap.mu.Unlock()
	rdapBootstrap.fetched = time.Time{}
	rdapBootstrap.byTLD = nil
}

func rdapGet(ctx context.Context, target string, into any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", userAgent())
	resp, err := rdapHTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, rdapMaxBody))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	if err := json.Unmarshal(body, into); err != nil {
		return resp.StatusCode, fmt.Errorf("unreadable RDAP response from %s: %w", resp.Request.URL.Host, err)
	}
	return resp.StatusCode, nil
}

// rdapServers returns the RDAP base URLs for a TLD, from the cached bootstrap.
func rdapServers(ctx context.Context, tld string) ([]string, error) {
	rdapBootstrap.mu.Lock()
	defer rdapBootstrap.mu.Unlock()
	if rdapBootstrap.byTLD == nil || time.Since(rdapBootstrap.fetched) > rdapBootstrapTTL {
		var doc struct {
			Services [][][]string `json:"services"`
		}
		code, err := rdapGet(ctx, rdapBootstrapURL, &doc)
		if err != nil {
			return nil, err
		}
		if code != http.StatusOK {
			return nil, fmt.Errorf("RDAP bootstrap returned HTTP %d", code)
		}
		byTLD := map[string][]string{}
		for _, svc := range doc.Services {
			if len(svc) < 2 {
				continue
			}
			for _, t := range svc[0] {
				byTLD[strings.ToLower(t)] = svc[1]
			}
		}
		rdapBootstrap.byTLD, rdapBootstrap.fetched = byTLD, time.Now()
	}
	servers := rdapBootstrap.byTLD[strings.ToLower(tld)]
	if len(servers) == 0 {
		return nil, fmt.Errorf("no RDAP service is registered for .%s", tld)
	}
	return servers, nil
}

// RunRdap looks up a domain's registration in its registry's RDAP service.
// It asks about the registrable domain, so "www.example.com" is looked up as
// example.com. The query goes to IANA (cached for a day) and the registry, not
// to the target.
func RunRdap(ctx context.Context, domain string) (*RdapResult, error) {
	label, suffix, err := registrableDomain(domain)
	if err != nil {
		return nil, err
	}
	name := label + "." + suffix
	tld := suffix[strings.LastIndex(suffix, ".")+1:]
	servers, err := rdapServers(ctx, tld)
	if err != nil {
		return nil, err
	}

	// Prefer https, as the bootstrap spec recommends.
	base := servers[0]
	for _, s := range servers {
		if strings.HasPrefix(s, "https://") {
			base = s
			break
		}
	}
	endpoint := strings.TrimSuffix(base, "/") + "/domain/" + url.PathEscape(name)

	var raw struct {
		Status []string `json:"status"`
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
		Nameservers []struct {
			LdhName string `json:"ldhName"`
		} `json:"nameservers"`
		SecureDNS struct {
			DelegationSigned bool `json:"delegationSigned"`
		} `json:"secureDNS"`
		Entities []struct {
			Roles      []string `json:"roles"`
			VcardArray []any    `json:"vcardArray"`
			PublicIDs  []struct {
				Type       string `json:"type"`
				Identifier string `json:"identifier"`
			} `json:"publicIds"`
		} `json:"entities"`
	}
	code, err := rdapGet(ctx, endpoint, &raw)
	if err != nil {
		return nil, err
	}
	switch code {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, fmt.Errorf("%s is not in the .%s registry's RDAP data (not registered, or the registry publishes none)", name, tld)
	default:
		return nil, fmt.Errorf("RDAP server returned HTTP %d for %s", code, name)
	}

	res := &RdapResult{
		Domain: name, Status: []string{}, Nameservers: []string{},
		DNSSEC: raw.SecureDNS.DelegationSigned, Server: base,
	}
	for _, s := range raw.Status {
		res.Status = append(res.Status, strings.ToLower(s))
	}
	for _, n := range raw.Nameservers {
		if n.LdhName != "" {
			res.Nameservers = append(res.Nameservers, strings.ToLower(n.LdhName))
		}
	}
	for _, e := range raw.Events {
		switch strings.ToLower(e.Action) {
		case "registration":
			res.Registered = e.Date
		case "expiration":
			res.Expires = e.Date
		case "last changed":
			res.LastChanged = e.Date
		}
	}
	for _, e := range raw.Entities {
		if !containsFold(e.Roles, "registrar") {
			continue
		}
		res.Registrar = vcardName(e.VcardArray)
		if res.Registrar == "" && len(e.PublicIDs) > 0 {
			res.Registrar = e.PublicIDs[0].Type + " " + e.PublicIDs[0].Identifier
		}
		break
	}
	return res, nil
}

func containsFold(xs []string, want string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, want) {
			return true
		}
	}
	return false
}

// vcardName reads the "fn" (formatted name) property of a jCard
// (["vcard", [["fn", {}, "text", "Name"], ...]]). Nothing else in the card is read.
func vcardName(card []any) string {
	if len(card) < 2 {
		return ""
	}
	props, _ := card[1].([]any)
	for _, p := range props {
		prop, _ := p.([]any)
		if len(prop) >= 4 {
			if name, _ := prop[0].(string); name == "fn" {
				v, _ := prop[3].(string)
				return v
			}
		}
	}
	return ""
}

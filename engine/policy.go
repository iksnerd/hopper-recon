package main

import (
	"os"
	"strings"
)

// Policy enforces hopper-recon's "don't be a jerk" rules at the engine layer.
// Lives at the engine, not the web, so direct MCP callers (Claude Code, Cline,
// etc.) hit the same gate as the dashboard.
//
// Two protections live here:
//   - blocklist:   refuse active probes against critical infrastructure
//     (.gov / .mil / equivalent) unless the operator explicitly
//     acknowledges the override
//   - active tool: tag the tools that actually send packets to the target so
//     the blocklist only applies where it matters (a passive
//     OSINT lookup against example.gov is fine; an httpx probe
//     is not)
//
// Cooldown lives in the DB layer because it needs persistent state — see
// (*DB).RecentScanWithin.
type Policy struct {
	blockedSuffixes []string
	overrideEnabled bool
	overrideReason  string
	// allowedDomains: when non-empty, only targets equal to (or subdomains of)
	// one of these apexes are permitted. Empty = no scope restriction.
	// Sourced from HOPPER_ALLOWED_DOMAINS — comma-separated, lowercased.
	allowedDomains []string
}

// blockedSuffixes — restricted ccTLDs / SLDs we refuse to actively probe by
// default. Match is case-insensitive suffix on the fully-qualified target.
var defaultBlockedSuffixes = []string{
	".gov",     // United States federal + most US states
	".mil",     // United States military
	".gouv.fr", // France
	".gov.uk",  // United Kingdom
	".go.jp",   // Japan
	".gc.ca",   // Canada (federal government)
	".gov.au",  // Australia
}

// activeTools — tools whose execution sends real packets to the target. The
// blocklist applies only to these. Passive tools (subfinder, urlfinder,
// cdncheck, dnsx, lookup_geoip) talk to third-party OSINT services or
// run fully offline; restricting them buys nothing and would surprise users.
var activeTools = map[string]struct{}{
	"probe_http":     {},
	"fetch_tls_cert": {},
}

// LoadPolicy reads override + scope config from the environment exactly once.
// Both override env vars must be set non-empty for the override to take
// effect — a typo'd reason ("yes") doesn't accidentally disable protection.
func LoadPolicy() *Policy {
	override := os.Getenv("HOPPER_OVERRIDE_BLOCKLIST") == "true"
	reason := strings.TrimSpace(os.Getenv("HOPPER_BLOCKLIST_OVERRIDE_REASON"))

	var allowed []string
	for d := range strings.SplitSeq(os.Getenv("HOPPER_ALLOWED_DOMAINS"), ",") {
		d = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(d, ".")))
		if d != "" {
			allowed = append(allowed, d)
		}
	}

	return &Policy{
		blockedSuffixes: defaultBlockedSuffixes,
		overrideEnabled: override && reason != "",
		overrideReason:  reason,
		allowedDomains:  allowed,
	}
}

// HasScope reports whether HOPPER_ALLOWED_DOMAINS narrowed the engine to a
// specific list. Used by the web banner to decide whether to nag operators.
func (p *Policy) HasScope() bool { return len(p.allowedDomains) > 0 }

// Decision is the result of a policy check. Reason is operator-facing prose
// suitable for an HTTP error body or an MCP tool error.
type Decision struct {
	Allowed bool
	Reason  string
	// HTTPStatus is the recommended status code for REST responses on a
	// blocked decision. 403 for scope (authorization), 451 for blocklist
	// (legal/ethical restriction). Caller is free to ignore.
	HTTPStatus int
	// OverrideReason is non-empty when the request was allowed only because
	// the operator set the override env. Audit logs should record this so
	// after-the-fact reviews see *why* a sensitive target got scanned.
	OverrideReason string
}

// Check returns whether tool may run against target. Order:
//
//  1. Scope (HOPPER_ALLOWED_DOMAINS) — applies to ALL tools, not just active
//     ones. If the operator narrowed scope, even a passive subfinder query
//     against an out-of-scope domain leaks intent + consumes OSINT quota.
//  2. Blocklist — applies only to active probes (sends real packets).
//
// A misconfigured override doesn't bypass either rule.
func (p *Policy) Check(tool, target string) Decision {
	host := strings.ToLower(strings.TrimSpace(target))
	host = strings.TrimSuffix(host, ".")

	if len(p.allowedDomains) > 0 && !p.inScope(host) {
		return Decision{
			Allowed:    false,
			Reason:     "off-scope: target not in HOPPER_ALLOWED_DOMAINS",
			HTTPStatus: 403,
		}
	}

	if _, active := activeTools[tool]; !active {
		return Decision{Allowed: true}
	}
	for _, suffix := range p.blockedSuffixes {
		if strings.HasSuffix(host, suffix) {
			if p.overrideEnabled {
				return Decision{Allowed: true, OverrideReason: p.overrideReason}
			}
			return Decision{
				Allowed: false,
				Reason: "blocked: target matches restricted suffix " + suffix +
					"; set HOPPER_OVERRIDE_BLOCKLIST=true and a non-empty " +
					"HOPPER_BLOCKLIST_OVERRIDE_REASON to override (will be audit-logged)",
				HTTPStatus: 451,
			}
		}
	}
	return Decision{Allowed: true}
}

// inScope returns true when host equals or is a subdomain of any allowed
// apex. "example.com" matches "example.com" and "api.example.com" but not
// "evil-example.com" — the boundary is on the dot.
func (p *Policy) inScope(host string) bool {
	for _, apex := range p.allowedDomains {
		if host == apex || strings.HasSuffix(host, "."+apex) {
			return true
		}
	}
	return false
}

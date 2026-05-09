package main

import (
	"testing"
)

// plainPolicy returns a policy with default blocked suffixes, no scope, no override.
func plainPolicy() *Policy {
	return &Policy{blockedSuffixes: defaultBlockedSuffixes}
}

// scopedPolicy returns a policy that restricts targets to the given apex domains.
func scopedPolicy(domains ...string) *Policy {
	return &Policy{blockedSuffixes: defaultBlockedSuffixes, allowedDomains: domains}
}

func TestPolicy_Check(t *testing.T) {
	tests := []struct {
		name        string
		policy      *Policy
		tool        string
		target      string
		wantAllowed bool
		wantStatus  int
	}{
		// Blocklist — active tools
		{
			name:        "probe_http_gov_blocked",
			policy:      plainPolicy(),
			tool:        "probe_http",
			target:      "example.gov",
			wantAllowed: false,
			wantStatus:  451,
		},
		{
			name:        "probe_http_subdomain_gov_blocked",
			policy:      plainPolicy(),
			tool:        "fetch_tls_cert",
			target:      "api.agency.gov",
			wantAllowed: false,
			wantStatus:  451,
		},
		{
			name:        "probe_http_mil_blocked",
			policy:      plainPolicy(),
			tool:        "probe_http",
			target:      "example.mil",
			wantAllowed: false,
			wantStatus:  451,
		},
		{
			name:        "probe_http_gov_override_allowed",
			policy:      &Policy{blockedSuffixes: defaultBlockedSuffixes, overrideEnabled: true, overrideReason: "pentest engagement"},
			tool:        "probe_http",
			target:      "example.gov",
			wantAllowed: true,
		},
		{
			name:        "passive_tool_gov_allowed",
			policy:      plainPolicy(),
			tool:        "passive_subdomains",
			target:      "example.gov",
			wantAllowed: true,
		},
		{
			name:        "resolve_dns_gov_allowed",
			policy:      plainPolicy(),
			tool:        "resolve_dns",
			target:      "example.gov",
			wantAllowed: true,
		},
		{
			name:        "probe_http_com_allowed",
			policy:      plainPolicy(),
			tool:        "probe_http",
			target:      "example.com",
			wantAllowed: true,
		},
		{
			name:        "evil_gov_prefix_not_blocked",
			policy:      plainPolicy(),
			tool:        "probe_http",
			target:      "evil-gov.com",
			wantAllowed: true,
		},
		{
			name:        "trailing_dot_normalised_blocked",
			policy:      plainPolicy(),
			tool:        "probe_http",
			target:      "example.gov.",
			wantAllowed: false,
			wantStatus:  451,
		},
		// Scope restrictions
		{
			name:        "in_scope_apex_allowed",
			policy:      scopedPolicy("example.com"),
			tool:        "passive_subdomains",
			target:      "example.com",
			wantAllowed: true,
		},
		{
			name:        "in_scope_subdomain_allowed",
			policy:      scopedPolicy("example.com"),
			tool:        "passive_subdomains",
			target:      "api.example.com",
			wantAllowed: true,
		},
		{
			name:        "out_of_scope_blocked",
			policy:      scopedPolicy("example.com"),
			tool:        "passive_subdomains",
			target:      "other.com",
			wantAllowed: false,
			wantStatus:  403,
		},
		{
			name:        "scope_applies_to_active_tools",
			policy:      scopedPolicy("example.com"),
			tool:        "probe_http",
			target:      "other.com",
			wantAllowed: false,
			wantStatus:  403,
		},
		{
			name:        "scope_takes_priority_over_blocklist",
			policy:      scopedPolicy("example.com"),
			tool:        "probe_http",
			target:      "evil.gov",
			wantAllowed: false,
			wantStatus:  403,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := tt.policy.Check(tt.tool, tt.target)
			if d.Allowed != tt.wantAllowed {
				t.Errorf("Check(%q, %q): Allowed=%v, want %v (reason: %s)",
					tt.tool, tt.target, d.Allowed, tt.wantAllowed, d.Reason)
			}
			if !tt.wantAllowed && tt.wantStatus != 0 && d.HTTPStatus != tt.wantStatus {
				t.Errorf("Check(%q, %q): HTTPStatus=%d, want %d",
					tt.tool, tt.target, d.HTTPStatus, tt.wantStatus)
			}
		})
	}
}

func TestPolicy_Check_OverrideReason(t *testing.T) {
	p := &Policy{
		blockedSuffixes: defaultBlockedSuffixes,
		overrideEnabled: true,
		overrideReason:  "authorised pentest",
	}
	d := p.Check("probe_http", "example.gov")
	if !d.Allowed {
		t.Fatalf("expected allowed with override, got blocked: %s", d.Reason)
	}
	if d.OverrideReason != "authorised pentest" {
		t.Errorf("OverrideReason=%q, want %q", d.OverrideReason, "authorised pentest")
	}
}

func TestPolicy_inScope(t *testing.T) {
	p := &Policy{allowedDomains: []string{"example.com", "other.org"}}
	tests := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"api.example.com", true},
		{"deep.api.example.com", true},
		{"evil-example.com", false},
		{"notexample.com", false},
		{"other.org", true},
		{"sub.other.org", true},
		{"unrelated.net", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := p.inScope(tt.host); got != tt.want {
			t.Errorf("inScope(%q)=%v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestPolicy_HasScope(t *testing.T) {
	if (&Policy{}).HasScope() {
		t.Error("empty allowedDomains should report no scope")
	}
	if !(&Policy{allowedDomains: []string{"example.com"}}).HasScope() {
		t.Error("non-empty allowedDomains should report scope")
	}
}

func TestLoadPolicy(t *testing.T) {
	t.Setenv("HOPPER_OVERRIDE_BLOCKLIST", "true")
	t.Setenv("HOPPER_BLOCKLIST_OVERRIDE_REASON", "pentest")
	t.Setenv("HOPPER_ALLOWED_DOMAINS", "example.com, Other.Org., , ")

	p := LoadPolicy()

	if !p.overrideEnabled {
		t.Error("expected overrideEnabled=true")
	}
	if p.overrideReason != "pentest" {
		t.Errorf("overrideReason=%q, want %q", p.overrideReason, "pentest")
	}
	if len(p.allowedDomains) != 2 {
		t.Fatalf("allowedDomains len=%d, want 2; got %v", len(p.allowedDomains), p.allowedDomains)
	}
	if p.allowedDomains[0] != "example.com" {
		t.Errorf("allowedDomains[0]=%q, want example.com", p.allowedDomains[0])
	}
	if p.allowedDomains[1] != "other.org" {
		t.Errorf("allowedDomains[1]=%q, want other.org", p.allowedDomains[1])
	}
}

func TestLoadPolicy_OverrideRequiresReason(t *testing.T) {
	t.Setenv("HOPPER_OVERRIDE_BLOCKLIST", "true")
	t.Setenv("HOPPER_BLOCKLIST_OVERRIDE_REASON", "")

	p := LoadPolicy()
	if p.overrideEnabled {
		t.Error("overrideEnabled should be false when reason is empty")
	}
}

func TestLoadPolicy_Defaults(t *testing.T) {
	t.Setenv("HOPPER_OVERRIDE_BLOCKLIST", "")
	t.Setenv("HOPPER_BLOCKLIST_OVERRIDE_REASON", "")
	t.Setenv("HOPPER_ALLOWED_DOMAINS", "")

	p := LoadPolicy()
	if p.overrideEnabled {
		t.Error("expected overrideEnabled=false with empty env vars")
	}
	if p.HasScope() {
		t.Error("expected no scope with empty HOPPER_ALLOWED_DOMAINS")
	}
}

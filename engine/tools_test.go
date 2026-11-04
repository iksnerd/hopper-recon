package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// withExecJSONL stubs the execJSONL var for the duration of one test.
// calls[i] and errs[i] are returned on the i-th call; extra calls are fatal.
func withExecJSONL(t *testing.T, calls [][]string, errs []error) {
	t.Helper()
	i := 0
	orig := execJSONL
	execJSONL = func(_ context.Context, _ string, _ []string, _ string) ([]string, error) {
		if i >= len(calls) {
			t.Errorf("unexpected execJSONL call #%d (only %d configured)", i+1, len(calls))
			return nil, nil
		}
		lines, err := calls[i], errs[i]
		i++
		return lines, err
	}
	t.Cleanup(func() { execJSONL = orig })
}

func TestUserAgent(t *testing.T) {
	ua := userAgent()
	if !strings.HasPrefix(ua, "hopper-recon/") {
		t.Errorf("userAgent()=%q, want prefix 'hopper-recon/'", ua)
	}
	if !strings.Contains(ua, Version) {
		t.Errorf("userAgent()=%q, does not contain Version %q", ua, Version)
	}
}

// dnsStub answers the dnsx queries RunDnsx makes, routed by what is asked
// (the first stdin line) rather than by call order, because the DMARC, DKIM,
// mail-policy and SPF lookups run concurrently.
type dnsStub struct {
	apex, dmarc, dkim, policy             []string
	apexErr, dmarcErr, dkimErr, policyErr error
	spf                                   map[string][]string // include-chain fake for lookupTXT
}

func withDnsStub(t *testing.T, s dnsStub) {
	t.Helper()
	origExec, origLookup := execJSONL, lookupTXT
	execJSONL = func(_ context.Context, _ string, _ []string, stdin string) ([]string, error) {
		first, _, _ := strings.Cut(stdin, "\n")
		switch {
		case strings.HasPrefix(first, "_dmarc."):
			return s.dmarc, s.dmarcErr
		case strings.Contains(first, "._domainkey."):
			return s.dkim, s.dkimErr
		case strings.HasPrefix(first, "_mta-sts."):
			return s.policy, s.policyErr
		default:
			return s.apex, s.apexErr
		}
	}
	lookupTXT = func(_ context.Context, name string) ([]string, error) {
		if v, ok := s.spf[name]; ok {
			return v, nil
		}
		return nil, errors.New("no such host")
	}
	t.Cleanup(func() { execJSONL, lookupTXT = origExec, origLookup })
}

func runDnsxRow(t *testing.T, s dnsStub) map[string]any {
	t.Helper()
	withDnsStub(t, s)
	results, err := RunDnsx(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	var row map[string]any
	if err := json.Unmarshal([]byte(results[0]), &row); err != nil {
		t.Fatalf("unmarshal merged result: %v", err)
	}
	return row
}

func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func TestRunDnsx_MergesDmarcTxt(t *testing.T) {
	row := runDnsxRow(t, dnsStub{
		apex:  []string{`{"host":"example.com","txt":["v=spf1 include:_spf.example.com ~all"]}`},
		dmarc: []string{`{"host":"_dmarc.example.com","txt":["v=DMARC1; p=none"]}`},
	})
	if txt := strs(row["txt"]); len(txt) != 2 {
		t.Errorf("merged txt=%v, want SPF + DMARC", txt)
	}
}

func TestRunDnsx_MergesDkimTxtAndNamesSelectors(t *testing.T) {
	row := runDnsxRow(t, dnsStub{
		apex: []string{`{"host":"example.com","txt":["v=spf1 -all"]}`},
		dkim: []string{
			`{"host":"google._domainkey.example.com","txt":["v=DKIM1; k=rsa; p=MIIBIjAN"]}`,
			// CNAME-hosted key: dnsx still reports the queried name as host.
			`{"host":"s1._domainkey.example.com","cname":["s1.domainkey.mail.example.net"],"txt":["k=rsa; t=s; p=MIIBIjAN"]}`,
		},
	})
	if txt := strs(row["txt"]); len(txt) != 3 {
		t.Errorf("merged txt=%v, want SPF + 2 DKIM", txt)
	}
	// Reported in dkimSelectors order, not answer order.
	if got := strs(row["dkim_selectors"]); len(got) != 2 || got[0] != "google" || got[1] != "s1" {
		t.Errorf("dkim_selectors=%v, want [google s1]", got)
	}
}

func TestRunDnsx_NoDkimAnswersIsEmptyNotMissing(t *testing.T) {
	row := runDnsxRow(t, dnsStub{apex: []string{`{"host":"example.com"}`}})
	got, ok := row["dkim_selectors"]
	if !ok || len(got.([]any)) != 0 {
		t.Errorf("dkim_selectors=%v present=%v, want present and empty", got, ok)
	}
}

func TestRunDnsx_DkimErrorOmitsSelectors(t *testing.T) {
	// A failed query must not read as "no selectors found".
	row := runDnsxRow(t, dnsStub{
		apex:    []string{`{"host":"example.com"}`},
		dkimErr: errors.New("dnsx: exit 1"),
	})
	if _, ok := row["dkim_selectors"]; ok {
		t.Error("dkim_selectors set although the DKIM lookup failed")
	}
}

func TestRunDnsx_MailPolicy(t *testing.T) {
	row := runDnsxRow(t, dnsStub{
		apex: []string{`{"host":"example.com"}`},
		policy: []string{
			`{"host":"_mta-sts.example.com","txt":["v=STSv1; id=1;"]}`,
			`{"host":"_smtp._tls.example.com","txt":["v=TLSRPTv1;rua=mailto:r@example.com"]}`,
		},
	})
	mp := row["mail_policy"].(map[string]any)
	if got := strs(mp["mta_sts"]); len(got) != 1 || got[0] != "v=STSv1; id=1;" {
		t.Errorf("mta_sts=%v", got)
	}
	if got := strs(mp["tls_rpt"]); len(got) != 1 {
		t.Errorf("tls_rpt=%v", got)
	}
	if got := strs(mp["bimi"]); len(got) != 0 {
		t.Errorf("bimi=%v, want empty (present, not missing)", got)
	}
}

func TestRunDnsx_MailPolicyErrorOmitsField(t *testing.T) {
	row := runDnsxRow(t, dnsStub{
		apex:      []string{`{"host":"example.com"}`},
		policyErr: errors.New("dnsx: exit 1"),
	})
	if _, ok := row["mail_policy"]; ok {
		t.Error("mail_policy set although the lookup failed")
	}
}

func TestRunDnsx_CaaPassThroughAndDefault(t *testing.T) {
	row := runDnsxRow(t, dnsStub{apex: []string{`{"host":"example.com","caa":["pki.goog"]}`}})
	if got := strs(row["caa"]); len(got) != 1 || got[0] != "pki.goog" {
		t.Errorf("caa=%v, want [pki.goog]", got)
	}
	row = runDnsxRow(t, dnsStub{apex: []string{`{"host":"example.com"}`}})
	if got := row["caa"].([]any); len(got) != 0 {
		t.Errorf("caa=%v, want empty array when the domain has none", got)
	}
}

func TestRunDnsx_SpfLookupCount(t *testing.T) {
	row := runDnsxRow(t, dnsStub{
		apex: []string{`{"host":"example.com","txt":["v=spf1 include:_spf.example.net mx ~all"]}`},
		spf:  map[string][]string{"_spf.example.net": {"v=spf1 include:a.example.net ip4:192.0.2.0/24 -all"}, "a.example.net": {"v=spf1 a -all"}},
	})
	// include + mx + nested include + nested a = 4
	if row["spf_lookups"] != float64(4) || row["spf_lookups_complete"] != true {
		t.Errorf("spf_lookups=%v complete=%v, want 4 true", row["spf_lookups"], row["spf_lookups_complete"])
	}
}

func TestRunDnsx_NoSpfNoCount(t *testing.T) {
	row := runDnsxRow(t, dnsStub{apex: []string{`{"host":"example.com","txt":["something else"]}`}})
	if _, ok := row["spf_lookups"]; ok {
		t.Error("spf_lookups set for a domain without SPF")
	}
}

func TestRunDnsx_DmarcErrorIgnored(t *testing.T) {
	withDnsStub(t, dnsStub{apex: []string{`{"host":"example.com"}`}, dmarcErr: errors.New("dnsx: exit 1")})
	results, err := RunDnsx(context.Background(), "example.com")
	if err != nil {
		t.Errorf("expected no error when _dmarc lookup fails, got: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
}

func TestRunDnsx_EmptyApex(t *testing.T) {
	withDnsStub(t, dnsStub{apex: []string{}})
	results, err := RunDnsx(context.Background(), "example.com")
	if err != nil || len(results) != 0 {
		t.Errorf("empty apex: got results=%v err=%v, want ([], nil)", results, err)
	}
}

func TestRunDnsx_ApexNotValidJSON(t *testing.T) {
	// Non-JSON apex: unmarshal fails early; no further queries are made.
	withDnsStub(t, dnsStub{apex: []string{"not-json"}})
	results, err := RunDnsx(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0] != "not-json" {
		t.Errorf("non-JSON apex: got %v, want ['not-json']", results)
	}
}

func TestRunDnsx_ApexError(t *testing.T) {
	withDnsStub(t, dnsStub{apexErr: errors.New("dnsx: exit status 1")})
	if _, err := RunDnsx(context.Background(), "example.com"); err == nil {
		t.Error("expected error when apex lookup fails")
	}
}

func TestCountSPFLookups(t *testing.T) {
	fake := func(m map[string][]string) txtLookup {
		return func(_ context.Context, name string) ([]string, error) {
			if v, ok := m[name]; ok {
				return v, nil
			}
			return nil, errors.New("nxdomain")
		}
	}
	cases := []struct {
		name         string
		record       string
		dns          map[string][]string
		wantCount    int
		wantComplete bool
	}{
		{"only ip and all cost nothing", "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all", nil, 0, true},
		{"direct mechanisms", "v=spf1 a mx ptr exists:%{i}.example.net -all", nil, 4, true},
		{"qualifiers and cidr are ignored", "v=spf1 +a/24 ~mx:mail.example.net/24 ?a:host.example.net -all", nil, 3, true},
		{"include is counted and followed", "v=spf1 include:_spf.example.net -all",
			map[string][]string{"_spf.example.net": {"v=spf1 a mx -all"}}, 3, true},
		{"redirect is counted and followed", "v=spf1 redirect=_spf.example.net",
			map[string][]string{"_spf.example.net": {"v=spf1 mx -all"}}, 2, true},
		{"include loop terminates", "v=spf1 include:a.example.net -all",
			map[string][]string{"a.example.net": {"v=spf1 include:b.example.net -all"}, "b.example.net": {"v=spf1 include:a.example.net -all"}}, 3, true},
		{"unfetchable include makes the count a lower bound", "v=spf1 include:gone.example.net a -all", nil, 2, false},
		{"include without an spf record is incomplete", "v=spf1 include:txt.example.net -all",
			map[string][]string{"txt.example.net": {"google-site-verification=x"}}, 1, false},
		{"term case does not matter", "v=spf1 INCLUDE:_SPF.Example.NET A -ALL",
			map[string][]string{"_spf.example.net": {"v=spf1 -all"}}, 2, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, complete := countSPFLookups(context.Background(), c.record, fake(c.dns))
			if got != c.wantCount || complete != c.wantComplete {
				t.Errorf("got (%d, %v), want (%d, %v)", got, complete, c.wantCount, c.wantComplete)
			}
		})
	}
}

func TestCountSPFLookups_StopsFarPastTheLimit(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("v=spf1")
	for range 200 {
		sb.WriteString(" a")
	}
	got, _ := countSPFLookups(context.Background(), sb.String(), func(context.Context, string) ([]string, error) { return nil, nil })
	if got <= 10 || got > spfLookupCap+1 {
		t.Errorf("got %d, want just past the cap of %d", got, spfLookupCap)
	}
}

func TestRunSubfinder_ParsesJSONL(t *testing.T) {
	line1 := `{"host":"api.example.com","sources":["crtsh"]}`
	line2 := `{"host":"mail.example.com","sources":["dnsdumpster"]}`
	malformed := `{bad json`
	withExecJSONL(t,
		[][]string{{line1, line2, malformed}},
		[]error{nil},
	)
	findings, err := RunSubfinder(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings (malformed skipped), got %d", len(findings))
	}
	if findings[0].Host != "api.example.com" {
		t.Errorf("findings[0].Host=%q, want api.example.com", findings[0].Host)
	}
	if len(findings[1].Sources) == 0 || findings[1].Sources[0] != "dnsdumpster" {
		t.Errorf("findings[1].Sources=%v, want [dnsdumpster]", findings[1].Sources)
	}
}

func TestRunSubfinder_PropagatesError(t *testing.T) {
	withExecJSONL(t,
		[][]string{nil},
		[]error{errors.New("subfinder: not found")},
	)
	_, err := RunSubfinder(context.Background(), "example.com")
	if err == nil {
		t.Error("expected error from failed subprocess, got nil")
	}
}

func TestRunTldfinder_ParsesJSONL(t *testing.T) {
	line1 := `{"host":"example.io","input":"example.com","sources":["dnsx"]}`
	line2 := `{"host":"example.net","input":"example.com","sources":["dnsx"]}`
	malformed := `{bad json`
	withExecJSONL(t,
		[][]string{{line1, line2, malformed}},
		[]error{nil},
	)
	findings, err := RunTldfinder(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings (malformed skipped), got %d", len(findings))
	}
	if findings[0].Host != "example.io" {
		t.Errorf("findings[0].Host=%q, want example.io", findings[0].Host)
	}
	if len(findings[1].Sources) == 0 || findings[1].Sources[0] != "dnsx" {
		t.Errorf("findings[1].Sources=%v, want [dnsx]", findings[1].Sources)
	}
}

func TestRunTldfinder_PropagatesError(t *testing.T) {
	withExecJSONL(t,
		[][]string{nil},
		[]error{errors.New("tldfinder: not found")},
	)
	_, err := RunTldfinder(context.Background(), "example.com")
	if err == nil {
		t.Error("expected error from failed subprocess, got nil")
	}
}

func TestRunAlterx_ParsesOutput(t *testing.T) {
	subLine1 := `{"host":"api.example.com","sources":["crtsh"]}`
	subLine2 := `{"host":"mail.example.com","sources":["dnsdumpster"]}`
	// alterx outputs plain text (one candidate per line, no JSON format).
	withExecJSONL(t,
		[][]string{{subLine1, subLine2}, {"api-dev.example.com", "api-staging.example.com"}},
		[]error{nil, nil},
	)
	findings, err := RunAlterx(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(findings))
	}
	if findings[0].Word != "api-dev.example.com" {
		t.Errorf("findings[0].Word=%q, want api-dev.example.com", findings[0].Word)
	}
}

func TestRunAlterx_EmptySubdomains(t *testing.T) {
	// subfinder returns nothing → alterx is never called, result is nil.
	withExecJSONL(t,
		[][]string{{}},
		[]error{nil},
	)
	findings, err := RunAlterx(context.Background(), "example.com")
	if err != nil {
		t.Errorf("empty subfinder: unexpected error %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("empty subfinder: got %d findings, want 0", len(findings))
	}
}

func TestRunAlterx_SubfinderError(t *testing.T) {
	withExecJSONL(t,
		[][]string{nil},
		[]error{errors.New("subfinder: not found")},
	)
	_, err := RunAlterx(context.Background(), "example.com")
	if err == nil {
		t.Error("expected error when subfinder fails")
	}
}

func TestRunAlterx_AlterxError(t *testing.T) {
	subLine := `{"host":"api.example.com","sources":["crtsh"]}`
	withExecJSONL(t,
		[][]string{{subLine}, nil},
		[]error{nil, errors.New("alterx: not found")},
	)
	_, err := RunAlterx(context.Background(), "example.com")
	if err == nil {
		t.Error("expected error when alterx fails")
	}
}

func TestRunResolveMutations_ResolvesLiveCandidates(t *testing.T) {
	subLine := `{"host":"api.example.com","sources":["crtsh"]}`
	// subfinder, alterx, dnsx resolve
	withExecJSONL(t,
		[][]string{
			{subLine},
			{"api-dev.example.com", "api-staging.example.com"},
			{`{"host":"api-dev.example.com","a":["1.2.3.4"]}`},
		},
		[]error{nil, nil, nil},
	)
	results, err := RunResolveMutations(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("want 1 resolved candidate, got %d", len(results))
	}
	var rec map[string]any
	if json.Unmarshal([]byte(results[0]), &rec) != nil {
		t.Fatalf("result is not valid JSON: %q", results[0])
	}
	if rec["host"] != "api-dev.example.com" {
		t.Errorf("host=%q, want api-dev.example.com", rec["host"])
	}
}

func TestRunResolveMutations_EmptyAlterx(t *testing.T) {
	// subfinder returns nothing → alterx not called → dnsx not called → nil
	withExecJSONL(t,
		[][]string{{}},
		[]error{nil},
	)
	results, err := RunResolveMutations(context.Background(), "example.com")
	if err != nil {
		t.Errorf("empty alterx: unexpected error %v", err)
	}
	if len(results) != 0 {
		t.Errorf("empty alterx: got %d results, want 0", len(results))
	}
}

func TestLookupGeoip_EmptyInput(t *testing.T) {
	results, err := LookupGeoip([]string{})
	if err != nil {
		t.Errorf("empty input: unexpected error %v", err)
	}
	if len(results) != 0 {
		t.Errorf("empty input: got %d results, want 0", len(results))
	}
}

func TestLookupGeoip_MalformedIP(t *testing.T) {
	// Invalid IPs must be silently skipped — no panic, no error.
	results, err := LookupGeoip([]string{"not-an-ip", "256.0.0.1", "999.999.999.999"})
	if err != nil {
		t.Errorf("malformed IPs: unexpected error %v", err)
	}
	// All malformed → 0 results (regardless of whether mmdb is present).
	if len(results) != 0 {
		t.Errorf("malformed IPs: got %d results, want 0", len(results))
	}
}

func TestLookupGeoip_NilReader(t *testing.T) {
	// Without the mmdb file (absent in CI), loadGeoipReader returns a not-exist
	// error; LookupGeoip must treat that as empty results, not an error.
	results, err := LookupGeoip([]string{"8.8.8.8"})
	if err != nil {
		t.Errorf("nil reader: unexpected error %v", err)
	}
	// Either a result (if mmdb present in this env) or empty — both are fine.
	_ = results
}

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

func TestRunDnsx_MergesDmarcTxt(t *testing.T) {
	apexLine := `{"host":"example.com","txt":["v=spf1 include:_spf.example.com ~all"]}`
	dmarcLine := `{"host":"_dmarc.example.com","txt":["v=DMARC1; p=none"]}`
	withExecJSONL(t,
		[][]string{{apexLine}, {dmarcLine}},
		[]error{nil, nil},
	)

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
	txt, _ := row["txt"].([]any)
	if len(txt) != 2 {
		t.Errorf("merged txt len=%d, want 2 (SPF + DMARC)", len(txt))
	}
}

func TestRunDnsx_NoDmarc(t *testing.T) {
	apexLine := `{"host":"example.com"}`
	withExecJSONL(t,
		[][]string{{apexLine}, {}},
		[]error{nil, nil},
	)
	results, err := RunDnsx(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0] != apexLine {
		t.Errorf("expected apex line unchanged, got %v", results)
	}
}

func TestRunDnsx_DmarcErrorIgnored(t *testing.T) {
	apexLine := `{"host":"example.com"}`
	withExecJSONL(t,
		[][]string{{apexLine}, nil},
		[]error{nil, errors.New("dnsx: exit 1")},
	)
	results, err := RunDnsx(context.Background(), "example.com")
	if err != nil {
		t.Errorf("expected no error when _dmarc lookup fails, got: %v", err)
	}
	if len(results) != 1 || results[0] != apexLine {
		t.Errorf("expected apex result unchanged, got %v", results)
	}
}

func TestRunDnsx_EmptyApex(t *testing.T) {
	withExecJSONL(t,
		[][]string{{}},
		[]error{nil},
	)
	results, err := RunDnsx(context.Background(), "example.com")
	if err != nil || len(results) != 0 {
		t.Errorf("empty apex: got results=%v err=%v, want ([], nil)", results, err)
	}
}

func TestRunDnsx_ApexNotValidJSON(t *testing.T) {
	// Non-JSON apex: merge should be skipped, original line returned unchanged.
	withExecJSONL(t,
		[][]string{{"not-json"}, {`{"txt":["v=DMARC1"]}`}},
		[]error{nil, nil},
	)
	results, err := RunDnsx(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0] != "not-json" {
		t.Errorf("non-JSON apex: got %v, want ['not-json']", results)
	}
}

func TestRunDnsx_ApexError(t *testing.T) {
	withExecJSONL(t,
		[][]string{nil},
		[]error{errors.New("dnsx: exit status 1")},
	)
	_, err := RunDnsx(context.Background(), "example.com")
	if err == nil {
		t.Error("expected error when apex lookup fails")
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
	// Without the mmdb file (absent in CI), loadGeoipReader returns (nil, nil).
	// LookupGeoip must handle a nil reader gracefully.
	results, err := LookupGeoip([]string{"8.8.8.8"})
	if err != nil {
		t.Errorf("nil reader: unexpected error %v", err)
	}
	// Either a result (if mmdb present in this env) or empty — both are fine.
	_ = results
}

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRegistrableDomain(t *testing.T) {
	ok := []struct{ in, label, suffix string }{
		{"example.com", "example", "com"},
		{"www.example.com", "example", "com"},
		{"a.b.example.com", "example", "com"},
		{"EXAMPLE.com.", "example", "com"},
		{"example.co.uk", "example", "co.uk"},
		{"shop.example.co.uk", "example", "co.uk"},
		{"example.com.au", "example", "com.au"},
	}
	for _, c := range ok {
		label, suffix, err := registrableDomain(c.in)
		if err != nil || label != c.label || suffix != c.suffix {
			t.Errorf("registrableDomain(%q) = (%q, %q, %v), want (%q, %q)", c.in, label, suffix, err, c.label, c.suffix)
		}
	}
	for _, bad := range []string{"", "localhost", ".example.com", "  "} {
		if _, _, err := registrableDomain(bad); err == nil {
			t.Errorf("registrableDomain(%q): want an error", bad)
		}
	}
}

func kindOf(cands []lookalikeCandidate, label string) string {
	for _, c := range cands {
		if c.label == label {
			return c.kind
		}
	}
	return ""
}

func TestLookalikeCandidates_KnownPermutations(t *testing.T) {
	cands := lookalikeCandidates("example")
	want := map[string]string{
		"exmple":         "omission",
		"eexample":       "duplication",
		"exmaple":        "transposition",
		"exanple":        "keyboard", // m is next to n
		"examp1e":        "homoglyph",
		"exarnple":       "homoglyph", // m looks like rn
		"ex-ample":       "hyphen",
		"exemple":        "vowel",
		"example-login":  "keyword",
		"secure-example": "keyword",
	}
	for label, kind := range want {
		if got := kindOf(cands, label); got != kind {
			t.Errorf("candidate %q: kind %q, want %q", label, got, kind)
		}
	}
}

func TestLookalikeCandidates_Invariants(t *testing.T) {
	cands := lookalikeCandidates("example")
	seen := map[string]bool{}
	for _, c := range cands {
		if c.label == "example" {
			t.Error("the original label must not be a candidate")
		}
		if !validLabel(c.label) {
			t.Errorf("invalid DNS label generated: %q", c.label)
		}
		if seen[c.label] {
			t.Errorf("duplicate candidate %q", c.label)
		}
		seen[c.label] = true
	}
	if len(cands) < 50 || len(cands) > 500 {
		t.Errorf("got %d candidates for an 7-letter label, want between 50 and 500", len(cands))
	}
	again := lookalikeCandidates("example")
	for i := range cands {
		if cands[i] != again[i] {
			t.Fatalf("order is not stable at %d: %v vs %v", i, cands[i], again[i])
		}
	}
}

func TestLookalikeCandidates_DropsInvalidLabels(t *testing.T) {
	// Removing the first or last character of "a-b" would leave a label that
	// starts or ends with a hyphen, which cannot be registered.
	for _, c := range lookalikeCandidates("a-b") {
		if strings.HasPrefix(c.label, "-") || strings.HasSuffix(c.label, "-") {
			t.Errorf("candidate %q starts or ends with a hyphen", c.label)
		}
	}
	for _, c := range lookalikeCandidates("a") {
		if c.label == "" {
			t.Error("the empty label must not be a candidate")
		}
	}
}

func TestLookalikeCandidates_Capped(t *testing.T) {
	orig := maxLookalikeCandidates
	maxLookalikeCandidates = 20
	t.Cleanup(func() { maxLookalikeCandidates = orig })
	if n := len(lookalikeCandidates("example")); n != 20 {
		t.Errorf("got %d candidates with a cap of 20", n)
	}
}

func TestLookalikeCandidates_LongestLabelStaysWithinTheRealCap(t *testing.T) {
	longest := strings.Repeat("abcdefghijklmnopqrstuvwxyz", 3)[:63]
	if n := len(lookalikeCandidates(longest)); n > 500 {
		t.Errorf("got %d candidates for a 63-letter label, want at most 500", n)
	}
}

// stubDns answers RunLookalikes' two dnsx calls: the wildcard canary first, then
// the candidates, and records what the candidate call was asked.
func stubDns(t *testing.T, canary, answers []string, canaryErr, answerErr error) *string {
	t.Helper()
	var asked string
	n := 0
	orig := execJSONL
	execJSONL = func(_ context.Context, _ string, _ []string, stdin string) ([]string, error) {
		n++
		switch n {
		case 1:
			if !strings.HasPrefix(stdin, "hopper-canary-") {
				t.Errorf("first query should be the wildcard canary, got %q", stdin)
			}
			return canary, canaryErr
		case 2:
			asked = stdin
			return answers, answerErr
		}
		t.Errorf("unexpected execJSONL call #%d", n)
		return nil, nil
	}
	t.Cleanup(func() { execJSONL = orig })
	return &asked
}

func TestRunLookalikes_KeepsResolvingCandidates(t *testing.T) {
	asked := stubDns(t, nil, []string{
		`{"host":"exmple.com","a":["192.0.2.1"]}`,
		`{"host":"examp1e.com","a":["192.0.2.2"],"mx":["10 mail.examp1e.com"]}`,
		`{"host":"EXAMPLE-LOGIN.com.","a":["192.0.2.3"]}`,
		`{"host":"unrelated.org","a":["192.0.2.9"]}`, // not asked about
		`{"host":"exanple.com"}`,                     // nothing to report
		`not json`,
	}, nil, nil)

	got, err := RunLookalikes(context.Background(), "www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d entries %v, want 3", len(got), got)
	}
	// Mail-capable first, then the rest in answer order.
	if got[0].Host != "examp1e.com" || got[0].Kind != "homoglyph" || len(got[0].MX) != 1 {
		t.Errorf("first = %+v, want the mail-capable examp1e.com (homoglyph)", got[0])
	}
	if got[1].Host != "exmple.com" || got[1].Kind != "omission" {
		t.Errorf("second = %+v", got[1])
	}
	if got[2].Host != "example-login.com" || got[2].Kind != "keyword" {
		t.Errorf("third = %+v, want normalised host example-login.com", got[2])
	}

	// A subdomain input is reduced to its registrable name, and every candidate
	// stays under the same suffix.
	for _, host := range strings.Fields(*asked) {
		if !strings.HasSuffix(host, ".com") || host == "example.com" || strings.HasPrefix(host, "ww") && !strings.HasPrefix(host, "wwexample") {
			t.Errorf("unexpected candidate host %q", host)
		}
	}
	if strings.Contains(*asked, "ww.example.com") {
		t.Error("asked about lookalikes of 'www' instead of 'example'")
	}
}

func TestRunLookalikes_WildcardSuffixIsAnError(t *testing.T) {
	stubDns(t, []string{`{"host":"hopper-canary-00000000.example","a":["192.0.2.1"]}`}, nil, nil, nil)
	_, err := RunLookalikes(context.Background(), "demo.example")
	if err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Errorf("err = %v, want a wildcard-DNS error", err)
	}
}

func TestRunLookalikes_RejectsBadInputWithoutQuerying(t *testing.T) {
	orig := execJSONL
	execJSONL = func(context.Context, string, []string, string) ([]string, error) {
		t.Error("no DNS query should be made for an invalid domain")
		return nil, nil
	}
	t.Cleanup(func() { execJSONL = orig })
	for _, bad := range []string{"localhost", "", "ünïcode.com"} {
		if _, err := RunLookalikes(context.Background(), bad); err == nil {
			t.Errorf("RunLookalikes(%q): want an error", bad)
		}
	}
}

func TestRunLookalikes_PropagatesDnsxErrors(t *testing.T) {
	stubDns(t, nil, nil, errors.New("dnsx: exit 1"), nil)
	if _, err := RunLookalikes(context.Background(), "example.com"); err == nil {
		t.Error("want the canary error")
	}
	stubDns(t, nil, nil, nil, errors.New("dnsx: exit 1"))
	if _, err := RunLookalikes(context.Background(), "example.com"); err == nil {
		t.Error("want the candidate-query error")
	}
}

func TestRunTool_FindLookalikes(t *testing.T) {
	stubDns(t, nil, []string{`{"host":"exmple.com","a":["192.0.2.1"]}`}, nil, nil)
	out, err := runTool(context.Background(), "find_lookalikes", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d results, want 1", len(out))
	}
	if e, ok := out[0].(LookalikeEntry); !ok || e.Host != "exmple.com" || e.Kind != "omission" {
		t.Errorf("result = %#v", out[0])
	}
}

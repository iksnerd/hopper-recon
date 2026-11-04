package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// LookalikeEntry is a registered domain that looks like the scanned one: it
// resolves, and Kind says how its name differs (e.g. "omission": exmple.com).
// MX records matter most: a lookalike that can receive or send mail is a
// ready-made phishing sender.
type LookalikeEntry struct {
	Host string   `json:"host"`
	Kind string   `json:"kind"`
	A    []string `json:"a,omitempty"`
	MX   []string `json:"mx,omitempty"`
}

// maxLookalikeCandidates bounds the DNS queries one scan can send. A typical
// 8-letter label yields about a hundred candidates and the longest valid label
// (63 characters) about 500, so this is a safety bound, not a tuning knob. It is
// a var so a test can lower it.
var maxLookalikeCandidates = 500

type lookalikeCandidate struct {
	label string
	kind  string
}

// twoPartSuffixes are common public suffixes with two labels, so that
// "shop.example.co.uk" is read as example.co.uk and not as co.uk. The full
// public-suffix list is deliberately not vendored for this: an unusual suffix
// can be mis-split, and the dashboard's target should be the registrable domain.
var twoPartSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "me.uk": true,
	"com.au": true, "net.au": true, "org.au": true, "co.nz": true, "org.nz": true,
	"co.jp": true, "ne.jp": true, "or.jp": true, "co.kr": true, "co.in": true,
	"com.br": true, "com.ar": true, "com.mx": true, "com.co": true, "com.tr": true,
	"com.cn": true, "com.hk": true, "com.sg": true, "com.tw": true, "com.my": true,
	"co.za": true, "co.il": true, "co.id": true, "co.th": true,
}

// registrableDomain splits host into the registrable label and its public
// suffix: "www.example.com" gives ("example", "com"), "shop.example.co.uk"
// gives ("example", "co.uk").
func registrableDomain(host string) (label, suffix string, err error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	parts := strings.Split(host, ".")
	if len(parts) < 2 || parts[0] == "" {
		return "", "", fmt.Errorf("expected a domain such as example.com, got %q", host)
	}
	suffixLabels := 1
	if len(parts) >= 3 && twoPartSuffixes[strings.Join(parts[len(parts)-2:], ".")] {
		suffixLabels = 2
	}
	if len(parts) <= suffixLabels {
		return "", "", fmt.Errorf("%q has no registrable name", host)
	}
	return parts[len(parts)-suffixLabels-1], strings.Join(parts[len(parts)-suffixLabels:], "."), nil
}

// qwertyNeighbours maps a key to the keys next to it, for fat-finger typos.
var qwertyNeighbours = map[byte]string{
	'q': "wa", 'w': "qes", 'e': "wrd", 'r': "etf", 't': "ryg", 'y': "tuh", 'u': "yij",
	'i': "uok", 'o': "ipl", 'p': "ol", 'a': "qsz", 's': "adwx", 'd': "sfec", 'f': "dgrv",
	'g': "fhtb", 'h': "gjyn", 'j': "hkum", 'k': "jlim", 'l': "kop", 'z': "ax", 'x': "zcs",
	'c': "xvd", 'v': "cbf", 'b': "vng", 'n': "bmh", 'm': "njk",
}

// homoglyphs are ASCII look-alikes. Multi-character forms (m as rn) are the
// ones people miss at a glance.
var homoglyphs = map[string][]string{
	"o": {"0"}, "l": {"1", "i"}, "i": {"1", "l"}, "s": {"5"}, "e": {"3"}, "a": {"4"},
	"m": {"rn"}, "w": {"vv"}, "d": {"cl"},
}

// phishingWords are appended or prepended with a hyphen: example-login.com.
var phishingWords = []string{"login", "secure", "support", "pay", "account", "verify"}

func validLabel(s string) bool {
	if s == "" || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// lookalikeCandidates returns the permutations of label that people mistype or
// misread, deduplicated, in a stable order, without label itself. Each carries
// the first kind that produced it.
func lookalikeCandidates(label string) []lookalikeCandidate {
	seen := map[string]bool{label: true}
	var out []lookalikeCandidate
	add := func(c, kind string) {
		if len(out) >= maxLookalikeCandidates || seen[c] || !validLabel(c) {
			return
		}
		seen[c] = true
		out = append(out, lookalikeCandidate{c, kind})
	}

	for i := range label {
		add(label[:i]+label[i+1:], "omission")
	}
	for i := range label {
		add(label[:i+1]+label[i:], "duplication")
	}
	for i := 0; i+1 < len(label); i++ {
		add(label[:i]+string(label[i+1])+string(label[i])+label[i+2:], "transposition")
	}
	for i := 0; i < len(label); i++ {
		for _, n := range qwertyNeighbours[label[i]] {
			add(label[:i]+string(n)+label[i+1:], "keyboard")
		}
	}
	for i := 0; i < len(label); i++ {
		for _, g := range homoglyphs[string(label[i])] {
			add(label[:i]+g+label[i+1:], "homoglyph")
		}
	}
	for i := 1; i < len(label); i++ {
		add(label[:i]+"-"+label[i:], "hyphen")
	}
	for i := 0; i < len(label); i++ {
		if strings.IndexByte("aeiou", label[i]) < 0 {
			continue
		}
		for _, v := range "aeiou" {
			add(label[:i]+string(v)+label[i+1:], "vowel")
		}
	}
	for _, w := range phishingWords {
		add(label+"-"+w, "keyword")
		add(w+"-"+label, "keyword")
	}
	return out
}

// RunLookalikes finds registered lookalikes of a domain: it permutes the
// registrable name (typos, look-alike characters, phishing words), keeps the
// same public suffix, and resolves each candidate for A and MX records with
// dnsx. Like find_domains this is DNS against public resolvers: nothing is sent
// to the target or to the candidates' own servers.
//
// Only the same suffix is tried (other TLDs are find_domains' job) so a scan
// stays at about a couple of hundred queries.
func RunLookalikes(ctx context.Context, domain string) ([]LookalikeEntry, error) {
	label, suffix, err := registrableDomain(domain)
	if err != nil {
		return nil, err
	}
	if !validLabel(label) {
		return nil, fmt.Errorf("cannot generate lookalikes for %q", label)
	}

	// A suffix that answers for any name would make every candidate "resolve".
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	canary := "hopper-canary-" + hex.EncodeToString(nonce[:]) + "." + suffix
	probe, err := execJSONL(ctx, "dnsx", []string{"-silent", "-a", "-json"}, canary+"\n")
	if err != nil {
		return nil, err
	}
	if len(probe) > 0 {
		return nil, errors.New("the suffix ." + suffix + " resolves any name (wildcard DNS), so lookalike results would be meaningless")
	}

	cands := lookalikeCandidates(label)
	kinds := make(map[string]string, len(cands))
	var sb strings.Builder
	for _, c := range cands {
		host := c.label + "." + suffix
		kinds[host] = c.kind
		sb.WriteString(host + "\n")
	}
	lines, err := execJSONL(ctx, "dnsx", []string{"-silent", "-a", "-mx", "-rl", "100", "-json"}, sb.String())
	if err != nil {
		return nil, err
	}

	var out []LookalikeEntry
	for _, l := range lines {
		var rec struct {
			Host string   `json:"host"`
			A    []string `json:"a"`
			MX   []string `json:"mx"`
		}
		if json.Unmarshal([]byte(l), &rec) != nil {
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(rec.Host, "."))
		kind, ok := kinds[host]
		if !ok || (len(rec.A) == 0 && len(rec.MX) == 0) {
			continue // an answer for a name we did not ask about, or an empty one
		}
		out = append(out, LookalikeEntry{Host: host, Kind: kind, A: rec.A, MX: rec.MX})
	}
	// Mail-capable lookalikes first: they are the ones that can send phishing.
	sort.SliceStable(out, func(i, j int) bool { return len(out[i].MX) > 0 && len(out[j].MX) == 0 })
	return out, nil
}

package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// All key values below are obviously fake. Failure messages print provider
// names and counts only, never file content.

// resetSubfinderSources clears the -ls cache so a test starts cold.
func resetSubfinderSources(t *testing.T) {
	t.Helper()
	clear := func() {
		sourcesMu.Lock()
		sourcesCached, sourcesErr, sourcesFailedAt = nil, nil, time.Time{}
		sourcesMu.Unlock()
	}
	clear()
	orig := sourcesRetryAfter
	t.Cleanup(func() { clear(); sourcesRetryAfter = orig })
}

// withProviderConfig points the engine at a fixture config; content == nil
// means the file does not exist.
func withProviderConfig(t *testing.T, content *string) {
	t.Helper()
	orig := subfinderProviderConfig
	path := filepath.Join(t.TempDir(), "provider-config.yaml")
	if content != nil {
		if err := os.WriteFile(path, []byte(*content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	subfinderProviderConfig = path
	t.Cleanup(func() { subfinderProviderConfig = orig })
}

// stubNoSubfinder keeps a test hermetic: no -ls subprocess, no real config file.
func stubNoSubfinder(t *testing.T) {
	t.Helper()
	resetSubfinderSources(t)
	withExecJSONL(t, [][]string{nil}, []error{errors.New("stubbed")})
	withProviderConfig(t, nil)
}

func strp(s string) *string { return &s }

const lsFixture = "anubis\r\n" +
	"\x1b[92mcrtsh\x1b[0m\n" +
	"alienvault *\n" +
	"\x1b[34mshodan\x1b[0m \x1b[33m*\x1b[0m\n" +
	"censys *\n" +
	"hackertarget ~\n" +
	"[\x1b[34mINF\x1b[0m] Current list of available sources. [54]\n" +
	"\n"

func TestParseSubfinderSources(t *testing.T) {
	s, err := parseSubfinderSources(strings.Split(lsFixture, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Total != 6 || s.Keyless != 2 || s.KeyRequired != 3 || s.OptionalKey != 1 {
		t.Errorf("total/keyless/required/optional = %d/%d/%d/%d, want 6/2/3/1",
			s.Total, s.Keyless, s.KeyRequired, s.OptionalKey)
	}
	if !s.required["shodan"] || !s.keyed["hackertarget"] || s.required["hackertarget"] {
		t.Error("ANSI-wrapped shodan must be key-required; hackertarget optional only")
	}
}

func TestParseSubfinderSources_Empty(t *testing.T) {
	if _, err := parseSubfinderSources([]string{"[INF] banner only"}); err == nil {
		t.Error("output with no sources must be an error, not zero sources")
	}
}

func TestParseConfiguredProviders(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want []string
	}{
		{"configured", "shodan:\n  - FAKE-KEY-1\ncensys:\n  - FAKE-ID:FAKE-SECRET\n", []string{"censys", "shodan"}},
		{"empty list", "shodan: []\ncensys:\n", []string{}},
		{"empty items", "shodan:\n  - \"\"\n  - ''\n", []string{}},
		{"comments", "# FAKE-KEY-9\nshodan:\n  # - FAKE-KEY-2\n  - FAKE-KEY-3 # trailing\nbevigil: [] # none\n", []string{"shodan"}},
		{"inline list", "github: [FAKE-KEY-4, FAKE-KEY-5]\nfofa: [\"\"]\n", []string{"github"}},
		{"unindented items", "shodan:\n- FAKE-KEY-6\n", []string{"shodan"}},
		{"comment only", "# nothing here\n", []string{}},
		{"empty file", "", []string{}},
	}
	for _, c := range cases {
		got, err := parseConfiguredProviders([]byte(c.yaml))
		if err != nil {
			t.Errorf("%s: unexpected error: %v", c.name, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: configured = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestParseConfiguredProviders_Malformed(t *testing.T) {
	// Non-empty content with no provider key must not read as "no keys".
	if _, err := parseConfiguredProviders([]byte("\x00\x01 not yaml at all\n{{{\n")); err == nil {
		t.Error("malformed config must be an error")
	}
	// A bad line among good ones is skipped; the good ones still count.
	got, err := parseConfiguredProviders([]byte("{{{ bad\nshodan:\n  - FAKE-KEY-7\n"))
	if err != nil || !reflect.DeepEqual(got, []string{"shodan"}) {
		t.Errorf("got %v, %v; want [shodan]", got, err)
	}
}

func TestLoadConfiguredProviders_MissingFile(t *testing.T) {
	withProviderConfig(t, nil)
	if _, err := loadConfiguredProviders(); err == nil {
		t.Error("missing provider config must be an error")
	}
}

func configBody(t *testing.T) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	handleConfig(plainPolicy())(rec, httptest.NewRequest(http.MethodGet, "/config", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestHandleConfig_SubfinderCoverage(t *testing.T) {
	resetSubfinderSources(t)
	withExecJSONL(t, [][]string{strings.Split(lsFixture, "\n")}, []error{nil})
	// unknownprov is not a subfinder source and must not be reported or counted;
	// anubis is keyless, so a key under it adds nothing.
	withProviderConfig(t, strp("shodan:\n  - FAKE-KEY-1\ncensys: []\nhackertarget:\n  - FAKE-KEY-2\nunknownprov:\n  - FAKE-KEY-3\nanubis:\n  - FAKE-KEY-4\n"))
	body := configBody(t)

	want := map[string]float64{
		"subfinder_sources_total":        6,
		"subfinder_sources_keyless":      2,
		"subfinder_sources_key_required": 3,
		"subfinder_sources_optional_key": 1,
		// keyless 2 + optional 1 + shodan (required, keyed) = 4
		"subfinder_sources_active": 4,
	}
	for k, v := range want {
		if body[k] != v {
			t.Errorf("%s = %v, want %v", k, body[k], v)
		}
	}
	if !reflect.DeepEqual(body["subfinder_providers_configured"], []any{"hackertarget", "shodan"}) {
		t.Errorf("providers = %v, want [hackertarget shodan]", body["subfinder_providers_configured"])
	}
	// Existing fields are untouched.
	if body["version"] == nil || body["has_scope"] != false || body["cooldown_s"] == nil {
		t.Error("existing /config fields missing")
	}
	if strings.Contains(string(mustJSON(t, body)), "FAKE-KEY") {
		t.Error("response contains key material")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHandleConfig_SourceListFailureOmitsFields(t *testing.T) {
	resetSubfinderSources(t)
	withExecJSONL(t, [][]string{nil}, []error{errors.New("subfinder: not found")})
	withProviderConfig(t, strp("shodan:\n  - FAKE-KEY-1\n"))
	body := configBody(t)
	for _, k := range []string{
		"subfinder_sources_total", "subfinder_sources_keyless", "subfinder_sources_key_required",
		"subfinder_sources_optional_key", "subfinder_sources_active",
	} {
		if _, ok := body[k]; ok {
			t.Errorf("%s present after a failed -ls; a failure must omit it", k)
		}
	}
	// Names are only reported against a known source list: with no list, a
	// malformed line in a credential file could surface as a "provider name".
	if _, ok := body["subfinder_providers_configured"]; ok {
		t.Errorf("providers reported without a source list to check them against: %v", body["subfinder_providers_configured"])
	}
}

func TestHandleConfig_UnvalidatedNamesNeverReported(t *testing.T) {
	resetSubfinderSources(t)
	withExecJSONL(t, [][]string{nil}, []error{errors.New("subfinder: not found")})
	// A stray top-level "name:value" line: as a name it would look like a token.
	withProviderConfig(t, strp("FAKE-TOKEN-9:FAKE-VALUE-9\nshodan:\n  - FAKE-KEY-1\n"))
	raw, err := json.Marshal(configBody(t))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "FAKE-TOKEN-9") || strings.Contains(string(raw), "FAKE-VALUE-9") {
		t.Error("an unvalidated config token appeared in /config")
	}
}

func TestSubfinderSources_FailureIsRememberedBriefly(t *testing.T) {
	resetSubfinderSources(t)
	sourcesRetryAfter = time.Hour
	// One stubbed call: a second -ls inside the window would be an unexpected call.
	withExecJSONL(t, [][]string{nil}, []error{errors.New("subfinder: not found")})
	withProviderConfig(t, strp("shodan:\n  - FAKE-KEY-1\n"))
	configBody(t)
	configBody(t)
}

func TestSubfinderSources_RetriesAfterTheWindow(t *testing.T) {
	resetSubfinderSources(t)
	sourcesRetryAfter = 0
	withExecJSONL(t,
		[][]string{nil, strings.Split(lsFixture, "\n")},
		[]error{errors.New("subfinder: timeout"), nil})
	withProviderConfig(t, strp("shodan:\n  - FAKE-KEY-1\n"))
	if _, ok := configBody(t)["subfinder_sources_total"]; ok {
		t.Error("first call failed; total must be omitted")
	}
	if configBody(t)["subfinder_sources_total"] == nil {
		t.Error("second call should have retried -ls and reported the total")
	}
}

func TestHandleConfig_ProviderConfigFailureOmitsFields(t *testing.T) {
	resetSubfinderSources(t)
	withExecJSONL(t, [][]string{strings.Split(lsFixture, "\n")}, []error{nil})
	withProviderConfig(t, nil)
	body := configBody(t)
	for _, k := range []string{"subfinder_providers_configured", "subfinder_sources_active"} {
		if _, ok := body[k]; ok {
			t.Errorf("%s present with an unreadable provider config; a failure must not read as zero keys", k)
		}
	}
	if body["subfinder_sources_total"] != float64(6) {
		t.Errorf("source counts should still report, got total=%v", body["subfinder_sources_total"])
	}
}

func TestHandleConfig_NoKeysIsEmptyListNotMissing(t *testing.T) {
	resetSubfinderSources(t)
	withExecJSONL(t, [][]string{strings.Split(lsFixture, "\n")}, []error{nil})
	withProviderConfig(t, strp("shodan: []\n"))
	body := configBody(t)
	if !reflect.DeepEqual(body["subfinder_providers_configured"], []any{}) {
		t.Errorf("providers = %v, want an empty list", body["subfinder_providers_configured"])
	}
	if body["subfinder_sources_active"] != float64(3) {
		t.Errorf("active = %v, want 3 (keyless + optional)", body["subfinder_sources_active"])
	}
}

func TestSubfinderSources_CachedAfterSuccess(t *testing.T) {
	resetSubfinderSources(t)
	// One stubbed call only: a second -ls would be an "unexpected call" error.
	withExecJSONL(t, [][]string{strings.Split(lsFixture, "\n")}, []error{nil})
	withProviderConfig(t, strp("shodan:\n  - FAKE-KEY-1\n"))
	configBody(t)
	configBody(t)
}

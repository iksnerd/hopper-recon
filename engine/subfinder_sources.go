package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// subfinderProviderConfig is where subfinder reads its API keys inside the
// container (docker-compose bind-mounts ~/.config/subfinder from the host).
// A var so tests can point it at a fixture.
var subfinderProviderConfig = "/root/.config/subfinder/provider-config.yaml"

// SubfinderSources is subfinder's source inventory, parsed from `subfinder -ls`.
type SubfinderSources struct {
	Total       int
	Keyless     int
	KeyRequired int
	OptionalKey int
	keyed       map[string]bool // sources that require or optionally take a key
	required    map[string]bool // sources that require a key
}

// ansiRE matches the SGR colour sequences subfinder wraps its log tags in.
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// sourceNameRE is what a provider or source name may look like. Anything else
// is not a name (a banner line, a stray value) and is never reported.
var sourceNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// parseSubfinderSources parses `subfinder -ls` output: one source per line,
// `name`, `name *` (key required) or `name ~` (key optional). The source names
// are on stdout; the log banner (with the ANSI colours) is on stderr, which
// runJSONL does not capture. Colours are stripped and lines are validated
// anyway, so a banner that ever reaches stdout is skipped rather than counted.
func parseSubfinderSources(lines []string) (*SubfinderSources, error) {
	s := &SubfinderSources{keyed: map[string]bool{}, required: map[string]bool{}}
	for _, raw := range lines {
		fields := strings.Fields(ansiRE.ReplaceAllString(raw, ""))
		if len(fields) == 0 || len(fields) > 2 || !sourceNameRE.MatchString(fields[0]) {
			continue
		}
		name := fields[0]
		marker := ""
		if len(fields) == 2 {
			marker = fields[1]
		}
		switch marker {
		case "":
			s.Keyless++
		case "*":
			s.KeyRequired++
			s.keyed[name] = true
			s.required[name] = true
		case "~":
			s.OptionalKey++
			s.keyed[name] = true
		default:
			continue
		}
		s.Total++
	}
	if s.Total == 0 {
		return nil, errors.New("subfinder -ls listed no sources")
	}
	return s, nil
}

var (
	sourcesMu       sync.Mutex
	sourcesCached   *SubfinderSources
	sourcesErr      error
	sourcesFailedAt time.Time
)

// sourcesRetryAfter is how long a failed `subfinder -ls` is remembered. /config
// is called on page loads (the operator banner), and a broken or slow subfinder
// would otherwise spawn a process, holding the lock for up to its 15s timeout,
// on every request. A var so a test can shorten it.
var sourcesRetryAfter = 30 * time.Second

// loadSubfinderSources runs `subfinder -ls` once and caches the result: the
// list is fixed for the life of the binary. A success is cached for good. A
// failure is remembered only for sourcesRetryAfter, so a transient one
// (timeout, cold start) recovers without an engine restart and a persistent one
// does not cost a subprocess per request.
func loadSubfinderSources(ctx context.Context) (*SubfinderSources, error) {
	sourcesMu.Lock()
	defer sourcesMu.Unlock()
	if sourcesCached != nil {
		return sourcesCached, nil
	}
	if sourcesErr != nil && time.Since(sourcesFailedAt) < sourcesRetryAfter {
		return nil, sourcesErr
	}
	fail := func(err error) (*SubfinderSources, error) {
		sourcesErr, sourcesFailedAt = err, time.Now()
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	lines, err := execJSONL(ctx, "subfinder", []string{"-ls"}, "")
	if err != nil {
		return fail(err)
	}
	s, err := parseSubfinderSources(lines)
	if err != nil {
		return fail(err)
	}
	sourcesCached, sourcesErr = s, nil
	return s, nil
}

// emptyYAMLScalar reports whether a YAML scalar carries no value.
func emptyYAMLScalar(v string) bool {
	switch v {
	case "", `""`, `''`, "null", "~":
		return true
	}
	return false
}

// parseConfiguredProviders returns the sorted names of providers that have at
// least one non-empty key in a subfinder provider-config.yaml. It reads only
// the structure it needs (a top-level `name:` followed by `- item` lines, or an
// inline `name: [a, b]`) and never returns, logs or wraps a value.
func parseConfiguredProviders(data []byte) ([]string, error) {
	configured := map[string]bool{}
	current := ""
	sawKey, sawContent := false, false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, " \t\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || trimmed == "---" {
			continue
		}
		sawContent = true
		if strings.HasPrefix(trimmed, "-") {
			// "- item" under the current key, indented or not (YAML allows both).
			if current != "" && !emptyYAMLScalar(strings.TrimSpace(stripYAMLComment(trimmed[1:]))) {
				configured[current] = true
			}
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue // nested content we do not interpret
		}
		name, rest, ok := strings.Cut(trimmed, ":")
		name = strings.TrimSpace(name)
		if !ok || !sourceNameRE.MatchString(name) {
			current = ""
			continue
		}
		sawKey = true
		current = name
		rest = strings.TrimSpace(stripYAMLComment(rest))
		if strings.HasPrefix(rest, "[") {
			// Inline flow list: configured only if some element is non-empty.
			if strings.Trim(rest, `[] ,"'`) != "" {
				configured[name] = true
			}
		} else if !emptyYAMLScalar(rest) {
			configured[name] = true
		}
	}
	if sawContent && !sawKey {
		return nil, errors.New("provider config has no recognisable provider entries")
	}
	names := make([]string, 0, len(configured))
	for n := range configured {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// stripYAMLComment drops a trailing ` # comment`. It only serves the
// empty-or-not decision; the value itself is never kept.
func stripYAMLComment(s string) string {
	if strings.HasPrefix(strings.TrimSpace(s), "#") {
		return ""
	}
	if i := strings.Index(s, " #"); i >= 0 {
		return s[:i]
	}
	return s
}

// loadConfiguredProviders reads the provider config. The error never carries
// file content: os errors name the path only and the parser's are fixed text.
func loadConfiguredProviders() ([]string, error) {
	data, err := os.ReadFile(subfinderProviderConfig)
	if err != nil {
		return nil, err
	}
	return parseConfiguredProviders(data)
}

// subfinderCoverageFields returns the /config fields describing subfinder's
// source coverage. A lookup that fails drops its own fields entirely: a
// failure must never read as "0 keys" or "0 sources".
func subfinderCoverageFields(ctx context.Context) map[string]any {
	out := map[string]any{}
	src, srcErr := loadSubfinderSources(ctx)
	if srcErr != nil {
		slog.Warn("subfinder source list unavailable", "err", srcErr)
	} else {
		out["subfinder_sources_total"] = src.Total
		out["subfinder_sources_keyless"] = src.Keyless
		out["subfinder_sources_key_required"] = src.KeyRequired
		out["subfinder_sources_optional_key"] = src.OptionalKey
	}
	if src == nil {
		// Without the source list there is nothing to check provider names
		// against, and the config file is a credential file: a malformed line
		// such as "token:value" would otherwise be reported as a provider
		// name. Names are reported only when they are known subfinder sources.
		return out
	}
	providers, cfgErr := loadConfiguredProviders()
	if cfgErr != nil {
		slog.Warn("subfinder provider config unavailable", "err", cfgErr)
		return out
	}
	// Report only names subfinder knows as key-taking sources; a typo or a
	// retired provider in the file adds no coverage.
	known := []string{}
	for _, p := range providers {
		if src.keyed[p] {
			known = append(known, p)
		}
	}
	out["subfinder_providers_configured"] = known
	// Keyless and optional-key sources run without a key; a key-required
	// source runs only when it has one.
	active := src.Keyless + src.OptionalKey
	for _, p := range known {
		if src.required[p] {
			active++
		}
	}
	out["subfinder_sources_active"] = active
	return out
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// runTool dispatches to the right tool function and returns parsed JSON
// values. Lines that aren't valid JSON are passed through as raw strings so
// the web layer's existing parser keeps working.
func runTool(ctx context.Context, tool, target string) ([]any, error) {
	var raw []string
	var err error
	switch tool {
	case "passive_subdomains":
		findings, ferr := RunSubfinder(ctx, target)
		if ferr != nil {
			return nil, ferr
		}
		out := make([]any, len(findings))
		for i, f := range findings {
			out[i] = f
		}
		return out, nil
	case "resolve_dns":
		raw, err = RunDnsx(ctx, target)
	case "fetch_tls_cert":
		raw, err = RunTlsx(ctx, target)
	case "probe_http":
		raw, err = RunHttpx(ctx, target)
	case "check_cdn":
		raw, err = RunCdncheck(ctx, target)
	case "find_urls":
		raw, err = RunUrlfinder(ctx, target)
	default:
		return nil, fmt.Errorf("unknown tool %q", tool)
	}
	if err != nil {
		return nil, err
	}
	return parseJSONLines(raw), nil
}

// parseJSONLines turns each JSONL line into a parsed value, falling back to
// the raw string when a line isn't JSON. Matches the web's existing shape.
func parseJSONLines(lines []string) []any {
	out := make([]any, 0, len(lines))
	for _, l := range lines {
		var v any
		if json.Unmarshal([]byte(l), &v) == nil {
			out = append(out, v)
		} else {
			out = append(out, l)
		}
	}
	return out
}

// extractMeta pulls indexed columns out of parsed results so the dashboard
// can filter without re-parsing the full JSON.
func extractMeta(tool string, parsed []any) ScanMeta {
	if len(parsed) == 0 {
		return ScanMeta{}
	}
	first, ok := parsed[0].(map[string]any)
	if !ok {
		return ScanMeta{}
	}
	switch tool {
	case "probe_http":
		var meta ScanMeta
		if sc, ok := first["status_code"].(float64); ok {
			n := int(sc)
			meta.HTTPStatus = &n
		}
		if tech, ok := first["tech"].([]any); ok && len(tech) > 0 {
			parts := make([]string, 0, len(tech))
			for _, t := range tech {
				if s, ok := t.(string); ok {
					parts = append(parts, s)
				}
			}
			if len(parts) > 0 {
				joined := strings.Join(parts, ",")
				meta.TechStack = &joined
			}
		}
		return meta
	case "fetch_tls_cert":
		var meta ScanMeta
		if na, ok := first["not_after"].(string); ok {
			meta.CertExpiry = &na
		}
		return meta
	}
	return ScanMeta{}
}

type scanRequest struct {
	Tool   string `json:"tool"`
	Target string `json:"target"`
}

type scanResponse struct {
	ID      string `json:"id"`
	Tool    string `json:"tool"`
	Target  string `json:"target"`
	Status  string `json:"status"`
	Results []any  `json:"results,omitempty"`
	Error   string `json:"error,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Hopper-Recon", "authorized-use-only")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// cooldownSeconds is the per-(domain, tool) window during which a repeat
// scan returns 429. 60s is short enough that real "I want to rescan after
// fixing something" workflows aren't blocked, long enough to defang
// mash-the-button accidents and trivial automation.
const cooldownSeconds = 60

// clientIP best-effort extracts the requester's address. Trusts X-Forwarded-For
// only when it's already set — operators putting hopper-recon behind nginx /
// Caddy / Cloudflare get attribution; bare-loopback dev gets RemoteAddr.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}

// handleRunScan: POST /scan {tool, target} → gate, run, persist, return
// final state. One transaction from the client's perspective. If the client
// disconnects before this returns, the boot sweep retires the pending row.
//
// Gate order is policy → cooldown → execute. Each request writes one
// audit_log row recording the decision (allowed / blocked) and reason.
func handleRunScan(db *DB, policy *Policy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req scanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		if req.Tool == "" || req.Target == "" {
			writeError(w, http.StatusBadRequest, "tool and target required")
			return
		}

		audit := AuditEntry{
			SourceIP:  clientIP(r),
			UserAgent: r.UserAgent(),
			Tool:      req.Tool,
			Target:    req.Target,
		}

		// 1. Scope + blocklist — Policy.Check covers both. 403 for off-scope
		//    (authorization), 451 for blocklist (legal/ethical), defaults to
		//    403 if a future Decision forgets to set it.
		if d := policy.Check(req.Tool, req.Target); !d.Allowed {
			audit.Decision, audit.Reason = "blocked", d.Reason
			_ = db.WriteAudit(audit)
			status := d.HTTPStatus
			if status == 0 {
				status = http.StatusForbidden
			}
			writeError(w, status, d.Reason)
			return
		} else if d.OverrideReason != "" {
			audit.Reason = "override: " + d.OverrideReason
		}

		// 2. Cooldown — stops mash-the-button accidents and cheap automated
		//    abuse. Reads audit_log so MCP tool calls and REST scans share
		//    one cooldown surface. Skipped when an explicit blocklist
		//    override is in force (the operator has already proven intent).
		if audit.Reason == "" {
			recent, err := db.RecentAllowedWithin(req.Target, req.Tool, cooldownSeconds)
			if err == nil && recent {
				audit.Decision = "blocked"
				audit.Reason = fmt.Sprintf("cooldown: same (target,tool) ran within %ds", cooldownSeconds)
				_ = db.WriteAudit(audit)
				w.Header().Set("Retry-After", strconv.Itoa(cooldownSeconds))
				writeError(w, http.StatusTooManyRequests, audit.Reason)
				return
			}
		}

		audit.Decision = "allowed"
		_ = db.WriteAudit(audit)

		id := uuid.NewString()
		if err := db.InsertScan(id, req.Target, req.Tool); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("insert: %v", err))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()

		results, runErr := runTool(ctx, req.Tool, req.Target)
		if runErr != nil {
			_ = db.FailScan(id, runErr.Error())
			writeJSON(w, http.StatusOK, scanResponse{
				ID: id, Tool: req.Tool, Target: req.Target, Status: "failed", Error: runErr.Error(),
			})
			return
		}

		meta := extractMeta(req.Tool, results)
		if err := db.CompleteScan(id, results, meta); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("persist: %v", err))
			return
		}
		_ = db.PurgeOldScans(req.Target, 50)

		writeJSON(w, http.StatusOK, scanResponse{
			ID: id, Tool: req.Tool, Target: req.Target, Status: "completed", Results: results,
		})
	}
}

// handleListScans: GET /scans?domain=&limit=
func handleListScans(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		rows, err := db.ListScans(q.Get("domain"), limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, rows)
	}
}

// handleDeleteScan: DELETE /scans/{id}
func handleDeleteScan(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			writeError(w, http.StatusBadRequest, "id required")
			return
		}
		if err := db.DeleteScan(id); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleGeoipLookup: GET /geoip?ips=a,b,c — checks cache, runs mmdb on misses,
// upserts back into cache, returns the union. Empty mmdb → empty union.
func handleGeoipLookup(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.Query().Get("ips")
		if raw == "" {
			writeJSON(w, http.StatusOK, []GeoipEntry{})
			return
		}
		seen := map[string]struct{}{}
		var unique []string
		for ip := range strings.SplitSeq(raw, ",") {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			if _, ok := seen[ip]; ok {
				continue
			}
			seen[ip] = struct{}{}
			unique = append(unique, ip)
			if len(unique) >= 100 {
				break
			}
		}
		if len(unique) == 0 {
			writeJSON(w, http.StatusOK, []GeoipEntry{})
			return
		}

		cached, err := db.GetCachedGeoip(unique)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		cachedSet := map[string]struct{}{}
		for _, c := range cached {
			cachedSet[c.IP] = struct{}{}
		}
		var misses []string
		for _, ip := range unique {
			if _, ok := cachedSet[ip]; !ok {
				misses = append(misses, ip)
			}
		}

		fresh := []GeoipEntry{}
		if len(misses) > 0 {
			f, lerr := LookupGeoip(misses)
			if lerr == nil {
				fresh = f
				_ = db.UpsertGeoip(fresh)
			}
		}
		out := append([]GeoipEntry{}, cached...)
		out = append(out, fresh...)
		writeJSON(w, http.StatusOK, out)
	}
}

// handleHealth is the liveness probe — process is up.
func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// handleConfig returns engine configuration that the web layer needs to
// shape its UI — booleans only, no env values are leaked. Used by the web's
// first-boot warning banner to decide whether to nag operators about running
// without scope or auth.
func handleConfig(policy *Policy) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"version":    Version,
			"has_scope":  policy.HasScope(),
			"has_auth":   false, // wired in v0.3 with Auth.js
			"cooldown_s": cooldownSeconds,
		})
	}
}

// handleReady is the readiness probe — DB is reachable.
func handleReady(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := db.PingContext(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	}
}

// runHTTPServer wires the REST routes plus an MCP-over-HTTP handler at /mcp
// (so AI agents can connect to the long-running engine instead of spawning a
// stdio container per call). Blocks until SIGTERM/SIGINT.
func runHTTPServer(addr, dbPath string) error {
	db, err := OpenDB(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	policy := LoadPolicy()
	log.Printf("Hopper Recon engine: db=%s addr=%s", dbPath, addr)

	mux := http.NewServeMux()

	mux.HandleFunc("POST /scan", handleRunScan(db, policy))
	mux.HandleFunc("GET /scans", handleListScans(db))
	mux.HandleFunc("DELETE /scans/{id}", handleDeleteScan(db))
	mux.HandleFunc("GET /geoip", handleGeoipLookup(db))
	mux.HandleFunc("GET /healthz", handleHealth)
	mux.HandleFunc("GET /readyz", handleReady(db))
	mux.HandleFunc("GET /config", handleConfig(policy))

	// Build a fresh MCP server per request so SourceIP / UserAgent in the
	// audit_log reflect the actual caller of THIS request, not the first one
	// the engine ever saw. Stateless mode means there's no per-session state
	// to reuse anyway, so the cost is just allocation.
	mcpHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return buildMCPServer(MCPCtx{
			Policy:    policy,
			Audit:     db,
			SourceIP:  clientIP(r),
			UserAgent: r.UserAgent(),
		})
	}, &mcp.StreamableHTTPOptions{Stateless: true})
	mux.Handle("/mcp", mcpHandler)
	mux.Handle("/mcp/", mcpHandler)

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		log.Println("shutdown: draining HTTP server")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

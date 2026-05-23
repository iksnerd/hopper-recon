package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// withToolRunner stubs the toolRunner var for the duration of one test.
func withToolRunner(t *testing.T, fn func(context.Context, string, string) ([]any, error)) {
	t.Helper()
	orig := toolRunner
	toolRunner = fn
	t.Cleanup(func() { toolRunner = orig })
}

func postScan(t *testing.T, handler http.HandlerFunc, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handler(rec, req)
	return rec
}

// ---- Pure function tests (no HTTP, no DB) ----

func TestParseJSONLines(t *testing.T) {
	lines := []string{
		`{"host":"example.com"}`,
		`not-json-at-all`,
		`{"status_code":200}`,
	}
	out := parseJSONLines(lines)
	if len(out) != 3 {
		t.Fatalf("want 3 elements, got %d", len(out))
	}
	if _, ok := out[0].(map[string]any); !ok {
		t.Error("first element should be parsed map")
	}
	if s, ok := out[1].(string); !ok || s != "not-json-at-all" {
		t.Errorf("second element should be raw string 'not-json-at-all', got %v", out[1])
	}

	// Empty slice → empty slice (not nil).
	empty := parseJSONLines(nil)
	if empty == nil {
		t.Error("parseJSONLines(nil) should return non-nil slice")
	}
}

func TestExtractMeta_ProbeHTTP(t *testing.T) {
	parsed := []any{
		map[string]any{
			"status_code": float64(200),
			"tech":        []any{"Nginx", "PHP"},
		},
	}
	meta := extractMeta("probe_http", parsed)
	if meta.HTTPStatus == nil || *meta.HTTPStatus != 200 {
		t.Errorf("HTTPStatus=%v, want 200", meta.HTTPStatus)
	}
	if meta.TechStack == nil || !strings.Contains(*meta.TechStack, "Nginx") {
		t.Errorf("TechStack=%v, want contains 'Nginx'", meta.TechStack)
	}
}

func TestExtractMeta_TLSCert(t *testing.T) {
	parsed := []any{
		map[string]any{"not_after": "2025-12-31T00:00:00Z"},
	}
	meta := extractMeta("fetch_tls_cert", parsed)
	if meta.CertExpiry == nil || *meta.CertExpiry != "2025-12-31T00:00:00Z" {
		t.Errorf("CertExpiry=%v, want 2025-12-31T00:00:00Z", meta.CertExpiry)
	}
}

func TestExtractMeta_Unknown(t *testing.T) {
	parsed := []any{map[string]any{"foo": "bar"}}
	meta := extractMeta("resolve_dns", parsed)
	if meta.HTTPStatus != nil || meta.CertExpiry != nil || meta.TechStack != nil {
		t.Errorf("unknown tool should return zero ScanMeta, got %+v", meta)
	}
}

func TestExtractMeta_Empty(t *testing.T) {
	meta := extractMeta("probe_http", nil)
	if meta.HTTPStatus != nil || meta.CertExpiry != nil {
		t.Errorf("empty parsed should return zero ScanMeta, got %+v", meta)
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		xff        string
		remoteAddr string
		want       string
	}{
		{
			name:       "xff_single",
			xff:        "203.0.113.1",
			remoteAddr: "127.0.0.1:12345",
			want:       "203.0.113.1",
		},
		{
			name:       "xff_comma_list",
			xff:        "203.0.113.1, 10.0.0.1",
			remoteAddr: "127.0.0.1:12345",
			want:       "203.0.113.1",
		},
		{
			name:       "no_xff_strips_port",
			remoteAddr: "192.168.1.1:54321",
			want:       "192.168.1.1",
		},
		{
			name:       "ipv6_remote_addr",
			remoteAddr: "[::1]:12345",
			want:       "::1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if got := clientIP(req); got != tt.want {
				t.Errorf("clientIP=%q, want %q", got, tt.want)
			}
		})
	}
}

// ---- HTTP handler tests ----

func TestHandleHealth(t *testing.T) {
	rec := httptest.NewRecorder()
	handleHealth(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status=%d, want 200", rec.Code)
	}
}

func TestHandleReady(t *testing.T) {
	db := newTestDB(t)
	rec := httptest.NewRecorder()
	handleReady(db)(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status=%d, want 200", rec.Code)
	}
}

func TestHandleConfig_NoScope(t *testing.T) {
	rec := httptest.NewRecorder()
	handleConfig(plainPolicy())(rec, httptest.NewRequest(http.MethodGet, "/config", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status=%d, want 200", rec.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["has_scope"] != false {
		t.Errorf("has_scope=%v, want false", body["has_scope"])
	}
	if body["version"] == nil {
		t.Error("version field missing")
	}
}

func TestHandleConfig_HasScope(t *testing.T) {
	rec := httptest.NewRecorder()
	handleConfig(scopedPolicy("example.com"))(rec, httptest.NewRequest(http.MethodGet, "/config", nil))
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["has_scope"] != true {
		t.Errorf("has_scope=%v, want true", body["has_scope"])
	}
}

func TestHandleListScans_Empty(t *testing.T) {
	db := newTestDB(t)
	rec := httptest.NewRecorder()
	handleListScans(db)(rec, httptest.NewRequest(http.MethodGet, "/scans", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status=%d, want 200", rec.Code)
	}
	var body []any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response not JSON array: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("want empty array, got %d elements", len(body))
	}
}

func TestHandleListScans_Filter(t *testing.T) {
	db := newTestDB(t)
	_ = db.InsertScan("x1", "alpha.com", "resolve_dns")
	_ = db.InsertScan("x2", "beta.com", "resolve_dns")
	_ = db.InsertScan("x3", "alpha.com", "probe_http")

	rec := httptest.NewRecorder()
	handleListScans(db)(rec, httptest.NewRequest(http.MethodGet, "/scans?domain=alpha.com", nil))

	var body []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if len(body) != 2 {
		t.Errorf("want 2 rows for alpha.com, got %d", len(body))
	}
}

func TestHandleDeleteScan(t *testing.T) {
	db := newTestDB(t)
	_ = db.InsertScan("del-id", "example.com", "probe_http")

	// Route through a mux so PathValue("id") is populated.
	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /scans/{id}", handleDeleteScan(db))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/scans/del-id", nil)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("status=%d, want 204", rec.Code)
	}
	rows, _ := db.ListScans("example.com", 10)
	if len(rows) != 0 {
		t.Errorf("scan not deleted, %d rows remain", len(rows))
	}
}

func TestHandleDeleteScan_EmptyID(t *testing.T) {
	db := newTestDB(t)
	// Call handler directly (no mux) → PathValue returns "" → 400.
	rec := httptest.NewRecorder()
	handleDeleteScan(db)(rec, httptest.NewRequest(http.MethodDelete, "/scans/", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", rec.Code)
	}
}

func TestHandleRunScan_BadInput(t *testing.T) {
	db := newTestDB(t)
	h := handleRunScan(db, plainPolicy())

	// GET not allowed.
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/scan", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: status=%d, want 405", rec.Code)
	}

	// Missing tool field.
	rec = postScan(t, h, `{"target":"example.com"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing tool: status=%d, want 400", rec.Code)
	}

	// Missing target field.
	rec = postScan(t, h, `{"tool":"probe_http"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing target: status=%d, want 400", rec.Code)
	}

	// Invalid JSON.
	rec = postScan(t, h, `{bad`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid JSON: status=%d, want 400", rec.Code)
	}
}

func TestHandleRunScan_PolicyBlocked(t *testing.T) {
	db := newTestDB(t)
	// probe_http on .gov → 451.
	rec := postScan(t, handleRunScan(db, plainPolicy()),
		`{"tool":"probe_http","target":"example.gov"}`)
	if rec.Code != http.StatusUnavailableForLegalReasons {
		t.Errorf("status=%d, want 451", rec.Code)
	}

	// Audit log should have one blocked entry.
	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE decision='blocked'").Scan(&count)
	if count != 1 {
		t.Errorf("audit_log blocked count=%d, want 1", count)
	}
}

func TestHandleRunScan_ScopeBlocked(t *testing.T) {
	db := newTestDB(t)
	rec := postScan(t, handleRunScan(db, scopedPolicy("allowed.com")),
		`{"tool":"passive_subdomains","target":"other.com"}`)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status=%d, want 403", rec.Code)
	}

	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE decision='blocked'").Scan(&count)
	if count != 1 {
		t.Errorf("audit_log blocked count=%d, want 1", count)
	}
}

func TestHandleRunScan_ToolError(t *testing.T) {
	db := newTestDB(t)
	withToolRunner(t, func(_ context.Context, _, _ string) ([]any, error) {
		return nil, fmt.Errorf("connection refused")
	})

	rec := postScan(t, handleRunScan(db, plainPolicy()),
		`{"tool":"resolve_dns","target":"example.com"}`)
	if rec.Code != http.StatusOK {
		t.Errorf("tool error: status=%d, want 200", rec.Code)
	}

	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["status"] != "failed" {
		t.Errorf("body status=%q, want 'failed'", body["status"])
	}
	if body["error"] == "" {
		t.Error("error field should be set")
	}

	// DB row should also be marked failed.
	rows, _ := db.ListScans("example.com", 10)
	if len(rows) == 0 || rows[0].Status != "failed" {
		t.Errorf("DB row status=%q, want failed", rows[0].Status)
	}
}

func TestHandleRunScan_Success(t *testing.T) {
	db := newTestDB(t)
	withToolRunner(t, func(_ context.Context, _, _ string) ([]any, error) {
		return []any{
			map[string]any{"status_code": float64(200), "tech": []any{"Nginx"}},
		}, nil
	})

	rec := postScan(t, handleRunScan(db, plainPolicy()),
		`{"tool":"probe_http","target":"example.com"}`)
	if rec.Code != http.StatusOK {
		t.Errorf("status=%d, want 200", rec.Code)
	}

	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["status"] != "completed" {
		t.Errorf("body status=%q, want 'completed'", body["status"])
	}

	// DB row should be completed with http_status populated.
	rows, _ := db.ListScans("example.com", 10)
	if len(rows) == 0 || rows[0].Status != "completed" {
		t.Errorf("DB row status=%q, want completed", rows[0].Status)
	}
	if rows[0].HTTPStatus == nil || *rows[0].HTTPStatus != 200 {
		t.Errorf("DB http_status=%v, want 200", rows[0].HTTPStatus)
	}
}

func TestHandleRunScan_ExpandSubdomains(t *testing.T) {
	db := newTestDB(t)
	withToolRunner(t, func(_ context.Context, tool, _ string) ([]any, error) {
		if tool != "expand_subdomains" {
			t.Errorf("unexpected tool %q", tool)
		}
		return []any{
			map[string]any{"word": "api-dev.example.com"},
			map[string]any{"word": "api-staging.example.com"},
		}, nil
	})

	rec := postScan(t, handleRunScan(db, plainPolicy()),
		`{"tool":"expand_subdomains","target":"example.com"}`)
	if rec.Code != http.StatusOK {
		t.Errorf("status=%d, want 200", rec.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["status"] != "completed" {
		t.Errorf("status=%q, want completed", body["status"])
	}
	results, _ := body["results"].([]any)
	if len(results) != 2 {
		t.Errorf("want 2 results, got %d", len(results))
	}
}

func TestHandleRunScan_Cooldown(t *testing.T) {
	db := newTestDB(t)
	withToolRunner(t, func(_ context.Context, _, _ string) ([]any, error) {
		return []any{}, nil
	})
	h := handleRunScan(db, plainPolicy())

	// First scan succeeds.
	rec1 := postScan(t, h, `{"tool":"resolve_dns","target":"example.com"}`)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first scan: status=%d, want 200", rec1.Code)
	}
	var body1 map[string]any
	_ = json.Unmarshal(rec1.Body.Bytes(), &body1)
	if body1["status"] != "completed" {
		t.Fatalf("first scan: status=%q, want completed", body1["status"])
	}

	// Second scan within cooldown window → 429.
	rec2 := postScan(t, h, `{"tool":"resolve_dns","target":"example.com"}`)
	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("second scan: status=%d, want 429", rec2.Code)
	}
	if rec2.Header().Get("Retry-After") == "" {
		t.Error("Retry-After header missing on 429 response")
	}

	// Two audit rows: first allowed, second blocked/cooldown.
	var total, blocked int
	_ = db.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&total)
	_ = db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE decision='blocked'").Scan(&blocked)
	if total != 2 {
		t.Errorf("audit_log total=%d, want 2", total)
	}
	if blocked != 1 {
		t.Errorf("audit_log blocked=%d, want 1 (cooldown)", blocked)
	}
}

// ---- handleGeoipLookup tests ----

func TestHandleGeoipLookup_Empty(t *testing.T) {
	db := newTestDB(t)
	rec := httptest.NewRecorder()
	handleGeoipLookup(db)(rec, httptest.NewRequest(http.MethodGet, "/geoip", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status=%d, want 200", rec.Code)
	}
	var body []any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if len(body) != 0 {
		t.Errorf("want empty array for missing ips param, got %d elements", len(body))
	}
}

func TestHandleGeoipLookup_CacheHit(t *testing.T) {
	db := newTestDB(t)
	_ = db.UpsertGeoip([]GeoipEntry{
		{IP: "1.2.3.4", Country: "US"},
		{IP: "5.6.7.8", Country: "DE"},
	})

	rec := httptest.NewRecorder()
	handleGeoipLookup(db)(rec, httptest.NewRequest(http.MethodGet, "/geoip?ips=1.2.3.4,5.6.7.8", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status=%d, want 200", rec.Code)
	}
	var body []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if len(body) != 2 {
		t.Errorf("want 2 cached entries, got %d", len(body))
	}
}

func TestHandleGeoipLookup_Dedupes(t *testing.T) {
	db := newTestDB(t)
	_ = db.UpsertGeoip([]GeoipEntry{{IP: "1.2.3.4", Country: "US"}})

	rec := httptest.NewRecorder()
	// Same IP three times — should dedupe to one result.
	handleGeoipLookup(db)(rec, httptest.NewRequest(http.MethodGet, "/geoip?ips=1.2.3.4,1.2.3.4,1.2.3.4", nil))
	var body []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if len(body) != 1 {
		t.Errorf("want 1 result after dedup, got %d", len(body))
	}
}

func TestHandleGeoipLookup_CacheMissNoMMDB(t *testing.T) {
	// With no mmdb file and an uncached IP, handler must return an empty array —
	// not an error — because LookupGeoip treats missing mmdb as "no results".
	db := newTestDB(t)
	rec := httptest.NewRecorder()
	handleGeoipLookup(db)(rec, httptest.NewRequest(http.MethodGet, "/geoip?ips=9.9.9.9", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status=%d, want 200 on cache miss with no mmdb", rec.Code)
	}
	// Body is either [] (no mmdb) or [{ip,country}] (mmdb present) — both fine.
	// The important invariant is no 5xx.
}

// ---- MCPCtx.gate tests ----

func TestMCPGate_PolicyBlocked(t *testing.T) {
	db := newTestDB(t)
	ctx := MCPCtx{
		Policy:    plainPolicy(),
		Audit:     db,
		SourceIP:  "127.0.0.1",
		UserAgent: "test",
	}
	reason, ok := ctx.gate("probe_http", "example.gov")
	if ok {
		t.Error("gate should block probe_http on .gov")
	}
	if reason == "" {
		t.Error("reason should be non-empty on block")
	}
	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE decision='blocked'").Scan(&count)
	if count != 1 {
		t.Errorf("audit_log blocked count=%d, want 1", count)
	}
}

func TestMCPGate_Allowed(t *testing.T) {
	db := newTestDB(t)
	ctx := MCPCtx{
		Policy:    plainPolicy(),
		Audit:     db,
		SourceIP:  "127.0.0.1",
		UserAgent: "test",
	}
	reason, ok := ctx.gate("resolve_dns", "example.com")
	if !ok {
		t.Errorf("gate should allow resolve_dns on .com, got reason: %s", reason)
	}
	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE decision='allowed'").Scan(&count)
	if count != 1 {
		t.Errorf("audit_log allowed count=%d, want 1", count)
	}
}

func TestMCPGate_Cooldown(t *testing.T) {
	db := newTestDB(t)
	ctx := MCPCtx{
		Policy:    plainPolicy(),
		Audit:     db,
		SourceIP:  "127.0.0.1",
		UserAgent: "test",
	}
	// First call allowed.
	_, ok1 := ctx.gate("resolve_dns", "example.com")
	if !ok1 {
		t.Fatal("first gate call should be allowed")
	}
	// Second call within cooldown window should be blocked.
	reason, ok2 := ctx.gate("resolve_dns", "example.com")
	if ok2 {
		t.Error("second gate call should be blocked by cooldown")
	}
	if !strings.Contains(reason, "cooldown") {
		t.Errorf("reason=%q, want contains 'cooldown'", reason)
	}
}

func TestEnvOr(t *testing.T) {
	t.Setenv("HOPPER_TEST_KEY", "from-env")
	if got := envOr("HOPPER_TEST_KEY", "default"); got != "from-env" {
		t.Errorf("envOr with env set=%q, want from-env", got)
	}

	t.Setenv("HOPPER_TEST_KEY", "")
	if got := envOr("HOPPER_TEST_KEY", "default"); got != "default" {
		t.Errorf("envOr with empty env=%q, want default", got)
	}
}

// Compile-time check that writeJSON and writeError don't panic on common inputs.
func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, map[string]string{"key": "val"})
	if rec.Code != http.StatusOK {
		t.Errorf("writeJSON status=%d, want 200", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Error("Content-Type header not set")
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"key"`)) {
		t.Error("body should contain encoded key")
	}
}

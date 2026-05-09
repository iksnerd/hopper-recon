package main

import (
	"fmt"
	"path/filepath"
	"testing"
)

func newTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("newTestDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestOpenDB_MigratesSchema(t *testing.T) {
	db := newTestDB(t)
	for _, tbl := range []string{"scans", "geoip_cache", "audit_log"} {
		var name string
		if err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", tbl).Scan(&name); err != nil {
			t.Errorf("table %q missing: %v", tbl, err)
		}
	}
}

func TestOpenDB_BootSweep(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(
		"INSERT INTO scans (id, domain, tool, status, started_at) VALUES (?,?,?,?,datetime('now', '-3 minutes'))",
		"sweep-test", "example.com", "probe_http", "pending",
	)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	db2, err := OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()

	var status string
	if err := db2.QueryRow("SELECT status FROM scans WHERE id='sweep-test'").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Errorf("boot sweep: status=%q, want failed", status)
	}
}

func TestWriteAuditAndCooldown(t *testing.T) {
	db := newTestDB(t)

	if err := db.WriteAudit(AuditEntry{
		SourceIP: "127.0.0.1", Tool: "probe_http", Target: "example.com", Decision: "allowed",
	}); err != nil {
		t.Fatal(err)
	}

	// Same tool + target within window → recent.
	if recent, err := db.RecentAllowedWithin("example.com", "probe_http", 60); err != nil || !recent {
		t.Errorf("same tool+target: RecentAllowedWithin=%v err=%v, want true nil", recent, err)
	}

	// Different tool → not recent.
	if recent, _ := db.RecentAllowedWithin("example.com", "resolve_dns", 60); recent {
		t.Error("different tool should not match cooldown")
	}

	// Different target → not recent.
	if recent, _ := db.RecentAllowedWithin("other.com", "probe_http", 60); recent {
		t.Error("different target should not match cooldown")
	}

	// Blocked decision should not count.
	db2 := newTestDB(t)
	_ = db2.WriteAudit(AuditEntry{Tool: "probe_http", Target: "blocked.com", Decision: "blocked"})
	if recent, _ := db2.RecentAllowedWithin("blocked.com", "probe_http", 60); recent {
		t.Error("blocked decision should not trigger cooldown")
	}

	// No entries at all → false, nil.
	db3 := newTestDB(t)
	if recent, err := db3.RecentAllowedWithin("nobody.com", "probe_http", 60); err != nil || recent {
		t.Errorf("empty DB: RecentAllowedWithin=%v err=%v, want false nil", recent, err)
	}
}

func TestInsertCompleteScan(t *testing.T) {
	db := newTestDB(t)
	if err := db.InsertScan("id1", "example.com", "resolve_dns"); err != nil {
		t.Fatal(err)
	}

	rows, err := db.ListScans("example.com", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Status != "pending" {
		t.Fatalf("want 1 pending row, got %d (status=%q)", len(rows), rows[0].Status)
	}

	results := []any{map[string]any{"host": "example.com"}}
	if err := db.CompleteScan("id1", results, ScanMeta{}); err != nil {
		t.Fatal(err)
	}

	rows, _ = db.ListScans("example.com", 10)
	if rows[0].Status != "completed" {
		t.Errorf("status=%q, want completed", rows[0].Status)
	}
	if rows[0].ResultsJSON == nil {
		t.Error("results_json should be populated after CompleteScan")
	}
	if rows[0].CompletedAt == nil {
		t.Error("completed_at should be set after CompleteScan")
	}
}

func TestScanMeta_HTTPStatus(t *testing.T) {
	db := newTestDB(t)
	_ = db.InsertScan("id-http", "example.com", "probe_http")
	n := 200
	_ = db.CompleteScan("id-http", []any{}, ScanMeta{HTTPStatus: &n})

	rows, _ := db.ListScans("example.com", 10)
	if rows[0].HTTPStatus == nil || *rows[0].HTTPStatus != 200 {
		t.Errorf("http_status=%v, want 200", rows[0].HTTPStatus)
	}
}

func TestScanMeta_CertExpiry(t *testing.T) {
	db := newTestDB(t)
	_ = db.InsertScan("id-tls", "example.com", "fetch_tls_cert")
	exp := "2025-12-31"
	_ = db.CompleteScan("id-tls", []any{}, ScanMeta{CertExpiry: &exp})

	rows, _ := db.ListScans("example.com", 10)
	if rows[0].CertExpiry == nil || *rows[0].CertExpiry != "2025-12-31" {
		t.Errorf("cert_expiry=%v, want 2025-12-31", rows[0].CertExpiry)
	}
}

func TestFailScan(t *testing.T) {
	db := newTestDB(t)
	_ = db.InsertScan("id-fail", "fail.com", "probe_http")
	if err := db.FailScan("id-fail", "connection refused"); err != nil {
		t.Fatal(err)
	}

	rows, _ := db.ListScans("fail.com", 10)
	if rows[0].Status != "failed" {
		t.Errorf("status=%q, want failed", rows[0].Status)
	}
	if rows[0].Error == nil || *rows[0].Error != "connection refused" {
		t.Errorf("error=%v, want 'connection refused'", rows[0].Error)
	}
	if rows[0].CompletedAt == nil {
		t.Error("completed_at should be set after FailScan")
	}
}

func TestDeleteScan(t *testing.T) {
	db := newTestDB(t)
	_ = db.InsertScan("id-del", "del.com", "probe_http")
	if err := db.DeleteScan("id-del"); err != nil {
		t.Fatal(err)
	}
	rows, _ := db.ListScans("del.com", 10)
	if len(rows) != 0 {
		t.Errorf("expected 0 rows after delete, got %d", len(rows))
	}
}

func TestPurgeOldScans(t *testing.T) {
	db := newTestDB(t)
	for i := range 7 {
		_ = db.InsertScan(fmt.Sprintf("purge-%d", i), "purge.com", "resolve_dns")
	}
	if err := db.PurgeOldScans("purge.com", 3); err != nil {
		t.Fatal(err)
	}
	rows, _ := db.ListScans("purge.com", 50)
	if len(rows) != 3 {
		t.Errorf("after purge(keepN=3): %d rows remain, want 3", len(rows))
	}
}

func TestListScans_DomainFilter(t *testing.T) {
	db := newTestDB(t)
	_ = db.InsertScan("a", "alpha.com", "resolve_dns")
	_ = db.InsertScan("b", "beta.com", "resolve_dns")
	_ = db.InsertScan("c", "alpha.com", "probe_http")

	rows, _ := db.ListScans("alpha.com", 50)
	if len(rows) != 2 {
		t.Fatalf("filter alpha.com: got %d rows, want 2", len(rows))
	}
	for _, r := range rows {
		if r.Domain != "alpha.com" {
			t.Errorf("unexpected domain %q in filtered results", r.Domain)
		}
	}
}

func TestListScans_LimitDefault(t *testing.T) {
	db := newTestDB(t)
	for i := range 60 {
		_ = db.InsertScan(fmt.Sprintf("lim-%d", i), "lim.com", "resolve_dns")
	}
	rows, _ := db.ListScans("", 0)
	if len(rows) != 50 {
		t.Errorf("default limit: got %d rows, want 50", len(rows))
	}
}

func TestGeoipCacheRoundTrip(t *testing.T) {
	db := newTestDB(t)
	entries := []GeoipEntry{
		{IP: "1.2.3.4", Country: "US"},
		{IP: "5.6.7.8", Country: "DE"},
	}

	if err := db.UpsertGeoip(entries); err != nil {
		t.Fatal(err)
	}

	cached, err := db.GetCachedGeoip([]string{"1.2.3.4", "5.6.7.8"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cached) != 2 {
		t.Fatalf("got %d cached entries, want 2", len(cached))
	}

	// Re-upsert — idempotent (INSERT OR REPLACE).
	if err := db.UpsertGeoip(entries); err != nil {
		t.Errorf("re-upsert failed: %v", err)
	}
	cached2, _ := db.GetCachedGeoip([]string{"1.2.3.4"})
	if len(cached2) != 1 {
		t.Errorf("after re-upsert: got %d rows for one IP, want 1", len(cached2))
	}

	// Empty input → no-op.
	if err := db.UpsertGeoip(nil); err != nil {
		t.Errorf("UpsertGeoip(nil) should not error: %v", err)
	}
	empty, _ := db.GetCachedGeoip(nil)
	if len(empty) != 0 {
		t.Errorf("GetCachedGeoip(nil): got %d entries, want 0", len(empty))
	}
}

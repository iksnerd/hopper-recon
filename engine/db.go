package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// ScanRow mirrors the row shape the web layer's TanStack Query expects.
type ScanRow struct {
	ID          string  `json:"id"`
	Domain      string  `json:"domain"`
	Tool        string  `json:"tool"`
	Status      string  `json:"status"`
	ResultsJSON *string `json:"results_json"`
	Error       *string `json:"error"`
	StartedAt   string  `json:"started_at"`
	CompletedAt *string `json:"completed_at"`
	HTTPStatus  *int    `json:"http_status"`
	CertExpiry  *string `json:"cert_expiry"`
	TechStack   *string `json:"tech_stack"`
}

// ScanMeta is the post-parse summary persisted alongside the raw results so
// the dashboard can filter without parsing JSON on every page load.
type ScanMeta struct {
	HTTPStatus *int    `json:"http_status,omitempty"`
	CertExpiry *string `json:"cert_expiry,omitempty"`
	TechStack  *string `json:"tech_stack,omitempty"`
}

// DB wraps the SQLite handle with the query helpers the REST server needs.
type DB struct {
	*sql.DB
}

// OpenDB opens (and migrates) the SQLite file at path. WAL mode is on; a
// single boot-time sweep retires any pending rows older than 2 minutes so
// abandoned scans don't show up as "in progress" forever.
func OpenDB(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	conn.SetMaxOpenConns(1) // SQLite write serialisation
	db := &DB{conn}
	if err := db.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if _, err := db.Exec(`UPDATE scans SET status='failed', error='scan interrupted', completed_at=CURRENT_TIMESTAMP
		WHERE status='pending' AND started_at < datetime('now', '-2 minutes')`); err != nil {
		return nil, fmt.Errorf("sweep: %w", err)
	}
	return db, nil
}

func (db *DB) migrate() error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS scans (
			id TEXT PRIMARY KEY, domain TEXT NOT NULL, tool TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending', results_json TEXT, error TEXT,
			started_at DATETIME DEFAULT CURRENT_TIMESTAMP, completed_at DATETIME,
			http_status INTEGER, cert_expiry TEXT, tech_stack TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_scans_domain      ON scans(domain);
		CREATE INDEX IF NOT EXISTS idx_scans_started     ON scans(started_at DESC);
		CREATE INDEX IF NOT EXISTS idx_scans_http_status ON scans(http_status);
		CREATE INDEX IF NOT EXISTS idx_scans_cert_expiry ON scans(cert_expiry);
		CREATE INDEX IF NOT EXISTS idx_scans_tech_stack  ON scans(tech_stack);

		CREATE TABLE IF NOT EXISTS geoip_cache (
			ip         TEXT PRIMARY KEY,
			country    TEXT NOT NULL,
			fetched_at INTEGER NOT NULL
		);
	`)
	return err
}

// InsertScan records a new pending scan row.
func (db *DB) InsertScan(id, domain, tool string) error {
	_, err := db.Exec("INSERT INTO scans (id, domain, tool) VALUES (?, ?, ?)", id, domain, tool)
	return err
}

// CompleteScan marks a scan completed and stores the parsed result + meta.
func (db *DB) CompleteScan(id string, results any, meta ScanMeta) error {
	resultsJSON, err := json.Marshal(results)
	if err != nil {
		return err
	}
	_, err = db.Exec(`UPDATE scans SET status='completed', results_json=?, completed_at=CURRENT_TIMESTAMP,
		http_status=COALESCE(?,http_status), cert_expiry=COALESCE(?,cert_expiry), tech_stack=COALESCE(?,tech_stack)
		WHERE id=?`, string(resultsJSON), meta.HTTPStatus, meta.CertExpiry, meta.TechStack, id)
	return err
}

// FailScan records a terminal failure on a previously inserted scan row.
func (db *DB) FailScan(id, errMsg string) error {
	_, err := db.Exec("UPDATE scans SET status='failed', error=?, completed_at=CURRENT_TIMESTAMP WHERE id=?",
		errMsg, id)
	return err
}

// DeleteScan removes a single scan row by id.
func (db *DB) DeleteScan(id string) error {
	_, err := db.Exec("DELETE FROM scans WHERE id=?", id)
	return err
}

// PurgeOldScans keeps only the most recent keepN scans per domain.
func (db *DB) PurgeOldScans(domain string, keepN int) error {
	if keepN <= 0 {
		keepN = 50
	}
	_, err := db.Exec(
		`DELETE FROM scans WHERE domain=? AND id NOT IN (
			SELECT id FROM scans WHERE domain=? ORDER BY started_at DESC LIMIT ?
		)`, domain, domain, keepN)
	return err
}

// ListScans returns scans ordered by started_at DESC. If domain is non-empty,
// it filters to that domain. limit defaults to 50 when zero.
func (db *DB) ListScans(domain string, limit int) ([]ScanRow, error) {
	if limit <= 0 {
		limit = 50
	}
	var (
		rows *sql.Rows
		err  error
	)
	if domain != "" {
		rows, err = db.Query("SELECT id, domain, tool, status, results_json, error, started_at, completed_at, http_status, cert_expiry, tech_stack FROM scans WHERE domain=? ORDER BY started_at DESC", domain)
	} else {
		rows, err = db.Query("SELECT id, domain, tool, status, results_json, error, started_at, completed_at, http_status, cert_expiry, tech_stack FROM scans ORDER BY started_at DESC LIMIT ?", limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScanRow
	for rows.Next() {
		var r ScanRow
		if err := rows.Scan(&r.ID, &r.Domain, &r.Tool, &r.Status, &r.ResultsJSON, &r.Error,
			&r.StartedAt, &r.CompletedAt, &r.HTTPStatus, &r.CertExpiry, &r.TechStack); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if out == nil {
		out = []ScanRow{}
	}
	return out, rows.Err()
}

// GetCachedGeoip returns rows for the IPs already in the cache. Order is not
// guaranteed; the caller dedupes by IP.
func (db *DB) GetCachedGeoip(ips []string) ([]GeoipEntry, error) {
	if len(ips) == 0 {
		return []GeoipEntry{}, nil
	}
	placeholders := strings.Repeat("?,", len(ips))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, len(ips))
	for i, ip := range ips {
		args[i] = ip
	}
	rows, err := db.Query("SELECT ip, country FROM geoip_cache WHERE ip IN ("+placeholders+")", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GeoipEntry{}
	for rows.Next() {
		var e GeoipEntry
		if err := rows.Scan(&e.IP, &e.Country); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// UpsertGeoip writes the given entries into the cache. Empty input is a no-op.
func (db *DB) UpsertGeoip(entries []GeoipEntry) error {
	if len(entries) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare("INSERT OR REPLACE INTO geoip_cache (ip, country, fetched_at) VALUES (?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()
	now := time.Now().UnixMilli()
	for _, e := range entries {
		if _, err := stmt.Exec(e.IP, e.Country, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

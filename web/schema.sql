CREATE TABLE IF NOT EXISTS scans (
    id           TEXT PRIMARY KEY,
    domain       TEXT NOT NULL,
    tool         TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    results_json TEXT,
    error        TEXT,
    started_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    http_status  INTEGER,
    cert_expiry  TEXT,
    tech_stack   TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_domain      ON scans(domain);
CREATE INDEX IF NOT EXISTS idx_scans_started     ON scans(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_http_status ON scans(http_status);
CREATE INDEX IF NOT EXISTS idx_scans_cert_expiry ON scans(cert_expiry);
CREATE INDEX IF NOT EXISTS idx_scans_tech_stack  ON scans(tech_stack);

import type { D1Database } from "@cloudflare/workers-types"

export interface ScanRow {
  id: string
  domain: string
  tool: string
  status: "pending" | "completed" | "failed"
  results_json: string | null
  error: string | null
  started_at: string
  completed_at: string | null
  http_status: number | null
  cert_expiry: string | null
  tech_stack: string | null
}

export interface ScanMeta {
  http_status?: number
  cert_expiry?: string
  tech_stack?: string
}

export interface DbAdapter {
  insertScan(id: string, domain: string, tool: string): Promise<void>
  completeScan(id: string, results: unknown, meta?: ScanMeta): Promise<void>
  failScan(id: string, error: string): Promise<void>
  deleteScan(id: string): Promise<void>
  purgeOldScans(domain: string, keepN?: number): Promise<void>
  sweepStaleScans(olderThanMinutes?: number): Promise<void>
  getRecentScans(limit?: number): Promise<ScanRow[]>
  getScansByDomain(domain: string): Promise<ScanRow[]>
}

// ── SQLite (local dev) ────────────────────────────────────────────────────────

function createSqliteAdapter(): DbAdapter {
  // Dynamic require defers the native module load so this file can be
  // imported on Cloudflare Workers without crashing at bundle time.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const Database = require("better-sqlite3") as typeof import("better-sqlite3") // nocheck
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const path = require("path") as typeof import("path") // nocheck

  const db = new Database(path.join(process.cwd(), "data", "recon.db"))
  db.pragma("journal_mode = WAL")
  db.exec(`
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY, domain TEXT NOT NULL, tool TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending', results_json TEXT, error TEXT,
      started_at DATETIME DEFAULT CURRENT_TIMESTAMP, completed_at DATETIME,
      http_status INTEGER, cert_expiry TEXT, tech_stack TEXT
    );
  `)
  // Migrate existing databases that predate the meta columns. Must run
  // BEFORE the indexes below — otherwise CREATE INDEX on a missing column
  // aborts the whole batch.
  for (const col of ["http_status INTEGER", "cert_expiry TEXT", "tech_stack TEXT"]) {
    try { db.exec(`ALTER TABLE scans ADD COLUMN ${col}`) } catch { /* already exists */ }
  }
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_scans_domain      ON scans(domain);
    CREATE INDEX IF NOT EXISTS idx_scans_started     ON scans(started_at DESC);
    CREATE INDEX IF NOT EXISTS idx_scans_http_status ON scans(http_status);
    CREATE INDEX IF NOT EXISTS idx_scans_cert_expiry ON scans(cert_expiry);
    CREATE INDEX IF NOT EXISTS idx_scans_tech_stack  ON scans(tech_stack);
  `)

  // On startup, mark any pending rows older than 2 min as failed — they were
  // abandoned by a page refresh or server restart mid-scan.
  db.exec(`UPDATE scans SET status='failed', error='scan interrupted', completed_at=CURRENT_TIMESTAMP
    WHERE status='pending' AND started_at < datetime('now', '-2 minutes')`)

  return {
    insertScan: (id, domain, tool) => {
      db.prepare("INSERT INTO scans (id, domain, tool) VALUES (?, ?, ?)").run(id, domain, tool)
      return Promise.resolve()
    },
    completeScan: (id, results, meta = {}) => {
      db.prepare(`UPDATE scans SET status='completed', results_json=?, completed_at=CURRENT_TIMESTAMP,
        http_status=COALESCE(?,http_status), cert_expiry=COALESCE(?,cert_expiry), tech_stack=COALESCE(?,tech_stack)
        WHERE id=?`)
        .run(JSON.stringify(results), meta.http_status ?? null, meta.cert_expiry ?? null, meta.tech_stack ?? null, id)
      return Promise.resolve()
    },
    failScan: (id, error) => {
      db.prepare("UPDATE scans SET status='failed', error=?, completed_at=CURRENT_TIMESTAMP WHERE id=?")
        .run(error, id)
      return Promise.resolve()
    },
    deleteScan: (id) => {
      db.prepare("DELETE FROM scans WHERE id=?").run(id)
      return Promise.resolve()
    },
    purgeOldScans: (domain, keepN = 50) => {
      db.prepare(
        "DELETE FROM scans WHERE domain=? AND id NOT IN (SELECT id FROM scans WHERE domain=? ORDER BY started_at DESC LIMIT ?)"
      ).run(domain, domain, keepN)
      return Promise.resolve()
    },
    sweepStaleScans: (olderThanMinutes = 2) => {
      db.prepare(
        `UPDATE scans SET status='failed', error='scan interrupted', completed_at=CURRENT_TIMESTAMP
         WHERE status='pending' AND started_at < datetime('now', '-${olderThanMinutes} minutes')`
      ).run()
      return Promise.resolve()
    },
    getRecentScans: (limit = 50) =>
      Promise.resolve(db.prepare("SELECT * FROM scans ORDER BY started_at DESC LIMIT ?").all(limit) as ScanRow[]),
    getScansByDomain: (domain) =>
      Promise.resolve(db.prepare("SELECT * FROM scans WHERE domain=? ORDER BY started_at DESC").all(domain) as ScanRow[]),
  }
}

// ── D1 (Cloudflare) ───────────────────────────────────────────────────────────

function createD1Adapter(d1: D1Database): DbAdapter {
  return {
    insertScan: (id, domain, tool) =>
      d1.prepare("INSERT INTO scans (id, domain, tool) VALUES (?, ?, ?)")
        .bind(id, domain, tool).run().then(() => undefined),

    completeScan: (id, results, meta = {}) =>
      d1.prepare(`UPDATE scans SET status='completed', results_json=?, completed_at=CURRENT_TIMESTAMP,
        http_status=COALESCE(?,http_status), cert_expiry=COALESCE(?,cert_expiry), tech_stack=COALESCE(?,tech_stack)
        WHERE id=?`)
        .bind(JSON.stringify(results), meta.http_status ?? null, meta.cert_expiry ?? null, meta.tech_stack ?? null, id)
        .run().then(() => undefined),

    failScan: (id, error) =>
      d1.prepare("UPDATE scans SET status='failed', error=?, completed_at=CURRENT_TIMESTAMP WHERE id=?")
        .bind(error, id).run().then(() => undefined),

    deleteScan: (id) =>
      d1.prepare("DELETE FROM scans WHERE id=?").bind(id).run().then(() => undefined),

    purgeOldScans: (domain, keepN = 50) =>
      d1.prepare(
        "DELETE FROM scans WHERE domain=? AND id NOT IN (SELECT id FROM scans WHERE domain=? ORDER BY started_at DESC LIMIT ?)"
      ).bind(domain, domain, keepN).run().then(() => undefined),

    sweepStaleScans: (olderThanMinutes = 2) =>
      d1.prepare(
        "UPDATE scans SET status='failed', error='scan interrupted', completed_at=CURRENT_TIMESTAMP WHERE status='pending' AND started_at < datetime('now', ?)"
      ).bind(`-${olderThanMinutes} minutes`).run().then(() => undefined),

    getRecentScans: async (limit = 50) => {
      const { results } = await d1.prepare("SELECT * FROM scans ORDER BY started_at DESC LIMIT ?")
        .bind(limit).all<ScanRow>()
      return results
    },

    getScansByDomain: async (domain) => {
      const { results } = await d1.prepare("SELECT * FROM scans WHERE domain=? ORDER BY started_at DESC")
        .bind(domain).all<ScanRow>()
      return results
    },
  }
}

// ── Factory — auto-detects environment ───────────────────────────────────────

let _sqliteAdapter: DbAdapter | null = null

export async function getDb(): Promise<DbAdapter> {
  try {
    const { getCloudflareContext } = await import("@opennextjs/cloudflare")
    const { env } = await getCloudflareContext()
    if (env.DB) return createD1Adapter(env.DB as unknown as D1Database)
  } catch {
    // Not on Cloudflare — fall through to SQLite
  }

  _sqliteAdapter ??= createSqliteAdapter()
  return _sqliteAdapter
}

//! SQLite-backed traffic log persistence.
//!
//! The hot ring buffer in AppState stays for live SSE streaming.
//! TrafficStore writes every entry to SQLite for querying, filtering,
//! time-range queries, and CSV export.

use std::path::PathBuf;
use std::sync::Mutex;
use rusqlite::{Connection, params};
use crate::RequestLog;
use crate::config::TrafficConfig;

/// Persistent traffic store backed by SQLite.
/// All DB operations use std::sync::Mutex + spawn_blocking to avoid
/// blocking the Tokio async runtime.
pub struct TrafficStore {
    conn: Mutex<Connection>,
}

impl TrafficStore {
    /// Open (or create) the traffic database at ~/.warden/traffic.db
    pub fn open(path: &PathBuf) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;

        // Performance pragmas for Pi
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA cache_size = -2000;
             PRAGMA busy_timeout = 5000;"
        )?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS traffic_log (
                id TEXT PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                method TEXT NOT NULL,
                service TEXT NOT NULL,
                path TEXT NOT NULL,
                origin TEXT NOT NULL,
                status INTEGER NOT NULL,
                duration_ms INTEGER NOT NULL,
                request_size INTEGER NOT NULL,
                response_size INTEGER NOT NULL,
                headers_stripped TEXT NOT NULL DEFAULT '[]',
                key_injected TEXT,
                tokens_substituted INTEGER NOT NULL DEFAULT 0,
                cookies_merged INTEGER NOT NULL DEFAULT 0,
                inspection_level TEXT NOT NULL DEFAULT 'metadata',
                request_headers TEXT,
                response_headers TEXT,
                request_body_preview TEXT,
                response_body_preview TEXT,
                alert_level TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_traffic_service ON traffic_log(service);
            CREATE INDEX IF NOT EXISTS idx_traffic_status ON traffic_log(status);
            CREATE INDEX IF NOT EXISTS idx_traffic_alert ON traffic_log(alert_level);"
        )?;

        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Insert a traffic entry into SQLite.
    pub fn insert(&self, entry: &RequestLog) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let headers_stripped = serde_json::to_string(&entry.headers_stripped).unwrap_or_else(|_| "[]".to_string());
        let request_headers = entry.request_headers.as_ref().map(|v| v.to_string());
        let response_headers = entry.response_headers.as_ref().map(|v| v.to_string());

        conn.execute(
            "INSERT OR IGNORE INTO traffic_log (
                id, timestamp, method, service, path, origin, status,
                duration_ms, request_size, response_size,
                headers_stripped, key_injected, tokens_substituted,
                cookies_merged, inspection_level,
                request_headers, response_headers,
                request_body_preview, response_body_preview, alert_level
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
            params![
                entry.id,
                entry.timestamp,
                entry.method,
                entry.service,
                entry.path,
                entry.origin,
                entry.status,
                entry.duration_ms,
                entry.request_size,
                entry.response_size,
                headers_stripped,
                entry.key_injected,
                entry.tokens_substituted,
                entry.cookies_merged,
                entry.inspection_level,
                request_headers,
                response_headers,
                entry.request_body_preview,
                entry.response_body_preview,
                entry.alert_level,
            ],
        )?;
        Ok(())
    }

    /// Load the last N entries from SQLite (for ring buffer warm-up on startup).
    pub fn load_recent(&self, limit: usize) -> Result<Vec<RequestLog>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, method, service, path, origin, status,
                    duration_ms, request_size, response_size,
                    headers_stripped, key_injected, tokens_substituted,
                    cookies_merged, inspection_level,
                    request_headers, response_headers,
                    request_body_preview, response_body_preview, alert_level
             FROM traffic_log ORDER BY timestamp DESC LIMIT ?1"
        )?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(row_to_entry(row))
        })?;

        let mut entries: Vec<RequestLog> = rows.filter_map(|r| r.ok()).collect();
        entries.reverse(); // oldest first for ring buffer push order
        Ok(entries)
    }

    /// Query traffic with filters. Returns newest-first.
    pub fn query(
        &self,
        since: Option<u64>,
        until: Option<u64>,
        service: Option<&str>,
        method: Option<&str>,
        status: Option<u16>,
        path_contains: Option<&str>,
        limit: usize,
    ) -> Result<Vec<RequestLog>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();

        let mut sql = String::from(
            "SELECT id, timestamp, method, service, path, origin, status,
                    duration_ms, request_size, response_size,
                    headers_stripped, key_injected, tokens_substituted,
                    cookies_merged, inspection_level,
                    request_headers, response_headers,
                    request_body_preview, response_body_preview, alert_level
             FROM traffic_log WHERE 1=1"
        );
        let mut bind_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(s) = since {
            bind_values.push(Box::new(s));
            sql.push_str(&format!(" AND timestamp > ?{}", bind_values.len()));
        }
        if let Some(u) = until {
            bind_values.push(Box::new(u));
            sql.push_str(&format!(" AND timestamp <= ?{}", bind_values.len()));
        }
        if let Some(svc) = service {
            bind_values.push(Box::new(svc.to_string()));
            sql.push_str(&format!(" AND service = ?{}", bind_values.len()));
        }
        if let Some(m) = method {
            bind_values.push(Box::new(m.to_string()));
            sql.push_str(&format!(" AND method = ?{}", bind_values.len()));
        }
        if let Some(s) = status {
            bind_values.push(Box::new(s));
            sql.push_str(&format!(" AND status = ?{}", bind_values.len()));
        }
        if let Some(p) = path_contains {
            bind_values.push(Box::new(format!("%{}%", p)));
            sql.push_str(&format!(" AND path LIKE ?{}", bind_values.len()));
        }

        bind_values.push(Box::new(limit as i64));
        sql.push_str(&format!(" ORDER BY timestamp DESC LIMIT ?{}", bind_values.len()));

        let mut stmt = conn.prepare(&sql)?;
        let params_ref: Vec<&dyn rusqlite::types::ToSql> = bind_values.iter().map(|b| b.as_ref()).collect();
        let rows = stmt.query_map(params_ref.as_slice(), |row| {
            Ok(row_to_entry(row))
        })?;

        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// Get aggregated stats for a time range.
    pub fn stats(&self, since: Option<u64>) -> Result<serde_json::Value, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let since_val = since.unwrap_or(0);

        // Total requests and error rate
        let (total, errors, avg_ms, p50, p95, p99): (i64, i64, f64, i64, i64, i64) = {
            let mut stmt = conn.prepare(
                "SELECT COUNT(*),
                        SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END),
                        COALESCE(AVG(duration_ms), 0)
                 FROM traffic_log WHERE timestamp > ?1"
            )?;
            let (total, errors, avg): (i64, i64, f64) = stmt.query_row(params![since_val], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?;

            // Percentiles via sorted durations
            let mut pstmt = conn.prepare(
                "SELECT duration_ms FROM traffic_log WHERE timestamp > ?1 ORDER BY duration_ms"
            )?;
            let durations: Vec<i64> = pstmt.query_map(params![since_val], |row| {
                row.get(0)
            })?.filter_map(|r| r.ok()).collect();

            let percentile = |p: f64| -> i64 {
                if durations.is_empty() { return 0; }
                let idx = ((p / 100.0) * durations.len() as f64).ceil() as usize;
                durations[idx.min(durations.len()) - 1]
            };

            (total, errors, avg, percentile(50.0), percentile(95.0), percentile(99.0))
        };

        // Top services
        let top_services: Vec<serde_json::Value> = {
            let mut stmt = conn.prepare(
                "SELECT service, COUNT(*) as cnt FROM traffic_log
                 WHERE timestamp > ?1 GROUP BY service ORDER BY cnt DESC LIMIT 10"
            )?;
            stmt.query_map(params![since_val], |row| {
                let svc: String = row.get(0)?;
                let cnt: i64 = row.get(1)?;
                Ok(serde_json::json!({"service": svc, "count": cnt}))
            })?.filter_map(|r| r.ok()).collect()
        };

        // Top paths
        let top_paths: Vec<serde_json::Value> = {
            let mut stmt = conn.prepare(
                "SELECT path, COUNT(*) as cnt FROM traffic_log
                 WHERE timestamp > ?1 GROUP BY path ORDER BY cnt DESC LIMIT 10"
            )?;
            stmt.query_map(params![since_val], |row| {
                let path: String = row.get(0)?;
                let cnt: i64 = row.get(1)?;
                Ok(serde_json::json!({"path": path, "count": cnt}))
            })?.filter_map(|r| r.ok()).collect()
        };

        let error_rate = if total > 0 { (errors as f64 / total as f64) * 100.0 } else { 0.0 };

        Ok(serde_json::json!({
            "total_requests": total,
            "error_count": errors,
            "error_rate_pct": format!("{:.1}", error_rate),
            "avg_latency_ms": format!("{:.0}", avg_ms),
            "p50_ms": p50,
            "p95_ms": p95,
            "p99_ms": p99,
            "top_services": top_services,
            "top_paths": top_paths,
        }))
    }

    /// Export traffic entries as CSV string.
    pub fn export_csv(
        &self,
        since: Option<u64>,
        until: Option<u64>,
        service: Option<&str>,
    ) -> Result<String, rusqlite::Error> {
        let entries = self.query(since, until, service, None, None, None, 100_000)?;
        let mut csv = String::from("id,timestamp,method,service,path,origin,status,duration_ms,request_size,response_size,headers_stripped,key_injected,tokens_substituted,cookies_merged,alert_level\n");

        for e in &entries {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                csv_escape(&e.id),
                e.timestamp,
                csv_escape(&e.method),
                csv_escape(&e.service),
                csv_escape(&e.path),
                csv_escape(&e.origin),
                e.status,
                e.duration_ms,
                e.request_size,
                e.response_size,
                csv_escape(&serde_json::to_string(&e.headers_stripped).unwrap_or_default()),
                csv_escape(e.key_injected.as_deref().unwrap_or("")),
                e.tokens_substituted,
                e.cookies_merged,
                csv_escape(e.alert_level.as_deref().unwrap_or("")),
            ));
        }
        Ok(csv)
    }

    /// Prune entries older than retention period and enforce max DB size.
    pub fn prune(&self, config: &TrafficConfig) -> Result<u64, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();

        // Prune by age
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
            - (config.retention_days * 86_400_000);

        let deleted: usize = conn.execute(
            "DELETE FROM traffic_log WHERE timestamp < ?1",
            params![cutoff],
        )?;

        // Check DB size and prune oldest if over limit
        let page_count: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        let page_size: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        let db_size_mb = (page_count * page_size) as f64 / (1024.0 * 1024.0);

        if db_size_mb > config.max_db_size_mb as f64 {
            // Delete oldest 10% of entries
            conn.execute(
                "DELETE FROM traffic_log WHERE id IN (
                    SELECT id FROM traffic_log ORDER BY timestamp ASC
                    LIMIT (SELECT COUNT(*) / 10 FROM traffic_log)
                )",
                [],
            )?;
            conn.execute_batch("PRAGMA incremental_vacuum;")?;
        }

        Ok(deleted as u64)
    }

    /// Update the response body preview for an existing entry.
    pub fn update_response_preview(&self, id: &str, preview: &str) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE traffic_log SET response_body_preview = ?1 WHERE id = ?2",
            params![preview, id],
        )?;
        Ok(())
    }

    /// Clear all traffic data.
    pub fn clear(&self) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM traffic_log", [])?;
        conn.execute_batch("VACUUM;")?;
        Ok(())
    }
}

fn row_to_entry(row: &rusqlite::Row) -> RequestLog {
    let headers_stripped_str: String = row.get(10).unwrap_or_else(|_| "[]".to_string());
    let headers_stripped: Vec<String> = serde_json::from_str(&headers_stripped_str).unwrap_or_default();
    let req_hdrs_str: Option<String> = row.get(15).unwrap_or(None);
    let resp_hdrs_str: Option<String> = row.get(16).unwrap_or(None);

    RequestLog {
        id: row.get(0).unwrap_or_default(),
        timestamp: row.get(1).unwrap_or(0),
        method: row.get(2).unwrap_or_default(),
        service: row.get(3).unwrap_or_default(),
        path: row.get(4).unwrap_or_default(),
        origin: row.get(5).unwrap_or_default(),
        status: row.get::<_, i32>(6).unwrap_or(0) as u16,
        duration_ms: row.get(7).unwrap_or(0),
        request_size: row.get(8).unwrap_or(0),
        response_size: row.get(9).unwrap_or(0),
        headers_stripped,
        key_injected: row.get(11).unwrap_or(None),
        tokens_substituted: row.get::<_, i32>(12).unwrap_or(0) as u32,
        cookies_merged: row.get::<_, i32>(13).unwrap_or(0) as u32,
        inspection_level: row.get(14).unwrap_or_else(|_| "metadata".to_string()),
        request_headers: req_hdrs_str.and_then(|s| serde_json::from_str(&s).ok()),
        response_headers: resp_hdrs_str.and_then(|s| serde_json::from_str(&s).ok()),
        request_body_preview: row.get(17).unwrap_or(None),
        response_body_preview: row.get(18).unwrap_or(None),
        alert_level: row.get(19).unwrap_or(None),
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> TrafficStore {
        // Use in-memory SQLite for tests
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS traffic_log (
                id TEXT PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                method TEXT NOT NULL,
                service TEXT NOT NULL,
                path TEXT NOT NULL,
                origin TEXT NOT NULL,
                status INTEGER NOT NULL,
                duration_ms INTEGER NOT NULL,
                request_size INTEGER NOT NULL,
                response_size INTEGER NOT NULL,
                headers_stripped TEXT NOT NULL DEFAULT '[]',
                key_injected TEXT,
                tokens_substituted INTEGER NOT NULL DEFAULT 0,
                cookies_merged INTEGER NOT NULL DEFAULT 0,
                inspection_level TEXT NOT NULL DEFAULT 'metadata',
                request_headers TEXT,
                response_headers TEXT,
                request_body_preview TEXT,
                response_body_preview TEXT,
                alert_level TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_traffic_service ON traffic_log(service);
            CREATE INDEX IF NOT EXISTS idx_traffic_status ON traffic_log(status);
            CREATE INDEX IF NOT EXISTS idx_traffic_alert ON traffic_log(alert_level);"
        ).unwrap();
        TrafficStore { conn: Mutex::new(conn) }
    }

    fn make_entry(id: u64, ts: u64, service: &str, status: u16) -> RequestLog {
        RequestLog::new(
            format!("wdn-{:08x}", id),
            ts,
            "GET".to_string(),
            service.to_string(),
            "/v1/test".to_string(),
            "http://localhost:3000".to_string(),
            status,
            50,
            100,
            200,
        )
    }

    #[test]
    fn insert_and_load_recent() {
        let store = temp_store();
        for i in 0..5 {
            store.insert(&make_entry(i, 1000 + i, "openai", 200)).unwrap();
        }
        let entries = store.load_recent(3).unwrap();
        assert_eq!(entries.len(), 3);
        // Oldest first (reversed from DESC query)
        assert!(entries[0].timestamp < entries[2].timestamp);
    }

    #[test]
    fn query_with_service_filter() {
        let store = temp_store();
        store.insert(&make_entry(1, 1000, "openai", 200)).unwrap();
        store.insert(&make_entry(2, 1001, "anthropic", 200)).unwrap();
        store.insert(&make_entry(3, 1002, "openai", 200)).unwrap();

        let results = store.query(None, None, Some("openai"), None, None, None, 100).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|e| e.service == "openai"));
    }

    #[test]
    fn query_with_time_range() {
        let store = temp_store();
        for i in 0..10 {
            store.insert(&make_entry(i, 1000 + i * 100, "openai", 200)).unwrap();
        }

        let results = store.query(Some(1500), Some(1800), None, None, None, None, 100).unwrap();
        assert!(results.iter().all(|e| e.timestamp > 1500 && e.timestamp <= 1800));
    }

    #[test]
    fn query_with_status_filter() {
        let store = temp_store();
        store.insert(&make_entry(1, 1000, "openai", 200)).unwrap();
        store.insert(&make_entry(2, 1001, "openai", 500)).unwrap();
        store.insert(&make_entry(3, 1002, "openai", 200)).unwrap();

        let results = store.query(None, None, None, None, Some(500), None, 100).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, 500);
    }

    #[test]
    fn stats_computes_correctly() {
        let store = temp_store();
        for i in 0..10 {
            let status = if i < 8 { 200 } else { 500 };
            store.insert(&make_entry(i, 1000 + i, "openai", status)).unwrap();
        }

        let stats = store.stats(None).unwrap();
        assert_eq!(stats["total_requests"], 10);
        assert_eq!(stats["error_count"], 2);
    }

    #[test]
    fn export_csv_produces_valid_output() {
        let store = temp_store();
        store.insert(&make_entry(1, 1000, "openai", 200)).unwrap();
        store.insert(&make_entry(2, 1001, "anthropic", 404)).unwrap();

        let csv = store.export_csv(None, None, None).unwrap();
        let lines: Vec<&str> = csv.trim().lines().collect();
        assert_eq!(lines.len(), 3); // header + 2 rows
        assert!(lines[0].starts_with("id,timestamp,method"));
    }

    #[test]
    fn clear_removes_all_entries() {
        let store = temp_store();
        for i in 0..5 {
            store.insert(&make_entry(i, 1000 + i, "openai", 200)).unwrap();
        }
        store.clear().unwrap();
        let entries = store.load_recent(100).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn prune_removes_old_entries() {
        let store = temp_store();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Old entry (8 days ago)
        store.insert(&make_entry(1, now - 8 * 86_400_000, "openai", 200)).unwrap();
        // Recent entry
        store.insert(&make_entry(2, now - 1000, "openai", 200)).unwrap();

        let config = TrafficConfig::default(); // 7 day retention
        store.prune(&config).unwrap();

        let entries = store.load_recent(100).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, format!("wdn-{:08x}", 2u64));
    }

    #[test]
    fn enhanced_fields_persist() {
        let store = temp_store();
        let mut entry = make_entry(1, 1000, "openai", 200);
        entry.headers_stripped = vec!["authorization".to_string(), "x-api-key".to_string()];
        entry.key_injected = Some("openai".to_string());
        entry.tokens_substituted = 3;
        entry.cookies_merged = 2;
        entry.alert_level = Some("warning".to_string());

        store.insert(&entry).unwrap();
        let loaded = store.load_recent(1).unwrap();
        assert_eq!(loaded[0].headers_stripped, vec!["authorization", "x-api-key"]);
        assert_eq!(loaded[0].key_injected.as_deref(), Some("openai"));
        assert_eq!(loaded[0].tokens_substituted, 3);
        assert_eq!(loaded[0].cookies_merged, 2);
        assert_eq!(loaded[0].alert_level.as_deref(), Some("warning"));
    }

    #[test]
    fn duplicate_insert_ignored() {
        let store = temp_store();
        store.insert(&make_entry(1, 1000, "openai", 200)).unwrap();
        // Same ID again — should not fail (OR IGNORE)
        store.insert(&make_entry(1, 1000, "openai", 200)).unwrap();

        let entries = store.load_recent(100).unwrap();
        assert_eq!(entries.len(), 1);
    }
}

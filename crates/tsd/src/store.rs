//! DuckDB sink for TokenScope events.
//!
//! Single-threaded by design (tsd's main loop is sync). Wrap in `RefCell`
//! at the call site for interior mutability — the same pattern as
//! `proc_cache`.
//!
//! Schema is embedded (one migration for now); will move to a
//! `migrations/` directory when the second migration lands.

use std::path::Path;

use anyhow::{Context, Result};
use duckdb::Connection;

const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS events_proc_exec (
    ts_ns       BIGINT  NOT NULL,
    pid         INTEGER NOT NULL,
    tgid        INTEGER NOT NULL,
    cgroup_id   BIGINT  NOT NULL,
    comm        VARCHAR NOT NULL,
    cmdline     VARCHAR
);

CREATE TABLE IF NOT EXISTS events_net_connect (
    ts_ns       BIGINT  NOT NULL,
    pid         INTEGER NOT NULL,
    tgid        INTEGER NOT NULL,
    cgroup_id   BIGINT  NOT NULL,
    comm        VARCHAR NOT NULL,
    cmdline     VARCHAR,
    dst_addr    BLOB    NOT NULL,
    dst_port    INTEGER NOT NULL,
    family      SMALLINT NOT NULL,
    protocol    SMALLINT NOT NULL
);

CREATE TABLE IF NOT EXISTS events_net_bytes (
    snapshot_ts_ns  BIGINT NOT NULL,
    sock_cookie     BIGINT NOT NULL,
    pid             INTEGER NOT NULL,
    comm            VARCHAR NOT NULL,
    cmdline         VARCHAR,
    tx_bytes        BIGINT NOT NULL,
    rx_bytes        BIGINT NOT NULL,
    last_event_ns   BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS schema_version (
    version    INTEGER NOT NULL,
    applied_at TIMESTAMP NOT NULL DEFAULT current_timestamp
);
"#;

pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (or create) the DuckDB file at `path`, ensuring the parent
    /// directory exists, and run any pending migrations.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create db parent dir {}", parent.display()))?;
        }
        let conn =
            Connection::open(path).with_context(|| format!("open duckdb {}", path.display()))?;
        let mut store = Self { conn };
        store.apply_migrations()?;
        Ok(store)
    }

    fn apply_migrations(&mut self) -> Result<()> {
        // Idempotent CREATE IF NOT EXISTS makes this safe to re-run.
        self.conn
            .execute_batch(SCHEMA_V1)
            .context("apply v1 schema")?;
        let current: i64 = self
            .conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |r| r.get(0),
            )
            .context("read schema_version")?;
        if current < 1 {
            self.conn
                .execute("INSERT INTO schema_version (version) VALUES (1)", [])
                .context("record schema v1")?;
        }
        Ok(())
    }

    /// Test-only smoke check: run a SELECT and return the count.
    #[cfg(test)]
    pub(crate) fn count_table(&self, table: &str) -> Result<i64> {
        let sql = format!("SELECT COUNT(*) FROM {table}");
        self.conn
            .query_row(&sql, [], |r| r.get(0))
            .map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn open_creates_tables_and_records_version() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("events.duckdb");
        let store = Store::open(&path).expect("open store");
        assert_eq!(store.count_table("events_proc_exec").unwrap(), 0);
        assert_eq!(store.count_table("events_net_connect").unwrap(), 0);
        assert_eq!(store.count_table("events_net_bytes").unwrap(), 0);
        let v: i64 = store
            .conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 1);
    }

    #[test]
    fn open_is_idempotent() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("events.duckdb");
        let _store1 = Store::open(&path).expect("first open");
        drop(_store1);
        let _store2 = Store::open(&path).expect("second open");
        // No panic, no extra schema_version rows beyond what's expected.
        let count: i64 = _store2
            .conn
            .query_row("SELECT COUNT(*) FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
}

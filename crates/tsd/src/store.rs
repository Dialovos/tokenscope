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

    /// Insert one ProcExec row. cmdline may be empty/sentinel; we still
    /// store it as-is — it's the cheapest format for queries to filter on.
    pub fn insert_proc_exec(
        &self,
        ts_ns: u64,
        pid: u32,
        tgid: u32,
        cgroup_id: u64,
        comm: &str,
        cmdline: &str,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO events_proc_exec (ts_ns, pid, tgid, cgroup_id, comm, cmdline)
                 VALUES (?, ?, ?, ?, ?, ?)",
                duckdb::params![
                    ts_ns as i64,
                    pid as i32,
                    tgid as i32,
                    cgroup_id as i64,
                    comm,
                    cmdline
                ],
            )
            .context("insert proc_exec")?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)] // mirrors the BPF event payload one-to-one
    pub fn insert_net_connect(
        &self,
        ts_ns: u64,
        pid: u32,
        tgid: u32,
        cgroup_id: u64,
        comm: &str,
        cmdline: &str,
        dst_addr: &[u8; 16],
        dst_port: u16,
        family: u16,
        protocol: u8,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO events_net_connect
                 (ts_ns, pid, tgid, cgroup_id, comm, cmdline, dst_addr, dst_port, family, protocol)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                duckdb::params![
                    ts_ns as i64,
                    pid as i32,
                    tgid as i32,
                    cgroup_id as i64,
                    comm,
                    cmdline,
                    dst_addr.as_slice(),
                    dst_port as i32,
                    family as i16,
                    protocol as i16,
                ],
            )
            .context("insert net_connect")?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)] // mirrors the BPF map key+value one-to-one
    pub fn insert_net_bytes(
        &self,
        snapshot_ts_ns: u64,
        sock_cookie: u64,
        pid: u32,
        comm: &str,
        cmdline: &str,
        tx_bytes: u64,
        rx_bytes: u64,
        last_event_ns: u64,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO events_net_bytes
                 (snapshot_ts_ns, sock_cookie, pid, comm, cmdline, tx_bytes, rx_bytes, last_event_ns)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                duckdb::params![
                    snapshot_ts_ns as i64,
                    sock_cookie as i64,
                    pid as i32,
                    comm,
                    cmdline,
                    tx_bytes as i64,
                    rx_bytes as i64,
                    last_event_ns as i64,
                ],
            )
            .context("insert net_bytes")?;
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

    #[test]
    fn insert_proc_exec_round_trip() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(&dir.path().join("events.duckdb")).unwrap();
        store
            .insert_proc_exec(123_456_789, 4242, 4242, 0x15, "sleep", "/bin/sleep 30")
            .unwrap();
        let (comm, cmdline): (String, String) = store
            .conn
            .query_row(
                "SELECT comm, cmdline FROM events_proc_exec WHERE pid = 4242",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(comm, "sleep");
        assert_eq!(cmdline, "/bin/sleep 30");
    }

    #[test]
    fn insert_net_connect_round_trip() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(&dir.path().join("events.duckdb")).unwrap();
        let addr: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4];
        store
            .insert_net_connect(999, 100, 100, 0x15, "curl", "[<gone>]", &addr, 443, 2, 6)
            .unwrap();
        let (port, family, proto): (i32, i16, i16) = store
            .conn
            .query_row(
                "SELECT dst_port, family, protocol FROM events_net_connect WHERE pid = 100",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(port, 443);
        assert_eq!(family, 2);
        assert_eq!(proto, 6);
    }

    #[test]
    fn insert_net_bytes_round_trip() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(&dir.path().join("events.duckdb")).unwrap();
        store
            .insert_net_bytes(1, 0xCAFE, 200, "wget", "[<gone>]", 1024, 2048, 99)
            .unwrap();
        let (tx, rx): (i64, i64) = store
            .conn
            .query_row(
                "SELECT tx_bytes, rx_bytes FROM events_net_bytes WHERE pid = 200",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(tx, 1024);
        assert_eq!(rx, 2048);
    }
}

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
use duckdb::{Appender, Connection};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

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

const SCHEMA_V3: &str = r#"
CREATE TABLE IF NOT EXISTS events_usage (
    capture_epoch VARCHAR NOT NULL,
    ts_ns UBIGINT NOT NULL,
    tgid UINTEGER NOT NULL,
    process_start UBIGINT NOT NULL,
    exec_generation UBIGINT NOT NULL,
    ssl_ctx UBIGINT NOT NULL,
    connection_generation UBIGINT NOT NULL,
    request_ordinal UBIGINT,
    usage_state VARCHAR NOT NULL,
    capture_integrity VARCHAR NOT NULL,
    termination VARCHAR NOT NULL,
    reason VARCHAR,
    reports_json VARCHAR NOT NULL
);
CREATE TABLE IF NOT EXISTS events_tls_metadata (
    capture_epoch VARCHAR NOT NULL,
    ts_ns UBIGINT NOT NULL, tgid UINTEGER NOT NULL,
    process_start UBIGINT NOT NULL,
    exec_generation UBIGINT NOT NULL, ssl_ctx UBIGINT NOT NULL,
    connection_generation UBIGINT NOT NULL, direction UTINYINT NOT NULL,
    call_sequence UBIGINT NOT NULL, loss_epoch UBIGINT NOT NULL,
    stream_offset UBIGINT NOT NULL, total_bytes UINTEGER NOT NULL, chunk_index USMALLINT NOT NULL,
    chunk_total USMALLINT NOT NULL, truncated BOOLEAN NOT NULL,
    read_failed BOOLEAN NOT NULL, lifecycle_end BOOLEAN NOT NULL
);
"#;

pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (or create) the DuckDB file at `path`, ensuring the parent
    /// directory exists, and run any pending migrations.
    pub fn open(path: &Path) -> Result<Self> {
        // Inspect legacy files READ_ONLY before chmod or migration. Never erase
        // historical plaintext evidence as part of a privacy migration.
        let existing = match std::fs::symlink_metadata(path) {
            Ok(meta) => {
                anyhow::ensure!(
                    meta.file_type().is_file(),
                    "database must be a regular file"
                );
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e.into()),
        };
        if existing {
            let inspect = Connection::open_in_memory()?;
            let quoted = path.to_string_lossy().replace('\'', "''");
            inspect.execute_batch(&format!("ATTACH '{quoted}' AS old (READ_ONLY)"))?;
            let legacy: i64 = inspect.query_row(
                "SELECT count(*) FROM information_schema.tables WHERE table_catalog='old' AND table_name='events_tls_plaintext'",
                [], |r| r.get(0))?;
            let usage_mode: i64 = inspect.query_row(
                "SELECT count(*) FROM information_schema.tables WHERE table_catalog='old' AND table_name IN ('events_usage','events_tls_metadata','schema_version')",
                [],|r|r.get(0))?;
            anyhow::ensure!(
                legacy == 0 && usage_mode == 3,
                "legacy plaintext or non-usage database refused; use a new database path"
            );
            let version: i64 =
                inspect.query_row("SELECT MAX(version) FROM old.schema_version", [], |r| {
                    r.get(0)
                })?;
            anyhow::ensure!(
                version == 3,
                "unrecognized usage schema version; use a new database path"
            );
        }
        // A bare filename lives in the current directory; it needs the same
        // privacy check as an explicitly supplied parent, including for WALs.
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .context("create private db directory")?;
        anyhow::ensure!(
            std::fs::metadata(parent)?.permissions().mode() & 0o077 == 0,
            "database directory must be private (mode 0700); use a dedicated directory"
        );
        // DuckDB rejects an existing empty file, so let it initialize the file
        // inside the already-private directory. Set the file mode before any
        // schema or event writes; the directory protects its initial contents.
        let conn =
            Connection::open(path).with_context(|| format!("open duckdb {}", path.display()))?;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        drop(file);
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
        self.conn
            .execute_batch(SCHEMA_V3)
            .context("apply v3 schema")?;
        if current < 3 {
            self.conn
                .execute("INSERT INTO schema_version (version) VALUES (3)", [])?;
        }
        Ok(())
    }

    pub fn usage_appender(&self) -> Result<Appender<'_>> {
        Ok(self.conn.appender("events_usage")?)
    }

    pub fn metadata_appender(&self) -> Result<Appender<'_>> {
        Ok(self.conn.appender("events_tls_metadata")?)
    }

    /// Insert process metadata and discard command-line arguments.
    pub fn insert_proc_exec(
        &self,
        ts_ns: u64,
        pid: u32,
        tgid: u32,
        cgroup_id: u64,
        comm: &str,
        _cmdline: &str,
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
                    ""
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
        _cmdline: &str,
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
                    "",
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
        _cmdline: &str,
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
                    "",
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
        let path = dir.path().join("private/events.duckdb");
        let store = Store::open(&path).expect("open store");
        assert_eq!(store.count_table("events_proc_exec").unwrap(), 0);
        assert_eq!(store.count_table("events_net_connect").unwrap(), 0);
        assert_eq!(store.count_table("events_net_bytes").unwrap(), 0);
        assert_eq!(store.count_table("events_usage").unwrap(), 0);
        let v: i64 = store
            .conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 3);
    }

    #[test]
    fn open_is_idempotent() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("private/events.duckdb");
        let _store1 = Store::open(&path).expect("first open");
        drop(_store1);
        let _store2 = Store::open(&path).expect("second open");
        // No panic, no extra schema_version rows beyond what's expected:
        // one row per applied migration (v1 + v2 = 2 rows).
        let count: i64 = _store2
            .conn
            .query_row("SELECT COUNT(*) FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn insert_proc_exec_round_trip() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(&dir.path().join("private/events.duckdb")).unwrap();
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
        assert_eq!(cmdline, "");
    }

    #[test]
    fn insert_net_connect_round_trip() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(&dir.path().join("private/events.duckdb")).unwrap();
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
        let store = Store::open(&dir.path().join("private/events.duckdb")).unwrap();
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

#[cfg(test)]
mod privacy_tests {
    use super::*;
    #[test]
    fn relative_database_filename_checks_its_current_directory() {
        const CHILD_MODE: &str = "TOKENSCOPE_RELATIVE_DB_TEST_MODE";
        if let Some(mode) = std::env::var_os(CHILD_MODE) {
            let path = Path::new("usage.duckdb");
            let result = Store::open(path);
            if mode == "private" {
                drop(result.expect("relative filename in a private directory"));
                assert_eq!(
                    std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            } else {
                assert!(result
                    .err()
                    .expect("shared current directory must be refused")
                    .to_string()
                    .contains("database directory must be private"));
                assert!(!path.exists());
            }
            return;
        }
        // Each child has its own cwd; parallel tests never change global cwd.
        for (label, mode) in [("private", 0o700), ("shared", 0o755)] {
            let directory = tempfile::TempDir::new().unwrap();
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(mode))
                .unwrap();
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "store::privacy_tests::relative_database_filename_checks_its_current_directory",
                    "--nocapture",
                ])
                .env(CHILD_MODE, label)
                .current_dir(directory.path())
                .output()
                .unwrap();
            assert!(
                child.status.success(),
                "{label} relative-path fixture failed: {}",
                String::from_utf8_lossy(&child.stdout)
            );
            assert_eq!(
                std::fs::metadata(directory.path())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                mode
            );
        }
    }
    #[test]
    fn refusal_preserves_an_existing_database_and_active_wal() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("legacy-with-wal.duckdb");
        let wal = path.with_extension("duckdb.wal");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE events_tls_plaintext(plaintext VARCHAR); INSERT INTO events_tls_plaintext VALUES ('HISTORICAL-WAL-EVIDENCE')").unwrap();
        assert!(wal.is_file(), "fixture must exercise an actual WAL");
        let original_db = std::fs::read(&path).unwrap();
        let original_wal = std::fs::read(&wal).unwrap();
        let db_mode = std::fs::metadata(&path).unwrap().permissions().mode();
        let wal_mode = std::fs::metadata(&wal).unwrap().permissions().mode();
        assert!(Store::open(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original_db);
        assert_eq!(std::fs::read(&wal).unwrap(), original_wal);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode(),
            db_mode
        );
        assert_eq!(
            std::fs::metadata(&wal).unwrap().permissions().mode(),
            wal_mode
        );
        drop(conn);
    }
    #[test]
    fn legacy_database_is_refused_and_preserved_byte_for_byte() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("legacy.duckdb");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE events_tls_plaintext(plaintext VARCHAR); INSERT INTO events_tls_plaintext VALUES ('HISTORICAL-EVIDENCE')").unwrap();
        drop(conn);
        let before = std::fs::read(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert!(Store::open(&path)
            .err()
            .unwrap()
            .to_string()
            .contains("legacy plaintext"));
        assert_eq!(before, std::fs::read(&path).unwrap());
        assert_eq!(mode, std::fs::metadata(&path).unwrap().permissions().mode());
        assert!(!path.with_extension("duckdb.wal").exists());
    }
    #[test]
    fn new_directory_and_database_are_private_and_symlinks_are_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("private/usage.duckdb");
        drop(Store::open(&path).unwrap());
        assert_eq!(
            std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let link = dir.path().join("symlink.duckdb");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(Store::open(&link).is_err());
        let missing_target = dir.path().join("must-not-be-created.duckdb");
        let dangling_link = path.parent().unwrap().join("dangling.duckdb");
        std::os::unix::fs::symlink(&missing_target, &dangling_link).unwrap();
        assert!(Store::open(&dangling_link).is_err());
        assert!(!missing_target.exists());
    }
    #[test]
    fn an_existing_shared_directory_is_refused_without_creating_a_database() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = dir.path().join("usage.duckdb");
        assert!(Store::open(&path)
            .err()
            .unwrap()
            .to_string()
            .contains("directory must be private"));
        assert!(!path.exists());
        assert_eq!(
            std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
}

#[cfg(test)]
mod legacy_v1_test {
    use super::*;
    #[test]
    fn legacy_command_line_database_is_preserved() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("phase1.duckdb");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.execute_batch(
            "INSERT INTO events_proc_exec VALUES (1,2,2,3,'fixture','PRIVATE-HISTORICAL-ARGS')",
        )
        .unwrap();
        drop(conn);
        let before = std::fs::read(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert!(Store::open(&path).is_err());
        assert_eq!(before, std::fs::read(&path).unwrap());
        assert_eq!(mode, std::fs::metadata(&path).unwrap().permissions().mode());
    }
}

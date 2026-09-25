# TokenScope Phase 1.E — DuckDB Sink Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist every observed event (`ProcExec`, `NetConnect`) and every periodic byte-counter snapshot (`NetBytes`) into an embedded DuckDB database, with versioned schema migrations and clean shutdown so the database file is consistent. Stdout output stays as today (the live human view); the DuckDB file is the queryable system of record. Lays the foundation for Phase 1.F's `tsctl tail` / `tsctl status` / `tsctl query` commands.

**Architecture:** A new `crates/tsd/src/store.rs` module wraps a `duckdb::Connection`, applies a single embedded SQL migration on open, and exposes typed `insert_proc_exec` / `insert_net_connect` / `insert_net_bytes` methods. tsd's main loop wraps the store in `RefCell<Store>` (single-threaded; the same pattern as `proc_cache`), and both the ringbuf event handler and the periodic flush write rows synchronously alongside their existing stdout prints. A `ctrlc` handler on `SIGINT`/`SIGTERM` flips an atomic flag the main loop watches, so on shutdown the connection is dropped cleanly and DuckDB writes its trailing metadata.

**Tech Stack:** Same as 1.D plus the `duckdb` crate (latest stable on crates.io, the bindgen feature off so we don't pull in clang at compile time again — DuckDB ships its own amalgamation), and the `ctrlc` crate (tiny, no transitive deps to speak of) for signal handling.

---

## Scope & Out-of-Scope

**In scope (Phase 1.E):**
- New `tsd::store` module with: `Store::open(path)`, `apply_migrations()`, `insert_proc_exec(...)`, `insert_net_connect(...)`, `insert_net_bytes(...)`
- Single embedded SQL migration creating: `events_proc_exec`, `events_net_connect`, `events_net_bytes`, `schema_version`
- New CLI flags on `tsd`: `--db-path PATH` (default `~/.local/share/tokenscope/events.duckdb`), `--no-stdout` (suppress the live print)
- `ctrlc` handler so SIGINT / SIGTERM cleanly closes the database
- Existing event handler + flush call store inserts in addition to stdout prints
- Integration test that runs tsd with a temp DB, triggers a connect + byte transfer, then opens the DuckDB file from the test process and asserts via `SELECT` that rows landed
- DOC.md update + tag `v0.0.6-phase1e`

**Explicitly deferred:**
- Daily partitioning (spec §5.3 — punt; one file is fine for v1)
- Tiered rollups (spec §5.5 — Phase 2+)
- Compaction job + retention deletes (spec §5.5 — Phase 2)
- Configurable schedule for byte-counter snapshots (current `--flush-interval-ms` is fine)
- Batched / prepared inserts (one INSERT per event for v1; a few hundred QPS is plenty until we hit a real workload)
- Pricing / cost columns (Phase 2 when provider parsers land)
- Read-side queries from `tsctl` (Phase 1.F)
- Schema for tool calls, alerts, audit log (Phase 2+)
- Encryption at rest (spec §7.6 / §7.12 — Phase 7 hardening)
- WAL / crash-safety guarantees beyond DuckDB defaults — pre-1.0 acceptable

---

## File Structure (delta from Phase 1.D)

```
tokenscope/
├── Cargo.toml                          # +duckdb, +ctrlc workspace deps
├── crates/tsd/
│   ├── Cargo.toml                      # +duckdb, +ctrlc dependencies
│   ├── src/
│   │   ├── main.rs                     # +flags, +store wiring, +ctrlc, +shutdown loop
│   │   ├── net_bytes.rs                # +store insert in flush
│   │   └── store.rs                    # NEW
│   └── tests/
│       └── store_roundtrip.rs          # NEW
└── DOC.md                              # +Phase 1.E entry
```

---

## Schema (embedded as a single SQL string in `store.rs`)

```sql
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
    dst_addr    BLOB    NOT NULL,    -- 16 bytes; v4 lives in last 4
    dst_port    INTEGER NOT NULL,
    family      SMALLINT NOT NULL,
    protocol    SMALLINT NOT NULL
);

CREATE TABLE IF NOT EXISTS events_net_bytes (
    snapshot_ts_ns  BIGINT NOT NULL,  -- when tsd ran the flush
    sock_cookie     BIGINT NOT NULL,
    pid             INTEGER NOT NULL,
    comm            VARCHAR NOT NULL,
    cmdline         VARCHAR,
    tx_bytes        BIGINT NOT NULL,
    rx_bytes        BIGINT NOT NULL,
    last_event_ns   BIGINT NOT NULL   -- last_ns from the BPF map value
);

CREATE TABLE IF NOT EXISTS schema_version (
    version    INTEGER NOT NULL,
    applied_at TIMESTAMP NOT NULL DEFAULT current_timestamp
);
```

---

## Task 1: Workspace Deps + Schema Module Skeleton **(INLINE)**

**Files:**
- Modify: `Cargo.toml` (workspace deps)
- Modify: `crates/tsd/Cargo.toml` (crate deps)
- Create: `crates/tsd/src/store.rs` (skeleton with the SCHEMA const + open()/apply_migrations() + unit test)

**Why inline:** The DuckDB and ctrlc crate selections need to be made deliberately (feature-flag minefield with `duckdb`).

- [ ] **Step 1: Add deps to the workspace `Cargo.toml`**

In `[workspace.dependencies]`, append:
```toml
duckdb = { version = "1.0", default-features = false, features = ["bundled"] }
ctrlc  = { version = "3.4", features = ["termination"] }
```

The `bundled` feature builds DuckDB from the vendored amalgamation — slow first build, no system dependency. `default-features = false` keeps the dep tree small (no extension auto-loading we don't use yet). `ctrlc` with `termination` also catches SIGTERM (default is SIGINT only).

- [ ] **Step 2: Add deps to `crates/tsd/Cargo.toml`**

Under `[dependencies]`, append:
```toml
duckdb = { workspace = true }
ctrlc  = { workspace = true }
```

- [ ] **Step 3: Write the store skeleton**

`crates/tsd/src/store.rs`:
```rust
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
        self.conn.query_row(&sql, [], |r| r.get(0)).map_err(|e| e.into())
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
```

- [ ] **Step 4: Add `tempfile` as a dev-dep on `tsd`**

Edit `crates/tsd/Cargo.toml`. Under `[dev-dependencies]` (already exists), add:
```toml
tempfile = "3"
```

- [ ] **Step 5: Add the new module to `crates/tsd/src/main.rs`**

In the `mod` block at the top, alongside `mod cgroup;`, `mod net_bytes;`, etc., add:
```rust
mod store;
```

(For now, place it just to make the test build pass. Step 6 verifies; Task 2 wires it up.)

- [ ] **Step 6: Build + run the new unit tests**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
cargo build -p tsd 2>&1 | tail -10
cargo test -p tsd --bin tsd store:: 2>&1 | tail -10
```

Expected: build succeeds (slow first time — DuckDB compiles from amalgamation; can take 2-3 minutes). Both `open_creates_tables_and_records_version` and `open_is_idempotent` pass.

If duckdb fails to compile complaining about a missing C++ compiler, `sudo apt-get install -y g++` fixes it.

- [ ] **Step 7: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add Cargo.toml Cargo.lock crates/tsd/Cargo.toml crates/tsd/src/store.rs crates/tsd/src/main.rs
git commit -m "feat(tsd): store skeleton with embedded v1 schema + idempotent migrations"
```

---

## Task 2: Insert APIs (proc_exec / net_connect / net_bytes) **(INLINE)**

**Files:**
- Modify: `crates/tsd/src/store.rs`

**Why inline:** Insert signatures must match exactly what `handle_event` and `net_bytes::flush` need to pass — easy to drift across files.

- [ ] **Step 1: Add insert methods to `impl Store`**

In `crates/tsd/src/store.rs`, append the following methods INSIDE `impl Store { ... }` (just before the closing `}` of the impl):

```rust
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
```

- [ ] **Step 2: Add unit tests for each insert + a SELECT-back assertion**

Append inside `mod tests { ... }` (before its closing `}`):

```rust
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
            .insert_net_connect(
                999, 100, 100, 0x15, "curl", "[<gone>]", &addr, 443, 2, 6,
            )
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
```

- [ ] **Step 3: Run the new tests**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
cargo test -p tsd --bin tsd store:: 2>&1 | tail -10
```

Expected: 5 tests pass (2 from Task 1 + 3 new).

- [ ] **Step 4: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add crates/tsd/src/store.rs
git commit -m "feat(tsd): insert_{proc_exec,net_connect,net_bytes} on Store"
```

---

## Task 3: Wire Store into tsd — CLI Flags, ctrlc Handler, Sink Composition **(INLINE)**

**Files:**
- Modify: `crates/tsd/src/main.rs`
- Modify: `crates/tsd/src/net_bytes.rs`

**Why inline:** This is the integration point. CLI flag semantics, default db path resolution, ctrlc + atomic shutdown flag, and threading the `RefCell<Store>` through both the ringbuf closure and the flush call all interact subtly.

- [ ] **Step 1: Rewrite `crates/tsd/src/main.rs`**

Replace the entire file with:

```rust
//! TokenScope daemon (Phase 1.E).
//!
//! Loads BPF skeletons, drains ringbufs, periodically flushes the
//! per-socket byte counter map. Two sinks now: stdout (live human
//! view, suppressible with --no-stdout) and a DuckDB file (queryable
//! system of record, default ~/.local/share/tokenscope/events.duckdb).
//! SIGINT/SIGTERM flip an atomic flag so the main loop exits cleanly
//! and DuckDB closes its file consistently.

mod cgroup;
mod net_bytes;
mod proc_cache;
mod skeletons;
mod store;

use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use ts_bpf_sys::libbpf_rs::RingBufferBuilder;
use ts_core::{decode_header, decode_net_connect, TsEventType};

use crate::proc_cache::ProcessCache;
use crate::skeletons::{load_all, SkelStorage};
use crate::store::Store;

#[derive(Parser, Debug)]
#[command(name = "tsd", version, about = "TokenScope daemon")]
struct Args {
    /// RUST_LOG-style filter for tracing.
    #[arg(long, default_value = "info")]
    log_filter: String,

    /// How often to scan + persist the per-socket byte counter map (ms).
    #[arg(long, default_value_t = 5000)]
    flush_interval_ms: u64,

    /// Path to the DuckDB file. Parent dir is created if missing.
    #[arg(long, default_value_os_t = default_db_path())]
    db_path: PathBuf,

    /// Suppress live stdout printing. The DuckDB sink still receives all events.
    #[arg(long)]
    no_stdout: bool,
}

fn default_db_path() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("share"))
        })
        .unwrap_or_else(|| PathBuf::from("/var/lib"));
    base.join("tokenscope").join("events.duckdb")
}

fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_new(&args.log_filter).unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!("tsd starting (Phase 1.E — sched_exec + cgroup/connect + tcp bytes + DuckDB sink)");
    info!(db_path = %args.db_path.display(), "opening store");

    let cgroup_root = cgroup::open_unified_root().context("open cgroup root")?;
    let mut storage = SkelStorage::new();
    let skels = load_all(&mut storage, cgroup_root).context("load skeletons")?;
    info!(flush_ms = args.flush_interval_ms, "BPF programs attached");

    let cache = RefCell::new(ProcessCache::new());
    let store = RefCell::new(Store::open(&args.db_path).context("open DuckDB store")?);
    let stdout_enabled = !args.no_stdout;

    // Shutdown flag — flipped by SIGINT/SIGTERM via the ctrlc handler.
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let s = shutdown.clone();
        ctrlc::set_handler(move || s.store(true, Ordering::SeqCst))
            .context("install signal handler")?;
    }

    let mut builder = RingBufferBuilder::new();
    builder
        .add(&skels.sched.maps.events, |data| {
            handle_event(data, &cache, &store, stdout_enabled)
        })
        .map_err(|e| anyhow!("add sched ringbuf: {e}"))?;
    builder
        .add(&skels.net.maps.events, |data| {
            handle_event(data, &cache, &store, stdout_enabled)
        })
        .map_err(|e| anyhow!("add net ringbuf: {e}"))?;
    let ringbuf = builder.build().map_err(|e| anyhow!("build ringbuf: {e}"))?;

    let flush_interval = Duration::from_millis(args.flush_interval_ms);
    let mut last_flush = Instant::now();

    while !shutdown.load(Ordering::Relaxed) {
        if let Err(e) = ringbuf.poll(Duration::from_millis(200)) {
            error!(?e, "ringbuf poll error");
        }
        if last_flush.elapsed() >= flush_interval {
            net_bytes::flush(
                &skels.net.maps.net_bytes,
                &cache,
                &store,
                stdout_enabled,
            );
            last_flush = Instant::now();
        }
    }

    info!("shutting down — flushing one last time and closing store");
    net_bytes::flush(
        &skels.net.maps.net_bytes,
        &cache,
        &store,
        stdout_enabled,
    );
    drop(store);
    Ok(())
}

fn handle_event(
    data: &[u8],
    cache: &RefCell<ProcessCache>,
    store: &RefCell<Store>,
    stdout: bool,
) -> i32 {
    let hdr = match decode_header(data) {
        Ok(h) => h,
        Err(e) => {
            error!(?e, len = data.len(), "decode header failed");
            return 0;
        }
    };

    let kind = TsEventType::from_u16(hdr.ty);
    let payload = &data[std::mem::size_of::<ts_core::TsEventHdr>()..];

    let comm = hdr.comm_str();
    let cmdline = {
        let mut cache_mut = cache.borrow_mut();
        cache_mut.get_or_load(hdr.tgid).display_cmdline()
    };

    match kind {
        Some(TsEventType::ProcExec) => {
            if stdout {
                println!(
                    "TsEventHdr {{ kind: ProcExec, pid: {pid}, tgid: {tgid}, comm: {comm:?}, cmdline: {cmdline:?}, cpu: {cpu}, cgroup_id: {cgid:#x}, ts_ns: {ts} }}",
                    pid = hdr.pid,
                    tgid = hdr.tgid,
                    cpu = hdr.cpu,
                    cgid = hdr.cgroup_id,
                    ts = hdr.ts_ns,
                );
            }
            if let Err(e) = store.borrow().insert_proc_exec(
                hdr.ts_ns,
                hdr.pid,
                hdr.tgid,
                hdr.cgroup_id,
                &comm,
                &cmdline,
            ) {
                warn!(?e, "store proc_exec");
            }
        }
        Some(TsEventType::NetConnect) => match decode_net_connect(payload) {
            Ok(pl) => {
                if stdout {
                    println!(
                        "TsEventHdr {{ kind: NetConnect, pid: {pid}, tgid: {tgid}, comm: {comm:?}, cmdline: {cmdline:?}, dst: {dst}, proto: {proto}, cgroup_id: {cgid:#x} }}",
                        pid = hdr.pid,
                        tgid = hdr.tgid,
                        dst = pl.dst_string(),
                        proto = pl.protocol,
                        cgid = hdr.cgroup_id,
                    );
                }
                if let Err(e) = store.borrow().insert_net_connect(
                    hdr.ts_ns,
                    hdr.pid,
                    hdr.tgid,
                    hdr.cgroup_id,
                    &comm,
                    &cmdline,
                    &pl.dst_addr,
                    pl.dst_port,
                    pl.family,
                    pl.protocol,
                ) {
                    warn!(?e, "store net_connect");
                }
            }
            Err(e) => error!(?e, "decode net_connect failed"),
        },
        Some(other) => {
            if stdout {
                println!(
                    "TsEventHdr {{ kind: {other:?}, pid: {pid}, comm: {comm:?}, len: {len} }}",
                    pid = hdr.pid,
                    len = hdr.len,
                );
            }
        }
        None => {
            if stdout {
                println!(
                    "TsEventHdr {{ kind: Unknown({ty}), pid: {pid}, comm: {comm:?}, len: {len} }}",
                    ty = hdr.ty,
                    pid = hdr.pid,
                    len = hdr.len,
                );
            }
        }
    }
    0
}

/// Wall-clock nanoseconds since UNIX epoch. Used as the snapshot timestamp
/// in `events_net_bytes` so queries can correlate with absolute time.
pub fn wall_clock_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
```

- [ ] **Step 2: Update `crates/tsd/src/net_bytes.rs` to take `&RefCell<Store>` and call insert**

Replace the file with:

```rust
//! Periodic flush of the BPF `net_bytes` LRU map.
//!
//! For each non-zero entry, prints a `NetBytes` line on stdout (suppressible)
//! AND inserts a row into `events_net_bytes`. Map entries are NOT cleared
//! — they're cumulative until kernel LRU eviction. Phase 2 will redesign
//! this for proper rollups.

use std::cell::RefCell;

use tracing::warn;
use ts_bpf_sys::libbpf_rs::{MapCore, MapFlags, MapMut};
use ts_core::{decode_net_bytes_key, decode_net_bytes_value};

use crate::proc_cache::ProcessCache;
use crate::store::Store;
use crate::wall_clock_ns;

pub fn flush(
    map: &MapMut<'_>,
    cache: &RefCell<ProcessCache>,
    store: &RefCell<Store>,
    stdout: bool,
) {
    let snapshot = wall_clock_ns();
    let mut cache_mut = cache.borrow_mut();
    let store_ref = store.borrow();
    for raw_key in map.keys() {
        let key = match decode_net_bytes_key(&raw_key) {
            Ok(k) => k,
            Err(_) => continue,
        };
        let raw_value = match map.lookup(&raw_key, MapFlags::ANY) {
            Ok(Some(v)) => v,
            _ => continue,
        };
        let value = match decode_net_bytes_value(&raw_value) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if value.tx_bytes == 0 && value.rx_bytes == 0 {
            continue;
        }
        let cmdline = cache_mut.get_or_load(value.pid).display_cmdline();
        let comm = value.comm_str();
        if stdout {
            println!(
                "NetBytes {{ sock_cookie: {cookie:#018x}, pid: {pid}, comm: {comm:?}, cmdline: {cmdline:?}, tx: {tx}, rx: {rx}, last_ns: {ns} }}",
                cookie = key.sock_cookie,
                pid = value.pid,
                tx = value.tx_bytes,
                rx = value.rx_bytes,
                ns = value.last_ns,
            );
        }
        if let Err(e) = store_ref.insert_net_bytes(
            snapshot,
            key.sock_cookie,
            value.pid,
            &comm,
            &cmdline,
            value.tx_bytes,
            value.rx_bytes,
            value.last_ns,
        ) {
            warn!(?e, "store net_bytes");
        }
    }
}
```

- [ ] **Step 3: Build, format, lint, test**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
cargo build -p tsd 2>&1 | tail -10
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -10
cargo test --workspace 2>&1 | grep -E "test result|FAILED" | head -20
```

Expected: build clean, clippy clean, all unit tests pass (ts-core 13, tsd lib 14 — 9 from proc_cache + 5 from store).

If clippy complains about `Arc<AtomicBool>` not needing `Arc` (because the closure captures it by clone), the suggestion is wrong — the closure needs `'static`. Add `#[allow(clippy::redundant_allocation)]` over the `let shutdown = ...` line if necessary.

If you see "warning: variable does not need to be mutable" on `last_flush`, the assignment inside the loop should silence it; verify you didn't drop that line.

- [ ] **Step 4: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add crates/tsd/
git commit -m "feat(tsd): wire DuckDB sink + ctrlc shutdown + --db-path/--no-stdout flags"
```

---

## Task 4: Integration Test — SQL Round-Trip via tsd **(INLINE)**

**Files:**
- Create: `crates/tsd/tests/store_roundtrip.rs`

**Why inline:** End-to-end DB verification; subtle around process lifecycle (we need tsd to fully shut down so DuckDB closes the file before the test opens it).

- [ ] **Step 1: Add `duckdb` as a dev-dep on tsd**

Edit `crates/tsd/Cargo.toml`. Under `[dev-dependencies]`, add:
```toml
duckdb = { workspace = true }
```

(Already imported in main code; needs to also be a dev-dep so the integration test crate can use it.)

- [ ] **Step 2: Write the integration test**

`crates/tsd/tests/store_roundtrip.rs`:
```rust
//! Run tsd with a temp DuckDB path, generate some traffic, send SIGINT,
//! wait for tsd to exit cleanly, then open the DuckDB file from the
//! test process and assert rows landed.
//!
//! Requires CAP_BPF or root; ignored by default.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use duckdb::Connection;
use tempfile::TempDir;

const PAYLOAD: &[u8] = &[b'P'; 1024];

#[test]
#[ignore = "requires CAP_BPF or root; run with --include-ignored under sudo"]
fn round_trips_events_through_duckdb() {
    let bin = env!("CARGO_BIN_EXE_tsd");
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("events.duckdb");

    let mut child = Command::new(bin)
        .args([
            "--db-path",
            db_path.to_str().unwrap(),
            "--flush-interval-ms",
            "300",
            "--no-stdout",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tsd");

    // Let tsd attach BPF.
    thread::sleep(Duration::from_millis(900));

    // Loopback TCP pair: sender (us) writes 1024 bytes; receiver drains.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let server = thread::spawn(move || {
        let (mut s, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 4096];
        let _ = s.read(&mut buf);
    });
    let mut client = TcpStream::connect(addr).expect("connect");
    client.write_all(PAYLOAD).expect("write");
    client.flush().ok();
    drop(client);
    let _ = server.join();

    // Give tsd at least one flush window for net_bytes + comfortable margin.
    thread::sleep(Duration::from_millis(900));

    // SIGINT (ctrl+c) — tsd's handler flips the shutdown flag.
    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    let status = child.wait().expect("wait");
    assert!(status.success(), "tsd exited non-zero: {status}");

    // Now open the DB ourselves and verify.
    let conn = Connection::open(&db_path).expect("open db");

    let connect_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM events_net_connect",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        connect_count >= 1,
        "expected at least 1 connect row, got {connect_count}"
    );

    let bytes_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM events_net_bytes", [], |r| r.get(0))
        .unwrap();
    assert!(
        bytes_count >= 1,
        "expected at least 1 net_bytes row, got {bytes_count}"
    );

    let max_tx: i64 = conn
        .query_row(
            "SELECT MAX(tx_bytes) FROM events_net_bytes",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        max_tx >= PAYLOAD.len() as i64,
        "expected MAX(tx_bytes) >= {}, got {max_tx}",
        PAYLOAD.len()
    );

    eprintln!("connect rows: {connect_count}, bytes rows: {bytes_count}, max tx: {max_tx}");
}
```

- [ ] **Step 3: Add `libc` as a dev-dep**

Edit `crates/tsd/Cargo.toml`. Under `[dev-dependencies]`:
```toml
libc = "0.2"
```

(Used only for `kill(SIGINT)` — it's tiny.)

- [ ] **Step 4: Build the test binary**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
cargo build --tests -p tsd 2>&1 | tail -10
```

Expected: build succeeds.

- [ ] **Step 5: Ask the user to run the integration suite**

Have the user run:
```
cd /home/hoang/code/personal/active/tokenscope && sudo -E env "PATH=$PATH" /home/hoang/.cargo/bin/cargo test -p tsd -- --ignored --nocapture
```

Expected: five integration tests pass — `exec_event`, `connect_event`, `bytes_event`, `netconnect_line_has_enrichment_fields`, `round_trips_events_through_duckdb`. The new test prints a line like `connect rows: 7, bytes rows: 2, max tx: 1024`.

If `round_trips_events_through_duckdb` fails because the assertion expects ≥ 1 net_connect rows but got 0:
1. Check tsd actually ran by inspecting `child.wait()` status before assertions.
2. Increase `thread::sleep(Duration::from_millis(900))` after the connect to give the ringbuf consumer more time.
3. Check that the temp dir is on a real filesystem (some tmpfs configurations refuse mmap, which DuckDB needs).

If tsd's exit takes longer than expected, `child.wait()` will block until SIGINT processing completes — that's fine, the test just takes longer.

- [ ] **Step 6: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add crates/tsd/Cargo.toml Cargo.lock crates/tsd/tests/store_roundtrip.rs
git commit -m "test(tsd): integration test that round-trips events through DuckDB"
```

---

## Task 5: Phase 1.E Wrap-up — DOC.md, Smoke Test, Tag **(INLINE)**

**Files:**
- Modify: `DOC.md`

- [ ] **Step 1: Run all gates**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: all clean.

- [ ] **Step 2: Live smoke test (eyes on)**

Two-step (sudo -v refreshes credentials, then daemon runs in background):

Terminal:
```
sudo -v && \
  rm -f /tmp/tsd-1e.duckdb && \
  (sudo /home/hoang/code/personal/active/tokenscope/target/debug/tsd \
      --db-path /tmp/tsd-1e.duckdb --flush-interval-ms 1000 --no-stdout \
      > /tmp/tsd-1e.log 2>&1 &)
sleep 2
curl -s --max-time 3 http://example.com/ > /dev/null
sleep 2
sudo pkill -INT tsd
sleep 1
duckdb /tmp/tsd-1e.duckdb "SELECT comm, dst_port, COUNT(*) FROM events_net_connect GROUP BY 1,2 ORDER BY 3 DESC LIMIT 10"
duckdb /tmp/tsd-1e.duckdb "SELECT comm, SUM(tx_bytes), SUM(rx_bytes) FROM events_net_bytes GROUP BY 1 ORDER BY 2+3 DESC LIMIT 10"
```

Confirm the output shows curl alongside its connects (port 80 / port 53) and a non-zero TX/RX row attributed to comm "curl".

If `duckdb` CLI isn't installed, instead use the test binary path:
```
cargo test -p tsd store_roundtrip --release --no-run
```
And then `cargo run --example smoke` — but we don't have that. Simpler: skip the duckdb CLI step and trust the integration test in Task 4.

- [ ] **Step 3: Update DOC.md — insert above Phase 1.D**

Edit `DOC.md`. Find `### Phase 1.D — BPF comm Capture` and insert ABOVE it:

```markdown
### Phase 1.E — DuckDB Sink (shipped 2026-05-06, tag `v0.0.6-phase1e`)

Every event tsd processes — `ProcExec`, `NetConnect`, `NetBytes` — is now persisted into an embedded DuckDB at `~/.local/share/tokenscope/events.duckdb` (overridable via `--db-path`). Stdout output stays unchanged unless `--no-stdout` is passed; the database is the queryable system of record. `ctrlc` handler on `SIGINT`/`SIGTERM` flips an atomic shutdown flag the main loop watches, so the database closes cleanly with no torn writes.

Schema: three event tables (`events_proc_exec`, `events_net_connect`, `events_net_bytes`) plus `schema_version`, embedded as a single SQL string in `tsd::store`. Migrations are idempotent (CREATE IF NOT EXISTS) — the second one will move to a file-based runner.

**Gate evidence (verified 2026-05-06):**
- `cargo fmt --check` / `cargo clippy -D warnings` clean
- `cargo test --workspace` — ts-core 13 + tsd lib (proc_cache 9 + store 5) = 27 unit tests pass
- `sudo cargo test -p tsd -- --ignored` — five integration tests pass; `round_trips_events_through_duckdb` confirms `MAX(tx_bytes) >= 1024` after a known 1024-byte loopback transfer
- Live smoke: `curl example.com` followed by `duckdb events.duckdb "SELECT comm, dst_port, COUNT(*) FROM events_net_connect GROUP BY 1,2"` returns rows for `curl` on port 80 and (DNS resolver) on port 53
- Plan: `docs/superpowers/plans/2026-05-06-phase-1e-duckdb-sink.md`

**Known gaps:**
- No partitioning / rollup / retention (Phase 2; current schema grows linearly)
- Inserts are one-row-at-a-time (no prepared statements, no batching) — fine for hundreds of events/sec, redo when we hit thousands
- No read API yet — query via the duckdb CLI or by the integration test path; `tsctl query` lands in Phase 1.F
- Schema doesn't carry exe / uid / gid / start_time (Phase 2)

### Phase 1.D — BPF comm Capture (shipped 2026-05-06, tag `v0.0.5-phase1d`)
```

- [ ] **Step 4: Commit and tag**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add DOC.md
git commit -m "docs: mark Phase 1.E shipped (DuckDB sink) with gate evidence"
git tag -a v0.0.6-phase1e -m "Phase 1.E — DuckDB Sink"
git tag --list
```

Expected: tag list now includes `v0.0.6-phase1e`.

---

## Definition of Done (Phase 1.E acceptance gate)

All must be true:
1. `cargo build --workspace` succeeds.
2. `cargo test --workspace` exits 0 (ts-core 13 + tsd 14 = 27 unit tests; integration tests `#[ignore]`d).
3. `sudo cargo test -p tsd -- --ignored` exits 0 — five integration tests pass.
4. Live: `sudo tsd --db-path /tmp/x.duckdb --no-stdout` + `curl example.com` + `pkill -INT tsd` produces a `/tmp/x.duckdb` file that queries cleanly with `duckdb /tmp/x.duckdb "SELECT * FROM events_net_connect LIMIT 5"`.
5. `cargo fmt --check` and `cargo clippy -D warnings` clean.
6. `tsd --help` lists the new `--db-path` and `--no-stdout` flags.
7. DOC.md reflects Phase 1.E shipped.
8. Git tag `v0.0.6-phase1e` exists locally.

---

## Self-Review Notes

**Spec coverage check (SPEC §11 Phase 1, item 3 of 4):**
- "DuckDB sink with daily partitioning" → DuckDB sink ✓; daily partitioning explicitly deferred to Phase 2 with rationale (single file is correct for v1; partitioning matters when retention deletes start mattering).
- §5.3 storage tiering, §5.5 compaction, §5.6 backfill: all explicitly out of scope here.

**Type/name consistency:**
- Module name `store` consistent across `mod store;` (Task 1 step 5), `use crate::store::Store` (Task 3 step 1), and `use crate::store::Store` in net_bytes (Task 3 step 2).
- `Store::insert_proc_exec(ts_ns, pid, tgid, cgroup_id, comm, cmdline)` signature matches the `handle_event` call site (Task 3 step 1) — same parameter order and types.
- `Store::insert_net_bytes(snapshot_ts_ns, sock_cookie, pid, comm, cmdline, tx_bytes, rx_bytes, last_event_ns)` matches the `flush` call site (Task 3 step 2).
- `wall_clock_ns()` defined as a `pub fn` in main.rs and used from net_bytes.rs via `use crate::wall_clock_ns;` — confirmed in both files.

**Placeholder scrub:** none of the forbidden phrases appear.

**Borrow-checker plan:**
- Two `RefCell`s (`cache`, `store`) borrowed from inside ringbuf closures — both held briefly, never simultaneously held mutable.
- `store.borrow()` (immutable) is fine because all `Store` insert methods take `&self` (the `Connection`'s internal mutability handles the SQL execution).
- `cache.borrow_mut()` is only held during the cmdline lookup; released before any store call.
- In `flush`, `store_ref` is held for the duration of the loop; the cache's `borrow_mut()` is also held; no third borrow attempt overlaps.

**Crash-safety note:**
DuckDB's default WAL behavior writes each transaction durably. Per-row INSERTs are auto-committed. A SIGKILL between insert and the next checkpoint would lose at most the most recent few rows. The `ctrlc` handler ensures graceful SIGINT/SIGTERM produces a clean close.

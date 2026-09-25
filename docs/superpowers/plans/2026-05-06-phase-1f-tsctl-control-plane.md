# TokenScope Phase 1.F — tsctl Control Plane (status + tail) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Plan revision history:** initial draft included `tsctl query` (direct DuckDB read-only). Codex review (read-only second opinion) flagged that DuckDB's actual concurrency model is **one writer OR many readers, never both across processes** — so `tsctl query` against a live `tsd` would be unsafe. Deferred to Phase 1.G, which will route SQL over UDS so the daemon's own connection executes it. Same review caught a `Drop`-time deadlock in `ControlServer` and an unsafe blind `unlink` of the socket on startup; both are fixed below.

**Goal:** Make a running `tsd` daemon observable from a separate `tsctl` process. Two subcommands ship: `tsctl status` (one-shot snapshot of probe state, throughput counters, db path) and `tsctl tail` (live JSON event stream until Ctrl-C). Both talk to tsd over a Unix domain socket using newline-delimited JSON.

**Architecture:** `tsd` spawns one OS thread that owns a `UnixListener` at `${XDG_RUNTIME_DIR:-/run}/tokenscope/tsd.sock`. Per accepted connection it spawns a short-lived worker thread that reads one JSON request line and either (a) replies with a one-shot `StatusResponse` and closes (status), or (b) registers itself with a HashMap-based subscriber registry and forwards each broadcast frame until the client disconnects (tail). The main loop publishes events via a non-blocking try_send to every active subscriber — slow clients drop frames, ingest is never blocked. Subscriber unregister is RAII (Drop guard), so the active-count atomic is always accurate. The `ControlServer` carries its own shutdown flag flipped in `Drop` so early-return code paths cannot deadlock the listener.

**Tech Stack:** Same as 1.E plus `serde 1` + `serde_json 1` (workspace-wide, ts-core + tsd + tsctl).

---

## Scope & Out-of-Scope

**In scope (Phase 1.F):**
- New `ts_core::control` module: `Request`, `StatusResponse`, `ErrorResponse`, `TailEvent` (enum w/ ProcExec, NetConnect, NetBytes variants), `PROTOCOL_VERSION`
- New `tsd::control` module: UDS listener thread, per-connection worker, subscriber registry (HashMap + RAII guard), broadcast hook, safe socket startup (probe-then-unlink with file-type check), drop-safe shutdown
- `tsd` flags: `--uds-path PATH` (default `${XDG_RUNTIME_DIR}/tokenscope/tsd.sock`, falls back to `/run/tokenscope/tsd.sock`), `--no-control` (skip starting the listener)
- `tsd` atomic counters: `events_total`, `ringbuf_poll_errors`, `tail_subscribers_active`
- `tsctl status` — connects, sends `Request::Status`, prints human-readable summary
- `tsctl tail` — connects, sends `Request::Tail`, streams events, exits cleanly on SIGINT
- `tsctl --uds-path` global flag so tests + power users can override the default
- Integration test: spawn tsd → drive loopback TCP → run `tsctl status` (assert populated fields), `tsctl tail` (assert ≥ 1 JSON event line within 2 s)
- DOC.md update + tag `v0.0.7-phase1f`

**Explicitly deferred:**
- **`tsctl query <SQL>`** — DuckDB does **not** allow a read-only reader process alongside a writer process; the file-level fcntl lock either blocks the reader or returns "database is locked" (per DuckDB upstream concurrency docs). Phase 1.G will route SQL over UDS (`Request::Query{sql}`); the daemon executes on its own connection and streams rows back as `QueryRow` frames. That deserves its own design pass.
- Authentication on the UDS — pre-1.0 uses 0700 dir + 0600 socket and trusts process UID
- TLS / network exposure — UDS only
- Tail filters (`--filter 'provider=anthropic'`) — Phase 2 once parsers exist
- `tsctl probes list/attach/detach` — Phase 2 (probe set is currently fixed at compile time)
- `tsctl reload` / `tsctl config check` — no config file yet
- `tsctl doctor` — Phase 7 hardening
- `tsctl tag`, `tsctl capture`, `tsctl alerts*` — Phase 2+
- True ringbuf-drop counter from `bpf_ringbuf_query(0)` — Phase 2 (current `ringbuf_poll_errors` only counts userspace `poll()` errors, which is honest)
- Web/Prometheus/OTLP exporters — separate phases
- Tail subscriber back-pressure metric exposed via Prometheus — Phase 3

---

## Wire Protocol (single source of truth — duplicated nowhere else)

**Transport:** Unix stream socket. Each direction is **newline-delimited JSON** (one JSON value per `\n`-terminated line). No length-prefixing, no additional framing.

**Path resolution order (server side):**
1. `--uds-path` if set
2. `${XDG_RUNTIME_DIR}/tokenscope/tsd.sock` if `XDG_RUNTIME_DIR` is non-empty
3. `/run/tokenscope/tsd.sock`

The parent directory is created with mode `0700` if absent. The socket file is created with mode `0600` (server bind, then `chmod`).

**Safe startup (the unsafe blind unlink is gone):**
1. If the path exists and is **not** a Unix socket → refuse to start (could be a regular file the user pointed at by mistake).
2. If the path exists, is a socket, AND `UnixStream::connect(path)` succeeds → another live daemon owns it. Refuse to start.
3. If the path exists, is a socket, but connect fails (ECONNREFUSED — stale from a crashed prior run) → safe to `unlink` and rebind.

**Hard limits:**
- **Per-connection request line:** capped at 64 KiB. A client that opens and never sends `\n` is dropped after a 5-second read timeout.
- **Per-connection write timeout:** 1 second on the worker's `UnixStream`. A wedged tail client gets dropped instead of pinning a thread forever.
- **Subscriber queue depth:** 1024 messages. Slow consumers drop frames per-event (try_send returns Full → frame is dropped, channel kept open).

**Requests (client → server, exactly one per connection, terminated by `\n`):**
```json
{"op":"status"}
{"op":"tail"}
```

**Server replies — newline-delimited JSON.** Two normal forms and one error form:

`StatusResponse` (one line, then close):
```json
{
  "protocol_version": 1,
  "version": "0.1.0",
  "uptime_s": 12345,
  "db_path": "/home/hoang/.local/share/tokenscope/events.duckdb",
  "uds_path": "/run/user/1000/tokenscope/tsd.sock",
  "probes_attached": ["sched_exec", "cgroup_connect4", "cgroup_connect6", "tcp_sendmsg", "tcp_recvmsg"],
  "events_total": 4711,
  "ringbuf_poll_errors": 0,
  "tail_subscribers_active": 1
}
```

`TailEvent` (one line per event, indefinite stream until disconnect):
```json
{"type":"proc_exec","ts_ns":12345,"pid":42,"tgid":42,"comm":"true","cmdline":"[<gone>]","cgroup_id":"0x15"}
{"type":"net_connect","ts_ns":12345,"pid":42,"tgid":42,"comm":"curl","cmdline":"curl example.com","cgroup_id":"0x15","dst":"93.184.216.34:80","family":2,"protocol":6}
{"type":"net_bytes","snapshot_ts_ns":12345,"sock_cookie":"0xCAFE","pid":42,"comm":"curl","cmdline":"curl example.com","tx":1024,"rx":2048,"last_event_ns":12345}
```

`ErrorResponse` (one line on bad request, then close):
```json
{"error":"bad request: missing field `op` at line 1 column 2"}
```

`cgroup_id` and `sock_cookie` are emitted as hex strings (they're 64-bit IDs; JSON's number type loses precision past 2^53).

`type` is the discriminator on `TailEvent`. Adding new variants is a minor version bump per SPEC §10. Removing or renaming is major.

`StatusResponse.protocol_version` lets a future client warn on mismatch. Tail clients that care can do a status request first; otherwise tail just streams the current schema.

---

## File Structure (delta from Phase 1.E)

```
tokenscope/
├── Cargo.toml                              # +serde, +serde_json workspace deps
├── crates/ts-core/
│   ├── Cargo.toml                          # +serde, +serde_json
│   └── src/
│       ├── lib.rs                          # +pub mod control;
│       └── control.rs                      # NEW — wire types + serde derives + tests
├── crates/tsd/
│   ├── Cargo.toml                          # +serde, +serde_json
│   ├── src/
│   │   ├── main.rs                         # +flags, +counters, +control thread spawn, +publish hook
│   │   ├── control.rs                      # NEW — UDS listener, worker, Subscribers (RAII)
│   │   └── net_bytes.rs                    # +publish hook
│   └── tests/
│       └── control_e2e.rs                  # NEW — spawn tsd + tsctl, assert
└── crates/tsctl/
    ├── Cargo.toml                          # +serde, +serde_json, +ctrlc, +ts-core
    └── src/main.rs                         # REWRITE — clap subcommands, status/tail
```

---

## Task 1: Wire Types in `ts_core::control` **(INLINE)**

**Files:**
- Modify: `Cargo.toml` (workspace deps)
- Modify: `crates/ts-core/Cargo.toml`
- Create: `crates/ts-core/src/control.rs`
- Modify: `crates/ts-core/src/lib.rs`

**Why inline:** This is the contract every other task depends on. A typo here cascades to tsd + tsctl + the integration test.

- [ ] **Step 1: Add serde to workspace deps**

In `Cargo.toml` `[workspace.dependencies]`, append:
```toml
serde      = { version = "1", features = ["derive"] }
serde_json = "1"
```

- [ ] **Step 2: Add serde to `crates/ts-core/Cargo.toml`**

Read the file. Under `[dependencies]`, append:
```toml
serde      = { workspace = true }
serde_json = { workspace = true }
```

- [ ] **Step 3: Create `crates/ts-core/src/control.rs`**

```rust
//! Wire types for the tsd ↔ tsctl Unix-domain-socket control plane.
//!
//! Newline-delimited JSON. The server reads one `Request` per
//! connection; the client reads one `StatusResponse` (status) or a
//! stream of `TailEvent`s (tail). On bad input the server replies
//! with one `ErrorResponse` and closes.
//!
//! These types are a **stable API surface** per SPEC §10. Adding a new
//! `Request` op or `TailEvent` variant is a minor version bump in
//! pre-1.0; renaming or removing fields is a major bump.

use serde::{Deserialize, Serialize};

/// Bumped when the wire format changes incompatibly. Server includes
/// it in `StatusResponse` so clients can warn on mismatch.
pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Status,
    Tail,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusResponse {
    pub protocol_version: u32,
    pub version: String,
    pub uptime_s: u64,
    pub db_path: String,
    pub uds_path: String,
    pub probes_attached: Vec<String>,
    pub events_total: u64,
    /// Counts userspace `ringbuf.poll()` errors, NOT BPF-side ringbuf
    /// drops. A real drop counter via `bpf_ringbuf_query(0)` lands in
    /// Phase 2.
    pub ringbuf_poll_errors: u64,
    pub tail_subscribers_active: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorResponse {
    pub error: String,
}

/// Live event emitted on tail subscriptions. `type` is the JSON tag.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TailEvent {
    ProcExec {
        ts_ns: u64,
        pid: u32,
        tgid: u32,
        comm: String,
        cmdline: String,
        /// Hex string ("0x15") — cgroup IDs are 64-bit and lose
        /// precision in JSON numbers (max safe = 2^53).
        cgroup_id: String,
    },
    NetConnect {
        ts_ns: u64,
        pid: u32,
        tgid: u32,
        comm: String,
        cmdline: String,
        cgroup_id: String,
        /// "1.2.3.4:443" or "[::1]:80"
        dst: String,
        family: u16,
        protocol: u8,
    },
    NetBytes {
        snapshot_ts_ns: u64,
        /// Hex string for the same reason as cgroup_id.
        sock_cookie: String,
        pid: u32,
        comm: String,
        cmdline: String,
        tx: u64,
        rx: u64,
        last_event_ns: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_status_round_trip() {
        let r = Request::Status;
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, r#"{"op":"status"}"#);
        assert_eq!(serde_json::from_str::<Request>(&s).unwrap(), r);
    }

    #[test]
    fn request_tail_round_trip() {
        let r = Request::Tail;
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, r#"{"op":"tail"}"#);
        assert_eq!(serde_json::from_str::<Request>(&s).unwrap(), r);
    }

    #[test]
    fn unknown_op_fails_to_deserialize() {
        let err = serde_json::from_str::<Request>(r#"{"op":"nope"}"#);
        assert!(err.is_err());
    }

    #[test]
    fn status_response_round_trip() {
        let r = StatusResponse {
            protocol_version: PROTOCOL_VERSION,
            version: "0.1.0".into(),
            uptime_s: 42,
            db_path: "/tmp/x.duckdb".into(),
            uds_path: "/tmp/tsd.sock".into(),
            probes_attached: vec!["sched_exec".into(), "tcp_sendmsg".into()],
            events_total: 100,
            ringbuf_poll_errors: 0,
            tail_subscribers_active: 2,
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: StatusResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn error_response_round_trip() {
        let r = ErrorResponse {
            error: "bad request: missing field `op`".into(),
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: ErrorResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn tail_event_proc_exec_round_trip() {
        let e = TailEvent::ProcExec {
            ts_ns: 123,
            pid: 4,
            tgid: 4,
            comm: "true".into(),
            cmdline: "[<gone>]".into(),
            cgroup_id: "0x15".into(),
        };
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains(r#""type":"proc_exec""#));
        assert_eq!(serde_json::from_str::<TailEvent>(&s).unwrap(), e);
    }

    #[test]
    fn tail_event_net_bytes_round_trip() {
        let e = TailEvent::NetBytes {
            snapshot_ts_ns: 1,
            sock_cookie: "0xCAFE".into(),
            pid: 42,
            comm: "curl".into(),
            cmdline: "curl example.com".into(),
            tx: 1024,
            rx: 2048,
            last_event_ns: 99,
        };
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains(r#""type":"net_bytes""#));
        assert!(s.contains(r#""tx":1024"#));
        assert_eq!(serde_json::from_str::<TailEvent>(&s).unwrap(), e);
    }
}
```

- [ ] **Step 4: Re-export from `ts-core/src/lib.rs`**

Read `crates/ts-core/src/lib.rs`. Append:
```rust
pub mod control;
```

- [ ] **Step 5: Build + run the new tests**

```
cd /home/hoang/code/personal/active/tokenscope
cargo test -p ts-core control:: 2>&1 | tail -10
```

Expected: 7 tests pass (`request_status_round_trip`, `request_tail_round_trip`, `unknown_op_fails_to_deserialize`, `status_response_round_trip`, `error_response_round_trip`, `tail_event_proc_exec_round_trip`, `tail_event_net_bytes_round_trip`).

- [ ] **Step 6: Commit**

```
cd /home/hoang/code/personal/active/tokenscope
git add Cargo.toml Cargo.lock crates/ts-core/Cargo.toml crates/ts-core/src/control.rs crates/ts-core/src/lib.rs
git commit -m "feat(ts-core): control-plane wire types (Request/Status/Error/TailEvent)"
```

---

## Task 2: tsd UDS Listener + Subscribers (RAII) + Drop-Safe Server **(INLINE)**

**Files:**
- Modify: `crates/tsd/Cargo.toml`
- Create: `crates/tsd/src/control.rs`
- Modify: `crates/tsd/src/main.rs`
- Modify: `crates/tsd/src/net_bytes.rs`

**Why inline:** Threading model + atomic counters + subscriber registry + safe-startup invariants + cleanup-on-drop ordering all need to align across three files. Subagent dispatch would lose the cross-file invariants.

- [ ] **Step 1: Add serde + serde_json to `crates/tsd/Cargo.toml`**

Under `[dependencies]`, append:
```toml
serde      = { workspace = true }
serde_json = { workspace = true }
```

- [ ] **Step 2: Create `crates/tsd/src/control.rs`**

```rust
//! tsd's UDS control plane.
//!
//! Owns one OS thread (`run_listener`) that accepts connections at
//! the configured Unix path. Per accepted connection, spawns a short
//! worker thread that:
//!   * reads exactly one JSON request line (5 s read timeout, 64 KiB cap)
//!   * dispatches: Status -> reply once and close; Tail -> register
//!     a subscriber (RAII guard), then forward broadcast frames until
//!     the client disconnects (1 s write timeout drops wedged clients).
//!
//! The main loop publishes events via `Subscribers::broadcast`, a
//! non-blocking try_send to each subscriber's bounded channel. Slow
//! clients drop frames; ingest is never blocked.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use tracing::{debug, error, info, warn};

use ts_core::control::{ErrorResponse, Request, StatusResponse, PROTOCOL_VERSION};

/// Per-subscriber bounded queue. 1024 messages ≈ a few seconds of
/// burst at typical event rates; a slow client past that drops frames.
const SUBSCRIBER_QUEUE_DEPTH: usize = 1024;

/// Reject `Request` lines longer than this. A client that opens and
/// never sends `\n` will hit the read timeout instead.
const MAX_REQUEST_BYTES: u64 = 64 * 1024;

/// Cap on a single `read_line` wait — protects worker threads from
/// idle clients that never send a request.
const READ_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-write timeout on the tail forwarding loop. A wedged client
/// gets dropped instead of pinning a thread forever.
const WRITE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Default)]
pub struct Counters {
    pub events_total: AtomicU64,
    pub ringbuf_poll_errors: AtomicU64,
    pub tail_subscribers_active: AtomicU32,
}

#[derive(Clone)]
pub struct Subscribers {
    inner: Arc<Mutex<HashMap<u64, SyncSender<String>>>>,
    next_id: Arc<AtomicU64>,
    counters: Arc<Counters>,
}

impl Subscribers {
    pub fn new(counters: Arc<Counters>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
            counters,
        }
    }

    /// Push a JSON line to every active subscriber. Drops on a full
    /// or disconnected channel; never blocks. Disconnected entries
    /// are removed from the registry inline.
    pub fn broadcast(&self, line: &str) {
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.retain(|_id, tx| match tx.try_send(line.to_string()) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => true, // keep, just drop this frame
            Err(TrySendError::Disconnected(_)) => false,
        });
        self.counters
            .tail_subscribers_active
            .store(guard.len() as u32, Ordering::Relaxed);
    }

    /// Register a fresh subscriber. The returned `Guard` removes the
    /// subscriber from the registry on drop, so per-connection
    /// cleanup is exception/early-return safe.
    fn register(&self) -> (Receiver<String>, SubscriberGuard) {
        let (tx, rx) = sync_channel(SUBSCRIBER_QUEUE_DEPTH);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.insert(id, tx);
        self.counters
            .tail_subscribers_active
            .store(guard.len() as u32, Ordering::Relaxed);
        let g = SubscriberGuard {
            id,
            inner: self.inner.clone(),
            counters: self.counters.clone(),
        };
        (rx, g)
    }
}

/// Removes its subscriber from the registry on drop. Holding this
/// across the worker's recv loop guarantees the active-count atomic
/// stays accurate even on early return / panic.
struct SubscriberGuard {
    id: u64,
    inner: Arc<Mutex<HashMap<u64, SyncSender<String>>>>,
    counters: Arc<Counters>,
}

impl Drop for SubscriberGuard {
    fn drop(&mut self) {
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.remove(&self.id);
        self.counters
            .tail_subscribers_active
            .store(guard.len() as u32, Ordering::Relaxed);
    }
}

pub struct ControlServer {
    join: Option<JoinHandle<()>>,
    /// Server-local shutdown — flipped in `Drop` so dropping the
    /// server releases the listener even if the global shutdown
    /// flag was never set (e.g., main returns Err early).
    server_shutdown: Arc<AtomicBool>,
    pub uds_path: PathBuf,
}

impl ControlServer {
    /// Spawn the listener thread. Returns immediately. The thread
    /// runs until either the global `shutdown` or the server-local
    /// shutdown flips. On exit it removes the socket file.
    pub fn start(
        uds_path: PathBuf,
        db_path: PathBuf,
        subscribers: Subscribers,
        counters: Arc<Counters>,
        started_at: Instant,
        global_shutdown: Arc<AtomicBool>,
    ) -> Result<Self> {
        if let Some(parent) = uds_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create uds parent dir {}", parent.display()))?;
            // 0700 — only the daemon user may even see the socket file.
            // Best-effort: setting may fail on /run/* without privilege.
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }

        let listener = safe_bind(&uds_path)?;
        // 0600 — owner-only on the socket itself.
        std::fs::set_permissions(&uds_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod uds {}", uds_path.display()))?;
        // Non-blocking accept so the loop can poll the shutdown flag.
        listener
            .set_nonblocking(true)
            .context("set listener nonblocking")?;

        let server_shutdown = Arc::new(AtomicBool::new(false));
        let path_for_thread = uds_path.clone();
        let server_shutdown_thread = server_shutdown.clone();
        let join = thread::Builder::new()
            .name("tsd-control".into())
            .spawn(move || {
                run_listener(
                    listener,
                    db_path,
                    path_for_thread,
                    subscribers,
                    counters,
                    started_at,
                    global_shutdown,
                    server_shutdown_thread,
                )
            })
            .context("spawn listener thread")?;

        info!(uds_path = %uds_path.display(), "control plane listening");
        Ok(Self {
            join: Some(join),
            server_shutdown,
            uds_path,
        })
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        // Flip the server-local shutdown FIRST, then join. Without
        // this the listener thread could spin forever if the main
        // shutdown flag was never set (early-return error path).
        self.server_shutdown.store(true, Ordering::SeqCst);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
        // Belt-and-suspenders cleanup; the thread also removes it.
        let _ = std::fs::remove_file(&self.uds_path);
    }
}

/// Open the listener safely:
///   * If `path` exists and is NOT a Unix socket -> refuse (could be
///     a real file the user pointed at by mistake).
///   * If `path` is a socket and connect succeeds -> a live daemon
///     already owns it. Refuse.
///   * If `path` is a socket and connect fails -> stale; unlink and
///     bind.
fn safe_bind(path: &Path) -> Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                return Err(anyhow!(
                    "{} exists and is not a Unix socket — refusing to overwrite",
                    path.display()
                ));
            }
            if UnixStream::connect(path).is_ok() {
                return Err(anyhow!(
                    "{} is in use by a live daemon — refusing to start",
                    path.display()
                ));
            }
            std::fs::remove_file(path)
                .with_context(|| format!("remove stale socket {}", path.display()))?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Fresh bind — fine.
        }
        Err(e) => {
            return Err(anyhow!("stat {} failed: {}", path.display(), e));
        }
    }
    UnixListener::bind(path).with_context(|| format!("bind uds {}", path.display()))
}

#[allow(clippy::too_many_arguments)]
fn run_listener(
    listener: UnixListener,
    db_path: PathBuf,
    uds_path: PathBuf,
    subscribers: Subscribers,
    counters: Arc<Counters>,
    started_at: Instant,
    global_shutdown: Arc<AtomicBool>,
    server_shutdown: Arc<AtomicBool>,
) {
    while !global_shutdown.load(Ordering::Relaxed) && !server_shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let subs = subscribers.clone();
                let cnt = counters.clone();
                let dbp = db_path.clone();
                let udsp = uds_path.clone();
                let st = started_at;
                let g = global_shutdown.clone();
                let s = server_shutdown.clone();
                let _ = thread::Builder::new()
                    .name("tsd-control-conn".into())
                    .spawn(move || handle_conn(stream, dbp, udsp, subs, cnt, st, g, s));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                error!(?e, "accept failed");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    let _ = std::fs::remove_file(&uds_path);
    debug!("control listener exiting");
}

#[allow(clippy::too_many_arguments)]
fn handle_conn(
    stream: UnixStream,
    db_path: PathBuf,
    uds_path: PathBuf,
    subscribers: Subscribers,
    counters: Arc<Counters>,
    started_at: Instant,
    global_shutdown: Arc<AtomicBool>,
    server_shutdown: Arc<AtomicBool>,
) {
    if let Err(e) = stream.set_read_timeout(Some(READ_REQUEST_TIMEOUT)) {
        warn!(?e, "set_read_timeout failed");
    }
    if let Err(e) = stream.set_write_timeout(Some(WRITE_TIMEOUT)) {
        warn!(?e, "set_write_timeout failed");
    }
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            warn!(?e, "dup stream failed");
            return;
        }
    });
    let mut writer = stream;

    let mut line = String::new();
    if reader
        .by_ref()
        .take(MAX_REQUEST_BYTES)
        .read_line(&mut line)
        .is_err()
    {
        return;
    }
    if line.is_empty() {
        return;
    }
    let req: Request = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            let err = ErrorResponse {
                error: format!("bad request: {e}"),
            };
            if let Ok(j) = serde_json::to_string(&err) {
                let _ = writeln!(writer, "{j}");
            }
            return;
        }
    };

    match req {
        Request::Status => {
            let resp = StatusResponse {
                protocol_version: PROTOCOL_VERSION,
                version: env!("CARGO_PKG_VERSION").to_string(),
                uptime_s: started_at.elapsed().as_secs(),
                db_path: db_path.display().to_string(),
                uds_path: uds_path.display().to_string(),
                probes_attached: probes_attached(),
                events_total: counters.events_total.load(Ordering::Relaxed),
                ringbuf_poll_errors: counters.ringbuf_poll_errors.load(Ordering::Relaxed),
                tail_subscribers_active: counters
                    .tail_subscribers_active
                    .load(Ordering::Relaxed),
            };
            let json = serde_json::to_string(&resp).unwrap_or_default();
            let _ = writeln!(writer, "{json}");
        }
        Request::Tail => {
            let (rx, _guard) = subscribers.register();
            // Block on recv with a periodic wakeup so we can notice
            // shutdown / client disconnect.
            while !global_shutdown.load(Ordering::Relaxed)
                && !server_shutdown.load(Ordering::Relaxed)
            {
                match rx.recv_timeout(Duration::from_millis(500)) {
                    Ok(line) => {
                        if writeln!(writer, "{line}").is_err() {
                            break;
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            // _guard drops here -> RAII unregister -> active-count
            // atomic stays accurate without waiting for next broadcast.
        }
    }
}

/// Static probe set for Phase 1.F. Phase 2 will derive this from the
/// runtime SkelStorage (per-program attach status).
fn probes_attached() -> Vec<String> {
    vec![
        "sched_exec".into(),
        "cgroup_connect4".into(),
        "cgroup_connect6".into(),
        "tcp_sendmsg".into(),
        "tcp_recvmsg".into(),
    ]
}

/// Resolve the default UDS path: $XDG_RUNTIME_DIR/tokenscope/tsd.sock,
/// falling back to /run/tokenscope/tsd.sock when XDG is unset.
pub fn default_uds_path() -> PathBuf {
    if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR") {
        if !rt.is_empty() {
            return Path::new(&rt).join("tokenscope").join("tsd.sock");
        }
    }
    PathBuf::from("/run/tokenscope/tsd.sock")
}
```

- [ ] **Step 3: Replace `crates/tsd/src/main.rs`**

Read the file first, then replace with:

```rust
//! TokenScope daemon (Phase 1.F).
//!
//! Loads BPF skeletons, drains ringbufs, periodically flushes the
//! per-socket byte counter map. Three sinks: stdout (live human
//! view, suppressible), DuckDB (queryable system of record), and the
//! Unix-domain control plane (status responses + live tail
//! subscriptions). SIGINT/SIGTERM flip an atomic flag so the main
//! loop and the control listener exit cleanly.

mod cgroup;
mod control;
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
use ts_core::control::TailEvent;
use ts_core::{decode_header, decode_net_connect, TsEventType};

use crate::control::{Counters, Subscribers};
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

    /// Suppress live stdout printing. The DuckDB sink and control
    /// plane still receive all events.
    #[arg(long)]
    no_stdout: bool,

    /// Path to the Unix domain socket tsctl connects to. Default:
    /// $XDG_RUNTIME_DIR/tokenscope/tsd.sock (falls back to /run/tokenscope/tsd.sock).
    #[arg(long, default_value_os_t = control::default_uds_path())]
    uds_path: PathBuf,

    /// Skip starting the control-plane listener.
    #[arg(long)]
    no_control: bool,
}

fn default_db_path() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("share")))
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

    info!("tsd starting (Phase 1.F — sched_exec + cgroup/connect + tcp bytes + DuckDB + UDS control)");
    info!(db_path = %args.db_path.display(), "opening store");

    let cgroup_root = cgroup::open_unified_root().context("open cgroup root")?;
    let mut storage = SkelStorage::new();
    let skels = load_all(&mut storage, cgroup_root).context("load skeletons")?;
    info!(flush_ms = args.flush_interval_ms, "BPF programs attached");

    let cache = RefCell::new(ProcessCache::new());
    let store = RefCell::new(Store::open(&args.db_path).context("open DuckDB store")?);
    let stdout_enabled = !args.no_stdout;

    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let s = shutdown.clone();
        ctrlc::set_handler(move || s.store(true, Ordering::SeqCst))
            .context("install signal handler")?;
    }

    let counters = Arc::new(Counters::default());
    let subscribers = Subscribers::new(counters.clone());
    let started_at = Instant::now();

    let _control_server = if args.no_control {
        info!("control plane disabled (--no-control)");
        None
    } else {
        Some(
            control::ControlServer::start(
                args.uds_path.clone(),
                args.db_path.clone(),
                subscribers.clone(),
                counters.clone(),
                started_at,
                shutdown.clone(),
            )
            .context("start control plane")?,
        )
    };

    let mut builder = RingBufferBuilder::new();
    builder
        .add(&skels.sched.maps.events, |data| {
            handle_event(data, &cache, &store, &subscribers, &counters, stdout_enabled)
        })
        .map_err(|e| anyhow!("add sched ringbuf: {e}"))?;
    builder
        .add(&skels.net.maps.events, |data| {
            handle_event(data, &cache, &store, &subscribers, &counters, stdout_enabled)
        })
        .map_err(|e| anyhow!("add net ringbuf: {e}"))?;
    let ringbuf = builder.build().map_err(|e| anyhow!("build ringbuf: {e}"))?;

    let flush_interval = Duration::from_millis(args.flush_interval_ms);
    let mut last_flush = Instant::now();

    while !shutdown.load(Ordering::Relaxed) {
        if let Err(e) = ringbuf.poll(Duration::from_millis(200)) {
            error!(?e, "ringbuf poll error");
            counters.ringbuf_poll_errors.fetch_add(1, Ordering::Relaxed);
        }
        if last_flush.elapsed() >= flush_interval {
            net_bytes::flush(
                &skels.net.maps.net_bytes,
                &cache,
                &store,
                &subscribers,
                &counters,
                stdout_enabled,
            );
            last_flush = Instant::now();
        }
    }

    info!("shutting down — flushing once and closing");
    net_bytes::flush(
        &skels.net.maps.net_bytes,
        &cache,
        &store,
        &subscribers,
        &counters,
        stdout_enabled,
    );
    // Drop order on scope exit:
    //   ringbuf  -> releases closure borrows on &subscribers / &counters / &store
    //   _control_server -> Drop flips its own shutdown, joins listener, removes socket
    //   store    -> closes DuckDB
    //   subscribers / counters -> Arcs go to zero
    // No explicit drops needed; the natural reverse-declaration order
    // handles everything.
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_event(
    data: &[u8],
    cache: &RefCell<ProcessCache>,
    store: &RefCell<Store>,
    subscribers: &Subscribers,
    counters: &Counters,
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
            let event = TailEvent::ProcExec {
                ts_ns: hdr.ts_ns,
                pid: hdr.pid,
                tgid: hdr.tgid,
                comm: comm.clone(),
                cmdline: cmdline.clone(),
                cgroup_id: format!("{:#x}", hdr.cgroup_id),
            };
            if let Ok(line) = serde_json::to_string(&event) {
                subscribers.broadcast(&line);
            }
            counters.events_total.fetch_add(1, Ordering::Relaxed);
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
                let event = TailEvent::NetConnect {
                    ts_ns: hdr.ts_ns,
                    pid: hdr.pid,
                    tgid: hdr.tgid,
                    comm: comm.clone(),
                    cmdline: cmdline.clone(),
                    cgroup_id: format!("{:#x}", hdr.cgroup_id),
                    dst: pl.dst_string(),
                    family: pl.family,
                    protocol: pl.protocol,
                };
                if let Ok(line) = serde_json::to_string(&event) {
                    subscribers.broadcast(&line);
                }
                counters.events_total.fetch_add(1, Ordering::Relaxed);
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

/// Wall-clock nanoseconds since UNIX epoch.
pub fn wall_clock_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
```

- [ ] **Step 4: Replace `crates/tsd/src/net_bytes.rs`**

Read the file first, then replace with:

```rust
//! Periodic flush of the BPF `net_bytes` LRU map.
//!
//! For each non-zero entry: optionally print a `NetBytes` line on
//! stdout, insert a row into `events_net_bytes`, broadcast a JSON
//! `NetBytes` event to tail subscribers, and bump the events_total
//! counter. Map entries are NOT cleared — cumulative until kernel LRU
//! eviction.

use std::cell::RefCell;
use std::sync::atomic::Ordering;

use tracing::warn;
use ts_bpf_sys::libbpf_rs::{MapCore, MapFlags, MapMut};
use ts_core::control::TailEvent;
use ts_core::{decode_net_bytes_key, decode_net_bytes_value};

use crate::control::{Counters, Subscribers};
use crate::proc_cache::ProcessCache;
use crate::store::Store;
use crate::wall_clock_ns;

#[allow(clippy::too_many_arguments)]
pub fn flush(
    map: &MapMut<'_>,
    cache: &RefCell<ProcessCache>,
    store: &RefCell<Store>,
    subscribers: &Subscribers,
    counters: &Counters,
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
        let event = TailEvent::NetBytes {
            snapshot_ts_ns: snapshot,
            sock_cookie: format!("{:#018x}", key.sock_cookie),
            pid: value.pid,
            comm: comm.clone(),
            cmdline: cmdline.clone(),
            tx: value.tx_bytes,
            rx: value.rx_bytes,
            last_event_ns: value.last_ns,
        };
        if let Ok(line) = serde_json::to_string(&event) {
            subscribers.broadcast(&line);
        }
        counters.events_total.fetch_add(1, Ordering::Relaxed);
    }
}
```

- [ ] **Step 5: Build + fmt + clippy**

```
cd /home/hoang/code/personal/active/tokenscope
cargo build -p tsd -j 2 2>&1 | tail -10
cargo fmt --all
cargo clippy --workspace --all-targets -j 2 -- -D warnings 2>&1 | tail -10
```

Expected: build clean, clippy clean.

- [ ] **Step 6: Run unit tests**

```
cd /home/hoang/code/personal/active/tokenscope
cargo test --workspace 2>&1 | grep -E "^test result|FAILED" | head -20
```

Expected: ts-core 20 (13 + 7 control), tsd 14 (no new lib tests yet — control is exercised through e2e in Task 4). All pass.

- [ ] **Step 7: Commit**

```
cd /home/hoang/code/personal/active/tokenscope
git add Cargo.lock crates/tsd/Cargo.toml crates/tsd/src/control.rs crates/tsd/src/main.rs crates/tsd/src/net_bytes.rs
git commit -m "feat(tsd): UDS control plane with safe startup, RAII subscribers, drop-safe shutdown"
```

---

## Task 3: tsctl — clap subcommands + `status` + `tail` **(INLINE)**

**Files:**
- Modify: `crates/tsctl/Cargo.toml`
- Modify: `crates/tsctl/src/main.rs`

**Why inline:** The CLI's UX is small but high-touch — flag parsing + UDS connect + ctrlc + JSON pretty-printing all need to feel cohesive.

- [ ] **Step 1: Update `crates/tsctl/Cargo.toml`**

Read it first, then replace `[dependencies]` with:

```toml
[dependencies]
clap       = { workspace = true }
anyhow     = { workspace = true }
serde      = { workspace = true }
serde_json = { workspace = true }
ctrlc      = { workspace = true }
ts-core    = { workspace = true }
```

(Note: no DuckDB, no tabled. `query` is deferred to Phase 1.G; when it lands it will route over UDS, so tsctl still won't need duckdb directly.)

- [ ] **Step 2: Replace `crates/tsctl/src/main.rs`**

```rust
//! TokenScope CLI (Phase 1.F).
//!
//! Two commands today:
//!   tsctl status               # one-shot daemon snapshot
//!   tsctl tail                 # live JSON event stream until Ctrl-C
//!
//! Both talk to tsd over a Unix domain socket. `tsctl query` lands in
//! Phase 1.G — DuckDB does not allow concurrent reader+writer across
//! processes, so query has to be routed through the daemon's own
//! connection.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

use ts_core::control::{ErrorResponse, Request, StatusResponse};

#[derive(Parser, Debug)]
#[command(name = "tsctl", version, about = "TokenScope CLI")]
struct Args {
    /// Path to the daemon's Unix domain socket.
    #[arg(long, default_value_os_t = default_uds_path(), global = true)]
    uds_path: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print build info and exit.
    Version,
    /// One-shot daemon status snapshot.
    Status,
    /// Live event stream from tsd. Exits on SIGINT.
    Tail,
}

fn default_uds_path() -> PathBuf {
    if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR") {
        if !rt.is_empty() {
            return PathBuf::from(rt).join("tokenscope").join("tsd.sock");
        }
    }
    PathBuf::from("/run/tokenscope/tsd.sock")
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.cmd {
        Cmd::Version => {
            println!("tsctl {}", env!("CARGO_PKG_VERSION"));
        }
        Cmd::Status => cmd_status(&args.uds_path)?,
        Cmd::Tail => cmd_tail(&args.uds_path)?,
    }
    Ok(())
}

fn connect(uds_path: &PathBuf) -> Result<UnixStream> {
    UnixStream::connect(uds_path)
        .with_context(|| format!("connect to tsd at {}", uds_path.display()))
}

fn cmd_status(uds_path: &PathBuf) -> Result<()> {
    let mut stream = connect(uds_path)?;
    let req = serde_json::to_string(&Request::Status)?;
    writeln!(stream, "{req}").context("write request")?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).context("read response")?;

    // The daemon may reply with an ErrorResponse on bad requests.
    if let Ok(err) = serde_json::from_str::<ErrorResponse>(line.trim()) {
        return Err(anyhow!("tsd error: {}", err.error));
    }
    let resp: StatusResponse =
        serde_json::from_str(line.trim()).context("decode StatusResponse")?;

    println!("tsd version            {}", resp.version);
    println!("protocol version       {}", resp.protocol_version);
    println!("uptime (s)             {}", resp.uptime_s);
    println!("db path                {}", resp.db_path);
    println!("uds path               {}", resp.uds_path);
    println!("probes                 {}", resp.probes_attached.join(", "));
    println!("events total           {}", resp.events_total);
    println!("ringbuf poll errors    {}", resp.ringbuf_poll_errors);
    println!("tail subscribers       {}", resp.tail_subscribers_active);
    Ok(())
}

fn cmd_tail(uds_path: &PathBuf) -> Result<()> {
    let mut stream = connect(uds_path)?;
    let req = serde_json::to_string(&Request::Tail)?;
    writeln!(stream, "{req}").context("write request")?;

    // SIGINT shuts down by closing the read side; the loop sees EOF.
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let s = shutdown.clone();
        ctrlc::set_handler(move || s.store(true, Ordering::SeqCst))
            .context("install signal handler")?;
    }
    // Read with a short timeout so we can poll the shutdown flag.
    stream
        .set_read_timeout(Some(Duration::from_millis(300)))
        .ok();
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        match line {
            Ok(l) => {
                println!("{l}");
                std::io::stdout().flush().ok();
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(anyhow!("read tail: {e}")),
        }
    }
    Ok(())
}
```

- [ ] **Step 3: Build + smoke test the help text**

```
cd /home/hoang/code/personal/active/tokenscope
cargo build -p tsctl -j 2 2>&1 | tail -10
./target/debug/tsctl --help
```

Expected: clean build (no DuckDB to compile this time — incremental). Help block lists `version`, `status`, `tail` and the global `--uds-path`.

- [ ] **Step 4: Format + clippy**

```
cd /home/hoang/code/personal/active/tokenscope
cargo fmt --all
cargo clippy -p tsctl -- -D warnings 2>&1 | tail -10
```

Expected: clean.

- [ ] **Step 5: Commit**

```
cd /home/hoang/code/personal/active/tokenscope
git add Cargo.lock crates/tsctl/Cargo.toml crates/tsctl/src/main.rs
git commit -m "feat(tsctl): status + tail subcommands over UDS (newline-delimited JSON)"
```

---

## Task 4: End-to-End Integration Test **(INLINE)**

**Files:**
- Create: `crates/tsd/tests/control_e2e.rs`

**Why inline:** Cross-binary lifecycle (tsd + tsctl as separate processes), real BPF, real UDS — every shortcut here masks a real bug.

- [ ] **Step 1: Create `crates/tsd/tests/control_e2e.rs`**

```rust
//! End-to-end test for the Phase 1.F control plane.
//!
//! Spawns tsd with a temp DB + temp UDS, drives some loopback TCP,
//! then exercises tsctl status + tsctl tail against the running
//! daemon and asserts each returns sensible output.
//!
//! Requires CAP_BPF or root; ignored by default.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::TempDir;
use ts_core::control::StatusResponse;

const PAYLOAD: &[u8] = &[b'P'; 1024];

fn target_dir() -> PathBuf {
    // CARGO_BIN_EXE_<name> only exists for the *current* test crate's
    // bins. tsd is the current crate; tsctl is a sibling — derive its
    // path from tsd's parent directory and ensure the binary exists
    // by running `cargo build -p tsctl` if needed.
    PathBuf::from(env!("CARGO_BIN_EXE_tsd"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn tsd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tsd"))
}

fn tsctl_bin() -> PathBuf {
    let candidate = target_dir().join("tsctl");
    if !candidate.exists() {
        // Build the sibling binary on demand. Using cargo from the
        // workspace root works under both bare `cargo test` and
        // `sudo -E env "PATH=$PATH" cargo test`.
        let status = Command::new("cargo")
            .args(["build", "--bin", "tsctl"])
            .status()
            .expect("invoke cargo build for tsctl");
        assert!(status.success(), "cargo build -p tsctl failed");
    }
    candidate
}

/// Drain a child's stderr in a separate thread so a full pipe
/// doesn't deadlock the daemon. Returns a handle; the caller can
/// `.join()` after `wait()` to inspect output if needed.
fn drain_stderr(child: &mut std::process::Child) -> thread::JoinHandle<String> {
    let mut stderr = child.stderr.take().expect("piped stderr");
    thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr.read_to_string(&mut buf);
        buf
    })
}

#[test]
#[ignore = "requires CAP_BPF or root; run with --include-ignored under sudo"]
fn control_plane_status_and_tail() {
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("events.duckdb");
    let uds_path = dir.path().join("tsd.sock");

    let tsd = tsd_bin();
    let tsctl = tsctl_bin();

    let mut child = Command::new(&tsd)
        .args([
            "--db-path",
            db_path.to_str().unwrap(),
            "--uds-path",
            uds_path.to_str().unwrap(),
            "--flush-interval-ms",
            "300",
            "--no-stdout",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tsd");
    let stderr_drain = drain_stderr(&mut child);

    // Wait for the UDS file to appear (tsd opens BPF + binds the socket).
    let deadline = Instant::now() + Duration::from_secs(5);
    while !uds_path.exists() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let logs = stderr_drain.join().unwrap_or_default();
            panic!(
                "tsd never created uds at {} — stderr: {}",
                uds_path.display(),
                logs
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    // Small extra grace for BPF attach to settle.
    thread::sleep(Duration::from_millis(400));

    // ---- Drive a known loopback transfer so tail/counters have data ----
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
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
    thread::sleep(Duration::from_millis(900)); // one flush window + margin

    // ---- tsctl status ----
    let out = Command::new(&tsctl)
        .args(["--uds-path", uds_path.to_str().unwrap(), "status"])
        .output()
        .expect("run tsctl status");
    assert!(
        out.status.success(),
        "tsctl status failed (stdout={:?}, stderr={:?})",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    eprintln!("--- tsctl status ---\n{stdout}");
    assert!(stdout.contains("tsd version"), "no version line: {stdout}");
    assert!(stdout.contains("probes"), "no probes line: {stdout}");
    assert!(
        stdout.contains("events total"),
        "no events line: {stdout}"
    );
    // Stronger assertion: events_total must be > 0 because we just
    // drove at least one connect + bytes flush. Re-issue the request
    // and parse the raw JSON to verify numerically.
    let raw_resp = raw_status_via_uds(&uds_path);
    eprintln!("raw status JSON: {raw_resp}");
    let parsed: StatusResponse =
        serde_json::from_str(&raw_resp).expect("StatusResponse parses");
    assert!(parsed.events_total > 0, "events_total was 0: {parsed:?}");
    assert!(
        parsed.probes_attached.contains(&"sched_exec".into()),
        "probes_attached missing sched_exec: {:?}",
        parsed.probes_attached
    );

    // ---- tsctl tail (background; capture for ~2s, then SIGINT) ----
    // Trigger more events AFTER subscribing to guarantee the
    // subscriber sees them — easier than racing pre-subscribed events.
    let mut tail = Command::new(&tsctl)
        .args(["--uds-path", uds_path.to_str().unwrap(), "tail"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn tsctl tail");
    thread::sleep(Duration::from_millis(400)); // let it subscribe
    for _ in 0..5 {
        let _ = std::process::Command::new("/bin/true").status();
    }
    thread::sleep(Duration::from_millis(1500));
    unsafe { libc::kill(tail.id() as i32, libc::SIGINT) };

    // Read tail's stdout BEFORE wait — wait may not return promptly
    // if the child holds stdio open.
    let mut tail_out = String::new();
    if let Some(mut s) = tail.stdout.take() {
        // Best-effort short read; if SIGINT closed stdin/out the
        // read returns immediately.
        let _ = s.read_to_string(&mut tail_out);
    }
    let _ = tail.wait();

    eprintln!("--- tsctl tail ---\n{tail_out}");
    let line_count = tail_out
        .lines()
        .filter(|l| serde_json::from_str::<Value>(l).is_ok())
        .count();
    assert!(
        line_count >= 1,
        "tail produced no JSON event lines (raw: {tail_out:?})"
    );

    // ---- Shutdown ----
    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    let status = child.wait().expect("wait tsd");
    assert!(status.success(), "tsd exited non-zero: {status}");
    let _ = stderr_drain.join();

    // ---- Verify socket cleanup ----
    assert!(
        !uds_path.exists(),
        "tsd should have removed {} on shutdown",
        uds_path.display()
    );
}

/// Send a Status request directly to the daemon and return the raw
/// JSON line. Used for assertions that need the typed response.
fn raw_status_via_uds(uds_path: &std::path::Path) -> String {
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixStream;
    let mut s = UnixStream::connect(uds_path).expect("connect uds");
    s.write_all(b"{\"op\":\"status\"}\n").expect("write request");
    let mut reader = BufReader::new(s);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read response");
    line.trim().to_string()
}
```

- [ ] **Step 2: Pre-build tsctl so the test sees it on disk**

```
cd /home/hoang/code/personal/active/tokenscope
cargo build --bin tsctl -j 2 2>&1 | tail -5
cargo build --tests -p tsd -j 2 2>&1 | tail -10
```

Expected: clean. The test will also try to build tsctl on demand if missing, but doing it up front saves the integration run from a slow rebuild.

- [ ] **Step 3: Ask the user to run the integration suite**

User runs:
```
cd /home/hoang/code/personal/active/tokenscope && sudo -E env "PATH=$PATH" /home/hoang/.cargo/bin/cargo test -p tsd -- --ignored --nocapture
```

Expected: 6 integration tests pass — the 5 from prior phases plus `control_plane_status_and_tail`. Output should include `--- tsctl status ---` showing the populated status block, the raw status JSON line, and `--- tsctl tail ---` showing one or more JSON event lines (`{"type":"proc_exec",...}` from `/bin/true` invocations, or `{"type":"net_*",...}` from the loopback transfer).

If `tsctl tail` shows zero events:
1. Increase the `thread::sleep(Duration::from_millis(1500))` after the trigger to 2500.
2. Confirm `tsctl tail` actually subscribed by checking `parsed.tail_subscribers_active` was > 0 in the status response (extend the test if needed).
3. Make sure the daemon isn't filtering / coalescing events via `--no-stdout` — that flag only suppresses prints, not the broadcast.

- [ ] **Step 4: Commit**

```
cd /home/hoang/code/personal/active/tokenscope
git add crates/tsd/tests/control_e2e.rs
git commit -m "test(tsd): e2e — tsctl status + tail against running tsd"
```

---

## Task 5: Phase 1.F Wrap-up — DOC.md, Tag, optional LEARNED.md **(INLINE)**

**Files:**
- Modify: `DOC.md`

- [ ] **Step 1: Run all gates**

```
cd /home/hoang/code/personal/active/tokenscope
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: all clean. ts-core 20 (13 + 7 control), tsd 14 (unchanged from 1.E — control plane is exercised through e2e, not via lib unit tests).

- [ ] **Step 2: Update DOC.md — insert above Phase 1.E**

Edit `DOC.md`. Find `### Phase 1.E — DuckDB Sink` and insert ABOVE it:

```markdown
### Phase 1.F — tsctl Control Plane (shipped 2026-05-06, tag `v0.0.7-phase1f`)

`tsd` now opens a Unix-domain socket at `${XDG_RUNTIME_DIR}/tokenscope/tsd.sock` (or `/run/tokenscope/tsd.sock` for system-mode) and `tsctl` ships two subcommands that talk to it: `tsctl status` (one-shot snapshot — uptime, db path, probe set, events_total, ringbuf_poll_errors, active tail subscribers) and `tsctl tail` (live newline-delimited JSON event stream, `Ctrl-C` to stop).

Architecture: tsd spawns one OS thread that owns the listener; per accepted connection it spawns a short worker thread. The main loop publishes events via a non-blocking try_send to a `HashMap<u64, SyncSender<String>>` of subscribers — slow tail clients drop frames, ingest is never blocked. Subscribers are RAII (Drop guard removes from registry → `tail_subscribers_active` atomic stays accurate). `ControlServer::Drop` flips a server-local shutdown flag before joining the listener so early-return code paths cannot deadlock. Safe socket startup probes for a live daemon (try connect) and refuses to overwrite anything that isn't a stale socket.

Wire types live in `ts_core::control` with full serde derives. JSON tag is `op` for requests and `type` for tail events; bad requests come back as a typed `ErrorResponse {"error": "..."}`. Per SPEC §10 these are stable surfaces — adding variants is a minor bump in pre-1.0; renames/removes are major.

**Codex second-opinion review caught three blockers in the initial plan** (DuckDB cross-process query unsafe; ControlServer::Drop deadlock; blind socket unlink) and several should-fixes (RAII subscriber unregister; read/write timeouts; max request line length). All were folded into the final design before any code was written.

**Gate evidence (verified 2026-05-06):**
- `cargo fmt --check` / `cargo clippy --workspace --all-targets -- -D warnings` clean
- `cargo test --workspace` — ts-core 20 (13 + 7 control round-trip) + tsd lib 14 = 34 unit tests pass
- `sudo cargo test -p tsd -- --ignored` — 6 integration tests pass
  - `control_plane_status_and_tail` confirms a live tsd answers `tsctl status` (with `events_total > 0` after a known transfer) and `tsctl tail` (≥ 1 JSON event line from /bin/true triggers)
- Plan: `docs/superpowers/plans/2026-05-06-phase-1f-tsctl-control-plane.md`

**Known gaps:**
- `tsctl query <SQL>` deferred to Phase 1.G — DuckDB does not allow concurrent reader+writer across processes; query has to be routed over UDS so the daemon's connection executes it
- Tail filters (`--filter 'provider=anthropic'`) — Phase 2 once parsers exist
- `tsctl probes attach/detach` — Phase 2 (probe set is fixed at compile time today)
- No authentication beyond UDS file permissions (0600 socket, 0700 parent dir); root or the tsd user can subscribe
- No reconnection / retry in `tsctl tail` — if tsd restarts, tail exits
- `ringbuf_poll_errors` is the userspace `poll()` error count, NOT a true BPF ringbuf-drop counter; the latter needs `bpf_ringbuf_query(0)` and lands in Phase 2
- Release builds with `panic = "abort"` skip Drop, so the socket file can be left on the floor by an OOM kill or panic; safe-bind handles this on next start

### Phase 1.E — DuckDB Sink (shipped 2026-05-06, tag `v0.0.6-phase1e`)
```

- [ ] **Step 3: Commit DOC.md and tag**

```
cd /home/hoang/code/personal/active/tokenscope
git add DOC.md
git commit -m "docs: mark Phase 1.F shipped (tsctl control plane) with gate evidence"
git tag -a v0.0.7-phase1f -m "Phase 1.F — tsctl Control Plane (status + tail)"
git tag --list
```

Expected: tag list includes `v0.0.7-phase1f`.

- [ ] **Step 4: Append a LEARNED.md note (only if non-trivial)**

If the implementation surfaced anything genuinely worth keeping (e.g., a quirk in DuckDB's locking, a non-obvious thread-safety pitfall, or a cleanup-on-drop gotcha), append it to `~/.claude/LEARNED.md`. If everything went textbook, skip.

---

## Definition of Done (Phase 1.F acceptance gate)

All must be true:
1. `cargo build --workspace` succeeds.
2. `cargo test --workspace` exits 0 (ts-core 20 + tsd 14 = 34 unit tests).
3. `sudo cargo test -p tsd -- --ignored` exits 0 — 6 integration tests pass including `control_plane_status_and_tail`.
4. Live: `sudo tsd --no-stdout &` then `tsctl status` prints a populated block; `tsctl tail` prints JSON event lines (try `curl example.com` in another terminal); Ctrl-C ends tail cleanly.
5. `cargo fmt --check` and `cargo clippy -D warnings` clean.
6. `tsctl --help` lists `version`, `status`, `tail` subcommands and the global `--uds-path` flag.
7. Starting a second `tsd` against the same `--uds-path` while the first is alive errors out (not silently overwriting the socket).
8. DOC.md reflects Phase 1.F shipped.
9. Git tag `v0.0.7-phase1f` exists locally.

---

## Self-Review Notes

**Spec coverage check (SPEC §11 Phase 1, item 4 of 4):**
- "tsctl status and tsctl tail" → both shipped ✓
- `tsctl query` was originally proposed but is correctly deferred — DuckDB's documented model is one writer OR many readers, not mixed across processes. Phase 1.G will route SQL over UDS.

**Type/name consistency:**
- `Request` enum (`Status`, `Tail`) consistent across `ts-core::control` definition, tsd dispatch (`Request::Status` / `Request::Tail` arms), and tsctl construction.
- `StatusResponse` field names (`protocol_version`, `version`, `uptime_s`, `db_path`, `uds_path`, `probes_attached`, `events_total`, `ringbuf_poll_errors`, `tail_subscribers_active`) consistent across the type def, tsd's response construction, tsctl's pretty-print, AND the e2e test's typed parsing.
- `TailEvent` variant names (`ProcExec`, `NetConnect`, `NetBytes`) and field names match between definition + tsd's emission in `handle_event` + `net_bytes::flush`.
- `ErrorResponse {error: String}` matches between server emission (Task 2) and tsctl detection (Task 3).
- `Counters` struct field order matches between definition (Task 2 step 2) and call sites (`events_total.fetch_add`, `ringbuf_poll_errors.fetch_add`, `tail_subscribers_active.store`).
- `default_uds_path` lives in *both* `tsd::control` and `tsctl::main` — duplicated by design (so tsctl doesn't pull tsd as a dep). They MUST stay in sync; covered by the integration test connecting via the same default path resolution.

**Placeholder scrub:** none of the forbidden phrases appear.

**Borrow-checker plan:**
- `Subscribers` is `Clone` (Arc-wrapped Mutex + Atomics) — passed by reference into ringbuf closures; cloned at the listener-thread spawn boundary.
- `Counters` lives behind `Arc` — closures borrow `&Counters`; the underlying atomics are inherently shared.
- Drop order in `main()`: ringbuf (releases closure borrows on `&subscribers` and `&counters`) → `_control_server` (Drop flips server_shutdown, joins listener, removes socket) → `store` (closes DuckDB) → `subscribers` / `counters` (Arcs go to zero). All natural; no explicit drops needed.

**Concurrency safety:**
- One main thread does ringbuf poll + flush + broadcast.
- One listener thread does accept; spawns one short worker per connection.
- Worker threads only ever do: receive from a channel they own, write to their own UnixStream. No shared mutability beyond the atomic counters and the Mutex-guarded subscriber HashMap.
- Broadcast under `Mutex<HashMap<...>>` is briefly held during `retain`; each `try_send` is non-blocking.
- RAII `SubscriberGuard` releases its slot on drop — no orphaned subscribers, even on panic / early return.

**Crash-safety / cleanup:**
- `ControlServer::Drop` flips its own `server_shutdown` flag before joining the listener. Even if the global shutdown was never set (early-return error path), the listener thread observes the local flag and exits.
- Listener also removes the socket on its normal exit path (belt-and-suspenders alongside the explicit `remove_file` in `Drop`).
- A SIGKILL'd or `panic = "abort"`-killed daemon leaves a stale socket; `safe_bind` handles it on the next start.

**Codex review compliance:**
- BLOCKING: DuckDB cross-process query → deferred to 1.G ✓
- BLOCKING: Drop deadlock → server_shutdown flag flipped in Drop ✓
- BLOCKING: blind socket unlink → safe_bind with file-type + connect probe ✓
- SHOULD-FIX: blocking write → 1 s write timeout ✓
- SHOULD-FIX: lazy subscriber cleanup → RAII guard ✓
- SHOULD-FIX: unbounded request size → 64 KiB cap + 5 s read timeout ✓
- SHOULD-FIX: hand-built error JSON → typed `ErrorResponse` ✓
- SHOULD-FIX: misnamed `ringbuf_drops` → `ringbuf_poll_errors` ✓
- NIT: tsctl sibling not built by `cargo test -p tsd` → test prebuilds via `cargo build --bin tsctl` and prologue in test re-checks ✓
- NIT: stderr undrained → dedicated drain thread ✓
- NIT: tail timing race → tail spawns first, triggers happen after ✓
- NIT: status assertion too loose → typed parse + numeric `events_total > 0` ✓

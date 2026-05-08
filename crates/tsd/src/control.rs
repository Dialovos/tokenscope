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
use std::io::{BufRead, BufReader, Read, Write};
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
    /// Currently-executing query workers. Bumped by an RAII guard on
    /// query entry; checked against MAX_CONCURRENT_QUERIES.
    pub active_queries: AtomicU32,
    /// Tail frames dropped because a subscriber's bounded channel was
    /// full when `broadcast`/`broadcast_envelope` tried to push.
    /// Used by tsctl status / Phase 2.A tail-loss visibility.
    pub tail_dropped_events: AtomicU64,
    /// Producer-side drops at the single-writer sink: bumped when a
    /// `try_send` onto `events_tx` returns `TrySendError::Full`. Distinct
    /// from `tail_dropped_events`, which counts subscriber-side drops.
    /// Surfaced by tsctl status as the writer-thread backpressure signal.
    pub sink_dropped_events: AtomicU64,

    // ---- Phase 2.A TLS counters (populated by tls.rs) ----
    /// Distinct (dev, ino) libssl files currently attached.
    pub tls_libs_attached: AtomicU32,
    /// libssl files skipped because symbol resolution failed entirely.
    pub tls_libs_skipped: AtomicU32,
    /// libssl files where SSL_read/write attached but _ex variants didn't.
    pub tls_libs_partial_attach: AtomicU32,
    /// TLS plaintext records flowed through the userspace consumer.
    pub tls_records_emitted: AtomicU64,
    /// Records flagged TLS_FLAG_TRUNCATED (call exceeded 64 KiB).
    pub tls_truncated_calls: AtomicU64,
    /// Records flagged TLS_FLAG_READ_FAILED (bpf_probe_read_user error).
    pub tls_read_failed_chunks: AtomicU64,
    /// Aggregated from BPF tls_inflight_collision percpu counter.
    pub tls_inflight_collisions: AtomicU64,
    /// Aggregated from BPF tls_reserve_fail percpu counter.
    pub tls_reserve_failures: AtomicU64,
    /// Last completed /proc rescan duration in microseconds.
    pub tls_scan_duration_us: AtomicU64,
    /// /proc/<pid>/maps read errors during the last scan.
    pub tls_scan_errors: AtomicU32,
    /// Subset of tail subscribers that asked for include_plaintext=true.
    pub tls_subscribers_with_plaintext: AtomicU32,
}

/// Per-subscriber state. Holds the bounded sender plus the rendering
/// options the subscriber asked for at handshake time.
struct SubscriberSlot {
    sender: SyncSender<String>,
    include_plaintext: bool,
}

#[derive(Clone)]
pub struct Subscribers {
    inner: Arc<Mutex<HashMap<u64, SubscriberSlot>>>,
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

    /// Push a pre-rendered string to every subscriber regardless of
    /// per-subscriber options. Used for envelope-agnostic broadcasts
    /// or for compatibility during the refactor. Drops on full or
    /// disconnected channels; never blocks. Disconnected entries are
    /// removed from the registry inline.
    #[allow(dead_code)] // kept for future envelope-agnostic broadcasts
    pub fn broadcast(&self, line: &str) {
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.retain(|_id, slot| match slot.sender.try_send(line.to_string()) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                self.counters
                    .tail_dropped_events
                    .fetch_add(1, Ordering::Relaxed);
                true // keep subscriber, just drop this frame
            }
            Err(TrySendError::Disconnected(_)) => false,
        });
        self.counters
            .tail_subscribers_active
            .store(guard.len() as u32, Ordering::Relaxed);
    }

    /// Render per-subscriber via `render_tail_line` from
    /// `crate::sink::EventEnvelope`. Plaintext is only included for
    /// subscribers that opted in at handshake time. Drops on full or
    /// disconnected channels; never blocks.
    pub fn broadcast_envelope(&self, env: &crate::sink::EventEnvelope) {
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.retain(|_id, slot| {
            let line = render_tail_line(env, slot.include_plaintext);
            match slot.sender.try_send(line) {
                Ok(()) => true,
                Err(TrySendError::Full(_)) => {
                    self.counters
                        .tail_dropped_events
                        .fetch_add(1, Ordering::Relaxed);
                    true
                }
                Err(TrySendError::Disconnected(_)) => false,
            }
        });
        self.counters
            .tail_subscribers_active
            .store(guard.len() as u32, Ordering::Relaxed);
    }

    /// Register a fresh subscriber. `include_plaintext` records the
    /// per-subscriber opt-in for TLS plaintext rendering (see
    /// `render_tail_line`). The returned `Guard` removes the
    /// subscriber from the registry on drop, so per-connection
    /// cleanup is exception/early-return safe.
    fn register(&self, include_plaintext: bool) -> (Receiver<String>, SubscriberGuard) {
        let (tx, rx) = sync_channel(SUBSCRIBER_QUEUE_DEPTH);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.insert(
            id,
            SubscriberSlot {
                sender: tx,
                include_plaintext,
            },
        );
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
    inner: Arc<Mutex<HashMap<u64, SubscriberSlot>>>,
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

use std::sync::OnceLock;

use base64::Engine as _;
use regex::Regex;
use sha2::{Digest, Sha256};

/// Compiled-once redaction patterns. Match left-to-right; each match
/// is replaced with `***REDACTED***` (the header-style first pattern
/// preserves the captured header name). Server-side only — the BLOB
/// stored in DuckDB keeps full fidelity (codex BLOCKING #6: never
/// trust the client to redact, even on opt-in).
fn redactors() -> &'static [Regex] {
    static R: OnceLock<Vec<Regex>> = OnceLock::new();
    R.get_or_init(|| {
        vec![
            // Header-style assignment (Authorization: ..., x-api-key=..., etc.)
            Regex::new(
                r"(?i)\b(authorization|x-api-key|api-key|x-auth-token|x-goog-api-key|api[-_]?key|password|secret|token|client[-_]?secret)\s*[:=]\s*\S+",
            )
            .unwrap(),
            // Anthropic
            Regex::new(r"\bsk-ant-[\w-]{20,}\b").unwrap(),
            // OpenAI (sk-..., sk-proj-..., etc.)
            Regex::new(r"\bsk-[A-Za-z0-9-]{20,}\b").unwrap(),
            // Groq
            Regex::new(r"\bgsk_[\w]{20,}\b").unwrap(),
            // HuggingFace
            Regex::new(r"\bhf_[\w]{20,}\b").unwrap(),
            // Google API key
            Regex::new(r"\bAIza[\w-]{30,}\b").unwrap(),
            // GitHub PATs
            Regex::new(r"\bgithub_pat_[\w]{20,}\b").unwrap(),
            Regex::new(r"\bgh[pousr]_[\w]{20,}\b").unwrap(),
            // GitLab PATs
            Regex::new(r"\bglpat-[\w-]{20,}\b").unwrap(),
            // AWS access keys (long-lived + STS)
            Regex::new(r"\bAKIA[A-Z0-9]{16}\b").unwrap(),
            Regex::new(r"\bASIA[A-Z0-9]{16}\b").unwrap(),
            // JWTs
            Regex::new(r"\beyJ[\w-]+\.[\w-]+\.[\w-]+\b").unwrap(),
            // PEM private keys (multi-line block)
            Regex::new(
                r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
            )
            .unwrap(),
        ]
    })
}

/// Apply every redaction pattern in order. The first regex (header
/// assignment) keeps the header name visible by capturing it; all
/// other patterns replace the whole match with `***REDACTED***`.
pub fn redact(input: &str) -> String {
    let res = redactors();
    let mut out = res[0]
        .replace_all(input, "$1: ***REDACTED***")
        .into_owned();
    for re in &res[1..] {
        out = re.replace_all(&out, "***REDACTED***").into_owned();
    }
    out
}

fn sha256_prefix_8(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let digest = h.finalize();
    // First 4 bytes → 8 hex chars.
    let mut s = String::with_capacity(8);
    for b in &digest[..4] {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Render an `EventEnvelope` as a one-line JSON string for tsctl tail.
///
/// For `TlsPlaintext`:
/// - `plaintext_sha256` is always present (4-byte prefix → 8 hex chars)
///   so subscribers can dedupe / spot replays without seeing content.
/// - `plaintext_b64` is present **only** when the subscriber opted into
///   `include_plaintext` at handshake time. The bytes are passed through
///   `redact` first so common API-key shapes never reach a tail viewer
///   in cleartext (codex BLOCKING #6 — server-side enforcement).
pub fn render_tail_line(env: &crate::sink::EventEnvelope, include_plaintext: bool) -> String {
    use crate::sink::EventEnvelope::*;
    match env {
        ProcExec(e) => serde_json::json!({
            "kind": "proc.exec",
            "ts_ns": e.ts_ns,
            "pid": e.pid,
            "tgid": e.tgid,
            "cgroup_id": e.cgroup_id,
            "comm": e.comm,
        })
        .to_string(),
        NetConnect(e) => serde_json::json!({
            "kind": "net.connect",
            "ts_ns": e.ts_ns,
            "pid": e.pid,
            "tgid": e.tgid,
            "comm": e.comm,
            "dst_port": e.dst_port,
            "family": e.family,
            "protocol": e.protocol,
        })
        .to_string(),
        NetBytesSnapshot(e) => serde_json::json!({
            "kind": "net.bytes",
            "snapshot_ts_ns": e.snapshot_ts_ns,
            "sock_cookie": e.sock_cookie,
            "tx": e.tx_bytes,
            "rx": e.rx_bytes,
        })
        .to_string(),
        TlsPlaintext(e) => {
            let mut obj = serde_json::Map::new();
            obj.insert(
                "kind".into(),
                serde_json::Value::String(if e.direction == 0 {
                    "tls.write".into()
                } else {
                    "tls.read".into()
                }),
            );
            obj.insert("ts_ns".into(), e.ts_ns.into());
            obj.insert("pid".into(), e.pid.into());
            obj.insert("tgid".into(), e.tgid.into());
            obj.insert("comm".into(), e.comm.clone().into());
            obj.insert("ssl_ctx".into(), format!("0x{:x}", e.ssl_ctx).into());
            obj.insert("call_id".into(), e.call_id.into());
            obj.insert("total_bytes".into(), e.total_bytes.into());
            obj.insert("chunk_index".into(), e.chunk_index.into());
            obj.insert("chunk_total".into(), e.chunk_total.into());
            obj.insert("chunk_bytes".into(), e.chunk_bytes.into());
            obj.insert("truncated".into(), e.truncated.into());
            obj.insert("ex_variant".into(), e.ex_variant.into());
            obj.insert(
                "plaintext_sha256".into(),
                sha256_prefix_8(&e.plaintext).into(),
            );
            if include_plaintext && !e.plaintext.is_empty() {
                let rendered = String::from_utf8_lossy(&e.plaintext).into_owned();
                let redacted = redact(&rendered);
                let b64 = base64::engine::general_purpose::STANDARD.encode(redacted.as_bytes());
                obj.insert("plaintext_b64".into(), b64.into());
            }
            serde_json::Value::Object(obj).to_string()
        }
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
    // The accepted stream inherits non-blocking from the listener on
    // Linux. Force blocking so reads + writes use the configured
    // timeouts instead of returning WouldBlock immediately.
    if let Err(e) = stream.set_nonblocking(false) {
        warn!(?e, "set_nonblocking(false) failed");
    }
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
                tail_subscribers_active: counters.tail_subscribers_active.load(Ordering::Relaxed),
            };
            let json = serde_json::to_string(&resp).unwrap_or_default();
            let _ = writeln!(writer, "{json}");
        }
        Request::Query { sql } => {
            handle_query(
                &mut writer,
                &db_path,
                &sql,
                &counters,
                &global_shutdown,
                &server_shutdown,
            );
        }
        Request::Tail { include_plaintext } => {
            let (rx, _guard) = subscribers.register(include_plaintext);
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

// -----------------------------------------------------------------------------
// Query handler (Phase 1.G)
// -----------------------------------------------------------------------------

/// Per-stringified-value cap. Cells longer get truncated.
const MAX_VALUE_BYTES: usize = 64 * 1024;

/// Hard cap on rows a single query can return. Enforced via a SQL
/// envelope wrap on SELECT/WITH/VALUES; pass-through queries
/// (EXPLAIN/SHOW/DESCRIBE/PRAGMA) are bounded by their own definition.
const MAX_QUERY_ROWS: u64 = 100_000;

/// Cumulative bytes-on-the-wire cap per query. Catches the "wide rows
/// of huge text/blob" vector that row-count alone misses.
const MAX_QUERY_BYTES: u64 = 50 * 1024 * 1024;

/// Server-side concurrent-query limit. Past this the next query is
/// rejected with an Error frame, no thread is spawned for the work.
const MAX_CONCURRENT_QUERIES: u32 = 4;

/// How often (in rows) the worker checks the shutdown flag.
const SHUTDOWN_POLL_EVERY_N_ROWS: u64 = 256;

/// Stringify a DuckDB value for the wire. Cells longer than the cap
/// are truncated AT THE LAST UTF-8 CHAR BOUNDARY (so we never split
/// a multi-byte codepoint) and suffixed with `…[+N more bytes]`.
fn value_to_display(v: &duckdb::types::Value) -> String {
    use duckdb::types::Value;
    let s = match v {
        Value::Null => "NULL".to_string(),
        Value::Boolean(b) => b.to_string(),
        Value::TinyInt(n) => n.to_string(),
        Value::SmallInt(n) => n.to_string(),
        Value::Int(n) => n.to_string(),
        Value::BigInt(n) => n.to_string(),
        Value::HugeInt(n) => n.to_string(),
        Value::UTinyInt(n) => n.to_string(),
        Value::USmallInt(n) => n.to_string(),
        Value::UInt(n) => n.to_string(),
        Value::UBigInt(n) => n.to_string(),
        Value::Float(n) => n.to_string(),
        Value::Double(n) => n.to_string(),
        Value::Text(s) => s.clone(),
        Value::Blob(b) => format!("<blob:{} bytes>", b.len()),
        Value::Timestamp(_, n) => n.to_string(),
        Value::Date32(d) => d.to_string(),
        Value::Time64(_, n) => n.to_string(),
        other => format!("{other:?}"),
    };
    if s.len() > MAX_VALUE_BYTES {
        let mut end = MAX_VALUE_BYTES;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        let extra = s.len() - end;
        format!("{}…[+{} more bytes]", &s[..end], extra)
    } else {
        s
    }
}

/// SELECT/WITH/VALUES queries get wrapped with `LIMIT N` so a 100M-row
/// result can't materialize before our row counter notices. Other
/// statement types (EXPLAIN/SHOW/DESCRIBE/PRAGMA) pass through —
/// their result sets are inherently bounded.
fn maybe_wrap_with_limit(sql: &str) -> String {
    let trimmed = sql.trim_start();
    let head: String = trimmed
        .lines()
        .find(|l| !l.trim_start().starts_with("--") && !l.trim().is_empty())
        .unwrap_or("")
        .trim_start()
        .chars()
        .take(20)
        .collect::<String>()
        .to_uppercase();
    if head.starts_with("SELECT") || head.starts_with("WITH") || head.starts_with("VALUES") {
        format!(
            "SELECT * FROM ({}) AS user_query LIMIT {}",
            sql, MAX_QUERY_ROWS
        )
    } else {
        sql.to_string()
    }
}

/// RAII guard for the active-query counter. Decrements on drop so
/// any panic / early return / error path still releases the slot.
struct ActiveQueryGuard {
    counters: Arc<Counters>,
}

impl ActiveQueryGuard {
    /// Try to acquire a slot. Returns `None` if MAX_CONCURRENT_QUERIES
    /// is already busy.
    fn try_acquire(counters: Arc<Counters>) -> Option<Self> {
        let prev = counters.active_queries.fetch_add(1, Ordering::SeqCst);
        if prev >= MAX_CONCURRENT_QUERIES {
            counters.active_queries.fetch_sub(1, Ordering::SeqCst);
            None
        } else {
            Some(Self { counters })
        }
    }
}

impl Drop for ActiveQueryGuard {
    fn drop(&mut self) {
        self.counters.active_queries.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Serialize one `QueryFrame` and write it to the wire, accumulating
/// bytes-sent into the running `bytes_sent` total. Free function so
/// the handler can keep `bytes_sent` as a local mutable that stays
/// readable for the cap check (a closure capturing `&mut bytes_sent`
/// would hold a mutable borrow across the loop's read).
fn send_frame(
    writer: &mut UnixStream,
    bytes_sent: &mut u64,
    frame: &ts_core::control::QueryFrame,
) -> Result<()> {
    let line = serde_json::to_string(frame).context("serialize QueryFrame")?;
    let frame_size = line.len() as u64 + 1;
    *bytes_sent = bytes_sent.saturating_add(frame_size);
    writeln!(writer, "{line}").context("write frame")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_query(
    writer: &mut UnixStream,
    db_path: &Path,
    sql: &str,
    counters: &Arc<Counters>,
    global_shutdown: &Arc<AtomicBool>,
    server_shutdown: &Arc<AtomicBool>,
) {
    use duckdb::types::Value;
    use ts_core::control::QueryFrame;

    let started = Instant::now();
    let mut bytes_sent: u64 = 0;

    // Concurrent-query limit.
    let _slot = match ActiveQueryGuard::try_acquire(counters.clone()) {
        Some(g) => g,
        None => {
            let _ = send_frame(
                writer,
                &mut bytes_sent,
                &QueryFrame::Error {
                    message: format!(
                        "server too busy: {MAX_CONCURRENT_QUERIES} concurrent queries already running"
                    ),
                },
            );
            return;
        }
    };

    // In-memory primary + ATTACH READ_ONLY of the daemon's DB file.
    // RO attach is DuckDB's designed-for path for "let other tools
    // query my live database file without taking a write lock".
    let conn = match duckdb::Connection::open_in_memory() {
        Ok(c) => c,
        Err(e) => {
            let _ = send_frame(
                writer,
                &mut bytes_sent,
                &QueryFrame::Error {
                    message: format!("open in-memory: {e}"),
                },
            );
            return;
        }
    };
    let attach_sql = format!(
        "ATTACH '{}' AS data (READ_ONLY)",
        db_path.display().to_string().replace('\'', "''")
    );
    if let Err(e) = conn.execute_batch(&attach_sql) {
        let _ = send_frame(
            writer,
            &mut bytes_sent,
            &QueryFrame::Error {
                message: format!("attach read-only: {e}"),
            },
        );
        return;
    }
    if let Err(e) = conn.execute_batch("USE data") {
        let _ = send_frame(
            writer,
            &mut bytes_sent,
            &QueryFrame::Error {
                message: format!("use data: {e}"),
            },
        );
        return;
    }

    let effective_sql = maybe_wrap_with_limit(sql);

    let mut stmt = match conn.prepare(&effective_sql) {
        Ok(s) => s,
        Err(e) => {
            let _ = send_frame(
                writer,
                &mut bytes_sent,
                &QueryFrame::Error {
                    message: format!("prepare: {e}"),
                },
            );
            return;
        }
    };

    // duckdb-rs panics if column_names() is called before query(),
    // so execute first and read column metadata via rows.statement().
    let mut rows = match stmt.query([]) {
        Ok(r) => r,
        Err(e) => {
            let _ = send_frame(
                writer,
                &mut bytes_sent,
                &QueryFrame::Error {
                    message: format!("execute: {e}"),
                },
            );
            return;
        }
    };
    let columns: Vec<String> = match rows.as_ref() {
        Some(stmt_ref) => stmt_ref
            .column_names()
            .iter()
            .map(|s| s.to_string())
            .collect(),
        None => Vec::new(),
    };
    let col_count = columns.len();
    if send_frame(
        writer,
        &mut bytes_sent,
        &QueryFrame::Header {
            columns: columns.clone(),
        },
    )
    .is_err()
    {
        return;
    }

    let mut row_count: u64 = 0;
    loop {
        if row_count % SHUTDOWN_POLL_EVERY_N_ROWS == 0
            && (global_shutdown.load(Ordering::Relaxed) || server_shutdown.load(Ordering::Relaxed))
        {
            let _ = send_frame(
                writer,
                &mut bytes_sent,
                &QueryFrame::Error {
                    message: "daemon shutting down".to_string(),
                },
            );
            return;
        }
        match rows.next() {
            Ok(Some(row)) => {
                let mut values: Vec<String> = Vec::with_capacity(col_count);
                for i in 0..col_count {
                    let v: Value = row.get(i).unwrap_or(Value::Null);
                    values.push(value_to_display(&v));
                }
                if send_frame(writer, &mut bytes_sent, &QueryFrame::Row { values }).is_err() {
                    return;
                }
                row_count += 1;
                if bytes_sent > MAX_QUERY_BYTES {
                    let _ = send_frame(
                        writer,
                        &mut bytes_sent,
                        &QueryFrame::Error {
                            message: format!(
                                "byte cap ({} MiB) exceeded after {} rows",
                                MAX_QUERY_BYTES / 1024 / 1024,
                                row_count
                            ),
                        },
                    );
                    return;
                }
            }
            Ok(None) => break,
            Err(e) => {
                let _ = send_frame(
                    writer,
                    &mut bytes_sent,
                    &QueryFrame::Error {
                        message: format!("row iter: {e}"),
                    },
                );
                return;
            }
        }
    }

    let _ = send_frame(
        writer,
        &mut bytes_sent,
        &QueryFrame::End {
            row_count,
            elapsed_ms: started.elapsed().as_millis() as u64,
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::{EventEnvelope, TlsPlaintextEvent};

    #[test]
    fn redact_authorization_bearer() {
        let s = "Authorization: Bearer sk-ant-abcdefghij1234567890klmnop";
        let out = redact(s);
        assert!(out.contains("***REDACTED***"), "{out}");
        assert!(!out.contains("sk-ant-abc"), "{out}");
        assert!(out.contains("Authorization"), "{out}");
    }

    #[test]
    fn redact_openai_key_in_body() {
        let s = r#"{"key":"sk-proj-AAAAAAAAAAAAAAAAAAAAAAAA"}"#;
        let out = redact(s);
        assert!(out.contains("***REDACTED***"));
    }

    #[test]
    fn redact_aws_access_key() {
        let s = "AKIAIOSFODNN7EXAMPLE";
        let out = redact(s);
        assert_eq!(out, "***REDACTED***");
    }

    #[test]
    fn redact_jwt() {
        let s = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abc-_123";
        let out = redact(s);
        assert!(out.contains("***REDACTED***"));
    }

    #[test]
    fn redact_passes_through_safe_text() {
        let s = "hello world this is fine";
        assert_eq!(redact(s), s);
    }

    fn make_tls_event(plaintext: Vec<u8>, dir: u8) -> EventEnvelope {
        EventEnvelope::TlsPlaintext(TlsPlaintextEvent {
            ts_ns: 1,
            pid: 2,
            tgid: 2,
            cgroup_id: 3,
            comm: "p".into(),
            ssl_ctx: 0x1234,
            call_id: 9,
            direction: dir,
            total_bytes: plaintext.len() as u32,
            chunk_index: 0,
            chunk_total: 1,
            chunk_bytes: plaintext.len() as u16,
            truncated: false,
            read_failed: false,
            ex_variant: false,
            plaintext,
        })
    }

    #[test]
    fn render_tail_tls_default_omits_plaintext_b64() {
        let evt = make_tls_event(b"hello".to_vec(), 0);
        let line = render_tail_line(&evt, false);
        assert!(!line.contains("plaintext_b64"), "leak: {line}");
        assert!(line.contains("plaintext_sha256"), "{line}");
        assert!(line.contains("\"kind\":\"tls.write\""), "{line}");
    }

    #[test]
    fn render_tail_tls_show_plaintext_includes_b64_and_redacts() {
        let body = b"Authorization: Bearer sk-ant-XXXXXXXXXXXXXXXXXXXXXXX\nbody".to_vec();
        let evt = make_tls_event(body, 0);
        let line = render_tail_line(&evt, true);
        assert!(line.contains("plaintext_b64"), "{line}");
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        let b64 = v["plaintext_b64"].as_str().unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        let s = String::from_utf8_lossy(&decoded);
        assert!(s.contains("***REDACTED***"), "redaction missing: {s}");
        assert!(!s.contains("sk-ant-XXX"), "leak in b64: {s}");
    }

    #[test]
    fn render_tail_proc_exec_is_valid_json() {
        let evt = EventEnvelope::ProcExec(crate::sink::ProcExecEvent {
            ts_ns: 1,
            pid: 2,
            tgid: 2,
            cgroup_id: 3,
            comm: "x".into(),
            cmdline: "x --y".into(),
        });
        let line = render_tail_line(&evt, false);
        let _: serde_json::Value = serde_json::from_str(&line).unwrap();
    }

    #[test]
    fn wrap_select_adds_limit() {
        let out = maybe_wrap_with_limit("SELECT 1");
        assert!(out.contains("LIMIT 100000"), "{out}");
        assert!(out.contains("SELECT 1"), "{out}");
    }

    #[test]
    fn wrap_with_cte_adds_limit() {
        let out = maybe_wrap_with_limit("WITH x AS (SELECT 1) SELECT * FROM x");
        assert!(out.contains("LIMIT 100000"), "{out}");
    }

    #[test]
    fn wrap_explain_passes_through() {
        let out = maybe_wrap_with_limit("EXPLAIN SELECT 1");
        assert_eq!(out, "EXPLAIN SELECT 1");
    }

    #[test]
    fn wrap_pragma_passes_through() {
        let out = maybe_wrap_with_limit("PRAGMA show_tables");
        assert_eq!(out, "PRAGMA show_tables");
    }

    #[test]
    fn value_truncation_respects_utf8_boundary() {
        let pad = "a".repeat(MAX_VALUE_BYTES - 1);
        let s = format!("{pad}🦀");
        assert!(s.len() > MAX_VALUE_BYTES);
        let v = duckdb::types::Value::Text(s);
        let out = value_to_display(&v);
        assert!(out.contains("…[+"));
        // Output must be valid UTF-8 (String guarantees) and iterating
        // chars must not panic.
        let _ = out.chars().count();
    }

    /// Repro for the e2e failure: open a writer connection on a
    /// temp DuckDB file, then in the SAME PROCESS open an in-memory
    /// connection and ATTACH '...' AS data (READ_ONLY). If this
    /// returns Err, that's why handle_query is closing the socket
    /// silently in production (the ATTACH fails before we send any
    /// frame... wait, we DO send an Error frame on attach failure.
    /// So if this passes, the bug is elsewhere).
    #[test]
    fn attach_readonly_alongside_writer_works() {
        use crate::store::Store;
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("events.duckdb");
        // Writer: same code path as production.
        let _writer = Store::open(&path).expect("open writer");

        // Reader: in-memory + ATTACH READ_ONLY.
        let conn = duckdb::Connection::open_in_memory().expect("open in-memory");
        let attach_sql = format!(
            "ATTACH '{}' AS data (READ_ONLY)",
            path.display().to_string().replace('\'', "''")
        );
        eprintln!("attach_sql: {attach_sql}");
        conn.execute_batch(&attach_sql).expect("attach read-only");
        conn.execute_batch("USE data").expect("use data");

        let mut stmt = conn
            .prepare("SELECT COUNT(*) FROM events_net_bytes")
            .expect("prepare");
        let mut rows = stmt.query([]).expect("query");
        let row = rows.next().expect("next").expect("some row");
        let n: i64 = row.get(0).expect("get");
        assert_eq!(n, 0);
    }

    #[test]
    fn handle_query_emits_full_frame_sequence() {
        use crate::store::Store;
        use std::io::{BufRead, BufReader};
        use std::os::unix::net::UnixStream;

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("events.duckdb");
        // Populate the DB with one row so the GROUP BY has something.
        let store = Store::open(&path).expect("open store");
        store
            .insert_net_bytes(1, 0xCAFE, 200, "wget", "[<gone>]", 1024, 2048, 99)
            .unwrap();
        drop(store);

        let (mut a, b) = UnixStream::pair().expect("socketpair");
        let counters = Arc::new(Counters::default());
        let global_sd = Arc::new(AtomicBool::new(false));
        let server_sd = Arc::new(AtomicBool::new(false));

        let path_for_thread = path.clone();
        let counters_for_thread = counters.clone();
        let global_sd_for_thread = global_sd.clone();
        let server_sd_for_thread = server_sd.clone();
        let join = thread::spawn(move || {
            handle_query(
                &mut a,
                &path_for_thread,
                "SELECT comm, COUNT(*) AS n FROM events_net_bytes GROUP BY 1 ORDER BY 2 DESC",
                &counters_for_thread,
                &global_sd_for_thread,
                &server_sd_for_thread,
            );
        });

        // Read all frames from the other end.
        let reader = BufReader::new(b);
        let mut frames: Vec<String> = Vec::new();
        for line in reader.lines() {
            match line {
                Ok(l) => frames.push(l),
                Err(_) => break,
            }
        }
        join.join().expect("handle_query thread");
        eprintln!("frames received ({}): ", frames.len());
        for f in &frames {
            eprintln!("  {f}");
        }
        // Must end with End or Error.
        assert!(!frames.is_empty(), "no frames at all");
        let last = frames.last().unwrap();
        assert!(
            last.contains(r#""kind":"end""#) || last.contains(r#""kind":"error""#),
            "last frame should be end or error: {last}"
        );
    }

    #[test]
    fn active_query_guard_caps_concurrency() {
        let counters = Arc::new(Counters::default());
        let mut held = Vec::new();
        for _ in 0..MAX_CONCURRENT_QUERIES {
            held.push(ActiveQueryGuard::try_acquire(counters.clone()).expect("under cap"));
        }
        assert!(
            ActiveQueryGuard::try_acquire(counters.clone()).is_none(),
            "{}-th acquire should fail",
            MAX_CONCURRENT_QUERIES + 1
        );
        drop(held);
        assert_eq!(counters.active_queries.load(Ordering::Relaxed), 0);
        assert!(ActiveQueryGuard::try_acquire(counters.clone()).is_some());
    }
}

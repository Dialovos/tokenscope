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
                tail_subscribers_active: counters.tail_subscribers_active.load(Ordering::Relaxed),
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

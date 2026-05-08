//! Single-writer sink for all event families. Phase 2.A introduces this
//! to (a) keep DuckDB single-writer when the TLS consumer thread joins
//! the party, and (b) let `Subscribers` render per-subscriber so the
//! `--show-plaintext` opt-in actually means something at the daemon
//! level (and not "trust the client to redact", which leaks plaintext
//! to every subscriber regardless).

use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};

use crate::control::Subscribers;
use crate::store::Store;

// NOTE: `Store` (wrapping a `duckdb::Connection`) is `Send` but not
// `Sync`, so we cannot pass it via `Arc<Store>` across thread
// boundaries. Since the writer thread is the sole owner of the
// connection, we move the `Store` by value into the spawned thread.
// `EventSink::drop` joins the thread on shutdown so the connection is
// closed deterministically.

/// Capacity of the `events_tx` channel. Sized so a brief DuckDB stall
/// doesn't drop events from a busy net_bytes flush, but small enough
/// that backpressure is observable. Same order of magnitude as
/// `Subscribers`' per-subscriber channel.
pub const EVENT_CHANNEL_CAPACITY: usize = 4096;

/// One enum per event family. Owns the data so `EventSink` doesn't
/// need to know how to serialize each one.
#[derive(Debug, Clone)]
pub enum EventEnvelope {
    ProcExec(ProcExecEvent),
    NetConnect(NetConnectEvent),
    NetBytesSnapshot(NetBytesSnapshot),
    /// Constructed by the TLS uprobe consumer in later Phase 2.A tasks.
    /// Kept here so `render_tail_line` and the writer's persistence
    /// match arms can already handle it.
    #[allow(dead_code)]
    TlsPlaintext(TlsPlaintextEvent),
}

#[derive(Debug, Clone)]
pub struct ProcExecEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub cgroup_id: u64,
    pub comm: String,
    pub cmdline: String,
}

#[derive(Debug, Clone)]
pub struct NetConnectEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub cgroup_id: u64,
    pub comm: String,
    pub cmdline: String,
    pub dst_addr: [u8; 16],
    pub dst_port: u16,
    pub family: u16,
    pub protocol: u8,
}

#[derive(Debug, Clone)]
pub struct NetBytesSnapshot {
    pub snapshot_ts_ns: u64,
    pub sock_cookie: u64,
    pub pid: u32,
    pub comm: String,
    pub cmdline: String,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub last_event_ns: u64,
}

/// Phase 2.A wire shape for a single TLS plaintext chunk emitted by a
/// uretprobe. Most fields are unused in Task 1 — they're consumed by
/// the BPF/decoder/render tasks that follow.
#[derive(Debug, Clone)]
#[allow(dead_code)] // fields populated by upcoming Phase 2.A tasks
pub struct TlsPlaintextEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub cgroup_id: u64,
    pub comm: String,
    pub ssl_ctx: u64,
    pub call_id: u64,
    pub direction: u8,
    pub total_bytes: u32,
    pub chunk_index: u16,
    pub chunk_total: u16,
    pub chunk_bytes: u16,
    pub truncated: bool,
    pub read_failed: bool,
    pub ex_variant: bool,
    pub plaintext: Vec<u8>, // owned; only the chunk_bytes prefix is meaningful
}

pub struct EventSink {
    pub tx: SyncSender<EventEnvelope>,
    writer_handle: Option<JoinHandle<()>>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
}

impl EventSink {
    pub fn spawn(store: Store, subs: Subscribers) -> Result<Self> {
        let (tx, rx) = sync_channel::<EventEnvelope>(EVENT_CHANNEL_CAPACITY);
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown_for_thread = shutdown.clone();
        let writer_handle = thread::Builder::new()
            .name("tsd-store-writer".into())
            .spawn(move || writer_loop(store, subs, rx, shutdown_for_thread))
            .context("spawn store-writer thread")?;
        Ok(Self {
            tx,
            writer_handle: Some(writer_handle),
            shutdown,
        })
    }
}

impl Drop for EventSink {
    fn drop(&mut self) {
        self.shutdown
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(h) = self.writer_handle.take() {
            let _ = h.join();
        }
    }
}

fn writer_loop(
    store: Store,
    subs: Subscribers,
    rx: Receiver<EventEnvelope>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) {
    // Hold a long-lived Appender for events_tls_plaintext alongside the
    // Connection. Both live until this function returns (the join in
    // EventSink::Drop), at which point the Appender is dropped first
    // (lifetime), then the Store/Connection.
    //
    // If creating the Appender fails (shouldn't — schema is migrated by
    // Store::open), TLS records still flow through subscribers; just
    // the persistence side becomes a no-op WARN per record.
    let mut tls_appender: Option<duckdb::Appender<'_>> = match store.tls_appender() {
        Ok(a) => Some(a),
        Err(e) => {
            tracing::warn!(error = ?e, "could not create TLS appender; tls persistence disabled");
            None
        }
    };
    let mut last_flush = std::time::Instant::now();
    const TLS_FLUSH_INTERVAL: Duration = Duration::from_secs(1);

    while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(env) => {
                match &env {
                    EventEnvelope::TlsPlaintext(e) if tls_appender.is_some() => {
                        let app = tls_appender.as_mut().unwrap();
                        if let Err(err) = app.append_row(duckdb::params![
                            e.ts_ns as i64,
                            e.pid as i32,
                            e.tgid as i32,
                            e.cgroup_id as i64,
                            e.comm.as_str(),
                            e.ssl_ctx as i64,
                            e.call_id as i64,
                            e.direction as i8,
                            e.total_bytes as i32,
                            e.chunk_index as i16,
                            e.chunk_total as i16,
                            e.chunk_bytes as i16,
                            e.truncated,
                            e.read_failed,
                            e.ex_variant,
                            e.plaintext.as_slice(),
                        ]) {
                            tracing::warn!(error = ?err, "tls appender row failed");
                        }
                    }
                    other => {
                        if let Err(e) = persist(&store, other) {
                            tracing::warn!(error=?e, "store insert failed");
                        }
                    }
                }
                subs.broadcast_envelope(&env);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Flush the TLS appender on the idle tick so writes
                // become visible to readers within ~1s of arrival.
                if last_flush.elapsed() > TLS_FLUSH_INTERVAL {
                    if let Some(app) = tls_appender.as_mut() {
                        if let Err(e) = app.flush() {
                            tracing::warn!(error = ?e, "tls appender flush failed");
                        }
                    }
                    last_flush = std::time::Instant::now();
                }
                continue;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    // Final flush so shutdown doesn't strand buffered TLS rows.
    if let Some(mut app) = tls_appender.take() {
        let _ = app.flush();
    }
}

fn persist(store: &Store, env: &EventEnvelope) -> Result<()> {
    match env {
        EventEnvelope::ProcExec(e) => {
            store.insert_proc_exec(e.ts_ns, e.pid, e.tgid, e.cgroup_id, &e.comm, &e.cmdline)
        }
        EventEnvelope::NetConnect(e) => store.insert_net_connect(
            e.ts_ns,
            e.pid,
            e.tgid,
            e.cgroup_id,
            &e.comm,
            &e.cmdline,
            &e.dst_addr,
            e.dst_port,
            e.family,
            e.protocol,
        ),
        EventEnvelope::NetBytesSnapshot(e) => store.insert_net_bytes(
            e.snapshot_ts_ns,
            e.sock_cookie,
            e.pid,
            &e.comm,
            &e.cmdline,
            e.tx_bytes,
            e.rx_bytes,
            e.last_event_ns,
        ),
        EventEnvelope::TlsPlaintext(_) => {
            // Handled directly in writer_loop via the long-lived
            // Appender — never reached.
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::Counters;

    #[test]
    fn sink_dropped_counter_works_with_capacity() {
        // Direct unit test of the counter bump pattern: simulate a
        // try_send-on-full by filling a small channel.
        use std::sync::mpsc::{sync_channel, TrySendError};
        let counters = Arc::new(Counters::default());
        let (tx, _rx) = sync_channel::<u32>(1);
        tx.try_send(1).unwrap(); // fills capacity
        let res = tx.try_send(2); // would block → Full
        if let Err(TrySendError::Full(_)) = res {
            counters
                .sink_dropped_events
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        assert_eq!(
            counters
                .sink_dropped_events
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }
}

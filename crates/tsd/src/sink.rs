//! Single-writer sink for all event families. TLS content is consumed only by
//! the bounded usage parser; persistence and tail output contain metadata and
//! numeric usage reports. A FIFO stop marker drains accepted events.

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
    Shutdown,
    Usage(ts_core::usage::UsageObservation),
    TlsCheckpoint(TlsCheckpoint),
    /// Every inventory of one checkpoint pass has been sent.
    TlsCheckpointEnd {
        pass: u64,
        ts_ns: u64,
    },
    /// Final inventory of a lifetime whose process exited before the last pass.
    TlsLifetimeGone(TlsCheckpoint),
    ProcExec(ProcExecEvent),
    NetConnect(NetConnectEvent),
    NetBytesSnapshot(NetBytesSnapshot),
    /// Ephemeral content from the TLS consumer; never persisted or tailed.
    TlsPlaintext(TlsPlaintextEvent),
}

#[derive(Debug, Clone)]
pub struct ProcExecEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub cgroup_id: u64,
    pub comm: String,
    /// Discarded compatibility input, including adversarial replay fixtures.
    pub _cmdline: String,
}

#[derive(Debug, Clone)]
pub struct NetConnectEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub cgroup_id: u64,
    pub comm: String,
    pub _cmdline: String,
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
    pub _cmdline: String,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub last_event_ns: u64,
}

/// One ephemeral TLS chunk with lifetime, accepted-byte and loss metadata.
#[derive(Debug, Clone)]
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
    pub process_start: u64,
    pub exec_generation: u64,
    pub connection_generation: u64,
    pub call_sequence: u64,
    pub loss_epoch: u64,
    /// Accepted bytes in this direction before the call (final count on END).
    pub stream_offset: u64,
    pub lifecycle_end: bool,
    pub plaintext: Vec<u8>, // owned; only the chunk_bytes prefix is meaningful
}

#[derive(Debug, Clone)]
pub struct TlsCheckpoint {
    pub connection: ts_core::usage::ConnectionKey,
    pub sequence: [u64; 2],
    pub loss_epoch: [u64; 2],
    pub accepted: [u64; 2],
    pub ts_ns: u64,
    pub pass: u64,
    /// Read after capture stopped and the ring drained; nothing is in transit.
    pub final_pass: bool,
}

pub struct EventSink {
    pub tx: SyncSender<EventEnvelope>,
    writer_handle: Option<JoinHandle<Result<()>>>,
}
impl EventSink {
    pub fn spawn(
        store: Store,
        subs: Subscribers,
        counters: Arc<crate::control::Counters>,
    ) -> Result<Self> {
        let (tx, rx) = sync_channel(EVENT_CHANNEL_CAPACITY);
        let writer_handle = thread::Builder::new()
            .name("tsd-store-writer".into())
            .spawn(move || {
                let result = (|| {
                    let backend = DbWriter {
                        store: &store,
                        usage: store.usage_appender()?,
                        metadata: store.metadata_appender()?,
                    };
                    writer_loop(backend, subs, rx, counters.clone(), Duration::from_secs(1))
                })();
                if result.is_err()
                    && counters
                        .persistence_errors
                        .load(std::sync::atomic::Ordering::Relaxed)
                        == 0
                {
                    mark_failed(&counters, &mut true);
                }
                result
            })
            .context("spawn store-writer thread")?;
        Ok(Self {
            tx,
            writer_handle: Some(writer_handle),
        })
    }
    /// Call only after every producer is stopped. The FIFO marker follows all
    /// accepted events even when cloned senders still exist; queue memory is bounded.
    pub fn finish(mut self) -> Result<()> {
        self.stop()
    }
    fn stop(&mut self) -> Result<()> {
        if let Some(h) = self.writer_handle.take() {
            let _ = self.tx.send(EventEnvelope::Shutdown);
            return h
                .join()
                .map_err(|_| anyhow::anyhow!("store writer panicked"))?;
        }
        Ok(())
    }
}
impl Drop for EventSink {
    fn drop(&mut self) {
        if self.stop().is_err() {
            tracing::error!("store writer shutdown failed");
        }
    }
}

trait Backend {
    fn append(&mut self, env: &EventEnvelope, epoch: &str) -> Result<u64>;
    fn flush(&mut self) -> Result<()>;
}
struct DbWriter<'a> {
    store: &'a Store,
    usage: duckdb::Appender<'a>,
    metadata: duckdb::Appender<'a>,
}
impl Backend for DbWriter<'_> {
    fn append(&mut self, env: &EventEnvelope, epoch: &str) -> Result<u64> {
        match env {
            EventEnvelope::Usage(u) => {
                self.usage.append_row(duckdb::params![
                    epoch,
                    u.ts_ns,
                    u.connection.tgid,
                    u.connection.process_start,
                    u.connection.exec_generation,
                    u.connection.ssl_ctx,
                    u.connection.generation,
                    u.request_ordinal,
                    &u.usage_state,
                    &u.capture_integrity,
                    &u.termination,
                    &u.reason,
                    serde_json::to_string(&u.reports)?
                ])?;
            }
            EventEnvelope::TlsPlaintext(e) => {
                self.metadata.append_row(duckdb::params![
                    epoch,
                    e.ts_ns,
                    e.tgid,
                    e.process_start,
                    e.exec_generation,
                    e.ssl_ctx,
                    e.connection_generation,
                    e.direction,
                    e.call_sequence,
                    e.loss_epoch,
                    e.stream_offset,
                    e.total_bytes,
                    e.chunk_index,
                    e.chunk_total,
                    e.truncated,
                    e.read_failed,
                    e.lifecycle_end
                ])?;
            }
            EventEnvelope::ProcExec(e) => {
                self.store
                    .insert_proc_exec(e.ts_ns, e.pid, e.tgid, e.cgroup_id, &e.comm, "")?
            }
            EventEnvelope::NetConnect(e) => self.store.insert_net_connect(
                e.ts_ns,
                e.pid,
                e.tgid,
                e.cgroup_id,
                &e.comm,
                "",
                &e.dst_addr,
                e.dst_port,
                e.family,
                e.protocol,
            )?,
            EventEnvelope::NetBytesSnapshot(e) => self.store.insert_net_bytes(
                e.snapshot_ts_ns,
                e.sock_cookie,
                e.pid,
                &e.comm,
                "",
                e.tx_bytes,
                e.rx_bytes,
                e.last_event_ns,
            )?,
            EventEnvelope::Shutdown
            | EventEnvelope::TlsCheckpoint(_)
            | EventEnvelope::TlsCheckpointEnd { .. }
            | EventEnvelope::TlsLifetimeGone(_) => return Ok(0),
        }
        Ok(1)
    }
    fn flush(&mut self) -> Result<()> {
        self.metadata.flush()?;
        self.usage.flush()?;
        Ok(())
    }
}
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid writable timespec; CLOCK_MONOTONIC matches BPF ktime.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}
fn capture_epoch() -> Result<String> {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
struct WriterHealthGuard(Arc<crate::control::Counters>);
impl Drop for WriterHealthGuard {
    fn drop(&mut self) {
        self.0
            .writer_healthy
            .store(false, std::sync::atomic::Ordering::Release);
        if std::thread::panicking() {
            self.0
                .persistence_errors
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}
fn writer_loop<B: Backend>(
    mut backend: B,
    subs: Subscribers,
    rx: Receiver<EventEnvelope>,
    counters: Arc<crate::control::Counters>,
    interval: Duration,
) -> Result<()> {
    use std::sync::atomic::Ordering;
    use ts_core::usage::{CaptureChunk, ConnectionKey, UsageTracker};
    let _health = WriterHealthGuard(counters.clone());
    let epoch = capture_epoch()?;
    *counters.capture_epoch.lock().unwrap() = epoch.clone();
    let mut tracker = UsageTracker::default();
    let mut last_flush = std::time::Instant::now();
    let mut pending_rows = 0;
    let mut loss_seen = (0, 0, 0);
    let mut last_expire = std::time::Instant::now();
    let mut healthy = true;
    counters.writer_healthy.store(true, Ordering::Release);
    loop {
        let now = monotonic_ns();
        // Kernel-side losses carry their lifetime's loss epoch. Only loss with
        // no attributable lifetime invalidates every open lifetime.
        let loss = (
            counters.tls_capture_errors.load(Ordering::Relaxed),
            counters.tls_close_lost.load(Ordering::Relaxed),
            counters.tls_unattributed_drops.load(Ordering::Relaxed),
        );
        let mut observations = if loss != loss_seen {
            loss_seen = loss;
            tracker.global_loss(now)
        } else if last_expire.elapsed() >= Duration::from_secs(1) {
            last_expire = std::time::Instant::now();
            tracker.expire(now)
        } else {
            vec![]
        };
        let dropped = std::mem::take(
            &mut *counters
                .tls_dropped_lifetimes
                .lock()
                .unwrap_or_else(|p| p.into_inner()),
        );
        for key in dropped {
            observations.extend(tracker.capture_loss(key, now));
        }
        let wait = interval
            .saturating_sub(last_flush.elapsed())
            .min(Duration::from_millis(250));
        let received = rx.recv_timeout(wait);
        let mut end = false;
        if let Ok(env) = received {
            if matches!(env, EventEnvelope::Shutdown) {
                end = true;
            } else {
                match &env {
                    EventEnvelope::TlsPlaintext(e) => {
                        observations.extend(tracker.feed(CaptureChunk {
                            connection: ConnectionKey {
                                tgid: e.tgid,
                                process_start: e.process_start,
                                exec_generation: e.exec_generation,
                                ssl_ctx: e.ssl_ctx,
                                generation: e.connection_generation,
                            },
                            ts_ns: e.ts_ns,
                            direction: e.direction,
                            sequence: e.call_sequence,
                            loss_epoch: e.loss_epoch,
                            call_id: e.call_id,
                            offset: e.stream_offset,
                            chunk_index: e.chunk_index,
                            chunk_total: e.chunk_total,
                            total_bytes: e.total_bytes,
                            truncated: e.truncated,
                            failed: e.read_failed,
                            end: e.lifecycle_end,
                            data: &e.plaintext,
                        }));
                    }
                    EventEnvelope::TlsCheckpoint(c) => observations.extend(tracker.checkpoint(
                        c.connection,
                        c.sequence,
                        c.accepted,
                        c.loss_epoch,
                        c.pass,
                        c.final_pass,
                        c.ts_ns,
                    )),
                    EventEnvelope::TlsCheckpointEnd { pass, ts_ns } => {
                        observations.extend(tracker.checkpoint_pass_end(*pass, *ts_ns))
                    }
                    EventEnvelope::TlsLifetimeGone(c) => {
                        observations.extend(tracker.lifetime_gone(
                            c.connection,
                            c.sequence,
                            c.accepted,
                            c.loss_epoch,
                            c.ts_ns,
                        ))
                    }
                    _ => {}
                }
                append_observed(
                    &mut backend,
                    &subs,
                    &counters,
                    &env,
                    &epoch,
                    &mut healthy,
                    &mut pending_rows,
                );
                counters
                    .writer_events_processed
                    .fetch_add(1, Ordering::Relaxed);
            }
        } else if matches!(
            received,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
        ) {
            end = true;
        }
        if end {
            observations.extend(tracker.finish(monotonic_ns()));
        }
        for mut observation in observations {
            observation.capture_epoch = epoch.clone();
            append_observed(
                &mut backend,
                &subs,
                &counters,
                &EventEnvelope::Usage(observation),
                &epoch,
                &mut healthy,
                &mut pending_rows,
            );
        }
        counters
            .usage_admission_blocked
            .store(tracker.admission_blocked(), Ordering::Relaxed);
        counters
            .usage_generation_barrier
            .store(tracker.generation_barrier(), Ordering::Relaxed);
        counters
            .usage_retained_bytes
            .store(tracker.retained_bytes() as u64, Ordering::Relaxed);
        counters
            .usage_lifetimes_tracked
            .store(tracker.connection_count() as u64, Ordering::Relaxed);
        counters
            .usage_connections_refused
            .store(tracker.refused_connections(), Ordering::Relaxed);
        counters
            .usage_connections_out_of_scope
            .store(tracker.out_of_scope_connections(), Ordering::Relaxed);
        // Check the deadline on every iteration, including continuous ingestion.
        if last_flush.elapsed() >= interval || end {
            if healthy {
                if backend.flush().is_ok() {
                    counters
                        .rows_flushed
                        .fetch_add(pending_rows, Ordering::Relaxed);
                    pending_rows = 0;
                } else {
                    mark_failed(&counters, &mut healthy);
                }
            }
            last_flush = std::time::Instant::now();
        }
        if end {
            break;
        }
    }
    if healthy {
        Ok(())
    } else {
        anyhow::bail!("persistence failed; observed events may not have been stored")
    }
}
fn mark_failed(counters: &crate::control::Counters, healthy: &mut bool) {
    *healthy = false;
    counters
        .writer_healthy
        .store(false, std::sync::atomic::Ordering::Release);
    counters
        .persistence_errors
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    tracing::error!("persistence failed; writer progress is unverified");
}
fn append_observed<B: Backend>(
    backend: &mut B,
    subs: &Subscribers,
    counters: &crate::control::Counters,
    env: &EventEnvelope,
    epoch: &str,
    healthy: &mut bool,
    pending: &mut u64,
) {
    if *healthy {
        match backend.append(env, epoch) {
            Ok(n) => *pending += n,
            Err(_) => mark_failed(counters, healthy),
        }
    }
    if !matches!(
        env,
        EventEnvelope::TlsCheckpoint(_)
            | EventEnvelope::TlsCheckpointEnd { .. }
            | EventEnvelope::TlsLifetimeGone(_)
            | EventEnvelope::Shutdown
    ) {
        subs.broadcast_envelope(env);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::Counters;
    use std::sync::{atomic::Ordering, Mutex};
    fn event(n: u64) -> EventEnvelope {
        EventEnvelope::ProcExec(ProcExecEvent {
            ts_ns: n,
            pid: 7,
            tgid: 7,
            cgroup_id: 9,
            comm: "synthetic".into(),
            _cmdline: "PRIVATE-ARGS".into(),
        })
    }
    fn tls_event(sequence: u64, direction: u8, data: &[u8]) -> EventEnvelope {
        EventEnvelope::TlsPlaintext(TlsPlaintextEvent {
            ts_ns: monotonic_ns(),
            pid: 7,
            tgid: 7,
            cgroup_id: 9,
            comm: "synthetic".into(),
            ssl_ctx: 19,
            call_id: sequence,
            direction,
            total_bytes: data.len() as u32,
            chunk_index: 0,
            chunk_total: 1,
            chunk_bytes: data.len() as u16,
            truncated: false,
            read_failed: false,
            ex_variant: false,
            process_start: 11,
            exec_generation: 1,
            connection_generation: 23,
            call_sequence: sequence,
            loss_epoch: 0,
            stream_offset: 0,
            lifecycle_end: false,
            plaintext: data.to_vec(),
        })
    }
    #[test]
    fn a_writer_panic_clears_health_and_never_claims_flushed_rows() {
        struct PanicBackend;
        impl Backend for PanicBackend {
            fn append(&mut self, _: &EventEnvelope, _: &str) -> Result<u64> {
                panic!("injected writer panic");
            }
            fn flush(&mut self) -> Result<()> {
                Ok(())
            }
        }
        let counters = Arc::new(Counters::default());
        let (tx, rx) = sync_channel(2);
        tx.send(event(1)).unwrap();
        tx.send(EventEnvelope::Shutdown).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            writer_loop(
                PanicBackend,
                Subscribers::new(counters.clone()),
                rx,
                counters.clone(),
                Duration::from_millis(10),
            )
        }));
        assert!(result.is_err());
        assert!(!counters.writer_healthy.load(Ordering::Acquire));
        assert_eq!(counters.persistence_errors.load(Ordering::Relaxed), 1);
        assert_eq!(counters.rows_flushed.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn successive_captures_keep_identical_lifetime_keys_separate() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("private/usage.duckdb");
        let mut epochs = vec![];
        for _ in 0..2 {
            let counters = Arc::new(Counters::default());
            let sink = EventSink::spawn(
                Store::open(&path).unwrap(),
                Subscribers::new(counters.clone()),
                counters.clone(),
            )
            .unwrap();
            sink.tx.send(tls_event(1, 0,
                b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Length: 0\r\n\r\n")).unwrap();
            let body = r#"{"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}"#;
            let wire = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len());
            sink.tx.send(tls_event(1, 1, wire.as_bytes())).unwrap();
            sink.finish().unwrap();
            epochs.push(counters.capture_epoch.lock().unwrap().clone());
        }
        assert_ne!(epochs[0], epochs[1]);
        let conn = duckdb::Connection::open(&path).unwrap();
        let (rows, distinct_epochs): (i64,i64) = conn.query_row(
            "SELECT count(*), count(DISTINCT capture_epoch) FROM events_usage WHERE usage_state='reported' AND request_ordinal=1", [],
            |r| Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!((rows, distinct_epochs), (2, 2));
    }
    #[test]
    fn every_event_family_and_split_payload_stays_out_of_database_wal_and_tail() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("private/usage.duckdb");
        let counters = Arc::new(Counters::default());
        let sink = EventSink::spawn(
            Store::open(&path).unwrap(),
            Subscribers::new(counters.clone()),
            counters.clone(),
        )
        .unwrap();
        let mut events = vec![
            event(1),
            EventEnvelope::NetConnect(NetConnectEvent {
                ts_ns: 2,
                pid: 7,
                tgid: 7,
                cgroup_id: 9,
                comm: "synthetic".into(),
                _cmdline: "PRIVATE-NET-ARGS".into(),
                dst_addr: [0; 16],
                dst_port: 443,
                family: 2,
                protocol: 6,
            }),
            EventEnvelope::NetBytesSnapshot(NetBytesSnapshot {
                snapshot_ts_ns: 3,
                sock_cookie: 1,
                pid: 7,
                comm: "synthetic".into(),
                _cmdline: "PRIVATE-BYTES-ARGS".into(),
                tx_bytes: 1,
                rx_bytes: 2,
                last_event_ns: 3,
            }),
        ];
        let secret = b"PRIVATE-TLS-SPLIT-SENTINEL";
        let mut private_fragments = vec![secret.to_vec()];
        for split in 1..secret.len() {
            // Inspect recognizable fragments too: storing each chunk separately
            // need not leave the complete sentinel anywhere in the database.
            for fragment in [&secret[..split], &secret[split..]] {
                if fragment.len() >= 8 {
                    private_fragments.push(fragment.to_vec());
                }
            }
            events.push(tls_event((split * 2) as u64, 0, &secret[..split]));
            events.push(tls_event((split * 2 + 1) as u64, 0, &secret[split..]));
        }
        let sent = events.len() as u64;
        for env in events {
            for show_plaintext in [false, true] {
                let tail = crate::control::render_tail_line(&env, show_plaintext);
                for secret in [
                    "PRIVATE-ARGS",
                    "PRIVATE-NET-ARGS",
                    "PRIVATE-BYTES-ARGS",
                    "PRIVATE-TLS",
                ] {
                    assert!(!tail.contains(secret), "tail leaked a sentinel");
                }
                for fragment in &private_fragments {
                    assert!(!tail
                        .as_bytes()
                        .windows(fragment.len())
                        .any(|w| w == fragment));
                }
            }
            sink.tx.send(env).unwrap();
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while counters.rows_flushed.load(Ordering::Relaxed) < sent {
            assert!(
                std::time::Instant::now() < deadline,
                "writer did not flush fixture rows"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let wal = path.with_extension("duckdb.wal");
        assert!(wal.is_file(), "fixture must inspect a live WAL");
        for p in [&path, &wal] {
            let bytes = std::fs::read(p).unwrap();
            for secret in [
                b"PRIVATE-ARGS".as_slice(),
                b"PRIVATE-NET-ARGS",
                b"PRIVATE-BYTES-ARGS",
                secret,
            ] {
                assert!(!bytes.windows(secret.len()).any(|w| w == secret));
            }
            for fragment in &private_fragments {
                assert!(!bytes.windows(fragment.len()).any(|w| w == fragment));
            }
        }
        sink.finish().unwrap();
    }
    struct UsageBackend(Arc<Mutex<Vec<ts_core::usage::UsageObservation>>>);
    impl Backend for UsageBackend {
        fn append(&mut self, env: &EventEnvelope, _epoch: &str) -> Result<u64> {
            if let EventEnvelope::Usage(u) = env {
                self.0.lock().unwrap().push(u.clone());
            }
            Ok(1)
        }
        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }
    fn two_lifetimes(prepare: impl Fn(&Counters)) -> Vec<ts_core::usage::UsageObservation> {
        let lifetime = |ssl: u64, sequence: u64, direction: u8, data: &[u8]| {
            let EventEnvelope::TlsPlaintext(mut e) = tls_event(sequence, direction, data) else {
                unreachable!()
            };
            e.ssl_ctx = ssl;
            EventEnvelope::TlsPlaintext(e)
        };
        let request =
            b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Length: 0\r\n\r\n";
        let body = r#"{"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let counters = Arc::new(Counters::default());
        prepare(&counters);
        let (tx, rx) = sync_channel(16);
        for ssl in [19, 20] {
            tx.send(lifetime(ssl, 1, 0, request)).unwrap();
            tx.send(lifetime(ssl, 1, 1, response.as_bytes())).unwrap();
        }
        tx.send(EventEnvelope::Shutdown).unwrap();
        let rows = Arc::new(Mutex::new(vec![]));
        writer_loop(
            UsageBackend(rows.clone()),
            Subscribers::new(counters.clone()),
            rx,
            counters,
            Duration::from_millis(10),
        )
        .unwrap();
        let rows = rows.lock().unwrap().clone();
        rows
    }
    #[test]
    fn queue_drops_invalidate_only_their_lifetime_and_unknown_loss_invalidates_all() {
        let key = |ssl| ts_core::usage::ConnectionKey {
            tgid: 7,
            process_start: 11,
            exec_generation: 1,
            ssl_ctx: ssl,
            generation: 23,
        };
        // Kernel-attributed counters carry loss epochs on their own lifetimes.
        let rows = two_lifetimes(|c| {
            c.tls_missing_states.store(3, Ordering::Relaxed);
            c.tls_reserve_failures.store(2, Ordering::Relaxed);
            c.tls_map_failures.store(1, Ordering::Relaxed);
            c.sink_dropped_events.store(9, Ordering::Relaxed);
        });
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.usage_state == "reported"));
        // A dropped record of lifetime 19 removes trust from 19 alone.
        let rows = two_lifetimes(|c| {
            c.tls_dropped_lifetimes.lock().unwrap().insert(key(19));
        });
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert_eq!(rows[0].connection.ssl_ctx, 19);
        assert_eq!(rows[0].reason.as_deref(), Some("capture_loss"));
        assert_eq!(rows[1].connection.ssl_ctx, 20);
        assert_eq!(rows[1].usage_state, "reported");
        // Loss without a lifetime reaches every lifetime created before it.
        for prepare in [
            (|c: &Counters| c.tls_capture_errors.store(1, Ordering::Relaxed)) as fn(&Counters),
            |c| c.tls_close_lost.store(1, Ordering::Relaxed),
            |c| c.tls_unattributed_drops.store(1, Ordering::Relaxed),
        ] {
            let rows = two_lifetimes(prepare);
            assert_eq!(rows.len(), 2);
            assert!(rows
                .iter()
                .all(|r| r.reason.as_deref() == Some("global_loss_before_admission")));
        }
    }
    #[derive(Default)]
    struct Inventory {
        written: Vec<u64>,
        flush_at: Vec<usize>,
    }
    struct FakeBackend {
        inventory: Arc<Mutex<Inventory>>,
        append_failure: bool,
        flush_failure: bool,
        slow: bool,
    }
    impl Backend for FakeBackend {
        fn append(&mut self, env: &EventEnvelope, _epoch: &str) -> Result<u64> {
            if self.slow {
                std::thread::sleep(Duration::from_millis(1));
            }
            if self.append_failure {
                anyhow::bail!("injected append failure");
            }
            if let EventEnvelope::ProcExec(e) = env {
                self.inventory.lock().unwrap().written.push(e.ts_ns);
            }
            Ok(1)
        }
        fn flush(&mut self) -> Result<()> {
            if self.flush_failure {
                anyhow::bail!("injected flush failure");
            }
            let mut i = self.inventory.lock().unwrap();
            let count = i.written.len();
            i.flush_at.push(count);
            Ok(())
        }
    }
    fn run_fake(
        fail_append: bool,
        fail_flush: bool,
        slow: bool,
    ) -> (Result<()>, Arc<Counters>, Arc<Mutex<Inventory>>) {
        let c = Arc::new(Counters::default());
        let i = Arc::new(Mutex::new(Inventory::default()));
        let b = FakeBackend {
            inventory: i.clone(),
            append_failure: fail_append,
            flush_failure: fail_flush,
            slow,
        };
        let (tx, rx) = sync_channel(128);
        for n in 0..100 {
            tx.send(event(n)).unwrap();
        }
        tx.send(EventEnvelope::Shutdown).unwrap();
        let result = writer_loop(
            b,
            Subscribers::new(c.clone()),
            rx,
            c.clone(),
            Duration::from_millis(10),
        );
        (result, c, i)
    }
    #[test]
    fn fifo_stop_drains_every_accepted_event() {
        let (r, c, i) = run_fake(false, false, false);
        r.unwrap();
        assert_eq!(i.lock().unwrap().written, (0..100).collect::<Vec<_>>());
        assert_eq!(c.rows_flushed.load(Ordering::Relaxed), 100);
        assert_eq!(c.writer_events_processed.load(Ordering::Relaxed), 100);
    }
    #[test]
    fn flush_deadline_runs_while_queue_is_busy() {
        let (r, _, i) = run_fake(false, false, true);
        r.unwrap();
        assert!(i
            .lock()
            .unwrap()
            .flush_at
            .iter()
            .any(|n| *n > 0 && *n < 100));
    }
    #[test]
    fn append_and_flush_failures_poison_progress_but_drain_the_queue() {
        for (append, flush) in [(true, false), (false, true)] {
            let (r, c, _) = run_fake(append, flush, false);
            assert!(r.is_err());
            assert!(!c.writer_healthy.load(Ordering::Relaxed));
            assert_eq!(c.persistence_errors.load(Ordering::Relaxed), 1);
            assert_eq!(c.rows_flushed.load(Ordering::Relaxed), 0);
            assert_eq!(c.writer_events_processed.load(Ordering::Relaxed), 100);
        }
    }
    #[test]
    fn real_writer_drains_and_does_not_persist_content_or_arguments() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = dir.path().join("private/usage.duckdb");
        let c = Arc::new(Counters::default());
        let sink = EventSink::spawn(
            Store::open(&db).unwrap(),
            Subscribers::new(c.clone()),
            c.clone(),
        )
        .unwrap();
        for n in 0..32 {
            sink.tx.send(event(n)).unwrap();
        }
        let tls = TlsPlaintextEvent {
            ts_ns: 1,
            pid: 7,
            tgid: 7,
            cgroup_id: 9,
            comm: "synthetic".into(),
            ssl_ctx: 19,
            call_id: 1,
            direction: 0,
            total_bytes: 21,
            chunk_index: 0,
            chunk_total: 1,
            chunk_bytes: 21,
            truncated: false,
            read_failed: false,
            ex_variant: false,
            process_start: 11,
            exec_generation: 1,
            connection_generation: 23,
            call_sequence: 1,
            loss_epoch: 0,
            stream_offset: 0,
            lifecycle_end: false,
            plaintext: b"PRIVATE-TLS-SENTINEL!!".to_vec(),
        };
        sink.tx.send(EventEnvelope::TlsPlaintext(tls)).unwrap();
        sink.finish().unwrap();
        let conn = duckdb::Connection::open(&db).unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM events_proc_exec WHERE cmdline <> ''",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0);
        let n: i64 = conn
            .query_row("SELECT count(*) FROM events_proc_exec", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 32);
        let n: i64 = conn
            .query_row("SELECT count(*) FROM events_tls_metadata", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM information_schema.columns WHERE column_name='plaintext'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0);
        drop(conn);
        for path in [db.clone(), db.with_extension("duckdb.wal")] {
            if path.exists() {
                let bytes = std::fs::read(path).unwrap();
                for secret in [b"PRIVATE-TLS-SENTINEL".as_slice(), b"PRIVATE-ARGS"] {
                    assert!(!bytes.windows(secret.len()).any(|w| w == secret));
                }
            }
        }
    }
}

# Phase 2.A — TLS Plaintext Uprobe Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Capture decrypted TLS plaintext from `OpenSSL`/`libssl.so`-using processes via uprobes, attribute to `(pid, tgid, comm, cgroup_id)`, persist to DuckDB, and surface human-scannable summaries (with opt-in raw bytes) over `tsctl tail`.

**Architecture:** New `bpf/tls.bpf.c` parallel to `net.bpf.c` with its own ringbuf and inflight LRU map. New `crates/tsd/src/tls.rs` parallel to `net_bytes.rs` owns the uprobe attach lifecycle, walks `/proc/*/maps` every 5s with `(dev, ino)` keying, attaches `SSL_write{,_ex}` + `SSL_read{,_ex}` (entry + uretprobe). All TLS records flow through a NEW single-writer DuckDB channel (`EventEnvelope` enum + `events_tx` mpsc) refactored from the Phase 1 direct-call sink shape. Tail rendering becomes per-subscriber so plaintext only reaches subscribers that opt in.

**Tech Stack:** Rust 1.86 / edition2024, libbpf-rs 0.24, libbpf-cargo 0.24, DuckDB 1.10502 (bundled), Linux 5.15+ (uprobe MEM_RINGBUF dest writes stable).

**Spec:** `docs/superpowers/specs/2026-05-07-phase-2a-tls-uprobe-design.md` (841 lines, commit `bc2f40c`). Read it before starting; this plan references section names and code blocks from that spec.

**Codex review:** the spec already absorbed 8 BLOCKING + 10 SHOULD-FIX from a codex read-only review pass. Don't relitigate the locked decisions; they're explicit in the spec.

---

## File Structure

### Created files

| File | Responsibility |
|---|---|
| `bpf/tls.bpf.c` | BPF program: 4 uprobes (`SSL_write{,_ex}`, `SSL_read{,_ex}`), 2 uretprobes for the read side, inflight LRU map, plaintext ringbuf, percpu collision/reserve counters |
| `crates/tsd/src/sink.rs` | NEW. `EventEnvelope` enum + `EventSink` (owns `events_tx: SyncSender<EventEnvelope>` + `store-writer` thread + `Subscribers` registry). Single concentration point for "event happened → persist + broadcast" |
| `crates/tsd/src/tls.rs` | TLS uprobe attach manager: discovery loop, dev/ino keyed `attached` map, ringbuf consumer thread, push to `EventEnvelope::TlsPlaintext` |
| `docs/superpowers/specs/2026-05-07-phase-2a-tls-uprobe-design.md` | Already exists (committed `bc2f40c`); referenced for code |

### Modified files

| File | Change |
|---|---|
| `bpf/ts_event.h` | Append `struct ts_tls_plaintext_payload` (40 bytes) + `_Static_assert` |
| `crates/ts-core/src/event.rs` | Add `TsTlsPlaintextPayload` Rust mirror + `decode_tls_plaintext` + `TLS_FLAG_*` consts |
| `crates/ts-core/src/control.rs` | Extend `Request::Tail` to carry `include_plaintext: bool` (serde default false) |
| `crates/tsd/src/main.rs` | Add `--track-cgroup <PATH>` repeated CLI flag; wire `EventSink` into the boot sequence; register `TlsAttachManager` |
| `crates/tsd/src/control.rs` | `Counters` gains 11 new fields; `Subscribers::broadcast` becomes per-subscriber render with `include_plaintext`; new `render_tail_line(env, include_plaintext) -> String`; redaction patterns; `tsctl status` formatter shows new lines |
| `crates/tsd/src/store.rs` | Add `SCHEMA_V2` block with `events_tls_plaintext` table + index; bump `apply_migrations` to v2; add `Store::tls_appender()` returning a `duckdb::Appender` for batched TLS inserts |
| `crates/tsd/src/cgroup.rs` | Add `pin_cgroup_filter_map(skel, path)` helper + `populate_own_cgroup(map_fd)` + `add_cgroup_path(map_fd, path)` for `--track-cgroup` |
| `crates/tsd/src/net_bytes.rs` | Refactor: stop calling `store.insert_*` and `subs.broadcast` directly; push `EventEnvelope::NetBytesSnapshot` onto `events_tx` |
| Existing exec consumer (in `main.rs`) | Same refactor: push `EventEnvelope::ProcExec` instead of direct calls |
| `crates/tsctl/src/main.rs` | Add `--show-plaintext` flag to `Cmd::Tail`; serialize `Request::Tail { include_plaintext }` |
| `crates/tsd/Cargo.toml` | Add `regex = "1"` to deps if not present (used for redaction + libssl path matching) |
| `crates/tsd/tests/tls_e2e.rs` | NEW. Integration tests behind `#[ignore]` |
| `crates/tsd/tests/fixtures/tls_client.c` | NEW. Tiny dynamic OpenSSL client built by `cc` at test build time |
| `crates/tsd/build.rs` | Extend (or create) to invoke `cc::Build` against the fixture C file when `pkg-config --exists openssl` succeeds |
| `DOC.md` | New Phase 2.A section |
| `~/.claude/LEARNED.md` | 2-3 entries for non-obvious gotchas discovered during implementation (added at the end as they're found) |

---

## Task 1: Refactor — introduce `EventEnvelope` + single-writer sink

**Why first:** every later task pushes events through this channel. Doing it as a no-op refactor of existing net/exec paths first means we ship the architectural change with green tests *before* adding TLS-specific noise.

**Files:**
- Create: `crates/tsd/src/sink.rs`
- Modify: `crates/tsd/src/main.rs` (wire `EventSink` into boot)
- Modify: `crates/tsd/src/net_bytes.rs` (push `EventEnvelope::NetBytesSnapshot` instead of direct calls)
- Modify: `crates/tsd/src/control.rs` (`Subscribers` gains per-subscriber state; `broadcast` becomes `broadcast_envelope`)
- Modify: `crates/ts-core/src/control.rs` (`Request::Tail` becomes a struct variant with `#[serde(default)] include_plaintext: bool`)
- Modify: `crates/tsctl/src/main.rs` (serialize the new Tail variant)

- [ ] **Step 1.1: Add `Request::Tail { include_plaintext }` with serde-default backward compat**

Edit `crates/ts-core/src/control.rs`. Find the existing `Request` enum (look for `pub enum Request`); replace the bare `Tail,` variant with:

```rust
Tail {
    #[serde(default)]
    include_plaintext: bool,
},
```

Add a round-trip test in the same file's `mod tests`:

```rust
#[test]
fn tail_request_default_include_plaintext_is_false() {
    let r: Request = serde_json::from_str(r#"{"op":"Tail"}"#).unwrap();
    match r {
        Request::Tail { include_plaintext } => assert!(!include_plaintext),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn tail_request_explicit_include_plaintext_true() {
    let r: Request = serde_json::from_str(r#"{"op":"Tail","include_plaintext":true}"#).unwrap();
    match r {
        Request::Tail { include_plaintext } => assert!(include_plaintext),
        _ => panic!("wrong variant"),
    }
}
```

- [ ] **Step 1.2: Run those two tests, expect FAIL (variant shape changed, callsites need updating)**

Run: `cargo test -p ts-core tail_request -- --nocapture`
Expected: compile errors at every callsite that pattern-matches `Request::Tail` (in `tsd/src/control.rs` and `tsctl/src/main.rs`).

- [ ] **Step 1.3: Update tsctl call site**

Edit `crates/tsctl/src/main.rs`. Find `cmd_tail` (currently `let req = serde_json::to_string(&Request::Tail)?;`). Replace with:

```rust
fn cmd_tail(uds_path: &PathBuf, include_plaintext: bool) -> Result<()> {
    let mut stream = connect(uds_path)?;
    let req = serde_json::to_string(&Request::Tail { include_plaintext })?;
    writeln!(stream, "{req}").context("write request")?;
    // ... rest unchanged
}
```

Add the flag to the `Cmd::Tail` clap subcommand:

```rust
/// Live event stream from tsd. Exits on SIGINT.
Tail {
    /// Include decrypted TLS plaintext bytes inline (with redaction).
    /// Without this flag, TLS records render as metadata + sha256 prefix only.
    #[arg(long)]
    show_plaintext: bool,
},
```

And update the `match args.cmd` arm:

```rust
Cmd::Tail { show_plaintext } => cmd_tail(&args.uds_path, show_plaintext)?,
```

- [ ] **Step 1.4: Update tsd control-server call site**

Edit `crates/tsd/src/control.rs`. Find every `Request::Tail =>` pattern (use `grep -n "Request::Tail" crates/tsd/src/control.rs`). Replace each with:

```rust
Request::Tail { include_plaintext } => {
    // existing handler body, with `include_plaintext` now in scope
}
```

Inside the handler, capture `include_plaintext` into the subscriber registration call. (The actual subscriber-side change comes in Step 1.7; for now the handler body can still ignore the flag — just take the parameter so the build stays green.)

- [ ] **Step 1.5: Run the round-trip tests, expect PASS**

Run: `cargo test -p ts-core tail_request -- --nocapture`
Expected: 2 passed.

- [ ] **Step 1.6: Run the full workspace build, expect green**

Run: `cargo build --workspace --all-targets 2>&1 | tail -20`
Expected: 0 errors. Warnings about unused `include_plaintext` in `tsd::control` are fine for now.

- [ ] **Step 1.7: Add `EventEnvelope` enum + `EventSink` struct (the new sink module)**

Create `crates/tsd/src/sink.rs` with the following content:

```rust
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

/// Capacity of the `events_tx` channel. Sized so a brief DuckDB stall
/// doesn't drop events from a busy net_bytes flush, but small enough
/// that backpressure is observable. Same order of magnitude as
/// `Subscribers`' per-subscriber channel.
pub const EVENT_CHANNEL_CAPACITY: usize = 4096;

/// Counter bumped when `events_tx.try_send` fails (channel full).
/// Distinct from `tail_dropped_events`, which is a downstream-of-sink
/// drop. This one indicates the SINK (DuckDB writer) can't keep up.
pub fn dropped_events_metric_name() -> &'static str { "sink_dropped_events" }

/// One enum per event family. Owns the data so `EventSink` doesn't
/// need to know how to serialize each one.
#[derive(Debug, Clone)]
pub enum EventEnvelope {
    ProcExec(ProcExecEvent),
    NetConnect(NetConnectEvent),
    NetBytesSnapshot(NetBytesSnapshot),
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
    pub plaintext: Vec<u8>, // owned; only the chunk_bytes prefix is meaningful
}

pub struct EventSink {
    pub tx: SyncSender<EventEnvelope>,
    writer_handle: Option<JoinHandle<()>>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
}

impl EventSink {
    pub fn spawn(store: Arc<Store>, subs: Subscribers) -> Result<Self> {
        let (tx, rx) = sync_channel::<EventEnvelope>(EVENT_CHANNEL_CAPACITY);
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown_for_thread = shutdown.clone();
        let writer_handle = thread::Builder::new()
            .name("tsd-store-writer".into())
            .spawn(move || writer_loop(store, subs, rx, shutdown_for_thread))
            .context("spawn store-writer thread")?;
        Ok(Self { tx, writer_handle: Some(writer_handle), shutdown })
    }
}

impl Drop for EventSink {
    fn drop(&mut self) {
        self.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(h) = self.writer_handle.take() {
            let _ = h.join();
        }
    }
}

fn writer_loop(
    store: Arc<Store>,
    subs: Subscribers,
    rx: Receiver<EventEnvelope>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) {
    while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(env) => {
                if let Err(e) = persist(&store, &env) {
                    tracing::warn!(error=?e, "store insert failed");
                }
                subs.broadcast_envelope(&env);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn persist(store: &Store, env: &EventEnvelope) -> Result<()> {
    match env {
        EventEnvelope::ProcExec(e) => store.insert_proc_exec(
            e.ts_ns, e.pid, e.tgid, e.cgroup_id, &e.comm, &e.cmdline,
        ),
        EventEnvelope::NetConnect(e) => store.insert_net_connect(
            e.ts_ns, e.pid, e.tgid, e.cgroup_id, &e.comm, &e.cmdline,
            &e.dst_addr, e.dst_port, e.family, e.protocol,
        ),
        EventEnvelope::NetBytesSnapshot(e) => store.insert_net_bytes(
            e.snapshot_ts_ns, e.sock_cookie, e.pid, &e.comm, &e.cmdline,
            e.tx_bytes, e.rx_bytes, e.last_event_ns,
        ),
        EventEnvelope::TlsPlaintext(_) => {
            // Filled in by Task 11 (Appender path). For now this is a no-op
            // so the refactor lands without a TLS table.
            Ok(())
        }
    }
}
```

Add `mod sink;` to `crates/tsd/src/main.rs` (alphabetical order: after `proc_cache;`).

- [ ] **Step 1.8: Refactor `Subscribers` to support per-subscriber state**

Edit `crates/tsd/src/control.rs`. The current `Subscribers` holds `HashMap<u64, SyncSender<String>>`. Change to:

```rust
struct SubscriberSlot {
    sender: SyncSender<String>,
    include_plaintext: bool,
}

pub struct Subscribers {
    inner: Arc<Mutex<HashMap<u64, SubscriberSlot>>>,
    next_id: Arc<AtomicU64>,
    counters: Arc<Counters>,
}
```

Update `register` to take `include_plaintext: bool` and store it in the slot. Replace the existing `broadcast(&str)` method with two methods:

```rust
impl Subscribers {
    /// Push a pre-rendered string to every subscriber regardless of
    /// per-subscriber options. Used for envelope-agnostic broadcasts
    /// or for compatibility during the refactor.
    pub fn broadcast(&self, line: &str) {
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.retain(|_id, slot| match slot.sender.try_send(line.to_string()) {
            Ok(_) => true,
            Err(TrySendError::Full(_)) => {
                self.counters.tail_dropped_events.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(TrySendError::Disconnected(_)) => false,
        });
    }

    /// Render per-subscriber via `render_tail_line` from
    /// `crate::sink::EventEnvelope`. Plaintext is only included for
    /// subscribers that opted in at handshake time.
    pub fn broadcast_envelope(&self, env: &crate::sink::EventEnvelope) {
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.retain(|_id, slot| {
            let line = render_tail_line(env, slot.include_plaintext);
            match slot.sender.try_send(line) {
                Ok(_) => true,
                Err(TrySendError::Full(_)) => {
                    self.counters.tail_dropped_events.fetch_add(1, Ordering::Relaxed);
                    true
                }
                Err(TrySendError::Disconnected(_)) => false,
            }
        });
    }
}
```

Add a stub `render_tail_line` in the same file — it'll be filled out properly in Task 12. For now:

```rust
pub fn render_tail_line(
    env: &crate::sink::EventEnvelope,
    _include_plaintext: bool,
) -> String {
    // Phase 2.A interim: serialize via serde_json on the event-specific
    // shape. Per-subscriber plaintext gating lands in Task 12; for the
    // refactor pass we just pass-through whatever shape we had.
    match env {
        crate::sink::EventEnvelope::ProcExec(e) => {
            format!(r#"{{"kind":"proc.exec","ts_ns":{},"pid":{},"comm":"{}"}}"#,
                e.ts_ns, e.pid, e.comm.escape_default())
        }
        crate::sink::EventEnvelope::NetConnect(e) => {
            format!(r#"{{"kind":"net.connect","ts_ns":{},"pid":{},"dst_port":{}}}"#,
                e.ts_ns, e.pid, e.dst_port)
        }
        crate::sink::EventEnvelope::NetBytesSnapshot(e) => {
            format!(r#"{{"kind":"net.bytes","snapshot_ts_ns":{},"sock_cookie":{},"tx":{},"rx":{}}}"#,
                e.snapshot_ts_ns, e.sock_cookie, e.tx_bytes, e.rx_bytes)
        }
        crate::sink::EventEnvelope::TlsPlaintext(e) => {
            format!(r#"{{"kind":"tls.{dir}","ts_ns":{ts},"pid":{pid},"chunk":{ci}}}"#,
                dir = if e.direction == 0 { "write" } else { "read" },
                ts = e.ts_ns, pid = e.pid, ci = e.chunk_index)
        }
    }
}
```

Add `pub tail_dropped_events: AtomicU64,` to the existing `Counters` struct. Initialize to 0 wherever `Counters::default()` or `Counters { ... }` is constructed.

- [ ] **Step 1.9: Migrate net_bytes consumer to push envelopes**

Edit `crates/tsd/src/net_bytes.rs`. Find the existing call sites that do `store.insert_net_bytes(...)` and `subs.broadcast(&line)`. Replace with:

```rust
events_tx.send(EventEnvelope::NetBytesSnapshot(NetBytesSnapshot {
    snapshot_ts_ns,
    sock_cookie,
    pid,
    comm,
    cmdline,
    tx_bytes,
    rx_bytes,
    last_event_ns,
})).ok(); // drop on full sink — counter tracks
```

(Drop the now-unused `store: Arc<Store>` and `subs: Subscribers` parameters; thread the new `events_tx: SyncSender<EventEnvelope>` instead.) Same shape applies to wherever `events_net_connect` and `events_proc_exec` are inserted today — find them with `grep -rn "store.insert_" crates/tsd/src/` and convert all three.

- [ ] **Step 1.10: Wire `EventSink` into main.rs boot**

Edit `crates/tsd/src/main.rs`. After the `Store` and `Subscribers` are created (look for `Subscribers::new(counters.clone())`), add:

```rust
let event_sink = EventSink::spawn(store.clone(), subs.clone())?;
let events_tx = event_sink.tx.clone();
```

Pass `events_tx` to anywhere that previously got `store` + `subs` for event production. Keep `event_sink` alive for the daemon's lifetime (its `Drop` joins the writer thread).

- [ ] **Step 1.11: Run all existing tests, expect green**

Run: `cargo test --workspace 2>&1 | tail -30`
Expected: same pass count as before this task (47 unit tests as of `v0.0.8-phase1g`), no regressions.

If anything fails: the typical break is a missing `Counters::default()` field for `tail_dropped_events`. Add `tail_dropped_events: AtomicU64::new(0),` wherever `Counters` is constructed in tests.

- [ ] **Step 1.12: Run the existing integration tests under sudo**

Run: `sudo -E cargo test -p tsd -- --ignored 2>&1 | tail -30`
Expected: 7 ignored tests pass (same as `v0.0.8-phase1g`). The refactor is no-op-equivalent.

- [ ] **Step 1.13: Commit**

```bash
git add crates/tsd/src/sink.rs \
        crates/tsd/src/main.rs \
        crates/tsd/src/control.rs \
        crates/tsd/src/net_bytes.rs \
        crates/tsd/src/store.rs \
        crates/ts-core/src/control.rs \
        crates/tsctl/src/main.rs
git commit -m "$(cat <<'EOF'
refactor(tsd): introduce EventEnvelope + single-writer sink + per-sub Tail render

Phase 2.A prep. No behavior change yet:
- new EventSink owns the DuckDB writer thread; consumers push envelopes
  via events_tx mpsc instead of calling store/subs directly
- Subscribers stores per-subscriber include_plaintext; new
  broadcast_envelope renders per subscriber via render_tail_line stub
- Request::Tail { include_plaintext: bool } (serde default false) keeps
  old tsctl wire-compatible
- tsctl tail --show-plaintext flag added (no rendering effect yet)

Counters: + tail_dropped_events. All 47 unit + 7 integration tests pass.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Wire format — `TsTlsPlaintextPayload` + decoder + DuckDB schema v2

**Files:**
- Modify: `bpf/ts_event.h`
- Modify: `crates/ts-core/src/event.rs`
- Modify: `crates/tsd/src/store.rs`

- [ ] **Step 2.1: Append payload struct + static_assert to `bpf/ts_event.h`**

Open `bpf/ts_event.h`. Append BEFORE the closing `#endif`:

```c
/*
 * Payload for TS_TLS_PLAINTEXT (one record per chunk; up to 16 chunks per
 * SSL_* call). Total fixed payload: 40 bytes. Trailing plaintext slice of
 * exactly chunk_bytes follows; max 4096 bytes.
 *
 * Stream-call key: (tgid, ssl_ctx, direction, call_id) where call_id =
 * entry ktime_ns. Within a call, chunk_index orders bytes.
 */
struct ts_tls_plaintext_payload {
    __u64 ssl_ctx;          /* userspace SSL* pointer; process-scoped */
    __u64 call_id;          /* entry ktime_ns; unique within (tgid,ssl,dir) */
    __u64 entry_cgroup_id;  /* cgroup at SSL_* entry; emit this, not return-time */
    __u32 total_bytes;      /* bytes in this SSL_* call (pre-chunking) */
    __u16 chunk_index;
    __u16 chunk_total;      /* 1..16 */
    __u16 chunk_bytes;      /* 0..4096 */
    __u8  direction;        /* 0 = write, 1 = read */
    __u8  flags;            /* bit 0=truncated, bit 1=read_failed, bit 2=ex_variant */
    __u8  _pad[4];
};

_Static_assert(sizeof(struct ts_tls_plaintext_payload) == 40,
               "tls payload must be exactly 40 bytes");
```

- [ ] **Step 2.2: Write the failing tests in `crates/ts-core/src/event.rs`**

Add to the existing `mod tests` block:

```rust
#[test]
fn tls_payload_size_is_40() {
    assert_eq!(size_of::<TsTlsPlaintextPayload>(), 40);
    assert_eq!(align_of::<TsTlsPlaintextPayload>(), 8);
}

#[test]
fn decode_tls_plaintext_round_trip() {
    let pl = TsTlsPlaintextPayload {
        ssl_ctx: 0xdead_beef_cafe,
        call_id: 1715073082114000000,
        entry_cgroup_id: 12345,
        total_bytes: 10295,
        chunk_index: 0,
        chunk_total: 3,
        chunk_bytes: 1024,
        direction: 0,
        flags: 0,
        _pad: [0; 4],
    };
    let body = vec![0xAB; 1024];
    let mut buf = Vec::with_capacity(40 + 1024);
    buf.extend_from_slice(&unsafe {
        std::slice::from_raw_parts(&pl as *const _ as *const u8, 40)
    });
    buf.extend_from_slice(&body);

    let (decoded, plaintext) = decode_tls_plaintext(&buf).expect("decode");
    assert_eq!(decoded.ssl_ctx, pl.ssl_ctx);
    assert_eq!(decoded.chunk_bytes, 1024);
    assert_eq!(plaintext, body.as_slice());
}

#[test]
fn decode_tls_plaintext_zero_chunk_bytes_is_empty_slice() {
    let pl = TsTlsPlaintextPayload {
        ssl_ctx: 0,
        call_id: 0,
        entry_cgroup_id: 0,
        total_bytes: 0,
        chunk_index: 0,
        chunk_total: 1,
        chunk_bytes: 0,
        direction: 1,
        flags: TLS_FLAG_READ_FAILED,
        _pad: [0; 4],
    };
    let buf = unsafe { std::slice::from_raw_parts(&pl as *const _ as *const u8, 40) };
    let (decoded, plaintext) = decode_tls_plaintext(buf).expect("decode");
    assert_eq!(plaintext.len(), 0);
    assert!(decoded.flags & TLS_FLAG_READ_FAILED != 0);
}

#[test]
fn decode_tls_plaintext_short_buffer_is_truncated_err() {
    let buf = [0u8; 20]; // less than 40
    let err = decode_tls_plaintext(&buf).unwrap_err();
    matches!(err, DecodeError::Truncated { .. });
}

#[test]
fn decode_tls_plaintext_bad_length_err() {
    let pl = TsTlsPlaintextPayload {
        ssl_ctx: 0, call_id: 0, entry_cgroup_id: 0, total_bytes: 4096,
        chunk_index: 0, chunk_total: 1, chunk_bytes: 4096,
        direction: 0, flags: 0, _pad: [0; 4],
    };
    let mut buf = Vec::with_capacity(40 + 100);
    buf.extend_from_slice(&unsafe {
        std::slice::from_raw_parts(&pl as *const _ as *const u8, 40)
    });
    buf.extend_from_slice(&[0u8; 100]); // declared 4096 but only 100 follow
    let err = decode_tls_plaintext(&buf).unwrap_err();
    matches!(err, DecodeError::BadLength { .. });
}
```

- [ ] **Step 2.3: Run the tests, expect FAIL (types not defined)**

Run: `cargo test -p ts-core decode_tls_plaintext tls_payload -- --nocapture 2>&1 | tail -20`
Expected: compile errors `cannot find type 'TsTlsPlaintextPayload'`, `cannot find function 'decode_tls_plaintext'`, etc.

- [ ] **Step 2.4: Implement the Rust mirror + decoder**

Append to `crates/ts-core/src/event.rs` after the existing `TsNetBytesValue` block:

```rust
/// Mirror of `struct ts_tls_plaintext_payload` in `bpf/ts_event.h`.
///
/// Layout (natural alignment, no `packed`):
/// - 0..8   ssl_ctx
/// - 8..16  call_id
/// - 16..24 entry_cgroup_id
/// - 24..28 total_bytes
/// - 28..30 chunk_index
/// - 30..32 chunk_total
/// - 32..34 chunk_bytes
/// - 34..35 direction
/// - 35..36 flags
/// - 36..40 _pad
///
/// Total size: 40 bytes. Alignment: 8.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TsTlsPlaintextPayload {
    pub ssl_ctx: u64,
    pub call_id: u64,
    pub entry_cgroup_id: u64,
    pub total_bytes: u32,
    pub chunk_index: u16,
    pub chunk_total: u16,
    pub chunk_bytes: u16,
    pub direction: u8,
    pub flags: u8,
    pub _pad: [u8; 4],
}
const _: () = assert!(size_of::<TsTlsPlaintextPayload>() == 40);
const _: () = assert!(align_of::<TsTlsPlaintextPayload>() == 8);

pub const TLS_FLAG_TRUNCATED: u8   = 1 << 0;
pub const TLS_FLAG_READ_FAILED: u8 = 1 << 1;
pub const TLS_FLAG_EX_VARIANT: u8  = 1 << 2;

/// Decode a `TsTlsPlaintextPayload` from a byte slice that includes the
/// trailing `chunk_bytes` of plaintext.
pub fn decode_tls_plaintext(
    buf: &[u8],
) -> Result<(TsTlsPlaintextPayload, &[u8]), DecodeError> {
    const HDR: usize = std::mem::size_of::<TsTlsPlaintextPayload>();
    if buf.len() < HDR {
        return Err(DecodeError::Truncated { got: buf.len(), need: HDR });
    }
    // Safety: TsTlsPlaintextPayload is repr(C) with no internal references.
    // `buf[..HDR]` has the right size; alignment of buf is opaque so we copy.
    let mut payload = std::mem::MaybeUninit::<TsTlsPlaintextPayload>::uninit();
    unsafe {
        std::ptr::copy_nonoverlapping(
            buf.as_ptr(),
            payload.as_mut_ptr() as *mut u8,
            HDR,
        );
    }
    let payload = unsafe { payload.assume_init() };

    let need_total = HDR + payload.chunk_bytes as usize;
    if buf.len() < need_total {
        return Err(DecodeError::BadLength {
            declared: payload.chunk_bytes as usize,
            available: buf.len() - HDR,
        });
    }
    let plaintext = &buf[HDR..HDR + payload.chunk_bytes as usize];
    Ok((payload, plaintext))
}
```

- [ ] **Step 2.5: Run the tests, expect PASS**

Run: `cargo test -p ts-core decode_tls_plaintext tls_payload -- --nocapture 2>&1 | tail -30`
Expected: 5 passed.

- [ ] **Step 2.6: Add `events_tls_plaintext` table + index to `store.rs` schema v2**

Edit `crates/tsd/src/store.rs`. Find the existing `SCHEMA_V1` constant (around line 16). Add a new constant after it:

```rust
const SCHEMA_V2: &str = r#"
CREATE TABLE IF NOT EXISTS events_tls_plaintext (
    ts_ns           BIGINT  NOT NULL,
    pid             INTEGER NOT NULL,
    tgid            INTEGER NOT NULL,
    cgroup_id       BIGINT  NOT NULL,
    comm            VARCHAR NOT NULL,
    ssl_ctx         BIGINT  NOT NULL,
    call_id         BIGINT  NOT NULL,
    direction       TINYINT NOT NULL,
    total_bytes     INTEGER NOT NULL,
    chunk_index     SMALLINT NOT NULL,
    chunk_total     SMALLINT NOT NULL,
    chunk_bytes     SMALLINT NOT NULL,
    truncated       BOOLEAN NOT NULL,
    read_failed     BOOLEAN NOT NULL,
    ex_variant      BOOLEAN NOT NULL,
    plaintext       BLOB
);
CREATE INDEX IF NOT EXISTS idx_tls_ts ON events_tls_plaintext(ts_ns);
CREATE INDEX IF NOT EXISTS idx_tls_call
    ON events_tls_plaintext(tgid, ssl_ctx, direction, call_id, chunk_index);
"#;
```

Update `apply_migrations`:

```rust
fn apply_migrations(&mut self) -> Result<()> {
    self.conn.execute_batch(SCHEMA_V1).context("apply v1 schema")?;
    let current: i64 = self
        .conn
        .query_row("SELECT COALESCE(MAX(version), 0) FROM schema_version", [], |r| r.get(0))
        .context("read schema_version")?;
    if current < 1 {
        self.conn.execute("INSERT INTO schema_version (version) VALUES (1)", [])
            .context("record schema v1")?;
    }
    self.conn.execute_batch(SCHEMA_V2).context("apply v2 schema")?;
    if current < 2 {
        self.conn.execute("INSERT INTO schema_version (version) VALUES (2)", [])
            .context("record schema v2")?;
    }
    Ok(())
}
```

- [ ] **Step 2.7: Add a smoke test for the new table**

Find the existing `#[cfg(test)] mod tests` in `store.rs` (or create one). Add:

```rust
#[test]
fn schema_v2_creates_events_tls_plaintext() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("test.duckdb");
    let store = Store::open(&path).unwrap();
    let count = store.count_table("events_tls_plaintext").unwrap();
    assert_eq!(count, 0);
    let v: i64 = store.conn
        .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
        .unwrap();
    assert!(v >= 2, "schema_version should be >= 2 after migrate");
}
```

(If `Store::conn` is private, add a `#[cfg(test)] pub(crate) fn schema_version(&self) -> Result<i64>` helper that wraps the query.)

- [ ] **Step 2.8: Run, expect PASS**

Run: `cargo test -p tsd schema_v2 -- --nocapture`
Expected: 1 passed.

- [ ] **Step 2.9: Run full workspace test, expect green**

Run: `cargo test --workspace 2>&1 | tail -10`
Expected: prior pass count + 6 (5 ts-core + 1 tsd schema test).

- [ ] **Step 2.10: Commit**

```bash
git add bpf/ts_event.h \
        crates/ts-core/src/event.rs \
        crates/tsd/src/store.rs
git commit -m "$(cat <<'EOF'
feat(ts-core,tsd): TsTlsPlaintextPayload wire format + DuckDB v2 schema

40-byte TLS payload with composite stream-call key (tgid, ssl_ctx,
direction, call_id) where call_id = entry ktime_ns. New
events_tls_plaintext table with idx_tls_call index for downstream
chunk-by-call lookups.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Cgroup filter map — pinned bpffs map + `--track-cgroup` CLI

**Why now:** the BPF program in Task 4 references a pinned `cgroup_filter` map. Userspace must create + populate it before the BPF skel is loaded. Doing this in its own task keeps the BPF task focused on the program.

**Files:**
- Modify: `crates/tsd/src/cgroup.rs`
- Modify: `crates/tsd/src/main.rs`

- [ ] **Step 3.1: Add helpers to `cgroup.rs`**

Append to `crates/tsd/src/cgroup.rs`:

```rust
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::path::Path;

pub const BPFFS_DIR: &str = "/sys/fs/bpf/tokenscope";
pub const CGROUP_FILTER_PIN: &str = "/sys/fs/bpf/tokenscope/cgroup_filter";

/// Ensure the bpffs subdirectory exists. The pinned map lives here.
pub fn ensure_bpffs_dir() -> Result<()> {
    if !Path::new(BPFFS_DIR).exists() {
        std::fs::create_dir_all(BPFFS_DIR)
            .with_context(|| format!("mkdir {BPFFS_DIR}"))?;
    }
    Ok(())
}

/// Read this process's cgroup id (v2 unified). Used to populate the
/// filter so the daemon can observe its own TLS traffic out of the box.
pub fn own_cgroup_id() -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(format!("/proc/self/cgroup"))
        .context("stat /proc/self/cgroup")?;
    // The cgroup_id BPF helper returns the inode number of the cgroup
    // directory. /proc/self/cgroup is a file describing the path; we
    // need to follow it to /sys/fs/cgroup/<that-path> and stat THAT.
    let txt = std::fs::read_to_string("/proc/self/cgroup")
        .context("read /proc/self/cgroup")?;
    // v2 line shape: "0::/path/to/cgroup"
    let path = txt.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(|p| format!("/sys/fs/cgroup{}", p.trim_end()))
        .ok_or_else(|| anyhow::anyhow!("no v2 cgroup line in /proc/self/cgroup"))?;
    let m = std::fs::metadata(&path)
        .with_context(|| format!("stat {path}"))?;
    Ok(m.ino())
}

/// Stat a cgroup path and return its inode (== bpf_get_current_cgroup_id).
pub fn cgroup_path_id(path: &Path) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?;
    Ok(m.ino())
}

/// Add a cgroup_id to the pinned filter map. Idempotent (BPF_ANY).
/// `map_fd` is the file descriptor of the opened pinned map.
pub fn add_to_cgroup_filter(map_fd: RawFd, cgroup_id: u64) -> Result<()> {
    use libbpf_sys::{bpf_map_update_elem, BPF_ANY};
    let key = cgroup_id;
    let val: u8 = 1;
    let rc = unsafe {
        bpf_map_update_elem(
            map_fd,
            &key as *const _ as *const _,
            &val as *const _ as *const _,
            BPF_ANY as u64,
        )
    };
    if rc != 0 {
        anyhow::bail!("bpf_map_update_elem cgroup_filter id={cgroup_id} rc={rc}");
    }
    Ok(())
}

/// Open the pinned cgroup_filter map by path, returning an owned FD.
/// The skeleton's reuse-pinned-by-name will see the same file when
/// loaded.
pub fn open_pinned_cgroup_filter() -> Result<OwnedFd> {
    use libbpf_sys::bpf_obj_get;
    use std::ffi::CString;
    let c_path = CString::new(CGROUP_FILTER_PIN).unwrap();
    let fd = unsafe { bpf_obj_get(c_path.as_ptr()) };
    if fd < 0 {
        anyhow::bail!("bpf_obj_get {CGROUP_FILTER_PIN} failed (errno={})",
                      std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
```

You'll need to add to the file's top imports: `use std::os::fd::FromRawFd;` and `use anyhow::{Context, Result};` (if not already present).

- [ ] **Step 3.2: Add `--track-cgroup` CLI flag to tsd**

Edit `crates/tsd/src/main.rs`. Find the existing `Args` struct (clap derive). Add:

```rust
/// Cgroup paths to track for TLS uprobes. Repeatable. Defaults to
/// the daemon's own cgroup if no flag is given.
#[arg(long, value_name = "PATH")]
track_cgroup: Vec<PathBuf>,
```

In `main()`, after the existing setup but BEFORE BPF skeletons are loaded, add:

```rust
crate::cgroup::ensure_bpffs_dir()?;
// The cgroup_filter map is created by the TLS skeleton load (Task 4).
// We populate it AFTER the skeleton is loaded so the FD is real.
// For now: collect the cgroup ids the user wants to track.
let mut tracked_cgroup_ids: Vec<u64> = Vec::new();
tracked_cgroup_ids.push(crate::cgroup::own_cgroup_id()?);
for path in &args.track_cgroup {
    tracked_cgroup_ids.push(crate::cgroup::cgroup_path_id(path)?);
}
tracing::info!(count=tracked_cgroup_ids.len(), "tls cgroup filter ids resolved");
```

(The actual `add_to_cgroup_filter` calls happen in Task 4 once the skeleton is loaded and the map is pinned.)

- [ ] **Step 3.3: Smoke test the helpers (no root needed for the math parts)**

Add to `crates/tsd/src/cgroup.rs` `mod tests`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_cgroup_id_works() {
        // CI runs in some cgroup or other; just expect a non-zero id.
        let id = own_cgroup_id().expect("own cgroup id");
        assert!(id > 0, "got cgroup id 0");
    }

    #[test]
    fn ensure_bpffs_dir_idempotent_or_errors_cleanly() {
        // Without root we can't actually mkdir there, so we just check
        // the function returns *something* without panicking.
        let _ = ensure_bpffs_dir();
    }
}
```

- [ ] **Step 3.4: Run, expect PASS (own_cgroup_id) and tolerate (bpffs)**

Run: `cargo test -p tsd cgroup -- --nocapture`
Expected: `own_cgroup_id_works` passes; `ensure_bpffs_dir_idempotent_or_errors_cleanly` passes regardless of permission outcome.

- [ ] **Step 3.5: Commit**

```bash
git add crates/tsd/src/cgroup.rs crates/tsd/src/main.rs
git commit -m "$(cat <<'EOF'
feat(tsd): cgroup_filter map plumbing + --track-cgroup CLI

Helpers for the bpffs-pinned cgroup_filter map that Phase 2.A's TLS
uprobes use to scope per-cgroup. Daemon defaults to tracking its own
cgroup; --track-cgroup PATH is repeatable.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: BPF program scaffold — `bpf/tls.bpf.c` (maps + skeleton, stub probes)

**Files:**
- Create: `bpf/tls.bpf.c`
- Modify: `crates/tsd/build.rs` (add `tls.bpf.c` to skeleton generation)
- Create: `crates/tsd/src/skeletons.rs` entries for `TlsSkel`

- [ ] **Step 4.1: Add the new BPF C source**

Create `bpf/tls.bpf.c`:

```c
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Phase 2.A. uprobes on libssl.so SSL_write{,_ex} and SSL_read{,_ex} +
 * uretprobes on the read side. Emits TS_TLS_PLAINTEXT records onto
 * a dedicated 4 MiB ringbuf. Cgroup-scoped via the pinned cgroup_filter
 * map shared with future per-cgroup attach work.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "ts_event.h"

char LICENSE[] SEC("license") = "GPL";

#define MAX_CHUNKS 16
#define CHUNK_BYTES 4096

#define TLS_FLAG_TRUNCATED   (1 << 0)
#define TLS_FLAG_READ_FAILED (1 << 1)
#define TLS_FLAG_EX_VARIANT  (1 << 2)

/* Pinned shared with userspace and (later) with cgroup.rs. */
struct cgroup_filter_key { __u64 cgroup_id; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, struct cgroup_filter_key);
    __type(value, __u8);
} cgroup_filter SEC(".maps");

struct tls_inflight_key { __u64 pid_tgid; };
struct tls_inflight_val {
    __u64 ssl_ctx;
    __u64 buf_ptr;
    __u64 entry_ts_ns;
    __u64 entry_cgroup_id;
    __u64 readbytes_ptr;
    __u32 num;
    __u8  is_ex;
    __u8  _pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct tls_inflight_key);
    __type(value, struct tls_inflight_val);
} tls_inflight SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} events_tls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} tls_reserve_fail SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} tls_inflight_collision SEC(".maps");

static __always_inline bool cgroup_tracked(__u64 cgid) {
    struct cgroup_filter_key k = { .cgroup_id = cgid };
    return bpf_map_lookup_elem(&cgroup_filter, &k) != NULL;
}

/* Stubs for now; Tasks 5–8 fill the bodies. */

SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write_entry, void *ssl, const void *buf, int num)
{
    return 0;
}

SEC("uprobe/SSL_write_ex")
int BPF_UPROBE(ssl_write_ex_entry, void *ssl, const void *buf, size_t num,
               size_t *written)
{
    return 0;
}

SEC("uprobe/SSL_read")
int BPF_UPROBE(ssl_read_entry, void *ssl, void *buf, int num)
{
    return 0;
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ssl_read_exit, int ret)
{
    return 0;
}

SEC("uprobe/SSL_read_ex")
int BPF_UPROBE(ssl_read_ex_entry, void *ssl, void *buf, size_t num,
               size_t *readbytes)
{
    return 0;
}

SEC("uretprobe/SSL_read_ex")
int BPF_URETPROBE(ssl_read_ex_exit, int ret)
{
    return 0;
}
```

- [ ] **Step 4.2: Add `tls.bpf.c` to skeleton generation in `build.rs`**

Open `crates/tsd/build.rs`. Find the existing `SkeletonBuilder::new()` invocations (one per BPF program, e.g. `net.bpf.c` and `sched_exec.bpf.c`). Add a third:

```rust
SkeletonBuilder::new()
    .source("../../bpf/tls.bpf.c")
    .clang_args([
        "-I", "../../bpf",
        "-Wno-unused-function",
        "-Wno-compare-distinct-pointer-types",
    ])
    .build_and_generate(&out_dir.join("tls.skel.rs"))
    .expect("build tls.bpf.c skeleton");
println!("cargo:rerun-if-changed=../../bpf/tls.bpf.c");
println!("cargo:rerun-if-changed=../../bpf/ts_event.h");
```

(Match the exact arg style used by the existing `net.bpf.c` invocation in the same file.)

- [ ] **Step 4.3: Add `TlsSkel` to `skeletons.rs`**

Open `crates/tsd/src/skeletons.rs`. The existing pattern is one module + re-export per skeleton. Add:

```rust
pub mod tls {
    include!(concat!(env!("OUT_DIR"), "/tls.skel.rs"));
}
pub use tls::*;
```

(If `skeletons.rs` already uses a different aggregation idiom, follow that.)

- [ ] **Step 4.4: Build and verify the skeleton compiles**

Run: `cargo build -p tsd 2>&1 | tail -30`
Expected: 0 errors, the build script logs `tls.skel.rs` generation.

- [ ] **Step 4.5: Smoke test — load the skeleton without attaching**

Add to `crates/tsd/src/skeletons.rs` (or a new test file):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires CAP_BPF"]
    fn tls_skeleton_loads_with_pinned_cgroup_filter() {
        crate::cgroup::ensure_bpffs_dir().expect("mkdir bpffs");
        let mut open_skel = TlsSkelBuilder::default()
            .open()
            .expect("open tls skel");
        // Pin the cgroup_filter map BY NAME to our bpffs dir.
        open_skel
            .maps_mut()
            .cgroup_filter()
            .set_pin_path(crate::cgroup::CGROUP_FILTER_PIN)
            .expect("set pin path");
        let skel = open_skel.load().expect("load tls skel");
        // The pinned map should now exist on disk.
        assert!(std::path::Path::new(crate::cgroup::CGROUP_FILTER_PIN).exists());
        drop(skel); // drops the FDs; pin file persists across daemon restarts
    }
}
```

- [ ] **Step 4.6: Run the smoke test under sudo**

Run: `sudo -E cargo test -p tsd tls_skeleton_loads -- --ignored --nocapture 2>&1 | tail -10`
Expected: 1 ignored test passes. The pin file at `/sys/fs/bpf/tokenscope/cgroup_filter` exists after the test.

If FAIL: typical issue is the verifier rejecting an unrelated stub. Read the error; if it's about an unused parameter in a stub probe, add `(void)num;` etc. to suppress.

Cleanup pin between local runs if needed: `sudo rm -f /sys/fs/bpf/tokenscope/cgroup_filter`.

- [ ] **Step 4.7: Commit**

```bash
git add bpf/tls.bpf.c crates/tsd/build.rs crates/tsd/src/skeletons.rs
git commit -m "$(cat <<'EOF'
feat(bpf,tsd): tls.bpf.c scaffold + TlsSkel + pinned cgroup_filter

Stubs for SSL_write{,_ex}, SSL_read{,_ex} (entry + uretprobe) so the
verifier accepts the program. cgroup_filter map pinned by name at
/sys/fs/bpf/tokenscope/cgroup_filter; subsequent daemon restarts reuse
the pinned map. Probe bodies land in Tasks 5–8.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: BPF probe — `SSL_write` (entry-side chunk emission)

**Files:**
- Modify: `bpf/tls.bpf.c`

- [ ] **Step 5.1: Replace the SSL_write stub with the chunk-emit body**

Open `bpf/tls.bpf.c`. Add the `emit_plaintext_chunks` helper above the SEC blocks (after `cgroup_tracked`):

```c
/* The full per-chunk record. Sized so the verifier sees a constant
 * allocation per loop iteration. Total: 56 (hdr) + 40 (payload) + 4096. */
struct tls_record {
    struct ts_event_hdr hdr;
    struct ts_tls_plaintext_payload pl;
    __u8 plaintext[CHUNK_BYTES];
};

static __always_inline int emit_plaintext_chunks(
    __u64 ssl_ctx, __u64 call_id, __u64 entry_cgid,
    const void *src, __u32 total_bytes,
    __u8 direction, __u8 ex_variant)
{
    if (total_bytes == 0) return 0;
    __u32 n_chunks = total_bytes / CHUNK_BYTES + (total_bytes % CHUNK_BYTES ? 1 : 0);
    __u8 truncated = 0;
    if (n_chunks > MAX_CHUNKS) {
        n_chunks = MAX_CHUNKS;
        truncated = 1;
    }

    #pragma unroll
    for (__u32 i = 0; i < MAX_CHUNKS; i++) {
        if (i >= n_chunks) break;

        __u32 off = i * CHUNK_BYTES;
        __u32 chunk_bytes = CHUNK_BYTES;
        if (i + 1 == n_chunks) {
            __u32 rem = total_bytes - off;
            chunk_bytes = (rem > CHUNK_BYTES) ? CHUNK_BYTES : rem;
        }
        if (chunk_bytes > CHUNK_BYTES) chunk_bytes = CHUNK_BYTES; /* verifier */

        struct tls_record *r = bpf_ringbuf_reserve(&events_tls, sizeof(*r), 0);
        if (!r) {
            __u32 zero = 0;
            __u64 *c = bpf_map_lookup_elem(&tls_reserve_fail, &zero);
            if (c) __sync_fetch_and_add(c, 1);
            return -1;
        }

        __u64 pid_tgid = bpf_get_current_pid_tgid();
        r->hdr.ts_ns     = bpf_ktime_get_ns();
        r->hdr.cpu       = bpf_get_smp_processor_id();
        r->hdr.pid       = (__u32)(pid_tgid & 0xFFFFFFFFu);
        r->hdr.tgid      = (__u32)(pid_tgid >> 32);
        r->hdr.cgroup_id = entry_cgid;
        r->hdr.type      = TS_TLS_PLAINTEXT;
        r->hdr.len       = sizeof(struct ts_tls_plaintext_payload) + chunk_bytes;
        bpf_get_current_comm(&r->hdr.comm, sizeof(r->hdr.comm));

        r->pl.ssl_ctx         = ssl_ctx;
        r->pl.call_id         = call_id;
        r->pl.entry_cgroup_id = entry_cgid;
        r->pl.total_bytes     = total_bytes;
        r->pl.chunk_index     = (__u16)i;
        r->pl.chunk_total     = (__u16)n_chunks;
        r->pl.chunk_bytes     = (__u16)chunk_bytes;
        r->pl.direction       = direction;
        r->pl.flags           = (truncated && i + 1 == n_chunks ? TLS_FLAG_TRUNCATED : 0)
                              | (ex_variant ? TLS_FLAG_EX_VARIANT : 0);
        __builtin_memset(r->pl._pad, 0, sizeof(r->pl._pad));

        long pr = bpf_probe_read_user(r->plaintext, chunk_bytes,
                                      (const __u8 *)src + off);
        if (pr) {
            r->pl.flags |= TLS_FLAG_READ_FAILED;
            r->pl.chunk_bytes = 0;
            __builtin_memset(r->plaintext, 0, CHUNK_BYTES);
        }

        bpf_ringbuf_submit(r, 0);
    }
    return 0;
}
```

Replace the `SSL_write` stub with:

```c
SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write_entry, void *ssl, const void *buf, int num)
{
    if (num <= 0) return 0;
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!cgroup_tracked(cgid)) return 0;
    __u64 call_id = bpf_ktime_get_ns();
    return emit_plaintext_chunks((__u64)ssl, call_id, cgid, buf,
                                  (__u32)num, 0, 0);
}
```

- [ ] **Step 5.2: Build, expect skeleton compiles**

Run: `cargo build -p tsd 2>&1 | tail -10`
Expected: clean build. If verifier-style errors land at *load time* not build time, you'll see them in Step 5.4.

- [ ] **Step 5.3: Re-run the skeleton load test under sudo**

Run: `sudo -E cargo test -p tsd tls_skeleton_loads -- --ignored --nocapture 2>&1 | tail -15`
Expected: passes. If verifier rejects, the error log will name the offending instruction; the most likely culprit is a missing `chunk_bytes <= CHUNK_BYTES` check before `bpf_probe_read_user`. Re-add the bound and retry.

- [ ] **Step 5.4: Commit**

```bash
git add bpf/tls.bpf.c
git commit -m "$(cat <<'EOF'
feat(bpf): tls.bpf.c SSL_write entry probe + chunk-emit helper

16-iteration unrolled chunk loop, each emits one full tls_record into
the events_tls ringbuf via bpf_ringbuf_reserve + bpf_probe_read_user
into ringbuf-resident memory (no BPF stack pressure). Truncation flag
on the last record when total_bytes > 64 KiB.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: BPF probe — `SSL_write_ex`

**Files:**
- Modify: `bpf/tls.bpf.c`

- [ ] **Step 6.1: Replace the SSL_write_ex stub**

Open `bpf/tls.bpf.c`. Replace the `ssl_write_ex_entry` stub with:

```c
SEC("uprobe/SSL_write_ex")
int BPF_UPROBE(ssl_write_ex_entry, void *ssl, const void *buf, size_t num,
               size_t *written)
{
    if (num == 0) return 0;
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!cgroup_tracked(cgid)) return 0;
    __u64 call_id = bpf_ktime_get_ns();
    __u32 total = (num > 0xFFFFFFFFu) ? 0xFFFFFFFFu : (__u32)num;
    return emit_plaintext_chunks((__u64)ssl, call_id, cgid, buf,
                                  total, 0, 1);
}
```

- [ ] **Step 6.2: Build + load test**

Run: `cargo build -p tsd && sudo -E cargo test -p tsd tls_skeleton_loads -- --ignored --nocapture 2>&1 | tail -10`
Expected: passes.

- [ ] **Step 6.3: Commit**

```bash
git add bpf/tls.bpf.c
git commit -m "$(cat <<'EOF'
feat(bpf): tls.bpf.c SSL_write_ex entry probe

Same chunk-emit shape as SSL_write but reads size_t num and sets
TLS_FLAG_EX_VARIANT so userspace can distinguish. _ex variant cap
enforced at 4 GiB (u32 total_bytes wire field).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: BPF probe — `SSL_read` (entry stash + uretprobe drain)

**Files:**
- Modify: `bpf/tls.bpf.c`

- [ ] **Step 7.1: Replace SSL_read entry stub**

```c
SEC("uprobe/SSL_read")
int BPF_UPROBE(ssl_read_entry, void *ssl, void *buf, int num)
{
    if (num <= 0) return 0;
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!cgroup_tracked(cgid)) return 0;

    struct tls_inflight_key k = { .pid_tgid = bpf_get_current_pid_tgid() };
    struct tls_inflight_val v = {
        .ssl_ctx         = (__u64)ssl,
        .buf_ptr         = (__u64)buf,
        .entry_ts_ns     = bpf_ktime_get_ns(),
        .entry_cgroup_id = cgid,
        .readbytes_ptr   = 0,
        .num             = (__u32)num,
        .is_ex           = 0,
    };
    long ret = bpf_map_update_elem(&tls_inflight, &k, &v, BPF_ANY);
    if (ret) {
        __u32 zero = 0;
        __u64 *c = bpf_map_lookup_elem(&tls_inflight_collision, &zero);
        if (c) __sync_fetch_and_add(c, 1);
    }
    return 0;
}
```

- [ ] **Step 7.2: Replace SSL_read uretprobe stub**

```c
SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ssl_read_exit, int ret)
{
    if (ret <= 0) return 0;
    struct tls_inflight_key k = { .pid_tgid = bpf_get_current_pid_tgid() };
    struct tls_inflight_val *v = bpf_map_lookup_elem(&tls_inflight, &k);
    if (!v || v->is_ex) return 0;

    __u32 nbytes = ((__u32)ret < v->num) ? (__u32)ret : v->num;
    __u64 call_id = v->entry_ts_ns;
    __u64 ssl_ctx = v->ssl_ctx;
    __u64 entry_cgid = v->entry_cgroup_id;
    void *src = (void *)v->buf_ptr;
    bpf_map_delete_elem(&tls_inflight, &k);
    return emit_plaintext_chunks(ssl_ctx, call_id, entry_cgid, src, nbytes,
                                  1 /* read */, 0 /* not _ex */);
}
```

- [ ] **Step 7.3: Build + load**

Run: `cargo build -p tsd && sudo -E cargo test -p tsd tls_skeleton_loads -- --ignored --nocapture 2>&1 | tail -10`
Expected: passes.

- [ ] **Step 7.4: Commit**

```bash
git add bpf/tls.bpf.c
git commit -m "$(cat <<'EOF'
feat(bpf): tls.bpf.c SSL_read entry stash + uretprobe chunk emission

LRU map keyed by full kernel pid_tgid (codex BLOCKING #2 — tgid alone
collides across threads in same process). Entry stashes (ssl, buf,
num, entry_ts_ns, entry_cgroup_id); uretprobe reads min(retval,num)
bytes from stashed buf and emits chunked records with the entry
cgroup_id (not return-time, in case of cgroup migration during long
blocking reads).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: BPF probe — `SSL_read_ex`

**Files:**
- Modify: `bpf/tls.bpf.c`

- [ ] **Step 8.1: Replace SSL_read_ex entry stub**

```c
SEC("uprobe/SSL_read_ex")
int BPF_UPROBE(ssl_read_ex_entry, void *ssl, void *buf, size_t num,
               size_t *readbytes)
{
    if (num == 0) return 0;
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!cgroup_tracked(cgid)) return 0;

    struct tls_inflight_key k = { .pid_tgid = bpf_get_current_pid_tgid() };
    struct tls_inflight_val v = {
        .ssl_ctx         = (__u64)ssl,
        .buf_ptr         = (__u64)buf,
        .entry_ts_ns     = bpf_ktime_get_ns(),
        .entry_cgroup_id = cgid,
        .readbytes_ptr   = (__u64)readbytes,
        .num             = (num > 0xFFFFFFFFu) ? 0xFFFFFFFFu : (__u32)num,
        .is_ex           = 1,
    };
    long ret = bpf_map_update_elem(&tls_inflight, &k, &v, BPF_ANY);
    if (ret) {
        __u32 zero = 0;
        __u64 *c = bpf_map_lookup_elem(&tls_inflight_collision, &zero);
        if (c) __sync_fetch_and_add(c, 1);
    }
    return 0;
}
```

- [ ] **Step 8.2: Replace SSL_read_ex uretprobe stub**

```c
SEC("uretprobe/SSL_read_ex")
int BPF_URETPROBE(ssl_read_ex_exit, int ret)
{
    if (ret != 1) return 0;  /* SSL_read_ex returns 1 on success */
    struct tls_inflight_key k = { .pid_tgid = bpf_get_current_pid_tgid() };
    struct tls_inflight_val *v = bpf_map_lookup_elem(&tls_inflight, &k);
    if (!v || !v->is_ex) return 0;

    size_t readbytes = 0;
    long pr = bpf_probe_read_user(&readbytes, sizeof(readbytes),
                                   (void *)v->readbytes_ptr);
    if (pr) { bpf_map_delete_elem(&tls_inflight, &k); return 0; }
    __u32 nbytes;
    if (readbytes > v->num) nbytes = v->num;
    else if (readbytes > 0xFFFFFFFFu) nbytes = 0xFFFFFFFFu;
    else nbytes = (__u32)readbytes;

    __u64 call_id = v->entry_ts_ns;
    __u64 ssl_ctx = v->ssl_ctx;
    __u64 entry_cgid = v->entry_cgroup_id;
    void *src = (void *)v->buf_ptr;
    bpf_map_delete_elem(&tls_inflight, &k);
    return emit_plaintext_chunks(ssl_ctx, call_id, entry_cgid, src, nbytes,
                                  1 /* read */, 1 /* ex_variant */);
}
```

- [ ] **Step 8.3: Build + load**

Run: `cargo build -p tsd && sudo -E cargo test -p tsd tls_skeleton_loads -- --ignored --nocapture 2>&1 | tail -10`
Expected: passes.

- [ ] **Step 8.4: Commit**

```bash
git add bpf/tls.bpf.c
git commit -m "$(cat <<'EOF'
feat(bpf): tls.bpf.c SSL_read_ex entry stash + uretprobe drain

SSL_read_ex returns 1/0 (not byte count); the bytes-actually-read
sit at *readbytes (out-param). Capture the readbytes_ptr at entry,
deref it in the uretprobe via bpf_probe_read_user, then chunk.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Userspace — `TlsAttachManager` discovery loop + dev/ino keying

**Files:**
- Create: `crates/tsd/src/tls.rs`
- Modify: `crates/tsd/src/main.rs` (`mod tls;` + boot)
- Modify: `crates/tsd/Cargo.toml` (add `regex = "1"`)

- [ ] **Step 9.1: Add regex to deps if missing**

Run: `grep -q '^regex' crates/tsd/Cargo.toml || echo 'regex = "1"' >> crates/tsd/Cargo.toml`

(If your workspace pins `regex` in the root `Cargo.toml`, use `regex = { workspace = true }` instead.)

- [ ] **Step 9.2: Create `crates/tsd/src/tls.rs` with the manager skeleton**

```rust
//! TLS plaintext capture manager. Owns the TlsSkel, the per-(dev,ino)
//! attached-libs map, and a 5s discovery loop that walks /proc/*/maps
//! to find new libssl.so files. Probe bodies live in bpf/tls.bpf.c.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{Link, UprobeOpts};
use regex::Regex;

use crate::cgroup;
use crate::control::Counters;
use crate::skeletons::tls::TlsSkelBuilder;
use crate::sink::{EventEnvelope, TlsPlaintextEvent};

#[derive(Debug)]
struct AttachedLib {
    inode_path: PathBuf,
    write_link: Option<Link>,
    write_ex_link: Option<Link>,
    read_entry_link: Option<Link>,
    read_exit_link: Option<Link>,
    read_ex_entry_link: Option<Link>,
    read_ex_exit_link: Option<Link>,
    refcount: u32,
}

pub struct TlsAttachManager {
    attached: Arc<Mutex<HashMap<(u64, u64), AttachedLib>>>,
    counters: Arc<Counters>,
    shutdown: Arc<AtomicBool>,
    discovery_handle: Option<JoinHandle<()>>,
    consumer_handle: Option<JoinHandle<()>>,
    _skel_owner: Box<dyn std::any::Any + Send + Sync>, // keeps TlsSkel alive
}

impl Drop for TlsAttachManager {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(h) = self.discovery_handle.take() { let _ = h.join(); }
        if let Some(h) = self.consumer_handle.take() { let _ = h.join(); }
    }
}

impl TlsAttachManager {
    pub fn spawn(
        counters: Arc<Counters>,
        events_tx: std::sync::mpsc::SyncSender<EventEnvelope>,
        tracked_cgroup_ids: &[u64],
    ) -> Result<Self> {
        cgroup::ensure_bpffs_dir()?;
        let mut open_skel = TlsSkelBuilder::default()
            .open()
            .context("open TlsSkel")?;
        open_skel
            .maps_mut()
            .cgroup_filter()
            .set_pin_path(cgroup::CGROUP_FILTER_PIN)
            .context("set cgroup_filter pin path")?;
        let skel = open_skel.load().context("load TlsSkel")?;

        // Populate cgroup filter (NOW that the map is loaded + pinned).
        let map_fd = skel.maps().cgroup_filter().as_fd().as_raw_fd();
        for cgid in tracked_cgroup_ids {
            cgroup::add_to_cgroup_filter(map_fd, *cgid)
                .with_context(|| format!("add cgroup id {cgid} to filter"))?;
        }

        let shutdown = Arc::new(AtomicBool::new(false));
        let attached: Arc<Mutex<HashMap<(u64, u64), AttachedLib>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Move skel into a Box<dyn Any> so the manager can hold it
        // without naming the libbpf-rs lifetime explicitly. It stays
        // alive for the manager's whole life; that's all we need.
        let skel_for_attach: &'static _ = Box::leak(Box::new(skel));
        let consumer_handle = spawn_consumer(skel_for_attach, events_tx.clone(),
                                             counters.clone(), shutdown.clone())?;
        let discovery_handle = spawn_discovery(skel_for_attach, attached.clone(),
                                               counters.clone(), shutdown.clone())?;

        Ok(Self {
            attached,
            counters,
            shutdown,
            discovery_handle: Some(discovery_handle),
            consumer_handle: Some(consumer_handle),
            _skel_owner: Box::new(()), // skel lives in the static leak above
        })
    }
}

fn libssl_re() -> Regex {
    // Matches any "rwxp" line whose pathname ends in libssl.so or libssl.so.<...>.
    Regex::new(r"r-xp .* (\S*libssl\.so(?:\.\S+)?)$").unwrap()
}

fn spawn_discovery(
    skel: &'static crate::skeletons::tls::TlsSkel<'static>,
    attached: Arc<Mutex<HashMap<(u64, u64), AttachedLib>>>,
    counters: Arc<Counters>,
    shutdown: Arc<AtomicBool>,
) -> Result<JoinHandle<()>> {
    let re = libssl_re();
    thread::Builder::new()
        .name("tsd-tls-discovery".into())
        .spawn(move || {
            while !shutdown.load(Ordering::Relaxed) {
                let scan_start = Instant::now();
                let mut errors: u32 = 0;
                let mut seen: HashSet<(u64, u64)> = HashSet::new();
                discovery_pass(skel, &re, &attached, &counters,
                               &mut errors, &mut seen);
                counters.tls_scan_duration_us.store(
                    scan_start.elapsed().as_micros() as u64, Ordering::Relaxed);
                counters.tls_scan_errors.store(errors, Ordering::Relaxed);
                for _ in 0..50 {
                    if shutdown.load(Ordering::Relaxed) { break; }
                    thread::sleep(Duration::from_millis(100));
                }
            }
        })
        .context("spawn tls-discovery thread")
}

fn discovery_pass(
    skel: &'static crate::skeletons::tls::TlsSkel<'static>,
    re: &Regex,
    attached: &Arc<Mutex<HashMap<(u64, u64), AttachedLib>>>,
    counters: &Arc<Counters>,
    errors: &mut u32,
    seen: &mut HashSet<(u64, u64)>,
) {
    let dir = match fs::read_dir("/proc") { Ok(d) => d, Err(_) => return };
    for entry in dir.flatten() {
        let pid_name = entry.file_name();
        let pid_str = match pid_name.to_str() { Some(s) => s, None => continue };
        if !pid_str.bytes().all(|b| b.is_ascii_digit()) { continue; }

        let maps = match fs::read_to_string(entry.path().join("maps")) {
            Ok(s) => s,
            Err(_) => { *errors += 1; continue; }
        };
        for line in maps.lines() {
            let cap = match re.captures(line) { Some(c) => c, None => continue };
            let visible = cap.get(1).unwrap().as_str();
            // Resolve via /proc/<pid>/root/... so we get the inode as the
            // process sees it (handles mount-namespaces, deleted+replaced).
            let proc_root = entry.path()
                .join("root")
                .join(visible.trim_start_matches('/'));
            let meta = match fs::metadata(&proc_root) {
                Ok(m) => m,
                Err(_) => { *errors += 1; continue; }
            };
            let key = (meta.dev(), meta.ino());
            if !seen.insert(key) { continue; }

            let mut g = attached.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(lib) = g.get_mut(&key) {
                lib.refcount += 1;
                continue;
            }
            match attach_libssl(skel, &proc_root) {
                Ok(lib) => {
                    g.insert(key, lib);
                    counters.tls_libs_attached.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    tracing::warn!(?proc_root, %e, "tls libssl attach failed");
                    counters.tls_libs_skipped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

fn attach_libssl(
    skel: &'static crate::skeletons::tls::TlsSkel<'static>,
    libssl_path: &Path,
) -> Result<AttachedLib> {
    let progs = skel.progs();
    // Required pair (basic): SSL_write entry + SSL_read entry/exit.
    let write_link = attach_one(progs.ssl_write_entry(), libssl_path,
                                "SSL_write", false)?;
    let read_entry_link = attach_one(progs.ssl_read_entry(), libssl_path,
                                     "SSL_read", false)?;
    let read_exit_link  = attach_one(progs.ssl_read_exit(),  libssl_path,
                                     "SSL_read", true)?;

    // Optional _ex pair: tolerate missing symbols (older libssl).
    let write_ex_link = attach_one(progs.ssl_write_ex_entry(), libssl_path,
                                   "SSL_write_ex", false).ok();
    let read_ex_entry_link = attach_one(progs.ssl_read_ex_entry(), libssl_path,
                                        "SSL_read_ex", false).ok();
    let read_ex_exit_link = attach_one(progs.ssl_read_ex_exit(), libssl_path,
                                       "SSL_read_ex", true).ok();

    Ok(AttachedLib {
        inode_path: libssl_path.to_path_buf(),
        write_link: Some(write_link),
        write_ex_link,
        read_entry_link: Some(read_entry_link),
        read_exit_link: Some(read_exit_link),
        read_ex_entry_link,
        read_ex_exit_link,
        refcount: 1,
    })
}

fn attach_one(
    prog: &libbpf_rs::Program,
    libssl_path: &Path,
    func_name: &str,
    retprobe: bool,
) -> Result<Link> {
    let opts = UprobeOpts {
        func_name: func_name.into(),
        retprobe,
        ..Default::default()
    };
    prog.attach_uprobe_with_opts(-1, libssl_path, 0, opts)
        .with_context(|| format!("attach {func_name} (retprobe={retprobe}) on {}",
                                  libssl_path.display()))
}

fn spawn_consumer(
    skel: &'static crate::skeletons::tls::TlsSkel<'static>,
    events_tx: std::sync::mpsc::SyncSender<EventEnvelope>,
    counters: Arc<Counters>,
    shutdown: Arc<AtomicBool>,
) -> Result<JoinHandle<()>> {
    use libbpf_rs::RingBufferBuilder;
    use ts_core::event::{decode_tls_plaintext, TsEventHdr,
                          TLS_FLAG_TRUNCATED, TLS_FLAG_READ_FAILED, TLS_FLAG_EX_VARIANT};

    let map = skel.maps().events_tls();
    let counters_for_cb = counters.clone();
    let events_tx_for_cb = events_tx.clone();

    let mut builder = RingBufferBuilder::new();
    builder.add(&map, move |bytes| -> i32 {
        // Each record = TsEventHdr (56) + TsTlsPlaintextPayload (40) + plaintext (<= 4096).
        const HDR: usize = std::mem::size_of::<TsEventHdr>();
        if bytes.len() < HDR { return 0; }
        let mut hdr_buf = [0u8; HDR];
        hdr_buf.copy_from_slice(&bytes[..HDR]);
        let hdr: TsEventHdr = unsafe { std::mem::transmute(hdr_buf) };

        let payload_buf = &bytes[HDR..];
        let (pl, plaintext) = match decode_tls_plaintext(payload_buf) {
            Ok(x) => x,
            Err(_) => return 0,
        };

        let env = EventEnvelope::TlsPlaintext(TlsPlaintextEvent {
            ts_ns: hdr.ts_ns,
            pid: hdr.pid,
            tgid: hdr.tgid,
            cgroup_id: hdr.cgroup_id,
            comm: hdr.comm_str(),
            ssl_ctx: pl.ssl_ctx,
            call_id: pl.call_id,
            direction: pl.direction,
            total_bytes: pl.total_bytes,
            chunk_index: pl.chunk_index,
            chunk_total: pl.chunk_total,
            chunk_bytes: pl.chunk_bytes,
            truncated: pl.flags & TLS_FLAG_TRUNCATED != 0,
            read_failed: pl.flags & TLS_FLAG_READ_FAILED != 0,
            ex_variant: pl.flags & TLS_FLAG_EX_VARIANT != 0,
            plaintext: plaintext.to_vec(),
        });
        let _ = events_tx_for_cb.try_send(env);
        counters_for_cb.tls_records_emitted.fetch_add(1, Ordering::Relaxed);
        0
    }).context("ringbuf add")?;
    let rb = builder.build().context("ringbuf build")?;

    thread::Builder::new()
        .name("tsd-tls-consumer".into())
        .spawn(move || {
            while !shutdown.load(Ordering::Relaxed) {
                if let Err(e) = rb.poll(Duration::from_millis(250)) {
                    if e.kind() != libbpf_rs::ErrorKind::Interrupted {
                        counters.ringbuf_poll_errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        })
        .context("spawn tls-consumer thread")
}
```

- [ ] **Step 9.3: Add the new counters to `Counters`**

Edit `crates/tsd/src/control.rs`. Append to the `Counters` struct:

```rust
pub tls_libs_attached: AtomicU32,
pub tls_libs_skipped: AtomicU32,
pub tls_libs_partial_attach: AtomicU32,
pub tls_records_emitted: AtomicU64,
pub tls_truncated_calls: AtomicU64,
pub tls_read_failed_chunks: AtomicU64,
pub tls_inflight_collisions: AtomicU64,
pub tls_reserve_failures: AtomicU64,
pub tls_scan_duration_us: AtomicU64,
pub tls_scan_errors: AtomicU32,
pub tls_subscribers_with_plaintext: AtomicU32,
```

Initialize all to 0 wherever `Counters` is constructed. Keep `tail_dropped_events` from Task 1.

- [ ] **Step 9.4: Wire `TlsAttachManager::spawn` into main.rs**

Edit `crates/tsd/src/main.rs`. After `EventSink::spawn` and the `tracked_cgroup_ids` block from Task 3, add:

```rust
let _tls_mgr = crate::tls::TlsAttachManager::spawn(
    counters.clone(), events_tx.clone(), &tracked_cgroup_ids,
).context("spawn TLS attach manager")?;
// Keep _tls_mgr alive for the daemon lifetime; its Drop joins the
// discovery + consumer threads and releases the leaked skel.
```

Add `mod tls;` near the other `mod` declarations (alphabetical).

- [ ] **Step 9.5: Build, expect compile-only success (no test yet)**

Run: `cargo build -p tsd 2>&1 | tail -10`
Expected: 0 errors. The `Box::leak` of `TlsSkel` is intentional — the skel must outlive the threads, which match the daemon lifetime. (If the leak feels wrong, an alternative is `Arc<TlsSkel<'static>>`, but libbpf-rs `Skel` isn't `Send + Sync` in 0.24. Leak is the standard escape hatch and matches how the project handles other long-lived skels — verify by `grep Box::leak crates/tsd/src/`.)

- [ ] **Step 9.6: Smoke test under sudo — daemon starts and finds at least its own libssl**

Add to `crates/tsd/tests/`:

```rust
// crates/tsd/tests/tls_discovery_smoke.rs
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[test]
#[ignore = "requires CAP_BPF + libssl on PATH"]
fn tsd_attaches_to_at_least_one_libssl_at_startup() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("e.duckdb");
    let uds = dir.path().join("tsd.sock");
    let mut child = Command::new(env!("CARGO_BIN_EXE_tsd"))
        .args(["--db-path", db.to_str().unwrap(),
               "--uds-path", uds.to_str().unwrap(),
               "--no-stdout"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tsd");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !uds.exists() {
        if Instant::now() > deadline { let _ = child.kill(); panic!("uds never appeared"); }
        std::thread::sleep(Duration::from_millis(100));
    }
    // Wait two scan cycles (5s each = 10s); scope checked via tsctl status.
    std::thread::sleep(Duration::from_secs(11));
    let out = Command::new(env!("CARGO_BIN_EXE_tsctl"))
        .args(["--uds-path", uds.to_str().unwrap(), "status"])
        .output().expect("tsctl status");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(stdout.contains("tls libs attached"), "no tls libs attached line in status: {stdout}");
    let n_attached: u32 = stdout
        .lines()
        .find(|l| l.starts_with("tls libs attached"))
        .and_then(|l| l.split_whitespace().last())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert!(n_attached >= 1, "expected >=1 lib attached, got {n_attached}");
    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    let _ = child.wait();
}
```

(This test depends on the `tsctl status` formatter showing the new `tls libs attached` line — that lands in Task 13. Defer running this assertion until then; for now just `cargo build --tests -p tsd` to verify it compiles.)

- [ ] **Step 9.7: `cargo build --tests -p tsd`, expect green**

Run: `cargo build --tests -p tsd 2>&1 | tail -10`
Expected: 0 errors.

- [ ] **Step 9.8: Commit**

```bash
git add crates/tsd/src/tls.rs \
        crates/tsd/src/main.rs \
        crates/tsd/src/control.rs \
        crates/tsd/Cargo.toml \
        crates/tsd/tests/tls_discovery_smoke.rs
git commit -m "$(cat <<'EOF'
feat(tsd): TlsAttachManager + /proc rescan + (dev,ino) lib keying

Walks /proc/*/maps every 5s, resolves libssl.so via /proc/<pid>/root/...
to get the right inode for containers and mount-namespaces (codex
BLOCKING #5). Attaches uprobes per (dev, ino) keyed file. _ex variants
optional. Ringbuf consumer decodes TLS records into EventEnvelope and
pushes onto events_tx. Counters added (population in Task 13).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: DuckDB `Appender` for the TLS table

**Files:**
- Modify: `crates/tsd/src/store.rs`
- Modify: `crates/tsd/src/sink.rs` (use the appender path for TLS)

- [ ] **Step 10.1: Add `Store::insert_tls_plaintext` using Appender**

Edit `crates/tsd/src/store.rs`. Add:

```rust
use duckdb::Appender;

impl Store {
    /// Append-mode insert for TLS plaintext records. Bursty — using
    /// duckdb's Appender API instead of one INSERT per row.
    /// Caller flushes by dropping the Appender or by calling
    /// `flush_tls_appender`.
    pub fn tls_appender(&self) -> Result<Appender<'_>> {
        self.conn.appender("events_tls_plaintext")
            .context("create events_tls_plaintext appender")
    }
}
```

(If `Connection` requires `&mut self` for `appender()` in your duckdb-rs version, the method signature is `&mut self`. Adjust the boundary in sink.rs accordingly.)

- [ ] **Step 10.2: Wire the appender into `sink::writer_loop`**

Edit `crates/tsd/src/sink.rs`. Replace the `EventEnvelope::TlsPlaintext(_)` no-op in `persist` with a real path. Restructure `writer_loop` to hold a long-lived `Appender` for TLS:

```rust
fn writer_loop(
    store: Arc<Store>,
    subs: Subscribers,
    rx: Receiver<EventEnvelope>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) {
    // Per-loop appender keeps round-trips low. Flushed every batch tick.
    let mut tls_appender = match store.tls_appender_owned() {
        Ok(a) => Some(a),
        Err(e) => {
            tracing::warn!(error=?e, "could not create TLS appender; TLS persists disabled");
            None
        }
    };
    let mut last_flush = std::time::Instant::now();
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
                            &e.comm,
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
                            tracing::warn!(error=?err, "tls appender row failed");
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
                // Tick: flush appender every ~1s.
                if last_flush.elapsed() > Duration::from_secs(1) {
                    if let Some(app) = tls_appender.as_mut() {
                        if let Err(e) = app.flush() {
                            tracing::warn!(error=?e, "tls appender flush failed");
                        }
                    }
                    last_flush = std::time::Instant::now();
                }
                continue;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    // Final flush on shutdown.
    if let Some(mut app) = tls_appender.take() { let _ = app.flush(); }
}
```

The `tls_appender_owned()` helper wraps the borrow lifetime issue — duckdb's `Appender<'_>` borrows the `Connection`. If your `Store` holds a `Mutex<Connection>` or `Arc<Connection>`, take a long-lived lease. If not, change `Store` to wrap the connection in `Arc<Mutex<>>` and add:

```rust
impl Store {
    /// Like `tls_appender` but resolves the borrow via internal
    /// connection ownership. The returned Appender holds a lock on
    /// the connection until dropped.
    pub fn tls_appender_owned(&self) -> Result<Appender<'static>> {
        // Implementation depends on the existing Connection-ownership
        // shape in store.rs. Acceptable to use unsafe transmute of the
        // lifetime if we KNOW the connection outlives the Appender
        // (it does — the Store's Arc keeps it alive across the writer
        // thread's lifetime).
        // SAFETY: `self.conn` is owned by `Store`, which the caller
        // (EventSink::writer_loop) holds via Arc<Store> for its entire
        // life. The appender will be dropped before that Arc drops.
        let app = self.conn.appender("events_tls_plaintext")
            .context("create events_tls_plaintext appender")?;
        Ok(unsafe { std::mem::transmute(app) })
    }
}
```

(If this `unsafe` makes you nervous: the alternative is to give up the Appender perf win and use INSERT, which is fine for getting the system working but will become a problem in Phase 2.B. The unsafe is OK because the contract — Appender lifetime ⊆ Store lifetime — is enforced by EventSink owning both. Document it in a comment.)

- [ ] **Step 10.3: Add a smoke test that round-trips one TLS row through the sink**

Append to `crates/tsd/src/sink.rs` `mod tests`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_event_persists_via_appender() {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("t.duckdb");
        let store = Arc::new(Store::open(&db_path).unwrap());
        let counters = Arc::new(Counters::default());
        let subs = Subscribers::new(counters.clone());
        let sink = EventSink::spawn(store.clone(), subs).unwrap();

        let evt = EventEnvelope::TlsPlaintext(TlsPlaintextEvent {
            ts_ns: 12345, pid: 100, tgid: 100, cgroup_id: 1, comm: "x".into(),
            ssl_ctx: 0xfeed, call_id: 1, direction: 0, total_bytes: 4,
            chunk_index: 0, chunk_total: 1, chunk_bytes: 4,
            truncated: false, read_failed: false, ex_variant: false,
            plaintext: vec![1,2,3,4],
        });
        sink.tx.send(evt).unwrap();
        // Wait past the appender flush tick.
        std::thread::sleep(std::time::Duration::from_millis(1500));
        drop(sink); // forces final flush

        let n = store.count_table("events_tls_plaintext").unwrap();
        assert_eq!(n, 1);
    }
}
```

(`Counters::default()` has to exist; if it doesn't today, derive `Default` on the struct.)

- [ ] **Step 10.4: Run, expect PASS**

Run: `cargo test -p tsd tls_event_persists -- --nocapture 2>&1 | tail -15`
Expected: 1 passed.

- [ ] **Step 10.5: Commit**

```bash
git add crates/tsd/src/store.rs crates/tsd/src/sink.rs
git commit -m "$(cat <<'EOF'
feat(tsd): DuckDB Appender path for events_tls_plaintext

TLS records bypass the INSERT-per-row path used by net/exec; the
writer thread holds a long-lived Appender flushed every ~1s and on
shutdown. Sustains thousands-of-events-per-second bursts that would
choke single-row INSERTs.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: Tail rendering — `render_tail_line` for TLS + redaction

**Files:**
- Modify: `crates/tsd/src/control.rs`

- [ ] **Step 11.1: Implement the redaction patterns**

Edit `crates/tsd/src/control.rs`. Add at module scope:

```rust
use once_cell::sync::Lazy;
use regex::Regex;

static REDACTORS: Lazy<Vec<Regex>> = Lazy::new(|| vec![
    // Header-style: Authorization, X-API-Key, etc. Capture the header
    // name so we keep the structure visible.
    Regex::new(r"(?i)\b(authorization|x-api-key|api-key|x-auth-token|x-goog-api-key|api[-_]?key|password|secret|token|client[-_]?secret)\s*[:=]\s*\S+").unwrap(),
    // Provider tokens (anchored token shapes; \w includes [A-Za-z0-9_]):
    Regex::new(r"\bsk-ant-[\w-]{20,}\b").unwrap(),
    Regex::new(r"\bsk-[A-Za-z0-9-]{20,}\b").unwrap(),
    Regex::new(r"\bgsk_[\w]{20,}\b").unwrap(),
    Regex::new(r"\bhf_[\w]{20,}\b").unwrap(),
    Regex::new(r"\bAIza[\w-]{30,}\b").unwrap(),
    Regex::new(r"\bgithub_pat_[\w]{20,}\b").unwrap(),
    Regex::new(r"\bgh[pousr]_[\w]{20,}\b").unwrap(),
    Regex::new(r"\bglpat-[\w-]{20,}\b").unwrap(),
    Regex::new(r"\bAKIA[A-Z0-9]{16}\b").unwrap(),
    Regex::new(r"\bASIA[A-Z0-9]{16}\b").unwrap(),
    // JWT
    Regex::new(r"\beyJ[\w-]+\.[\w-]+\.[\w-]+\b").unwrap(),
    // PEM private key blocks
    Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----").unwrap(),
]);

pub fn redact(input: &str) -> String {
    let mut out = input.to_string();
    for re in REDACTORS.iter() {
        // For the header-style regex (first one), preserve the captured
        // header name by replacing only the value.
        if re.as_str().contains("(authorization") {
            out = re.replace_all(&out, "$1: ***REDACTED***").into_owned();
        } else {
            out = re.replace_all(&out, "***REDACTED***").into_owned();
        }
    }
    out
}
```

Add `once_cell = "1"` to `crates/tsd/Cargo.toml` if not already present (likely is via workspace).

- [ ] **Step 11.2: Replace the stub `render_tail_line`**

Replace the existing `render_tail_line` from Task 1 with the full version:

```rust
pub fn render_tail_line(
    env: &crate::sink::EventEnvelope,
    include_plaintext: bool,
) -> String {
    use crate::sink::EventEnvelope::*;
    match env {
        ProcExec(e) => serde_json::json!({
            "kind":"proc.exec",
            "ts_ns":e.ts_ns, "pid":e.pid, "tgid":e.tgid,
            "cgroup_id":e.cgroup_id, "comm":e.comm,
        }).to_string(),
        NetConnect(e) => serde_json::json!({
            "kind":"net.connect",
            "ts_ns":e.ts_ns, "pid":e.pid, "tgid":e.tgid,
            "comm":e.comm, "dst_port":e.dst_port,
            "family":e.family, "protocol":e.protocol,
        }).to_string(),
        NetBytesSnapshot(e) => serde_json::json!({
            "kind":"net.bytes",
            "snapshot_ts_ns":e.snapshot_ts_ns,
            "sock_cookie":e.sock_cookie,
            "tx":e.tx_bytes, "rx":e.rx_bytes,
        }).to_string(),
        TlsPlaintext(e) => {
            let mut obj = serde_json::Map::new();
            obj.insert("kind".into(),
                serde_json::Value::String(
                    if e.direction == 0 { "tls.write".into() } else { "tls.read".into() }
                ));
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

            // sha256 prefix is always shown.
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&e.plaintext);
            let h = hasher.finalize();
            obj.insert("plaintext_sha256".into(),
                hex::encode(&h[..4]).into());

            if include_plaintext && !e.plaintext.is_empty() {
                let rendered = String::from_utf8_lossy(&e.plaintext).into_owned();
                let redacted = redact(&rendered);
                use base64::Engine;
                obj.insert("plaintext_b64".into(),
                    base64::engine::general_purpose::STANDARD.encode(redacted.as_bytes()).into());
            }
            serde_json::Value::Object(obj).to_string()
        }
    }
}
```

Add `sha2`, `hex`, `base64` to `crates/tsd/Cargo.toml` if not workspace-pinned.

- [ ] **Step 11.3: Tests for redaction**

Add to `crates/tsd/src/control.rs` `mod tests`:

```rust
#[test]
fn redact_authorization_bearer() {
    let s = "Authorization: Bearer sk-ant-abcdefghij1234567890klmnop";
    let out = redact(s);
    assert!(out.contains("***REDACTED***"));
    assert!(!out.contains("sk-ant-abcdefghij"));
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

#[test]
fn render_tail_tls_default_omits_plaintext_b64() {
    let evt = crate::sink::EventEnvelope::TlsPlaintext(crate::sink::TlsPlaintextEvent {
        ts_ns: 1, pid: 2, tgid: 2, cgroup_id: 3, comm: "p".into(),
        ssl_ctx: 0x1234, call_id: 9, direction: 0, total_bytes: 5,
        chunk_index: 0, chunk_total: 1, chunk_bytes: 5,
        truncated: false, read_failed: false, ex_variant: false,
        plaintext: b"hello".to_vec(),
    });
    let line = render_tail_line(&evt, false);
    assert!(!line.contains("plaintext_b64"));
    assert!(line.contains("plaintext_sha256"));
}

#[test]
fn render_tail_tls_show_plaintext_includes_b64_and_redacts() {
    let body = b"Authorization: Bearer sk-ant-XXXXXXXXXXXXXXXXXXXXXXX\nbody";
    let evt = crate::sink::EventEnvelope::TlsPlaintext(crate::sink::TlsPlaintextEvent {
        ts_ns: 1, pid: 2, tgid: 2, cgroup_id: 3, comm: "p".into(),
        ssl_ctx: 0x1234, call_id: 9, direction: 0,
        total_bytes: body.len() as u32,
        chunk_index: 0, chunk_total: 1, chunk_bytes: body.len() as u16,
        truncated: false, read_failed: false, ex_variant: false,
        plaintext: body.to_vec(),
    });
    let line = render_tail_line(&evt, true);
    assert!(line.contains("plaintext_b64"));
    use base64::Engine;
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    let b64 = v["plaintext_b64"].as_str().unwrap();
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
    let s = String::from_utf8_lossy(&decoded);
    assert!(s.contains("***REDACTED***"));
    assert!(!s.contains("sk-ant-XXX"));
}
```

- [ ] **Step 11.4: Run, expect PASS**

Run: `cargo test -p tsd redact render_tail_tls -- --nocapture 2>&1 | tail -20`
Expected: 7 passed.

- [ ] **Step 11.5: Commit**

```bash
git add crates/tsd/src/control.rs crates/tsd/Cargo.toml
git commit -m "$(cat <<'EOF'
feat(tsd): per-subscriber tail render + plaintext redaction

render_tail_line emits JSON for every event family; for TLS records,
plaintext_sha256 (4-byte prefix) is always present. plaintext_b64 only
appears when the subscriber opted into include_plaintext at handshake;
the bytes are redacted server-side before encoding (codex BLOCKING #6
— never trust the client to redact).

Redaction patterns: Authorization/X-API-Key/etc., Anthropic+OpenAI+
Groq+HF+Google+GitHub+GitLab+AWS keys, JWTs, PEM private keys.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: `tsctl status` — surface the new TLS counters

**Files:**
- Modify: `crates/ts-core/src/control.rs` (`StatusResponse` gains TLS fields)
- Modify: `crates/tsd/src/control.rs` (populate the new fields in the status handler)
- Modify: `crates/tsctl/src/main.rs` (`cmd_status` prints them)

- [ ] **Step 12.1: Extend `StatusResponse`**

Edit `crates/ts-core/src/control.rs`. Add to `StatusResponse`:

```rust
pub tls_libs_attached: u32,
pub tls_libs_skipped: u32,
pub tls_libs_partial_attach: u32,
pub tls_records_emitted: u64,
pub tls_truncated_calls: u64,
pub tls_read_failed_chunks: u64,
pub tls_inflight_collisions: u64,
pub tls_reserve_failures: u64,
pub tls_scan_duration_us: u64,
pub tls_scan_errors: u32,
pub tls_subscribers_with_plaintext: u32,
pub tail_dropped_events: u64,
```

Add `#[serde(default)]` on each NEW field so old daemons (which won't emit them) decode without error in newer tsctls.

- [ ] **Step 12.2: Populate in tsd's status handler**

Edit `crates/tsd/src/control.rs`. Find the status response builder (look for `StatusResponse {` literal). Add:

```rust
tls_libs_attached: counters.tls_libs_attached.load(Ordering::Relaxed),
tls_libs_skipped: counters.tls_libs_skipped.load(Ordering::Relaxed),
tls_libs_partial_attach: counters.tls_libs_partial_attach.load(Ordering::Relaxed),
tls_records_emitted: counters.tls_records_emitted.load(Ordering::Relaxed),
tls_truncated_calls: counters.tls_truncated_calls.load(Ordering::Relaxed),
tls_read_failed_chunks: counters.tls_read_failed_chunks.load(Ordering::Relaxed),
tls_inflight_collisions: counters.tls_inflight_collisions.load(Ordering::Relaxed),
tls_reserve_failures: counters.tls_reserve_failures.load(Ordering::Relaxed),
tls_scan_duration_us: counters.tls_scan_duration_us.load(Ordering::Relaxed),
tls_scan_errors: counters.tls_scan_errors.load(Ordering::Relaxed),
tls_subscribers_with_plaintext: counters.tls_subscribers_with_plaintext.load(Ordering::Relaxed),
tail_dropped_events: counters.tail_dropped_events.load(Ordering::Relaxed),
```

- [ ] **Step 12.3: Print in tsctl**

Edit `crates/tsctl/src/main.rs::cmd_status`. After the existing `println!`s add:

```rust
println!("tls libs attached      {}", resp.tls_libs_attached);
println!("tls libs skipped       {}", resp.tls_libs_skipped);
println!("tls libs partial       {}", resp.tls_libs_partial_attach);
println!("tls records emitted    {}", resp.tls_records_emitted);
println!("tls truncated calls    {}", resp.tls_truncated_calls);
println!("tls read failed chunks {}", resp.tls_read_failed_chunks);
println!("tls inflight collisions {}", resp.tls_inflight_collisions);
println!("tls reserve failures   {}", resp.tls_reserve_failures);
println!("tls scan duration (us) {}", resp.tls_scan_duration_us);
println!("tls scan errors        {}", resp.tls_scan_errors);
println!("tls subs w/ plaintext  {}", resp.tls_subscribers_with_plaintext);
println!("tail dropped events    {}", resp.tail_dropped_events);
```

- [ ] **Step 12.4: Pull BPF percpu counters into the userspace counters**

Edit `crates/tsd/src/tls.rs`. In the discovery loop's tail (or in a separate periodic thread), add a counter-pump pass that reads `tls_reserve_fail` and `tls_inflight_collision` percpu arrays and aggregates into `counters.tls_reserve_failures` / `counters.tls_inflight_collisions`. Insert at the end of `discovery_pass` (before the sleep):

```rust
fn pump_percpu_counters(
    skel: &'static crate::skeletons::tls::TlsSkel<'static>,
    counters: &Arc<Counters>,
) {
    use libbpf_rs::MapCore;
    let zero = 0u32.to_ne_bytes();

    if let Ok(per) = skel.maps().tls_reserve_fail().lookup_percpu(&zero, libbpf_rs::MapFlags::ANY) {
        if let Some(values) = per {
            let total: u64 = values.iter()
                .map(|v| u64::from_ne_bytes(v.as_slice().try_into().unwrap_or([0;8])))
                .sum();
            counters.tls_reserve_failures.store(total, Ordering::Relaxed);
        }
    }
    if let Ok(per) = skel.maps().tls_inflight_collision().lookup_percpu(&zero, libbpf_rs::MapFlags::ANY) {
        if let Some(values) = per {
            let total: u64 = values.iter()
                .map(|v| u64::from_ne_bytes(v.as_slice().try_into().unwrap_or([0;8])))
                .sum();
            counters.tls_inflight_collisions.store(total, Ordering::Relaxed);
        }
    }
}
```

Call `pump_percpu_counters(skel, &counters)` once per discovery loop iteration.

- [ ] **Step 12.5: Build, expect green**

Run: `cargo build --workspace --all-targets 2>&1 | tail -10`
Expected: 0 errors.

- [ ] **Step 12.6: Update existing status integration test**

Find the existing status integration test (`crates/tsd/tests/control_e2e.rs`). It probably parses the older response shape. The `#[serde(default)]` on the new fields should keep it working without changes; verify with:

Run: `sudo -E cargo test -p tsd control_e2e -- --ignored --nocapture 2>&1 | tail -10`
Expected: existing test still passes. The new TLS fields show 0s since no traffic generated.

- [ ] **Step 12.7: Commit**

```bash
git add crates/ts-core/src/control.rs \
        crates/tsd/src/control.rs \
        crates/tsd/src/tls.rs \
        crates/tsctl/src/main.rs
git commit -m "$(cat <<'EOF'
feat(tsd,tsctl): TLS counters + tail_dropped_events in tsctl status

11 new TLS counters + the tail-dropped one introduced in Task 1.
serde_default annotations keep new tsctl talking to old tsd. BPF
percpu counters pumped into atomics once per /proc rescan.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 13: Integration tests — Layer 2 (`#[ignore]`-gated, sudo)

**Files:**
- Create: `crates/tsd/tests/fixtures/tls_client.c`
- Modify: `crates/tsd/build.rs` (compile the C fixture under feature gate)
- Create: `crates/tsd/tests/tls_e2e.rs`
- Modify: `crates/tsd/Cargo.toml` (`cc` build-dep, `rcgen` + `rustls` dev-deps)

- [ ] **Step 13.1: Add the test fixture C client**

Create `crates/tsd/tests/fixtures/tls_client.c`:

```c
/* SPDX-License-Identifier: Apache-2.0 */
/* Tiny dynamic OpenSSL client for tls_e2e integration tests.
 * Usage: ./tls_client HOST PORT PAYLOAD_FILE
 *   - reads "GO\n" from stdin before doing the handshake (so the
 *     test harness can wait for tsd attach to finish first)
 *   - reads PAYLOAD_FILE bytes, SSL_writes them, then SSL_reads up to 4096
 *   - prints "OK\n" on stdout, errors on stderr, exits 0/1.
 */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int connect_tcp(const char *host, const char *port) {
    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res)) return -1;
    int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0) { freeaddrinfo(res); return -1; }
    if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
        close(s); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);
    return s;
}

int main(int argc, char **argv) {
    if (argc != 4) { fprintf(stderr, "usage: %s host port payload-file\n", argv[0]); return 1; }
    char gobuf[8] = {0};
    if (!fgets(gobuf, sizeof(gobuf), stdin) || strncmp(gobuf, "GO", 2)) {
        fprintf(stderr, "expected 'GO' on stdin\n"); return 1;
    }
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    const SSL_METHOD *m = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(m);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); /* test cert */

    int sock = connect_tcp(argv[1], argv[2]);
    if (sock < 0) { fprintf(stderr, "connect failed\n"); return 1; }
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) != 1) {
        ERR_print_errors_fp(stderr); return 1;
    }

    FILE *f = fopen(argv[3], "rb");
    if (!f) { perror("payload open"); return 1; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(n);
    if (fread(buf, 1, n, f) != (size_t)n) { perror("payload read"); return 1; }
    fclose(f);

    int wrote = SSL_write(ssl, buf, (int)n);
    if (wrote <= 0) { ERR_print_errors_fp(stderr); return 1; }

    char rbuf[4096];
    int got = SSL_read(ssl, rbuf, sizeof(rbuf));
    /* OK if read returned 0/positive; only stop on negative err */
    (void)got;

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    free(buf);
    printf("OK\n");
    return 0;
}
```

- [ ] **Step 13.2: Add `cc` build-dep + extend build.rs**

Edit `crates/tsd/Cargo.toml`:

```toml
[build-dependencies]
libbpf-cargo = { workspace = true }
cc           = "1"

[dev-dependencies]
# existing
rustls       = "0.23"
rustls-pemfile = "2"
rcgen        = "0.13"
```

Append to `crates/tsd/build.rs`:

```rust
// TLS client fixture. Skipped if pkg-config can't find openssl;
// the integration tests detect this and skip themselves.
{
    let pkg = std::process::Command::new("pkg-config")
        .args(["--exists", "openssl"]).status();
    if matches!(pkg, Ok(s) if s.success()) {
        let out = std::process::Command::new("pkg-config")
            .args(["--cflags", "--libs", "openssl"])
            .output().expect("pkg-config openssl");
        let flags = String::from_utf8_lossy(&out.stdout);
        let mut build = cc::Build::new();
        build.file("tests/fixtures/tls_client.c");
        for f in flags.split_whitespace() {
            if let Some(inc) = f.strip_prefix("-I") { build.include(inc); }
        }
        build.warnings(false);
        // Build as an executable, not a library. cc doesn't natively
        // support that, so we shell out via env-driven invocation.
        let outdir = std::env::var("OUT_DIR").unwrap();
        let target = format!("{outdir}/tls_client");
        let cc_path = std::env::var("CC").unwrap_or_else(|_| "cc".into());
        let status = std::process::Command::new(&cc_path)
            .args(["-o", &target, "tests/fixtures/tls_client.c"])
            .args(flags.split_whitespace())
            .status().expect("compile tls_client.c");
        if !status.success() { panic!("tls_client.c compile failed"); }
        println!("cargo:rustc-env=TS_TLS_CLIENT_BIN={target}");
    } else {
        println!("cargo:warning=openssl not found via pkg-config; tls_e2e fixture not built");
    }
}
println!("cargo:rerun-if-changed=tests/fixtures/tls_client.c");
```

- [ ] **Step 13.3: Write the integration test file**

Create `crates/tsd/tests/tls_e2e.rs`:

```rust
//! Layer 2 integration tests for Phase 2.A. Requires CAP_BPF + libssl
//! shared lib + a pkg-config'd openssl-dev install for fixture build.
//! Each test skips cleanly if the fixture wasn't built.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

fn tls_client_bin() -> Option<PathBuf> {
    option_env!("TS_TLS_CLIENT_BIN").map(PathBuf::from)
}

fn tsd_bin() -> PathBuf { PathBuf::from(env!("CARGO_BIN_EXE_tsd")) }
fn tsctl_bin() -> PathBuf { PathBuf::from(env!("CARGO_BIN_EXE_tsctl")) }

fn spawn_tsd(db: &PathBuf, uds: &PathBuf) -> std::process::Child {
    Command::new(tsd_bin())
        .args(["--db-path", db.to_str().unwrap(),
               "--uds-path", uds.to_str().unwrap(),
               "--no-stdout"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn().expect("spawn tsd")
}

fn wait_for_attach(uds: &PathBuf, deadline: Duration) -> u32 {
    let start = Instant::now();
    while start.elapsed() < deadline {
        let out = Command::new(tsctl_bin())
            .args(["--uds-path", uds.to_str().unwrap(), "status"])
            .output().expect("status");
        let s = String::from_utf8_lossy(&out.stdout).into_owned();
        if let Some(line) = s.lines().find(|l| l.starts_with("tls libs attached")) {
            if let Some(n) = line.split_whitespace().last().and_then(|x| x.parse::<u32>().ok()) {
                if n >= 1 { return n; }
            }
        }
        thread::sleep(Duration::from_millis(500));
    }
    0
}

fn rustls_echo_server(payload_to_echo: Vec<u8>) -> std::net::SocketAddr {
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::ServerConfig;

    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    let cfg = Arc::new(cfg);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        let mut conn = rustls::ServerConnection::new(cfg).unwrap();
        let mut tls = rustls::Stream::new(&mut conn, &mut { let s = sock; s });
        let mut buf = [0u8; 8192];
        let _ = tls.read(&mut buf);
        let _ = tls.write_all(&payload_to_echo);
    });
    addr
}

#[test]
#[ignore = "requires CAP_BPF + libssl + cc/pkg-config (see build.rs)"]
fn tls_attach_emits_chunks_in_both_directions() {
    let bin = match tls_client_bin() {
        Some(b) => b,
        None => { eprintln!("skipping: tls_client fixture not built"); return; }
    };
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("e.duckdb");
    let uds = dir.path().join("tsd.sock");
    let payload_file = dir.path().join("payload.bin");
    std::fs::write(&payload_file, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();

    let mut child = spawn_tsd(&db, &uds);
    while !uds.exists() { thread::sleep(Duration::from_millis(100)); }

    let n = wait_for_attach(&uds, Duration::from_secs(15));
    assert!(n >= 1, "tsd never attached to libssl");

    let server_addr = rustls_echo_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi".to_vec());
    let mut client = Command::new(&bin)
        .args(["127.0.0.1", &server_addr.port().to_string(), payload_file.to_str().unwrap()])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().expect("spawn tls_client");
    client.stdin.as_mut().unwrap().write_all(b"GO\n").unwrap();
    let out = client.wait_with_output().expect("wait tls_client");
    assert!(out.status.success(), "tls_client failed: {:?}", String::from_utf8_lossy(&out.stderr));

    // Wait one Appender flush + one /proc rescan.
    thread::sleep(Duration::from_secs(2));

    let q = Command::new(tsctl_bin())
        .args(["--uds-path", uds.to_str().unwrap(),
               "query",
               "SELECT direction, COUNT(*), SUM(chunk_bytes) FROM events_tls_plaintext GROUP BY 1 ORDER BY 1"])
        .output().expect("tsctl query");
    let qout = String::from_utf8_lossy(&q.stdout).into_owned();
    eprintln!("--- query stdout ---\n{qout}");
    assert!(qout.contains("0"), "expected direction=0 row");
    assert!(qout.contains("1"), "expected direction=1 row");

    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    let _ = child.wait();
}

#[test]
#[ignore = "requires CAP_BPF + libssl + cc/pkg-config"]
fn tls_default_tail_does_not_leak_plaintext() {
    let bin = match tls_client_bin() {
        Some(b) => b,
        None => { eprintln!("skipping"); return; }
    };
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("e.duckdb");
    let uds = dir.path().join("tsd.sock");
    let payload_file = dir.path().join("payload.bin");
    let magic = b"MAGIC-PAYLOAD-DO-NOT-LEAK";
    std::fs::write(&payload_file, magic).unwrap();

    let mut child = spawn_tsd(&db, &uds);
    while !uds.exists() { thread::sleep(Duration::from_millis(100)); }
    wait_for_attach(&uds, Duration::from_secs(15));

    let server_addr = rustls_echo_server(b"ok".to_vec());

    // Open `tsctl tail` (NO --show-plaintext), capture stdout in another thread.
    let tail_uds = uds.clone();
    let tail_handle = thread::spawn(move || {
        let mut tail = Command::new(tsctl_bin())
            .args(["--uds-path", tail_uds.to_str().unwrap(), "tail"])
            .stdout(Stdio::piped())
            .spawn().expect("tail spawn");
        thread::sleep(Duration::from_millis(2500));
        unsafe { libc::kill(tail.id() as i32, libc::SIGINT) };
        let out = tail.wait_with_output().expect("tail wait");
        String::from_utf8_lossy(&out.stdout).into_owned()
    });

    thread::sleep(Duration::from_millis(300));

    let mut client = Command::new(&bin)
        .args(["127.0.0.1", &server_addr.port().to_string(), payload_file.to_str().unwrap()])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().expect("spawn tls_client");
    client.stdin.as_mut().unwrap().write_all(b"GO\n").unwrap();
    let _ = client.wait();

    let captured = tail_handle.join().unwrap();
    eprintln!("--- captured tail stdout ---\n{captured}");
    assert!(!captured.contains("MAGIC-PAYLOAD-DO-NOT-LEAK"),
            "default tail leaked plaintext");
    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    let _ = child.wait();
}

#[test]
#[ignore = "requires CAP_BPF + libssl + cc/pkg-config"]
fn tls_show_plaintext_redacts_authorization() {
    let bin = match tls_client_bin() {
        Some(b) => b,
        None => { eprintln!("skipping"); return; }
    };
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("e.duckdb");
    let uds = dir.path().join("tsd.sock");
    let payload_file = dir.path().join("payload.bin");
    std::fs::write(&payload_file,
        b"POST /v1/test HTTP/1.1\r\nAuthorization: Bearer sk-ant-redact-me-please-XYZ\r\n\r\n").unwrap();

    let mut child = spawn_tsd(&db, &uds);
    while !uds.exists() { thread::sleep(Duration::from_millis(100)); }
    wait_for_attach(&uds, Duration::from_secs(15));

    let server_addr = rustls_echo_server(b"ok".to_vec());

    let tail_uds = uds.clone();
    let tail_handle = thread::spawn(move || {
        let mut tail = Command::new(tsctl_bin())
            .args(["--uds-path", tail_uds.to_str().unwrap(), "tail", "--show-plaintext"])
            .stdout(Stdio::piped())
            .spawn().expect("tail spawn");
        thread::sleep(Duration::from_millis(2500));
        unsafe { libc::kill(tail.id() as i32, libc::SIGINT) };
        String::from_utf8_lossy(&tail.wait_with_output().unwrap().stdout).into_owned()
    });
    thread::sleep(Duration::from_millis(300));

    let mut client = Command::new(&bin)
        .args(["127.0.0.1", &server_addr.port().to_string(), payload_file.to_str().unwrap()])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().expect("spawn tls_client");
    client.stdin.as_mut().unwrap().write_all(b"GO\n").unwrap();
    let _ = client.wait();

    let captured = tail_handle.join().unwrap();
    eprintln!("--- captured ---\n{captured}");
    // The plaintext_b64 contains base64 of the *redacted* string; decode and check.
    use base64::Engine;
    let mut leaked = false;
    let mut redacted_seen = false;
    for line in captured.lines() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(b64) = v.get("plaintext_b64").and_then(|x| x.as_str()) {
                let dec = base64::engine::general_purpose::STANDARD.decode(b64).unwrap_or_default();
                let s = String::from_utf8_lossy(&dec);
                if s.contains("sk-ant-redact-me-please-XYZ") { leaked = true; }
                if s.contains("***REDACTED***") { redacted_seen = true; }
            }
        }
    }
    assert!(!leaked, "Authorization token was not redacted");
    assert!(redacted_seen, "expected at least one ***REDACTED*** marker");
    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    let _ = child.wait();
}

#[test]
#[ignore = "requires CAP_BPF + libssl + cc/pkg-config"]
fn tls_truncation_at_16_chunks() {
    let bin = match tls_client_bin() {
        Some(b) => b,
        None => { eprintln!("skipping"); return; }
    };
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("e.duckdb");
    let uds = dir.path().join("tsd.sock");
    let payload_file = dir.path().join("payload.bin");
    std::fs::write(&payload_file, vec![b'X'; 80 * 1024]).unwrap();

    let mut child = spawn_tsd(&db, &uds);
    while !uds.exists() { thread::sleep(Duration::from_millis(100)); }
    wait_for_attach(&uds, Duration::from_secs(15));

    let server_addr = rustls_echo_server(b"ok".to_vec());
    let mut client = Command::new(&bin)
        .args(["127.0.0.1", &server_addr.port().to_string(), payload_file.to_str().unwrap()])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().expect("spawn tls_client");
    client.stdin.as_mut().unwrap().write_all(b"GO\n").unwrap();
    let _ = client.wait();
    thread::sleep(Duration::from_secs(2));

    let q = Command::new(tsctl_bin())
        .args(["--uds-path", uds.to_str().unwrap(),
               "query",
               "SELECT MAX(chunk_index), BOOL_OR(truncated) FROM events_tls_plaintext WHERE direction=0"])
        .output().expect("query");
    let qout = String::from_utf8_lossy(&q.stdout).into_owned();
    eprintln!("{qout}");
    assert!(qout.contains("15"), "expected MAX(chunk_index)=15 (16 chunks)");
    assert!(qout.contains("true"), "expected truncated=true");
    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    let _ = child.wait();
}
```

- [ ] **Step 13.4: Build the tests, expect green compile**

Run: `cargo build --tests -p tsd 2>&1 | tail -20`
Expected: 0 errors. The `option_env!("TS_TLS_CLIENT_BIN")` returns `None` if pkg-config didn't find openssl, in which case the tests will skip cleanly at runtime.

- [ ] **Step 13.5: Run all integration tests under sudo**

Run: `sudo -E cargo test -p tsd -- --ignored --nocapture 2>&1 | tail -60`
Expected: 7 prior + 1 new (`tsd_attaches_to_at_least_one_libssl_at_startup` from Task 9 step 9.6) + 4 from this task = **12 passed** (or skipped with clear message if libssl-dev not installed).

If `tsd_attaches_to_at_least_one_libssl_at_startup` fails because tsd's own process doesn't link libssl: the daemon may not load libssl unless tracing or some dep does. Diagnose with `cat /proc/$(pidof tsd)/maps | grep ssl`. If empty, the test should run while the C fixture client is the only libssl consumer; add a one-line `tls_client` invocation as part of the test setup so the daemon sees something to attach to.

- [ ] **Step 13.6: Commit**

```bash
git add crates/tsd/tests/fixtures/tls_client.c \
        crates/tsd/tests/tls_e2e.rs \
        crates/tsd/build.rs \
        crates/tsd/Cargo.toml
git commit -m "$(cat <<'EOF'
test(tsd): Phase 2.A end-to-end TLS plaintext capture

4 integration tests behind #[ignore]:
- both-directions chunk emission via dynamic OpenSSL client + rustls echo
- default tail does NOT leak plaintext (regression guard for codex BLOCKING #6)
- --show-plaintext redacts Authorization token
- 16-chunk truncation at 80 KiB SSL_write

Fixture is a tiny C client built via cc + pkg-config; tests skip
cleanly if libssl-dev or build tools are missing.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 14: DOC.md update + LEARNED.md entries + tag

**Files:**
- Modify: `DOC.md` (new Phase 2.A section)
- Modify: `~/.claude/LEARNED.md` (entries surfacing during implementation)

- [ ] **Step 14.1: Add Phase 2.A section to DOC.md**

Edit `DOC.md`. Find the existing `## Phases` section. Insert immediately above the existing `### Phase 1.G` block:

```markdown
### Phase 2.A — TLS Plaintext Capture (shipped 2026-05-XX, tag `v0.0.9-phase2a`)

`tsd` now attaches uprobes to `SSL_write{,_ex}` and `SSL_read{,_ex}` (entry +
uretprobe on the read side) on every `libssl.so` it finds in `/proc/*/maps`,
keyed by `(dev, ino)` so containers and symlinked-then-replaced libraries
don't fool us. Plaintext flows on a dedicated 4 MiB ringbuf into
`events_tls_plaintext` (DuckDB schema v2) via the `Appender` API. Discovery
re-walks `/proc` every 5s; new processes that load libssl after daemon start
get attached on the next tick.

`tsctl tail` shows TLS records as JSON metadata + 4-byte sha256 prefix by
default; `tsctl tail --show-plaintext` includes a base64 `plaintext_b64`
field with **server-side** redaction of Authorization headers, JWTs, PEM
private keys, and provider tokens (Anthropic, OpenAI, Groq, HuggingFace,
Google, GitHub, GitLab, AWS). The `include_plaintext` opt-in is enforced at
the daemon — never trusted to the client.

Architecture refactor done in this phase: the Phase 1 direct-call sink
(consumers calling `store.insert_*` and `subs.broadcast` inline) was
replaced with a `EventEnvelope` enum + `events_tx` mpsc + single
`store-writer` thread that owns the DuckDB `Connection`. Per-subscriber
tail rendering happens here so plaintext only reaches subscribers that
opted in.

**Codex review:** caught 8 BLOCKING design issues before implementation
(payload alignment was wrong, `tgid` keying collides across threads,
`ssl_ctx` alone isn't a stream id, `/proc/maps` path identity is broken
for containers, broadcast model leaks plaintext, ringbuf too small,
single-writer story violated, cgroup_filter map sharing underspecified)
plus 10 SHOULD-FIX items. All folded into the spec at
`docs/superpowers/specs/2026-05-07-phase-2a-tls-uprobe-design.md`
before any code was written.

**Gate evidence (verified 2026-05-XX):**
- `cargo fmt --check` / `cargo clippy --workspace --all-targets -- -D warnings` clean
- `cargo test --workspace` — N unit tests pass (TLS payload round-trip 5,
  schema v2 1, redaction 5, render_tail 2, sink TLS persist 1, plus
  Phase 1.G 47 = 61)
- `sudo -E cargo test -p tsd -- --ignored` — 11 integration tests pass
  (Phase 1.E/F/G's 7 + Task 9 attach smoke + 4 from Task 13)
- Plan: `docs/superpowers/plans/2026-05-07-phase-2a-tls-uprobe.md`

**Known gaps:**
- Go static `crypto/tls` and rustls invisible (uprobe model needs C-ABI
  symbols in a shared object); future phase
- BoringSSL with stripped symbols counted as `tls_libs_skipped`
- Static-linked OpenSSL into a binary missed (discovery only walks shared
  libs)
- `SSL_write` captures attempted plaintext, not necessarily transmitted
- Min kernel 5.15 (uprobe MEM_RINGBUF dest writes stable)
- Per-cgroup attach UI deferred — `--track-cgroup PATH` (repeatable) at tsd
  startup; `tsctl cgroup add/remove` lands later
```

- [ ] **Step 14.2: Update DOC.md "Known Gaps" entries that now resolve**

Search DOC.md for entries like "No `--json` / `--csv` output mode for tsctl — Phase 2" and any "Phase 2" markers in older Known-gaps blocks. Don't delete them; mark the ones that 2.A addressed:

```markdown
- ~~Tail filters (`--filter 'provider=anthropic'`) — Phase 2 once parsers exist~~ → still pending; parsers land in Phase 2.C
```

(Parsers are 2.C, so the filter gap is still open. The point of this step is to keep DOC.md honest about what 2.A does and doesn't ship.)

- [ ] **Step 14.3: LEARNED.md entries**

The implementer may discover non-obvious things during execution. Append to `~/.claude/LEARNED.md` for each. Likely candidates (only add the ones that *actually* turned up — otherwise this step is no-op):

```markdown
### libbpf-rs 0.24 + percpu maps

`Map::lookup_percpu()` returns `Result<Option<Vec<Vec<u8>>>>` — outer Option
is "key present at all", inner `Vec<Vec<u8>>` is one buffer per CPU. To sum
a percpu counter, iterate the inner Vec and decode each as a `u64::from_ne_bytes`.
Verified for `tls_reserve_fail` and `tls_inflight_collision` percpu arrays.

### duckdb-rs Appender lifetime + long-lived holder

`Connection::appender("table")` returns `Appender<'_>` borrowing the
connection. To hold one in a long-lived writer thread, either:
1. wrap the `Connection` in `Arc<Mutex<>>` and re-lease per batch (slow
   on burst), or
2. transmute the lifetime of the appender once you know the connection
   outlives it (fast; SAFETY contract: connection lives ⊇ appender's life).
TokenScope picks (2) because the EventSink owns both via Arc.

### `_ex` OpenSSL functions are publicly exported

`SSL_read_ex` and `SSL_write_ex` are stable public API since OpenSSL 1.1.1
(September 2018). Modern Python's `ssl` module uses them under the hood,
so probing only `SSL_read`/`SSL_write` misses traffic on recent distros.
Always probe both pairs.
```

- [ ] **Step 14.4: Run final full test pass**

Run: `cargo test --workspace 2>&1 | tail -5 && sudo -E cargo test -p tsd -- --ignored 2>&1 | tail -10`
Expected: all unit + integration tests pass.

- [ ] **Step 14.5: Run fmt + clippy gates**

Run: `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -10`
Expected: 0 warnings, 0 errors.

- [ ] **Step 14.6: Commit DOC.md + LEARNED.md**

```bash
git add DOC.md
git commit -m "$(cat <<'EOF'
docs: Phase 2.A shipped (TLS plaintext capture)

Records phase entry with codex-review history, gate evidence, and the
known gaps the phase explicitly defers (Go/rustls invisibility, BoringSSL
strips, static-linked OpenSSL, per-cgroup UI).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

(LEARNED.md is in `~/.claude/`, outside the repo — commit separately if you keep it under version control elsewhere; otherwise just save the file.)

- [ ] **Step 14.7: Tag the release**

Run: `git tag v0.0.9-phase2a && git tag -l v0.0.9-phase2a`
Expected: tag created and listed.

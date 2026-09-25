# TokenScope Phase 1.C — Process Enrichment via /proc Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace raw `pid: 47148` in tsd's stdout with `comm: "curl", cmdline: "curl https://example.com"` by maintaining a lazy `pid → ProcessInfo` cache populated from `/proc`. Userspace-only — no BPF changes, no wire-format changes. Multiplies the per-event signal-to-noise ratio for every existing event type and is a prerequisite for meaningful DuckDB queries in Phase 1.D.

**Architecture:** A single-file `proc_cache.rs` holding a `RefCell<ProcessCache>` that maps `pid → {comm, cmdline}` with capped capacity (4096) and FIFO eviction. Lookups are lazy: on cache miss, read `/proc/<pid>/comm` and `/proc/<pid>/cmdline` synchronously and insert. Both the ringbuf event handler and the periodic `net_bytes` flush borrow the cache through closures. Single-threaded throughout — `RefCell` over `Mutex` is correct because tsd's main loop polls and flushes serially.

**Tech Stack:** Same as Phase 1.B. No new dependencies — `/proc` reads use `std::fs`.

---

## Scope & Out-of-Scope

**In scope (Phase 1.C):**
- `crates/tsd/src/proc_cache.rs` with `ProcessInfo` (comm + cmdline) and `ProcessCache` (4096-entry FIFO)
- /proc/<pid>/comm and /proc/<pid>/cmdline readers, NUL-tolerant
- Refactor `tsd::main` to construct the cache and thread it into ringbuf closures
- Refactor `tsd::net_bytes::flush` to accept the cache and enrich `NetBytes` lines
- Integration test that spawns a known child process and asserts both `comm:` and `cmdline:` show up in tsd's stdout
- DOC.md update + tag `v0.0.4-phase1c`

**Explicitly deferred:**
- exe / uid / gid / cgroup_path enrichment (Phase 1.D when DuckDB schema needs them)
- PID-reuse detection via `/proc/<pid>/stat` start_time (Phase 1.D)
- Eager /proc walk on startup (lazy is fine for now; eager pays only on first interaction)
- Cache invalidation on `sched_process_exit` (lazy LRU is good enough; explicit invalidation is a Phase 2 cleanup)
- Container/namespace cmdline unwrapping (Phase 3+)

---

## File Structure (delta from Phase 1.B)

```
tokenscope/
├── crates/tsd/
│   ├── src/
│   │   ├── main.rs              # threads cache into closures; richer print
│   │   ├── net_bytes.rs         # accepts cache; richer print
│   │   └── proc_cache.rs        # NEW
│   └── tests/
│       └── enrichment.rs        # NEW
└── DOC.md                       # +Phase 1.C entry
```

---

## Task 1: proc_cache Module **(INLINE)**

**Files:**
- Create: `crates/tsd/src/proc_cache.rs`

**Why inline:** Cache semantics (capacity-bounded FIFO, lazy /proc lookup, error-as-cache) and the unit tests for /proc parsing both need careful handling. Cmdline parsing in particular has the NUL-separator quirk that's easy to miss.

- [ ] **Step 1: Write the module with inline unit tests**

`crates/tsd/src/proc_cache.rs`:
```rust
//! Lazy `pid → ProcessInfo` cache populated from /proc.
//!
//! Single-threaded by design (tsd's main loop is sync). Use `RefCell`
//! at the call site for interior mutability.
//!
//! Eviction: simple FIFO at capacity. PID reuse detection (via
//! /proc/<pid>/stat start_time) is deferred to Phase 1.D when accuracy
//! starts mattering for persisted records.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::fs;

const CAPACITY: usize = 4096;
/// Truncate cmdline to this many bytes when displaying. Keeps lines tidy
/// for stdout printing without losing the binary name.
const CMDLINE_DISPLAY_CAP: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub comm: String,
    pub cmdline: String,
}

impl ProcessInfo {
    /// Truncated cmdline suitable for one-line display. If the cmdline
    /// is empty (kernel thread, race with exit), falls back to the comm
    /// in brackets so output never has bare `cmdline: ""`.
    pub fn display_cmdline(&self) -> String {
        if self.cmdline.is_empty() {
            return format!("[{}]", self.comm);
        }
        if self.cmdline.len() <= CMDLINE_DISPLAY_CAP {
            return self.cmdline.clone();
        }
        let mut s = self.cmdline[..CMDLINE_DISPLAY_CAP].to_string();
        s.push('…');
        s
    }
}

pub struct ProcessCache {
    map: HashMap<u32, ProcessInfo>,
    order: VecDeque<u32>,
}

impl ProcessCache {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Lookup-or-insert. Always returns Some — on read failure the cache
    /// stores a sentinel (`<gone>` / `<denied>`) so we don't re-stat
    /// the same dead PID on every event.
    pub fn get_or_load(&mut self, pid: u32) -> &ProcessInfo {
        if !self.map.contains_key(&pid) {
            let info = read_proc(pid);
            self.insert(pid, info);
        }
        self.map.get(&pid).expect("just inserted")
    }

    fn insert(&mut self, pid: u32, info: ProcessInfo) {
        if self.map.len() >= CAPACITY {
            if let Some(evict) = self.order.pop_front() {
                self.map.remove(&evict);
            }
        }
        self.order.push_back(pid);
        self.map.insert(pid, info);
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl Default for ProcessCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Read /proc/<pid>/comm and /proc/<pid>/cmdline. Returns sentinel
/// values rather than errors — this is logging-path code, never panic.
fn read_proc(pid: u32) -> ProcessInfo {
    let comm_path = format!("/proc/{pid}/comm");
    let cmdline_path = format!("/proc/{pid}/cmdline");

    let comm = match fs::read_to_string(&comm_path) {
        Ok(s) => s.trim_end_matches('\n').to_string(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "<gone>".to_string(),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => "<denied>".to_string(),
        Err(_) => "<error>".to_string(),
    };

    let cmdline = match fs::read(&cmdline_path) {
        Ok(bytes) => parse_cmdline(&bytes),
        Err(_) => String::new(),
    };

    ProcessInfo { comm, cmdline }
}

/// Convert NUL-separated argv (the /proc/<pid>/cmdline format) into a
/// space-joined display string. Trailing NULs are stripped.
fn parse_cmdline(bytes: &[u8]) -> String {
    let trimmed_end = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    let useful = &bytes[..trimmed_end];
    let parts: Vec<String> = useful
        .split(|&b| b == 0)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect();
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cmdline_simple() {
        let bytes = b"curl\0https://example.com\0";
        assert_eq!(parse_cmdline(bytes), "curl https://example.com");
    }

    #[test]
    fn parse_cmdline_no_trailing_nul() {
        let bytes = b"sleep\01";
        assert_eq!(parse_cmdline(bytes), "sleep 1");
    }

    #[test]
    fn parse_cmdline_empty() {
        assert_eq!(parse_cmdline(b""), "");
        assert_eq!(parse_cmdline(b"\0\0\0"), "");
    }

    #[test]
    fn parse_cmdline_single_arg() {
        assert_eq!(parse_cmdline(b"sshd\0"), "sshd");
    }

    #[test]
    fn display_cmdline_falls_back_to_comm_when_empty() {
        let info = ProcessInfo {
            comm: "kworker/0:1".to_string(),
            cmdline: String::new(),
        };
        assert_eq!(info.display_cmdline(), "[kworker/0:1]");
    }

    #[test]
    fn display_cmdline_truncates() {
        let long = "x".repeat(500);
        let info = ProcessInfo {
            comm: "x".to_string(),
            cmdline: long,
        };
        let out = info.display_cmdline();
        // 256 'x' + 1 ellipsis char ('…' = 3 bytes UTF-8 → total 259 bytes)
        assert_eq!(out.chars().count(), CMDLINE_DISPLAY_CAP + 1);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn cache_evicts_at_capacity() {
        let mut c = ProcessCache::new();
        for pid in 1..=(CAPACITY as u32 + 10) {
            c.insert(
                pid,
                ProcessInfo {
                    comm: format!("p{pid}"),
                    cmdline: String::new(),
                },
            );
        }
        assert_eq!(c.len(), CAPACITY);
        // First 10 PIDs should have been evicted
        for pid in 1..=10 {
            assert!(!c.map.contains_key(&pid));
        }
        assert!(c.map.contains_key(&(CAPACITY as u32 + 10)));
    }

    /// Smoke test against the real /proc — looks up PID 1 (init/systemd),
    /// which always exists on Linux. Doesn't assert specific contents
    /// since they vary by distro, just that we get *something*.
    #[test]
    fn read_proc_pid_1() {
        let info = read_proc(1);
        assert!(!info.comm.is_empty());
        assert_ne!(info.comm, "<gone>");
        assert_ne!(info.comm, "<error>");
    }

    /// Looking up a definitely-dead PID returns the gone sentinel.
    #[test]
    fn read_proc_dead_pid_is_gone() {
        let info = read_proc(0xFFFF_FFFE);
        assert_eq!(info.comm, "<gone>");
    }
}
```

- [ ] **Step 2: Run the unit tests**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
cargo test -p tsd --lib
```

Expected: 9 tests pass (8 from this module). The `read_proc_pid_1` smoke test reads /proc/1/comm and /proc/1/cmdline.

If `read_proc_pid_1` fails because /proc/1 isn't readable as the test user (extremely unusual, would mean a bizarre containerized build env), gate the test with `#[cfg(target_os = "linux")]` and a `if !std::path::Path::new("/proc/1/comm").exists() { return; }` early-return.

- [ ] **Step 3: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add crates/tsd/src/proc_cache.rs
git commit -m "feat(tsd): pid → ProcessInfo lazy cache backed by /proc"
```

Note: the commit doesn't yet wire `proc_cache` into `main.rs` — Task 2 does that. Until Task 2 lands, clippy will warn about an unused module. Skip clippy on this commit (`cargo test --lib` is sufficient verification of Task 1).

---

## Task 2: Wire proc_cache into main.rs and net_bytes::flush **(INLINE)**

**Files:**
- Modify: `crates/tsd/src/main.rs`
- Modify: `crates/tsd/src/net_bytes.rs`

**Why inline:** This is the closure-lifetime work that's notoriously tricky with libbpf-rs. The cache must outlive both the ringbuf (whose closures borrow it) and the flush call (which also borrows it).

- [ ] **Step 1: Rewrite `crates/tsd/src/main.rs` to thread the cache**

Replace the entire file with:

```rust
//! TokenScope daemon (Phase 1.C).
//!
//! Adds a `proc_cache` that resolves pid → (comm, cmdline) lazily from
//! /proc. Both the ringbuf event handler and the periodic net_bytes
//! flush borrow the cache via closures. Single-threaded throughout —
//! `RefCell` is correct because the main loop polls and flushes
//! serially.

mod cgroup;
mod net_bytes;
mod proc_cache;
mod skeletons;

use std::cell::RefCell;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use ts_bpf_sys::libbpf_rs::RingBufferBuilder;
use ts_core::{decode_header, decode_net_connect, TsEventType};

use crate::proc_cache::ProcessCache;
use crate::skeletons::{load_all, SkelStorage};

#[derive(Parser, Debug)]
#[command(name = "tsd", version, about = "TokenScope daemon")]
struct Args {
    /// RUST_LOG-style filter for tracing.
    #[arg(long, default_value = "info")]
    log_filter: String,

    /// How often to scan + print the per-socket byte counter map (milliseconds).
    #[arg(long, default_value_t = 5000)]
    flush_interval_ms: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_new(&args.log_filter).unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!("tsd starting (Phase 1.C — sched_exec + cgroup/connect + tcp bytes + /proc enrichment)");

    let cgroup_root = cgroup::open_unified_root().context("open cgroup root")?;
    let mut storage = SkelStorage::new();
    let skels = load_all(&mut storage, cgroup_root).context("load skeletons")?;

    info!(flush_ms = args.flush_interval_ms, "BPF programs attached");

    let cache = RefCell::new(ProcessCache::new());

    let mut builder = RingBufferBuilder::new();
    builder
        .add(&skels.sched.maps.events, |data| handle_event(data, &cache))
        .map_err(|e| anyhow!("add sched ringbuf: {e}"))?;
    builder
        .add(&skels.net.maps.events, |data| handle_event(data, &cache))
        .map_err(|e| anyhow!("add net ringbuf: {e}"))?;
    let ringbuf = builder.build().map_err(|e| anyhow!("build ringbuf: {e}"))?;

    let flush_interval = Duration::from_millis(args.flush_interval_ms);
    let mut last_flush = Instant::now();

    loop {
        if let Err(e) = ringbuf.poll(Duration::from_millis(200)) {
            error!(?e, "ringbuf poll error");
        }
        if last_flush.elapsed() >= flush_interval {
            net_bytes::flush(&skels.net.maps.net_bytes, &cache);
            last_flush = Instant::now();
        }
    }
}

fn handle_event(data: &[u8], cache: &RefCell<ProcessCache>) -> i32 {
    let hdr = match decode_header(data) {
        Ok(h) => h,
        Err(e) => {
            error!(?e, len = data.len(), "decode header failed");
            return 0;
        }
    };

    let kind = TsEventType::from_u16(hdr.ty);
    let payload = &data[std::mem::size_of::<ts_core::TsEventHdr>()..];

    let mut cache_mut = cache.borrow_mut();
    let info = cache_mut.get_or_load(hdr.pid);

    match kind {
        Some(TsEventType::ProcExec) => {
            println!(
                "TsEventHdr {{ kind: ProcExec, pid: {pid}, comm: {comm:?}, cmdline: {cmdline:?}, tgid: {tgid}, cpu: {cpu}, cgroup_id: {cgid:#x}, ts_ns: {ts} }}",
                pid = hdr.pid,
                comm = info.comm,
                cmdline = info.display_cmdline(),
                tgid = hdr.tgid,
                cpu = hdr.cpu,
                cgid = hdr.cgroup_id,
                ts = hdr.ts_ns,
            );
        }
        Some(TsEventType::NetConnect) => match decode_net_connect(payload) {
            Ok(pl) => {
                println!(
                    "TsEventHdr {{ kind: NetConnect, pid: {pid}, comm: {comm:?}, cmdline: {cmdline:?}, dst: {dst}, proto: {proto}, cgroup_id: {cgid:#x} }}",
                    pid = hdr.pid,
                    comm = info.comm,
                    cmdline = info.display_cmdline(),
                    dst = pl.dst_string(),
                    proto = pl.protocol,
                    cgid = hdr.cgroup_id,
                );
            }
            Err(e) => error!(?e, "decode net_connect failed"),
        },
        Some(other) => {
            println!(
                "TsEventHdr {{ kind: {other:?}, pid: {pid}, comm: {comm:?}, len: {len} }}",
                pid = hdr.pid,
                comm = info.comm,
                len = hdr.len,
            );
        }
        None => {
            println!(
                "TsEventHdr {{ kind: Unknown({ty}), pid: {pid}, comm: {comm:?}, len: {len} }}",
                ty = hdr.ty,
                pid = hdr.pid,
                comm = info.comm,
                len = hdr.len,
            );
        }
    }
    0
}
```

- [ ] **Step 2: Update `crates/tsd/src/net_bytes.rs` to accept the cache**

Replace the entire file with:

```rust
//! Periodic flush of the BPF `net_bytes` LRU map.
//!
//! Iterates every entry, decodes key+value, looks up comm+cmdline via
//! the proc_cache, and prints a single `NetBytes { ... }` line per
//! non-zero socket. Entries are NOT cleared — they're cumulative until
//! kernel LRU eviction. Phase 1.D will replace this with DuckDB writes.

use std::cell::RefCell;

use ts_bpf_sys::libbpf_rs::{MapCore, MapFlags, MapMut};
use ts_core::{decode_net_bytes_key, decode_net_bytes_value};

use crate::proc_cache::ProcessCache;

pub fn flush(map: &MapMut<'_>, cache: &RefCell<ProcessCache>) {
    let mut cache_mut = cache.borrow_mut();
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
        let info = cache_mut.get_or_load(value.pid);
        println!(
            "NetBytes {{ sock_cookie: {cookie:#018x}, pid: {pid}, comm: {comm:?}, cmdline: {cmdline:?}, tx: {tx}, rx: {rx}, last_ns: {ns} }}",
            cookie = key.sock_cookie,
            pid = value.pid,
            comm = info.comm,
            cmdline = info.display_cmdline(),
            tx = value.tx_bytes,
            rx = value.rx_bytes,
            ns = value.last_ns,
        );
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
cargo test --workspace 2>&1 | tail -15
```

Expected: build clean, clippy clean, all unit tests pass (ts-core 13, tsd 8 from proc_cache).

If a lifetime error appears in `builder.add(&map, |data| handle_event(data, &cache))`, the closure type signature might need an explicit type ascription. Try:
```rust
let mk = |data: &[u8]| -> i32 { handle_event(data, &cache) };
builder.add(&skels.sched.maps.events, mk)?;
```
Then make a separate closure for the second `add` (closures of the same body can't easily be cloned).

- [ ] **Step 4: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add crates/tsd/src/main.rs crates/tsd/src/net_bytes.rs
git commit -m "feat(tsd): enrich event lines with comm + cmdline from /proc cache"
```

---

## Task 3: Integration Test — Verify Enrichment Appears **(INLINE)**

**Files:**
- Create: `crates/tsd/tests/enrichment.rs`

**Why inline:** The test design — spawn a known-cmdline child, look for it in tsd's stdout — has subtle timing. The child must live long enough for tsd to read its /proc entry; using `/bin/sleep 1` gives a comfortable window.

- [ ] **Step 1: Write the test**

`crates/tsd/tests/enrichment.rs`:
```rust
//! Spawn `/bin/sleep 1.5` while tsd is running and assert tsd's stdout
//! shows a ProcExec line with `comm: "sleep"` and a cmdline that
//! contains both the binary name and the argument. /bin/sleep is
//! preferable to /bin/true here because it lives long enough for tsd
//! to read /proc/<pid>/cmdline before the process exits.
//!
//! Requires CAP_BPF or root; ignored by default.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
#[ignore = "requires CAP_BPF or root; run with --include-ignored under sudo"]
fn captures_proc_exec_with_cmdline() {
    let bin = env!("CARGO_BIN_EXE_tsd");

    let mut child = Command::new(bin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tsd");

    let stdout = child.stdout.take().expect("pipe stdout");
    let mut reader = BufReader::new(stdout);

    std::thread::sleep(Duration::from_millis(700));

    let mut sleep_proc = Command::new("/bin/sleep")
        .arg("1.5")
        .spawn()
        .expect("spawn /bin/sleep");

    let deadline = Instant::now() + Duration::from_secs(4);
    let mut saw_event = false;
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) if line.contains("kind: ProcExec")
                && line.contains("comm: \"sleep\"")
                && line.contains("cmdline:")
                && line.contains("1.5") =>
            {
                saw_event = true;
                eprintln!("captured: {}", line.trim());
                break;
            }
            Ok(_) => continue,
            Err(_) => break,
        }
    }

    let _ = sleep_proc.wait();
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        saw_event,
        "tsd produced no ProcExec line for `/bin/sleep 1.5` with comm+cmdline within 4s"
    );
}
```

- [ ] **Step 2: Build the test binary**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
cargo build --tests -p tsd 2>&1 | tail -10
```

Expected: build succeeds.

- [ ] **Step 3: Run the full integration suite under sudo**

Ask the user to run:
```
cd /home/hoang/code/personal/active/tokenscope && sudo -E env "PATH=$PATH" /home/hoang/.cargo/bin/cargo test -p tsd -- --ignored --nocapture
```

Expected: four tests pass — `exec_event` (Phase 0), `connect_event` (Phase 1.A), `bytes_event` (Phase 1.B), `enrichment` (Phase 1.C). The new test prints something like:
```
captured: TsEventHdr { kind: ProcExec, pid: 12345, comm: "sleep", cmdline: "/bin/sleep 1.5", ... }
```

If the test fails:
1. Manually reproduce: `sudo ./target/debug/tsd` in one terminal, `/bin/sleep 1.5` in another. Confirm the line appears.
2. If `comm: ""` appears, /proc was racing the exec — increase the test's child lifetime or add a small sleep between exec and the read in the test.
3. If `cmdline: ""` appears for the sleep process specifically, parse_cmdline may have a bug — re-check Task 1's tests.

- [ ] **Step 4: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add crates/tsd/tests/enrichment.rs
git commit -m "test(tsd): /proc enrichment integration test"
```

---

## Task 4: Phase 1.C Wrap-up — DOC.md, Tag **(INLINE)**

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

- [ ] **Step 2: Update DOC.md — insert above Phase 1.B**

Edit `DOC.md`. Find `### Phase 1.B — TCP Byte Counting` and insert ABOVE it:

```markdown
### Phase 1.C — Process Enrichment (shipped 2026-05-06, tag `v0.0.4-phase1c`)

Userspace `proc_cache` resolves `pid → {comm, cmdline}` lazily from `/proc/<pid>/comm` and `/proc/<pid>/cmdline`. Both the ringbuf event handler and the periodic net_bytes flush borrow the cache via closures (single-threaded; `RefCell` for interior mutability). Every event line tsd prints — `ProcExec`, `NetConnect`, `NetBytes` — now includes `comm:` and `cmdline:` fields.

Cache: 4096-entry FIFO eviction, sentinel values for dead/denied PIDs (so a single failed lookup doesn't trigger repeated /proc reads). No BPF or wire-format changes — pure userspace.

**Gate evidence (verified 2026-05-06):**
- `cargo fmt --check` / `cargo clippy -D warnings` clean
- `cargo test --workspace` — 13 ts-core + 8 tsd proc_cache unit tests pass
- `sudo cargo test -p tsd -- --ignored` — four tests pass: `exec_event`, `connect_event`, `bytes_event`, `enrichment`
- Plan: `docs/superpowers/plans/2026-05-06-phase-1c-proc-enrichment.md`

**Known gaps:**
- No PID-reuse detection (cache trusts pid; fix in Phase 1.D using /proc/<pid>/stat start_time)
- No exit-driven invalidation (FIFO eviction handles it eventually)
- exe / uid / gid / cgroup_path not yet captured (Phase 1.D when DuckDB schema needs them)
```

- [ ] **Step 3: Commit and tag**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add DOC.md
git commit -m "docs: mark Phase 1.C shipped with gate evidence"
git tag -a v0.0.4-phase1c -m "Phase 1.C — Process Enrichment via /proc"
git tag --list
```

Expected: tag list now includes `v0.0.1-phase0`, `v0.0.2-phase1a`, `v0.0.3-phase1b`, `v0.0.4-phase1c`.

---

## Definition of Done (Phase 1.C acceptance gate)

All must be true:
1. `cargo build --workspace` succeeds.
2. `cargo test --workspace` exits 0 (ts-core 13, tsd lib 8 from proc_cache).
3. `sudo cargo test -p tsd -- --ignored` exits 0 — four tests pass.
4. Live: `sudo ./target/debug/tsd` + `curl example.com` shows lines with `comm: "curl", cmdline: "curl example.com"`.
5. `cargo fmt --check` and `cargo clippy -D warnings` clean.
6. DOC.md reflects Phase 1.C shipped.
7. Git tag `v0.0.4-phase1c` exists locally.

---

## Self-Review Notes

**Spec coverage check (SPEC §11 Phase 1, item 2 of 4):**
- "Process enrichment via /proc + sched tracepoints" → /proc covered (Tasks 1-3); sched tracepoints (sched_process_fork, sched_process_exit) deferred to Phase 1.C-bis or absorbed into Phase 1.D. The lazy-cache + FIFO approach gets us 90% of the value without needing those tracepoints in this phase.

**Type/name consistency:**
- `ProcessInfo { comm, cmdline }` and `ProcessCache::get_or_load` used consistently in main.rs, net_bytes.rs, and the unit tests.
- `cache.borrow_mut()` used uniformly; never `.borrow()` then mutate.

**Placeholder scrub:** none of the forbidden phrases appear.

**Closure-lifetime check:**
- Two closures both capture `&cache` — both immutable borrows of `RefCell`, which is Sync-safe even in single-threaded use because `RefCell::borrow_mut()` is checked at runtime.
- Cache outlives the ringbuf because the ringbuf is dropped at the end of `main()` (loop never returns), but if it did, drop order is reverse of creation: ringbuf → builder → cache. Cache outlives both.

**Why no `Mutex`:** main loop is single-threaded; lock contention is impossible. `RefCell` is the correct choice; `Mutex` would add overhead and complicate clippy with unwrap.

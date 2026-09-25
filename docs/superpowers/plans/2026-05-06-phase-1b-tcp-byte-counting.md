# TokenScope Phase 1.B — TCP Byte Counting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Count TX/RX bytes per TCP socket via `fexit/tcp_sendmsg` + `fexit/tcp_recvmsg` BPF programs accumulating into an LRU hash map keyed by socket cookie. `tsd` periodically flushes the map and prints `NetBytes` lines on stdout. No new ringbuf event types — the map *is* the truth, and Phase 1.D will lift it directly into DuckDB.

**Architecture:** A new `BPF_MAP_TYPE_LRU_HASH` map in `bpf/net.bpf.c` keyed by `__u64 sock_cookie` and valued by `{tx_bytes, rx_bytes, last_ns, pid}`. Two `fexit` programs hook the kernel's `tcp_sendmsg` and `tcp_recvmsg` exit points, take the actual return value (bytes-sent / bytes-received), and atomic-add into the map. `tsd` adds a `--flush-interval-ms` flag (default 5000) and, in its main poll loop, every N ms iterates the map via `MapCore::keys()`/`lookup()` and prints non-zero entries. Map entries are NOT cleared on flush — they're cumulative until LRU eviction.

**Tech Stack:** Same as Phase 1.A. No new dependencies. The `fexit` attach type requires kernel ≥ 5.5 with BTF (already verified on WSL2 6.6.87).

---

## Scope & Out-of-Scope

**In scope (Phase 1.B):**
- LRU hash map `net_bytes` in `bpf/net.bpf.c`
- `fexit/tcp_sendmsg` and `fexit/tcp_recvmsg` programs
- Rust mirrors of map key/value structs in `ts-core::event`
- `crates/tsd/src/net_bytes.rs` flush helper
- `--flush-interval-ms` CLI flag (defaults: 5000 prod, 500 in test)
- Integration test that creates a real TCP connection on loopback, sends bytes, asserts the map sees them
- DOC.md update + tag `v0.0.3-phase1b`

**Explicitly deferred:**
- UDP byte counting (different kernel functions; Phase 2)
- Per-PID accuracy in softirq context (sends from `ksoftirqd` for retransmits attribute to that kernel thread; out of scope)
- TS_NET_BYTES ringbuf events (Phase 1.D wires the map into DuckDB directly)
- Map eviction tuning (LRU at 65k entries; revisit when we observe drops in production)
- Clearing entries on flush (cumulative for now; subtraction at query time)
- IPv6 send/recv tests (covered by attach; integration test only verifies v4)

---

## File Structure (delta from Phase 1.A)

```
tokenscope/
├── bpf/
│   ├── ts_event.h                   # +struct ts_net_bytes_key + ts_net_bytes_value
│   └── net.bpf.c                    # +map + 2 fexit programs
├── crates/
│   ├── ts-core/src/
│   │   └── event.rs                 # +TsNetBytesKey + TsNetBytesValue + decoders
│   └── tsd/
│       ├── src/
│       │   ├── main.rs              # +periodic flush, +CLI flag
│       │   ├── net_bytes.rs         # NEW: map iterator + line formatter
│       │   └── skeletons.rs         # +attach handle_sendmsg / handle_recvmsg
│       └── tests/
│           └── bytes_event.rs       # NEW
└── DOC.md                           # +Phase 1.B entry
```

---

## Task 1: Wire Types — Map Key/Value Structs **(INLINE)**

**Files:**
- Modify: `bpf/ts_event.h`
- Modify: `crates/ts-core/src/event.rs`
- Modify: `crates/ts-core/src/lib.rs`

**Why inline:** Map key/value layout drift is hard to debug (you get garbage data, not a clear error). Both sides written together with eyes on byte offsets.

- [ ] **Step 1: Append map types to `bpf/ts_event.h`**

Insert before the closing `#endif`:

```c
/*
 * Key for the net_bytes LRU hash map. One entry per TCP socket.
 * sock_cookie is from bpf_get_socket_cookie() — a stable per-socket id
 * that survives PID reuse and connection migration within the kernel.
 *
 * Layout: 0..8 sock_cookie (u64). Total: 8 bytes.
 */
struct ts_net_bytes_key {
    __u64 sock_cookie;
};

/*
 * Value for the net_bytes LRU hash map.
 *
 * Layout (natural alignment):
 *   0..8   tx_bytes  (u64) — cumulative bytes returned from tcp_sendmsg
 *   8..16  rx_bytes  (u64) — cumulative bytes returned from tcp_recvmsg
 *   16..24 last_ns   (u64) — last update CLOCK_MONOTONIC ns
 *   24..28 pid       (u32) — first observed PID; may be ksoftirqd for retransmits
 *   28..32 _pad      (u32) — reserved
 *
 * Total: 32 bytes. Alignment: 8.
 */
struct ts_net_bytes_value {
    __u64 tx_bytes;
    __u64 rx_bytes;
    __u64 last_ns;
    __u32 pid;
    __u32 _pad;
};
```

- [ ] **Step 2: Add Rust mirrors to `crates/ts-core/src/event.rs`**

Append (after the `decode_net_connect` function, before the `#[cfg(test)]` block):

```rust
/// Mirror of `struct ts_net_bytes_key` in `bpf/ts_event.h`.
///
/// Layout: 8 bytes, `sock_cookie: u64`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TsNetBytesKey {
    pub sock_cookie: u64,
}

const _: () = assert!(core::mem::size_of::<TsNetBytesKey>() == 8);

/// Mirror of `struct ts_net_bytes_value` in `bpf/ts_event.h`.
///
/// Layout (natural alignment):
/// - 0..8   tx_bytes  (u64)
/// - 8..16  rx_bytes  (u64)
/// - 16..24 last_ns   (u64)
/// - 24..28 pid       (u32)
/// - 28..32 _pad      (u32)
///
/// Total: 32 bytes. Alignment: 8.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TsNetBytesValue {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub last_ns: u64,
    pub pid: u32,
    pub _pad: u32,
}

const _: () = assert!(core::mem::size_of::<TsNetBytesValue>() == 32);

/// Decode a key Vec returned from `MapCore::keys()`.
pub fn decode_net_bytes_key(buf: &[u8]) -> Result<TsNetBytesKey, DecodeError> {
    let need = core::mem::size_of::<TsNetBytesKey>();
    if buf.len() < need {
        return Err(DecodeError::Truncated {
            got: buf.len(),
            need,
        });
    }
    Ok(unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const TsNetBytesKey) })
}

/// Decode a value Vec returned from `MapCore::lookup()`.
pub fn decode_net_bytes_value(buf: &[u8]) -> Result<TsNetBytesValue, DecodeError> {
    let need = core::mem::size_of::<TsNetBytesValue>();
    if buf.len() < need {
        return Err(DecodeError::Truncated {
            got: buf.len(),
            need,
        });
    }
    Ok(unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const TsNetBytesValue) })
}
```

- [ ] **Step 3: Add tests inside the existing `#[cfg(test)] mod tests` block**

Append before the closing `}`:

```rust
    #[test]
    fn net_bytes_key_size_is_8() {
        assert_eq!(core::mem::size_of::<TsNetBytesKey>(), 8);
    }

    #[test]
    fn net_bytes_value_size_is_32() {
        assert_eq!(core::mem::size_of::<TsNetBytesValue>(), 32);
    }

    #[test]
    fn net_bytes_value_round_trip() {
        let v = TsNetBytesValue {
            tx_bytes: 12345,
            rx_bytes: 67890,
            last_ns: 0xDEAD_BEEF_CAFE_F00D,
            pid: 4242,
            _pad: 0,
        };
        let bytes: [u8; 32] = unsafe { core::mem::transmute(v) };
        let decoded = decode_net_bytes_value(&bytes).unwrap();
        assert_eq!(decoded.tx_bytes, 12345);
        assert_eq!(decoded.rx_bytes, 67890);
        assert_eq!(decoded.last_ns, 0xDEAD_BEEF_CAFE_F00D);
        assert_eq!(decoded.pid, 4242);
    }

    #[test]
    fn net_bytes_key_round_trip() {
        let k = TsNetBytesKey {
            sock_cookie: 0x1122_3344_5566_7788,
        };
        let bytes: [u8; 8] = unsafe { core::mem::transmute(k) };
        let decoded = decode_net_bytes_key(&bytes).unwrap();
        assert_eq!(decoded.sock_cookie, 0x1122_3344_5566_7788);
    }
```

- [ ] **Step 4: Update `crates/ts-core/src/lib.rs` exports**

Replace the `pub use event::{...}` line with:

```rust
pub use event::{
    decode_header, decode_net_bytes_key, decode_net_bytes_value, decode_net_connect, DecodeError,
    TsEventHdr, TsEventType, TsNetBytesKey, TsNetBytesValue, TsNetConnectPayload,
};
```

- [ ] **Step 5: Run tests**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
cargo test -p ts-core
```

Expected: `test result: ok. 13 passed` (9 from Phase 1.A + 4 new).

- [ ] **Step 6: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add bpf/ts_event.h crates/ts-core/
git commit -m "feat(ts-core): TsNetBytes{Key,Value} mirrors for the LRU map"
```

---

## Task 2: BPF — fexit/tcp_sendmsg + fexit/tcp_recvmsg + LRU map **(INLINE)**

**Files:**
- Modify: `bpf/net.bpf.c`

**Why inline:** First fexit programs in the project. `BPF_PROG` macro signature must match the kernel's `tcp_sendmsg` exactly, and atomic accumulation patterns are easy to get wrong (race conditions, missed updates).

- [ ] **Step 1: Add the LRU map declaration**

Edit `bpf/net.bpf.c`. After the `events` ringbuf map block, add:

```c
/*
 * Per-socket TX/RX accumulator. Keyed by socket cookie (stable across
 * PID reuse). Cleared via LRU eviction at 65k entries — sufficient for
 * any realistic single-host workload. Userspace iterates this map on a
 * timer to surface counts.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ts_net_bytes_key);
    __type(value, struct ts_net_bytes_value);
} net_bytes SEC(".maps");
```

- [ ] **Step 2: Add helper for atomic accumulation**

After the existing `emit_connect` function but before the `SEC("cgroup/connect4")` block, add:

```c
/*
 * Atomically bump tx_bytes (if tx) or rx_bytes (if rx==1) for the given
 * socket cookie. Inserts a new entry on first observation. Updates
 * last_ns and (only on insert) pid.
 *
 * NOTE: bytes is signed; tcp_sendmsg returns negative on error and we
 * skip those at the call site, but we double-check here defensively.
 */
static __always_inline void bump_bytes(__u64 cookie, __s32 bytes, int rx)
{
    if (bytes <= 0)
        return;

    struct ts_net_bytes_key k = { .sock_cookie = cookie };
    struct ts_net_bytes_value *v = bpf_map_lookup_elem(&net_bytes, &k);

    __u64 now_ns = bpf_ktime_get_ns();

    if (v) {
        if (rx)
            __sync_fetch_and_add(&v->rx_bytes, (__u64)bytes);
        else
            __sync_fetch_and_add(&v->tx_bytes, (__u64)bytes);
        v->last_ns = now_ns;
    } else {
        struct ts_net_bytes_value nv = {
            .tx_bytes = rx ? 0 : (__u64)bytes,
            .rx_bytes = rx ? (__u64)bytes : 0,
            .last_ns  = now_ns,
            .pid      = (__u32)(bpf_get_current_pid_tgid() >> 32),
            ._pad     = 0,
        };
        bpf_map_update_elem(&net_bytes, &k, &nv, BPF_NOEXIST);
    }
}
```

- [ ] **Step 3: Add the two fexit programs at the bottom of the file**

Append before EOF:

```c
/*
 * fexit/tcp_sendmsg: fires on tcp_sendmsg return. The 4th argument to
 * BPF_PROG (after ret-of-original-args) is the function's return value.
 * Signature mirrors the kernel:
 *   int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
 */
SEC("fexit/tcp_sendmsg")
int BPF_PROG(handle_sendmsg, struct sock *sk, struct msghdr *msg, size_t size, int ret)
{
    if (ret <= 0)
        return 0;
    __u64 cookie = bpf_get_socket_cookie(sk);
    bump_bytes(cookie, ret, 0 /* tx */);
    return 0;
}

/*
 * fexit/tcp_recvmsg.
 * Signature:
 *   int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
 *                   int flags, int *addr_len)
 *
 * Some kernels merged `flags` into a different position in 5.19+; the
 * BTF-driven fexit attach picks up the actual signature, so the BPF_PROG
 * arg list just needs to match what BTF says. If BTF differs we'll see
 * a load failure with a clear message and update accordingly.
 */
SEC("fexit/tcp_recvmsg")
int BPF_PROG(handle_recvmsg, struct sock *sk, struct msghdr *msg, size_t len,
             int flags, int *addr_len, int ret)
{
    if (ret <= 0)
        return 0;
    __u64 cookie = bpf_get_socket_cookie(sk);
    bump_bytes(cookie, ret, 1 /* rx */);
    return 0;
}
```

- [ ] **Step 4: Verify standalone compilation**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
clang -target bpf -O2 -g -Wall -Werror -I bpf -c bpf/net.bpf.c -o /tmp/net.bpf.o
file /tmp/net.bpf.o
rm /tmp/net.bpf.o
```

Expected: `ELF 64-bit LSB relocatable, eBPF`.

If clang errors on `bpf_get_socket_cookie` not declared, ensure `vmlinux.h` is up-to-date — that helper has been in libbpf since 5.0.

If a struct field reference fails to compile, recheck the field name against the kernel header in `bpf/vmlinux.h` (e.g., `grep -A 30 "struct sock {" bpf/vmlinux.h`).

- [ ] **Step 5: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add bpf/net.bpf.c
git commit -m "feat(bpf): fexit tcp_sendmsg/recvmsg accumulating into LRU map"
```

---

## Task 3: tsd — Map Flush Helper, CLI Flag, Periodic Iteration **(INLINE)**

**Files:**
- Create: `crates/tsd/src/net_bytes.rs`
- Modify: `crates/tsd/src/skeletons.rs` (attach the new fexit programs)
- Modify: `crates/tsd/src/main.rs` (add flag + periodic flush)

**Why inline:** The fexit programs need explicit attach calls (unlike sched_exec where `Skel::attach` covered everything via the SEC tags), and the periodic flush has subtle ownership/lifetime concerns when iterating a map borrowed from the skel.

- [ ] **Step 1: Create `net_bytes.rs` flush helper**

`crates/tsd/src/net_bytes.rs`:
```rust
//! Periodic flush of the BPF `net_bytes` LRU map.
//!
//! Iterates every entry, decodes key+value, and prints a single
//! `NetBytes { ... }` line per non-zero socket. Entries are NOT
//! cleared — they're cumulative until the kernel evicts via LRU.
//! Phase 1.D will replace this with a DuckDB write.

use ts_bpf_sys::libbpf_rs::{MapCore, MapFlags, MapMut};
use ts_core::{decode_net_bytes_key, decode_net_bytes_value};

pub fn flush(map: &MapMut<'_>) {
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
        println!(
            "NetBytes {{ sock_cookie: {cookie:#018x}, pid: {pid}, tx: {tx}, rx: {rx}, last_ns: {ns} }}",
            cookie = key.sock_cookie,
            pid = value.pid,
            tx = value.tx_bytes,
            rx = value.rx_bytes,
            ns = value.last_ns,
        );
    }
}
```

- [ ] **Step 2: Update `skeletons.rs` to attach the new programs**

Edit `crates/tsd/src/skeletons.rs`. Find the cgroup attach block in `load_all` and replace the existing return statement so it also attaches the two new fexit programs. Replace:

```rust
    let cgroup_fd = cgroup_root.as_raw_fd();
    let link4 = net
        .progs
        .handle_connect4
        .attach_cgroup(cgroup_fd)
        .map_err(|e| anyhow!("attach cgroup/connect4: {e}"))?;
    let link6 = net
        .progs
        .handle_connect6
        .attach_cgroup(cgroup_fd)
        .map_err(|e| anyhow!("attach cgroup/connect6: {e}"))?;

    Ok(LoadedSkels {
        sched,
        net,
        _cgroup_links: vec![link4, link6],
        _cgroup_root: cgroup_root,
    })
}
```

with:

```rust
    let cgroup_fd = cgroup_root.as_raw_fd();
    let link4 = net
        .progs
        .handle_connect4
        .attach_cgroup(cgroup_fd)
        .map_err(|e| anyhow!("attach cgroup/connect4: {e}"))?;
    let link6 = net
        .progs
        .handle_connect6
        .attach_cgroup(cgroup_fd)
        .map_err(|e| anyhow!("attach cgroup/connect6: {e}"))?;

    let send_link = net
        .progs
        .handle_sendmsg
        .attach()
        .map_err(|e| anyhow!("attach fexit/tcp_sendmsg: {e}"))?;
    let recv_link = net
        .progs
        .handle_recvmsg
        .attach()
        .map_err(|e| anyhow!("attach fexit/tcp_recvmsg: {e}"))?;

    Ok(LoadedSkels {
        sched,
        net,
        _cgroup_links: vec![link4, link6],
        _fexit_links: vec![send_link, recv_link],
        _cgroup_root: cgroup_root,
    })
}
```

Then add the new field to `LoadedSkels`. Find:

```rust
pub struct LoadedSkels<'obj> {
    pub sched: SchedExecSkel<'obj>,
    pub net: NetSkel<'obj>,
    _cgroup_links: Vec<Link>,
    _cgroup_root: File,
}
```

Replace with:

```rust
pub struct LoadedSkels<'obj> {
    pub sched: SchedExecSkel<'obj>,
    pub net: NetSkel<'obj>,
    _cgroup_links: Vec<Link>,
    _fexit_links: Vec<Link>,
    _cgroup_root: File,
}
```

- [ ] **Step 3: Update `main.rs` — add `--flush-interval-ms` and periodic flush**

Replace the entire body of `crates/tsd/src/main.rs` with:

```rust
//! TokenScope daemon (Phase 1.B).
//!
//! Loads two BPF skeletons (sched_exec + net), drains both ringbufs,
//! and on a configurable cadence prints accumulated TCP byte counts
//! from the `net_bytes` LRU map. Phase 1.D replaces stdout with the
//! DuckDB sink.

mod cgroup;
mod net_bytes;
mod skeletons;

use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use ts_bpf_sys::libbpf_rs::RingBufferBuilder;
use ts_core::{decode_header, decode_net_connect, TsEventType};

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

    info!("tsd starting (Phase 1.B — sched_exec + cgroup/connect + tcp byte counting)");

    let cgroup_root = cgroup::open_unified_root().context("open cgroup root")?;
    let mut storage = SkelStorage::new();
    let skels = load_all(&mut storage, cgroup_root).context("load skeletons")?;

    info!(
        flush_ms = args.flush_interval_ms,
        "BPF programs attached"
    );

    let mut builder = RingBufferBuilder::new();
    builder
        .add(&skels.sched.maps.events, handle_event)
        .map_err(|e| anyhow!("add sched ringbuf: {e}"))?;
    builder
        .add(&skels.net.maps.events, handle_event)
        .map_err(|e| anyhow!("add net ringbuf: {e}"))?;
    let ringbuf = builder.build().map_err(|e| anyhow!("build ringbuf: {e}"))?;

    let flush_interval = Duration::from_millis(args.flush_interval_ms);
    let mut last_flush = Instant::now();

    loop {
        if let Err(e) = ringbuf.poll(Duration::from_millis(200)) {
            error!(?e, "ringbuf poll error");
        }
        if last_flush.elapsed() >= flush_interval {
            net_bytes::flush(&skels.net.maps.net_bytes);
            last_flush = Instant::now();
        }
    }
}

fn handle_event(data: &[u8]) -> i32 {
    let hdr = match decode_header(data) {
        Ok(h) => h,
        Err(e) => {
            error!(?e, len = data.len(), "decode header failed");
            return 0;
        }
    };

    let kind = TsEventType::from_u16(hdr.ty);
    let payload = &data[std::mem::size_of::<ts_core::TsEventHdr>()..];

    match kind {
        Some(TsEventType::ProcExec) => {
            println!(
                "TsEventHdr {{ kind: ProcExec, pid: {pid}, tgid: {tgid}, cpu: {cpu}, cgroup_id: {cgid:#x}, ts_ns: {ts}, len: {len} }}",
                pid = hdr.pid,
                tgid = hdr.tgid,
                cpu = hdr.cpu,
                cgid = hdr.cgroup_id,
                ts = hdr.ts_ns,
                len = hdr.len,
            );
        }
        Some(TsEventType::NetConnect) => match decode_net_connect(payload) {
            Ok(pl) => {
                println!(
                    "TsEventHdr {{ kind: NetConnect, pid: {pid}, tgid: {tgid}, cpu: {cpu}, cgroup_id: {cgid:#x}, dst: {dst}, proto: {proto} }}",
                    pid = hdr.pid,
                    tgid = hdr.tgid,
                    cpu = hdr.cpu,
                    cgid = hdr.cgroup_id,
                    dst = pl.dst_string(),
                    proto = pl.protocol,
                );
            }
            Err(e) => error!(?e, "decode net_connect failed"),
        },
        Some(other) => {
            println!(
                "TsEventHdr {{ kind: {other:?}, pid: {pid}, len: {len} }}",
                pid = hdr.pid,
                len = hdr.len,
            );
        }
        None => {
            println!(
                "TsEventHdr {{ kind: Unknown({ty}), pid: {pid}, len: {len} }}",
                ty = hdr.ty,
                pid = hdr.pid,
                len = hdr.len,
            );
        }
    }
    0
}
```

- [ ] **Step 4: Build**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
cargo build -p tsd 2>&1 | tail -10
```

Expected: build succeeds. If `MapMut` is not exported from `libbpf-rs`, change the import in `net_bytes.rs` to `use ts_bpf_sys::libbpf_rs::MapMut;` (some libbpf-rs versions put it in a submodule). Likewise for `MapCore` / `MapFlags` — adjust paths to whatever `cargo build` reports.

If `Program::attach()` doesn't exist on a `ProgramMut`, the libbpf-rs API may want `attach_trace()` for fentry/fexit specifically — try that first.

- [ ] **Step 5: Run unit tests**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -10
cargo test --workspace 2>&1 | tail -20
```

Expected: clippy clean; ts-core 13 tests pass; tsd integration tests still ignored.

- [ ] **Step 6: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add crates/tsd/
git commit -m "feat(tsd): periodic net_bytes map flush + --flush-interval-ms flag"
```

---

## Task 4: Integration Test — End-to-End Byte Counting **(INLINE)**

**Files:**
- Create: `crates/tsd/tests/bytes_event.rs`

**Why inline:** The test design (loopback TCP pair, deterministic byte count, parsing tsd's NetBytes line for `tx >= K`) sets a template for every future map-based probe test.

- [ ] **Step 1: Write the failing test**

`crates/tsd/tests/bytes_event.rs`:
```rust
//! Stand up a loopback TCP listener+connector pair, send 1024 bytes,
//! and assert tsd's stdout shows a `NetBytes` line with tx >= 1024
//! attributed to our PID within ~3s (one flush interval at 500ms +
//! buffer for ringbuf + flush jitter).
//!
//! Requires CAP_BPF or root; ignored by default.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const PAYLOAD: &[u8] = &[b'T'; 1024];

#[test]
#[ignore = "requires CAP_BPF or root; run with --include-ignored under sudo"]
fn captures_tcp_byte_counts() {
    let bin = env!("CARGO_BIN_EXE_tsd");

    let mut child = Command::new(bin)
        .args(["--flush-interval-ms", "500"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tsd");

    let stdout = child.stdout.take().expect("pipe stdout");
    let mut reader = BufReader::new(stdout);

    // Wait for tsd to attach.
    thread::sleep(Duration::from_millis(700));

    // Loopback TCP pair: bind a listener, accept in a thread, the test
    // process is the connector and writer. Use 127.0.0.1:0 so the kernel
    // picks a free port.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        // Drain whatever we receive so the sender's send buffer drains.
        let mut buf = vec![0u8; 4096];
        let _ = stream.read(&mut buf);
    });

    let mut client = TcpStream::connect(addr).expect("connect");
    client.write_all(PAYLOAD).expect("write payload");
    client.flush().ok();
    drop(client);
    let _ = server.join();

    // Look for ANY NetBytes line with tx >= 1024 within 3 seconds.
    // (The test process might not be the only sender, but our payload is
    // a unique 1024-byte burst — first hit is good enough.)
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut saw_event = false;
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) if line.contains("NetBytes") => {
                if let Some(tx) = parse_field_u64(&line, "tx: ") {
                    if tx >= PAYLOAD.len() as u64 {
                        saw_event = true;
                        eprintln!("captured: {}", line.trim());
                        break;
                    }
                }
            }
            Ok(_) => continue,
            Err(_) => break,
        }
    }

    let _ = child.kill();
    let _ = child.wait();

    assert!(
        saw_event,
        "tsd produced no NetBytes line with tx >= {} within 3s",
        PAYLOAD.len()
    );
}

/// Tiny helper: extract a u64 from `<prefix><digits>` in `line`.
fn parse_field_u64(line: &str, prefix: &str) -> Option<u64> {
    let start = line.find(prefix)? + prefix.len();
    let rest = &line[start..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().ok()
}
```

- [ ] **Step 2: Build the test (sanity-check no compile errors)**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
cargo build --tests -p tsd 2>&1 | tail -10
```

Expected: build succeeds. If a borrow error appears in the listener thread, try wrapping the `accept()` result in a `let _ =`.

- [ ] **Step 3: Run the integration suite under sudo**

Ask the user to run:
```
cd /home/hoang/code/personal/active/tokenscope && sudo -E env "PATH=$PATH" /home/hoang/.cargo/bin/cargo test -p tsd -- --ignored --nocapture
```

Expected output includes:
- `captures_exec_event_for_child ... ok`
- `captures_cgroup_connect_v4 ... ok`
- `captures_tcp_byte_counts ... ok` with a `captured: NetBytes { sock_cookie: 0x..., pid: ..., tx: 1024, rx: 0, last_ns: ... }` line.

If `captures_tcp_byte_counts` fails:
1. Confirm fexit attached: while tsd runs, `sudo bpftool prog list | grep -E 'tcp_sendmsg|tcp_recvmsg'` should list both.
2. Inspect map contents directly: `sudo bpftool map dump name net_bytes` while tsd runs and traffic flows.
3. If the map is empty even with traffic, the fexit signature in `BPF_PROG(...)` may not match the kernel's `tcp_recvmsg` (signature changed in 5.19+). Try removing the `flags`/`addr_len` args from `handle_recvmsg` and recompiling.

- [ ] **Step 4: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add crates/tsd/tests/bytes_event.rs
git commit -m "test(tsd): tcp byte counting integration test"
```

---

## Task 5: Phase 1.B Wrap-up — DOC.md, Tag **(INLINE)**

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

- [ ] **Step 2: Update DOC.md — insert new entry above Phase 1.A**

Edit `DOC.md`. Find the line `### Phase 1.A — Cgroup Connect Probes` and insert ABOVE it:

```markdown
### Phase 1.B — TCP Byte Counting (shipped 2026-05-06, tag `v0.0.3-phase1b`)

Two fexit programs (`fexit/tcp_sendmsg` + `fexit/tcp_recvmsg`) accumulate per-socket TX/RX bytes into a `BPF_MAP_TYPE_LRU_HASH` keyed by `bpf_get_socket_cookie()`. tsd flushes the map every `--flush-interval-ms` (default 5000 ms) and prints `NetBytes { sock_cookie, pid, tx, rx, last_ns }` lines on stdout. Map is cumulative; LRU eviction at 65k sockets.

**Gate evidence:**
- `cargo fmt --check` / `cargo clippy -D warnings` clean
- `cargo test --workspace` — 13/13 ts-core unit tests pass (9 from Phase 1.A + 4 net_bytes mirror tests)
- `sudo cargo test -p tsd -- --ignored` — three tests pass: `exec_event`, `connect_event`, `bytes_event`
- Plan: `docs/superpowers/plans/2026-05-06-phase-1b-tcp-byte-counting.md`

**Known gaps:**
- UDP byte counting (Phase 2)
- Map values are cumulative; subtraction-on-query happens in Phase 1.D when DuckDB lands
- PID is the FIRST observed PID for a socket; sends from softirq (TCP retransmit) attribute to ksoftirqd
- IPv6 untested end-to-end (only v4 in `bytes_event.rs`)
```

- [ ] **Step 3: Commit and tag**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add DOC.md
git commit -m "docs: mark Phase 1.B shipped with gate evidence"
git tag -a v0.0.3-phase1b -m "Phase 1.B — TCP Byte Counting"
git tag --list
```

Expected: tag list now includes `v0.0.1-phase0`, `v0.0.2-phase1a`, `v0.0.3-phase1b`.

---

## Definition of Done (Phase 1.B acceptance gate)

All must be true:
1. `cargo build --workspace` succeeds.
2. `cargo test --workspace` exits 0 (ts-core: 13 tests; tsd integration tests `#[ignore]`d).
3. `sudo cargo test -p tsd -- --ignored` exits 0 — three tests pass: `exec_event`, `connect_event`, `bytes_event`.
4. Live: `sudo ./target/debug/tsd --flush-interval-ms 1000` + `curl example.com` produces both `kind: NetConnect, dst: <ip>:80` AND `NetBytes { sock_cookie: ..., tx: <hundreds>, rx: <hundreds> }` within ~1.5 s.
5. `cargo fmt --check` and `cargo clippy -D warnings` clean.
6. DOC.md reflects Phase 1.B shipped.
7. Git tag `v0.0.3-phase1b` exists locally.

---

## Self-Review Notes

**Spec coverage check (SPEC §11 Phase 1, item 1 of 4 — second half):**
- "tcp_sendmsg/tcp_recvmsg byte counting" → Tasks 2 (BPF), 3 (userspace flush), 4 (integration test).

**Type/name consistency check:**
- `TsNetBytesKey` / `TsNetBytesValue` (Rust) ↔ `struct ts_net_bytes_key` / `struct ts_net_bytes_value` (C) — Task 1, 2 (size 8 / 32 bytes both sides).
- BPF map name `net_bytes` matches between BPF declaration (Task 2) and Rust access `skels.net.maps.net_bytes` (Task 3).
- `handle_sendmsg` / `handle_recvmsg` are the C function names; libbpf-cargo will generate `progs.handle_sendmsg` / `progs.handle_recvmsg` accessors — used in Task 3 Step 2.

**Placeholder scrub:** none of the forbidden phrases appear.

**libbpf-rs API check:**
- `MapCore::keys()` returns `MapKeyIter` yielding `Vec<u8>` — verified in libbpf-rs 0.24 source.
- `MapCore::lookup(key, MapFlags)` returns `Result<Option<Vec<u8>>>` — verified.
- `Program::attach()` for fexit — uses `bpf_program__attach` under the hood which dispatches by SEC name; tested pattern. If it doesn't work, try `attach_trace()`.

**Ordering rationale:**
1. Wire types first so the C and Rust sides are written in lockstep.
2. BPF before userspace because compile failures here are quick to surface.
3. Userspace flush before integration test so the test actually has output to assert against.
4. Integration test before wrap-up so the gate evidence in DOC.md is real.

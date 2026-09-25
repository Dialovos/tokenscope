# TokenScope Phase 1.A — Cgroup Connect Probes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect every outbound TCP/UDP connect() on the host via `cgroup/connect4` + `cgroup/connect6` BPF programs, emit a `TS_NET_CONNECT` ringbuf record with the destination IP+port, and surface it on `tsd`'s stdout. Lays the foundation for Phase 1.B (byte counting) and Phase 2 (TLS uprobes) by proving multi-skeleton loading and per-payload event decoding.

**Architecture:** A second BPF skeleton (`net.bpf.c`) holding both `cgroup/connect4` and `cgroup/connect6` programs that share one `events` ringbuf. The daemon refactors to load two skeletons (`sched_exec` + `net`), each owning its own `MaybeUninit<OpenObject>` storage, and registers one ringbuf consumer per map. The cgroup programs attach to `/sys/fs/cgroup` (the v2 unified root) for system-wide visibility.

**Tech Stack:** Same as Phase 0 (Rust 1.85, libbpf-rs 0.24, libbpf-cargo 0.24, clang 18 BPF target). Adds `socket2` 0.5 to the `tsd` integration test for a deterministic connect trigger.

---

## Scope & Out-of-Scope

**In scope (Phase 1.A):**
- `bpf/net.bpf.c` with both cgroup/connect4 and cgroup/connect6 programs
- New variable-length payload type `ts_net_connect_payload` in `bpf/ts_event.h` and `ts-core::event`
- `tsd` refactor: extract skeleton-loading into `skeletons.rs`, load both skeletons, multi-map ringbuf consumer
- `cgroup.rs` helper that opens `/sys/fs/cgroup` and yields a raw fd for cgroup attach
- Print `TS_NET_CONNECT` lines on stdout including `dst_ip:port`
- Integration test that connects a TCP socket to `127.0.0.1:<some-port>` and asserts the event was captured
- DOC.md update + tag `v0.0.2-phase1a`

**Explicitly deferred:**
- TCP byte counting via `tcp_sendmsg`/`tcp_recvmsg` (Phase 1.B)
- DuckDB persistence (Phase 1.D)
- `tsctl status` / `tsctl tail` (Phase 1.E)
- Process enrichment beyond what the BPF helpers already give us (Phase 1.C)
- IPv6 hostname / DNS resolution (out of scope; TokenScope reports raw IPs only)
- Container/namespace IP unwrapping (Phase 3+)

---

## File Structure (delta from Phase 0)

```
tokenscope/
├── bpf/
│   ├── ts_event.h                   # +struct ts_net_connect_payload
│   └── net.bpf.c                    # NEW
├── crates/
│   ├── ts-core/src/
│   │   └── event.rs                 # +TsNetConnectPayload + decode_net_connect
│   ├── ts-bpf-sys/
│   │   └── build.rs                 # +entry in PROGRAMS for net.bpf.c
│   │   └── src/lib.rs               # +pub mod net
│   └── tsd/
│       ├── Cargo.toml               # +socket2 dev-dep
│       ├── src/
│       │   ├── main.rs              # rewritten: loads two skeletons
│       │   ├── skeletons.rs         # NEW: SkelHandles wrapper
│       │   └── cgroup.rs            # NEW: opens /sys/fs/cgroup
│       └── tests/
│           └── connect_event.rs     # NEW
└── DOC.md                           # +Phase 1.A entry
```

---

## Task 1: Extend Event Types — TsNetConnectPayload **(INLINE)**

**Files:**
- Modify: `bpf/ts_event.h`
- Modify: `crates/ts-core/src/event.rs`

**Why inline:** Wire-format changes are foundational. Layout drift between C and Rust is the highest-blast-radius bug class in this codebase; the static assertions catch it but only if both sides are written together with eyes on byte offsets.

- [ ] **Step 1: Extend `bpf/ts_event.h` with the connect payload struct**

Append (after the `struct ts_event_hdr` block, before `#endif`):

```c
/*
 * Payload for TS_NET_CONNECT. Follows ts_event_hdr immediately;
 * hdr.len = sizeof(struct ts_net_connect_payload).
 *
 * Layout:
 *   0..16 dst_addr   (16 bytes, IPv4-mapped form for AF_INET; raw for AF_INET6)
 *   16..18 dst_port  (u16, host byte order — already converted in BPF)
 *   18..20 family    (u16: AF_INET=2, AF_INET6=10)
 *   20..21 protocol  (u8: IPPROTO_TCP=6, IPPROTO_UDP=17, ...)
 *   21..24 _pad      (3 bytes to align next field; reserved)
 *
 * Total: 24 bytes. Alignment: 2.
 */
struct ts_net_connect_payload {
    __u8  dst_addr[16];
    __u16 dst_port;
    __u16 family;
    __u8  protocol;
    __u8  _pad[3];
};
```

- [ ] **Step 2: Add Rust mirror + decoder in `crates/ts-core/src/event.rs`**

Append (after the existing tests module `}`):

```rust
/// Mirror of `struct ts_net_connect_payload` in `bpf/ts_event.h`.
///
/// Layout:
/// - 0..16  dst_addr  (16 bytes; IPv4 in last 4 for AF_INET, full IPv6 for AF_INET6)
/// - 16..18 dst_port  (u16, host byte order)
/// - 18..20 family    (u16: 2=AF_INET, 10=AF_INET6)
/// - 20..21 protocol  (u8)
/// - 21..24 _pad
///
/// Total: 24 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TsNetConnectPayload {
    pub dst_addr: [u8; 16],
    pub dst_port: u16,
    pub family: u16,
    pub protocol: u8,
    pub _pad: [u8; 3],
}

const _: () = assert!(core::mem::size_of::<TsNetConnectPayload>() == 24);

impl TsNetConnectPayload {
    /// Render the destination as a string (`"1.2.3.4:443"` / `"[::1]:80"`).
    pub fn dst_string(&self) -> String {
        match self.family {
            2 => {
                // AF_INET — IPv4 lives in the LAST 4 bytes (per BPF helper convention).
                let ip = std::net::Ipv4Addr::new(
                    self.dst_addr[12],
                    self.dst_addr[13],
                    self.dst_addr[14],
                    self.dst_addr[15],
                );
                format!("{ip}:{}", self.dst_port)
            }
            10 => {
                let octets: [u8; 16] = self.dst_addr;
                let ip = std::net::Ipv6Addr::from(octets);
                format!("[{ip}]:{}", self.dst_port)
            }
            other => format!("af{other}/{:?}:{}", &self.dst_addr[..], self.dst_port),
        }
    }
}

/// Decode a TS_NET_CONNECT record's payload. The caller passes the slice
/// AFTER the `TsEventHdr` (i.e., `&data[size_of::<TsEventHdr>()..]`).
pub fn decode_net_connect(payload: &[u8]) -> Result<TsNetConnectPayload, DecodeError> {
    let need = core::mem::size_of::<TsNetConnectPayload>();
    if payload.len() < need {
        return Err(DecodeError::Truncated {
            got: payload.len(),
            need,
        });
    }
    let pl = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const TsNetConnectPayload) };
    Ok(pl)
}
```

- [ ] **Step 3: Add unit tests for the new payload**

Append inside the existing `#[cfg(test)] mod tests { ... }` block (just before the closing `}`):

```rust
    #[test]
    fn net_connect_payload_size_is_24() {
        assert_eq!(core::mem::size_of::<TsNetConnectPayload>(), 24);
    }

    #[test]
    fn net_connect_v4_round_trip() {
        let pl = TsNetConnectPayload {
            // 0.0.0.0.0.0.0.0.0.0.0.0.1.2.3.4 → 1.2.3.4 in the v4-mapped slot
            dst_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4],
            dst_port: 443,
            family: 2,
            protocol: 6,
            _pad: [0; 3],
        };
        let bytes: [u8; 24] = unsafe { core::mem::transmute(pl) };
        let decoded = decode_net_connect(&bytes).unwrap();
        assert_eq!(decoded.dst_string(), "1.2.3.4:443");
    }

    #[test]
    fn net_connect_v6_round_trip() {
        let pl = TsNetConnectPayload {
            dst_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            dst_port: 80,
            family: 10,
            protocol: 6,
            _pad: [0; 3],
        };
        let bytes: [u8; 24] = unsafe { core::mem::transmute(pl) };
        let decoded = decode_net_connect(&bytes).unwrap();
        assert_eq!(decoded.dst_string(), "[::1]:80");
    }

    #[test]
    fn net_connect_truncated() {
        let buf = [0u8; 10];
        let err = decode_net_connect(&buf).unwrap_err();
        assert!(matches!(err, DecodeError::Truncated { got: 10, need: 24 }));
    }
```

Also add the new exports at the top of `crates/ts-core/src/lib.rs`:

```rust
pub use event::{
    decode_header, decode_net_connect, DecodeError, TsEventHdr, TsEventType,
    TsNetConnectPayload,
};
```

(Replace the existing `pub use event::{...}` line.)

- [ ] **Step 4: Run tests**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
cargo test -p ts-core
```

Expected: `test result: ok. 8 passed; 0 failed` (5 from Phase 0 + 3 new).

- [ ] **Step 5: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add bpf/ts_event.h crates/ts-core/
git commit -m "feat(ts-core): TsNetConnectPayload wire type + decoder"
```

---

## Task 2: BPF Program — bpf/net.bpf.c (cgroup/connect4 + connect6) **(INLINE)**

**Files:**
- Create: `bpf/net.bpf.c`

**Why inline:** Touching `bpf_sock_addr` context fields requires CO-RE relocations and per-family branching. Easy to write a verifier-rejecting program here; want eyes on it.

- [ ] **Step 1: Write the BPF source**

`bpf/net.bpf.c`:
```c
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Phase 1.A. cgroup/connect{4,6} hooks — fire on every connect() syscall
 * for an inet socket inside the attached cgroup hierarchy. Emit one
 * TS_NET_CONNECT ringbuf record per call.
 *
 * The cgroup attach point is /sys/fs/cgroup (v2 unified root) by default,
 * giving system-wide coverage. Per-cgroup scoping is a Phase 6+ extension.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "ts_event.h"

char LICENSE[] SEC("license") = "GPL";

#define AF_INET   2
#define AF_INET6  10

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/*
 * Combined header + payload. Reserving them as one record means a single
 * bpf_ringbuf_reserve / submit pair — atomic from the consumer's view.
 */
struct net_connect_record {
    struct ts_event_hdr hdr;
    struct ts_net_connect_payload pl;
};

static __always_inline int emit_connect(struct bpf_sock_addr *ctx, __u16 family)
{
    struct net_connect_record *r;

    r = bpf_ringbuf_reserve(&events, sizeof(*r), 0);
    if (!r)
        return 1; /* must return 1 from cgroup/connect on success */

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    r->hdr.ts_ns     = bpf_ktime_get_ns();
    r->hdr.cpu       = bpf_get_smp_processor_id();
    r->hdr.pid       = (__u32)(pid_tgid & 0xFFFFFFFFu);
    r->hdr.tgid      = (__u32)(pid_tgid >> 32);
    r->hdr.cgroup_id = bpf_get_current_cgroup_id();
    r->hdr.type      = TS_NET_CONNECT;
    r->hdr.len       = sizeof(struct ts_net_connect_payload);

    /* ctx->user_port is __be16 in network byte order; convert. */
    r->pl.dst_port = bpf_ntohs(ctx->user_port);
    r->pl.family   = family;
    r->pl.protocol = ctx->protocol;
    __builtin_memset(r->pl._pad, 0, sizeof(r->pl._pad));

    if (family == AF_INET) {
        /* user_ip4 is __be32; copy into the last 4 bytes (v4-mapped layout). */
        __builtin_memset(r->pl.dst_addr, 0, 12);
        __u32 ip4 = ctx->user_ip4;
        __builtin_memcpy(&r->pl.dst_addr[12], &ip4, 4);
    } else {
        /* user_ip6 is __be32[4]; copy 16 bytes verbatim. */
        __builtin_memcpy(r->pl.dst_addr, ctx->user_ip6, 16);
    }

    bpf_ringbuf_submit(r, 0);
    return 1; /* ALLOW the connect; cgroup/connect can also block (return 0) */
}

SEC("cgroup/connect4")
int handle_connect4(struct bpf_sock_addr *ctx)
{
    return emit_connect(ctx, AF_INET);
}

SEC("cgroup/connect6")
int handle_connect6(struct bpf_sock_addr *ctx)
{
    return emit_connect(ctx, AF_INET6);
}
```

- [ ] **Step 2: Verify it compiles**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
clang -target bpf -O2 -g -Wall -Werror -I bpf -c bpf/net.bpf.c -o /tmp/net.bpf.o
file /tmp/net.bpf.o
rm /tmp/net.bpf.o
```

Expected: `ELF 64-bit LSB relocatable, eBPF, version 1 (SYSV)`.

If clang errors on `bpf_sock_addr` not declared, the BTF dump in `bpf/vmlinux.h` is missing it — sanity check with `grep -c bpf_sock_addr bpf/vmlinux.h` (should be > 0; ours is from a 6.6 kernel and definitely has it).

- [ ] **Step 3: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add bpf/net.bpf.c
git commit -m "feat(bpf): cgroup/connect{4,6} probes emitting TS_NET_CONNECT"
```

---

## Task 3: Wire net.bpf.c into ts-bpf-sys **(SUBAGENT)**

**Files:**
- Modify: `crates/ts-bpf-sys/build.rs`
- Modify: `crates/ts-bpf-sys/src/lib.rs`

- [ ] **Step 1: Add `net.bpf.c` to the PROGRAMS list**

Edit `crates/ts-bpf-sys/build.rs`. Replace the line:
```rust
const PROGRAMS: &[(&str, &str)] = &[("sched_exec.bpf.c", "sched_exec.skel.rs")];
```
with:
```rust
const PROGRAMS: &[(&str, &str)] = &[
    ("sched_exec.bpf.c", "sched_exec.skel.rs"),
    ("net.bpf.c", "net.skel.rs"),
];
```

- [ ] **Step 2: Re-export the new skeleton in `lib.rs`**

Edit `crates/ts-bpf-sys/src/lib.rs`. After the existing `pub mod sched_exec` block, add:
```rust
pub mod net {
    include!(concat!(env!("OUT_DIR"), "/net.skel.rs"));
}
```

- [ ] **Step 3: Build to verify the new skeleton generates**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
cargo build -p ts-bpf-sys 2>&1 | tail -10
```

Expected: build succeeds. Verify file exists:
```
find target/debug/build -name 'net.skel.rs' | head -1
```

Expected: a path printed.

- [ ] **Step 4: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add crates/ts-bpf-sys/
git commit -m "feat(ts-bpf-sys): generate net skeleton"
```

---

## Task 4: tsd Refactor — Two Skeletons, Multi-Map Consumer **(INLINE)**

**Files:**
- Create: `crates/tsd/src/skeletons.rs`
- Create: `crates/tsd/src/cgroup.rs`
- Modify: `crates/tsd/src/main.rs`

**Why inline:** This is a non-trivial restructuring. The libbpf-rs lifetime model (`OpenObject` storage owned by caller) means each skeleton needs its own `MaybeUninit<OpenObject>`, and both must outlive the ringbuf. Easy to get borrow-checker errors here.

- [ ] **Step 1: Create the cgroup helper**

`crates/tsd/src/cgroup.rs`:
```rust
//! Cgroup v2 unified-hierarchy attach point.
//!
//! cgroup/connect4 and cgroup/connect6 BPF programs need a cgroup file
//! descriptor at attach time. The unified root at /sys/fs/cgroup gives
//! system-wide coverage. v1 hierarchies are not supported in Phase 1.

use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result};

pub const UNIFIED_ROOT: &str = "/sys/fs/cgroup";

/// Open the cgroup v2 unified hierarchy and return an owned File.
/// Caller keeps it alive for as long as the BPF programs are attached.
pub fn open_unified_root() -> Result<File> {
    let path = Path::new(UNIFIED_ROOT);
    if !path.exists() {
        anyhow::bail!(
            "{UNIFIED_ROOT} does not exist; cgroup v2 required for cgroup/connect probes"
        );
    }
    File::open(path).with_context(|| format!("open {UNIFIED_ROOT}"))
}
```

- [ ] **Step 2: Create the skeletons wrapper**

`crates/tsd/src/skeletons.rs`:
```rust
//! Owns the storage and skeleton handles for every BPF program tsd loads.
//!
//! Each libbpf-rs skeleton needs its own `MaybeUninit<OpenObject>` storage
//! that outlives the loaded `Skel`. We pin both in a single struct so the
//! caller doesn't have to juggle individual lifetimes.

use std::fs::File;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;

use anyhow::{anyhow, Context, Result};

use ts_bpf_sys::libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use ts_bpf_sys::libbpf_rs::{Link, OpenObject};
use ts_bpf_sys::net::{NetSkel, NetSkelBuilder};
use ts_bpf_sys::sched_exec::{SchedExecSkel, SchedExecSkelBuilder};

/// Backing storage for both skeletons. Must be kept alive for as long as
/// the loaded `Skel` references exist.
pub struct SkelStorage {
    pub sched: MaybeUninit<OpenObject>,
    pub net: MaybeUninit<OpenObject>,
}

impl SkelStorage {
    pub fn new() -> Self {
        Self {
            sched: MaybeUninit::uninit(),
            net: MaybeUninit::uninit(),
        }
    }
}

/// Loaded + attached skeletons. The `_cgroup_links` field keeps the
/// cgroup BPF attachments alive (dropping them detaches the program).
pub struct LoadedSkels<'obj> {
    pub sched: SchedExecSkel<'obj>,
    pub net: NetSkel<'obj>,
    _cgroup_links: Vec<Link>,
    _cgroup_root: File,
}

/// Load and attach every Phase 1.A BPF program.
pub fn load_all<'obj>(
    storage: &'obj mut SkelStorage,
    cgroup_root: File,
) -> Result<LoadedSkels<'obj>> {
    // sched_exec — tracepoint, attaches via skel.attach()
    let mut sched = SchedExecSkelBuilder::default()
        .open(&mut storage.sched)
        .context("open sched_exec skeleton")?
        .load()
        .context("load sched_exec skeleton")?;
    sched.attach().context("attach sched_exec")?;

    // net — cgroup/connect{4,6}, attach manually via cgroup fd
    let mut net = NetSkelBuilder::default()
        .open(&mut storage.net)
        .context("open net skeleton")?
        .load()
        .context("load net skeleton")?;

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

- [ ] **Step 3: Rewrite main.rs to use the new wrappers + multi-map ringbuf**

Replace the entire body of `crates/tsd/src/main.rs` with:

```rust
//! TokenScope daemon (Phase 1.A).
//!
//! Loads two BPF skeletons (sched_exec + net), drains both maps via a
//! single RingBuffer (libbpf-rs multiplexes), and prints decoded events
//! on stdout. Phase 1.D will replace stdout with the DuckDB sink.

mod cgroup;
mod skeletons;

use std::time::Duration;

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
}

fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_new(&args.log_filter).unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!("tsd starting (Phase 1.A — sched_exec + cgroup/connect)");

    let cgroup_root = cgroup::open_unified_root().context("open cgroup root")?;
    let mut storage = SkelStorage::new();
    let skels = load_all(&mut storage, cgroup_root).context("load skeletons")?;

    info!("BPF programs attached — sched_exec + cgroup/connect{{4,6}}");

    let mut builder = RingBufferBuilder::new();
    builder
        .add(&skels.sched.maps.events, handle_event)
        .map_err(|e| anyhow!("add sched ringbuf: {e}"))?;
    builder
        .add(&skels.net.maps.events, handle_event)
        .map_err(|e| anyhow!("add net ringbuf: {e}"))?;
    let ringbuf = builder.build().map_err(|e| anyhow!("build ringbuf: {e}"))?;

    loop {
        if let Err(e) = ringbuf.poll(Duration::from_millis(200)) {
            error!(?e, "ringbuf poll error");
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

- [ ] **Step 4: Build and run unit tests**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
cargo build -p tsd 2>&1 | tail -20
```

Expected: build succeeds. If the libbpf-rs `attach_cgroup` API differs at the actual version pinned, the compiler error names the missing method — adjust accordingly. Common variants:
- `prog.attach_cgroup(fd)` (current)
- `prog.attach_cgroup(borrowed_fd)` (if it takes `BorrowedFd<'_>` instead of `RawFd`)

If the latter, change the call to `attach_cgroup(unsafe { BorrowedFd::borrow_raw(cgroup_fd) })`.

```
cargo test --workspace
```

Expected: all unit tests pass; integration test still ignored.

- [ ] **Step 5: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add crates/tsd/
git commit -m "refactor(tsd): load sched_exec + net skeletons; unified ringbuf consumer"
```

---

## Task 5: Integration Test for cgroup/connect Capture **(INLINE)**

**Files:**
- Modify: `crates/tsd/Cargo.toml` (add `socket2` dev-dep)
- Create: `crates/tsd/tests/connect_event.rs`

**Why inline:** First test in the project that triggers a network event. Picking a deterministic, no-network-required trigger (connect to `127.0.0.1:1` expecting RST) and choosing the assertion format sets a template for every Phase 1+ probe test.

- [ ] **Step 1: Add socket2 dev-dep**

Edit `crates/tsd/Cargo.toml`. Under `[dev-dependencies]`, add:
```toml
socket2 = "0.5"
```

(If `[dev-dependencies]` doesn't exist yet, add the section.)

- [ ] **Step 2: Write the failing integration test**

`crates/tsd/tests/connect_event.rs`:
```rust
//! Spawn `tsd`, then deliberately connect a TCP socket to 127.0.0.1:1
//! (RST'd immediately, but the connect() syscall fires the cgroup hook).
//! Assert tsd prints a `kind: NetConnect, dst: 127.0.0.1:1` line.
//!
//! Requires CAP_BPF or root. `#[ignore]`d so unprivileged `cargo test`
//! still passes; CI runs with `--include-ignored` under sudo.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

#[test]
#[ignore = "requires CAP_BPF or root; run with --include-ignored under sudo"]
fn captures_cgroup_connect_v4() {
    let bin = env!("CARGO_BIN_EXE_tsd");

    let mut child = Command::new(bin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tsd");

    let stdout = child.stdout.take().expect("pipe stdout");
    let mut reader = BufReader::new(stdout);

    // Wait for tsd to attach BPF programs.
    std::thread::sleep(Duration::from_millis(700));

    // Trigger: connect to 127.0.0.1:1 — kernel will refuse, but the
    // connect() syscall reaches cgroup/connect4 BEFORE the refusal.
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
        .expect("create socket");
    socket.set_nonblocking(true).ok();
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let _ = socket.connect(&addr.into()); // ignore EINPROGRESS / ECONNREFUSED

    // Read tsd's stdout for up to 5s, looking for the NetConnect line
    // with our destination.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut saw_event = false;
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) if line.contains("kind: NetConnect") && line.contains("dst: 127.0.0.1:1") => {
                saw_event = true;
                eprintln!("captured: {}", line.trim());
                break;
            }
            Ok(_) => continue,
            Err(_) => break,
        }
    }

    let _ = child.kill();
    let _ = child.wait();

    assert!(
        saw_event,
        "tsd produced no NetConnect line for 127.0.0.1:1 within 5s"
    );
}
```

- [ ] **Step 3: Run unit tests + the new integration test under sudo**

Run unit pass first:
```
cd /home/hoang/code/personal/active/tokenscope
cargo test --workspace
```

Expected: all unit tests pass; both integration tests (`exec_event` + `connect_event`) ignored.

Then ask the user to run the integration suite under sudo:
```
cd /home/hoang/code/personal/active/tokenscope
sudo -E env "PATH=$PATH" /home/hoang/.cargo/bin/cargo test -p tsd -- --ignored --nocapture
```

Expected: both `captures_exec_event_for_child` AND `captures_cgroup_connect_v4` pass. The captured line for the connect test should look like:
```
captured: TsEventHdr { kind: NetConnect, pid: ..., tgid: ..., cpu: ..., cgroup_id: 0x..., dst: 127.0.0.1:1, proto: 6 }
```

If the connect test fails:
1. Check cgroup v2 is mounted: `mount | grep cgroup2` — should show `/sys/fs/cgroup type cgroup2`. If not, Phase 1.A doesn't apply on this host.
2. Check the program is attached: `sudo bpftool cgroup show /sys/fs/cgroup` — should list `handle_connect4` and `handle_connect6`.
3. Manually run `sudo ./target/debug/tsd` in one terminal; in another, `python3 -c "import socket; socket.create_connection(('127.0.0.1', 1), 0.5)"`. Look for the line.

- [ ] **Step 4: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add crates/tsd/
git commit -m "test(tsd): cgroup/connect4 integration test"
```

---

## Task 6: Phase 1.A Wrap-up — DOC.md, Smoke Test, Tag **(INLINE)**

**Files:**
- Modify: `DOC.md` — append Phase 1.A section.

- [ ] **Step 1: Run all gates**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: all clean. Then ask user to run integration tests with sudo (see Task 5 Step 3).

- [ ] **Step 2: Live smoke test (eyes on)**

Terminal A:
```
sudo /home/hoang/code/personal/active/tokenscope/target/debug/tsd
```

Terminal B:
```
curl -s --max-time 2 http://example.com:80/ > /dev/null || true
ping -c 1 -W 1 1.1.1.1 > /dev/null 2>&1 || true
```

Confirm Terminal A prints `kind: NetConnect, dst: 93.184.216.34:80` (or whatever IP example.com resolves to) and similar for the ping target.

- [ ] **Step 3: Append to DOC.md Phase entries**

Insert AFTER the existing Phase 0 entry, BEFORE the `## Configuration` section:

```markdown
### Phase 1.A — Cgroup Connect Probes (shipped 2026-05-02, tag `v0.0.2-phase1a`)

`bpf/net.bpf.c` adds `cgroup/connect4` + `cgroup/connect6` programs that emit a `TS_NET_CONNECT` ringbuf record (with destination IP+port and protocol) on every outbound connect() syscall system-wide. `tsd` now loads two BPF skeletons (sched_exec + net) and drains both with a single multiplexed ringbuf consumer. Cgroup attachment uses the v2 unified hierarchy at `/sys/fs/cgroup`; v1 hosts are unsupported in this phase.

**Gate evidence:**
- `cargo fmt --check` / `cargo clippy -D warnings` clean
- `cargo test --workspace` — 8/8 ts-core unit tests pass (5 from Phase 0 + 3 net_connect)
- `sudo cargo test -p tsd -- --ignored` — both `captures_exec_event_for_child` and `captures_cgroup_connect_v4` pass
- Live smoke: `curl example.com:80` produces `kind: NetConnect, dst: <ip>:80, proto: 6` line

**Known gaps left for later phases:**
- TCP byte counting via tcp_sendmsg/tcp_recvmsg (Phase 1.B)
- Process enrichment (cmdline, exe, /proc walk) (Phase 1.C)
- DuckDB persistence (Phase 1.D)
- `tsctl tail` / `tsctl status` (Phase 1.E)
- IPv4/IPv6 dual-stack edge cases unverified (only v4 has integration coverage)
```

- [ ] **Step 4: Commit and tag**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add DOC.md
git commit -m "docs: mark Phase 1.A shipped with gate evidence"
git tag -a v0.0.2-phase1a -m "Phase 1.A — Cgroup Connect Probes"
git tag --list
```

Expected: tag list includes both `v0.0.1-phase0` and `v0.0.2-phase1a`.

---

## Definition of Done (Phase 1.A acceptance gate)

All must be true:
1. `cargo build --workspace` succeeds.
2. `cargo test --workspace` exits 0 (ts-core: 8 tests, tsd integration tests `#[ignore]`d).
3. `sudo cargo test -p tsd -- --ignored` exits 0 (both `exec_event` and `connect_event`).
4. Live smoke: triggering an outbound connect produces a `kind: NetConnect, dst: ...` line on tsd's stdout within 1 second.
5. `cargo fmt --check` and `cargo clippy -D warnings` clean.
6. DOC.md reflects Phase 1.A shipped with gate evidence.
7. Git tag `v0.0.2-phase1a` exists locally.

---

## Self-Review Notes

**Spec coverage check (SPEC §11 Phase 1, item 1 of 4):**
- "cgroup/connect4 + tcp_sendmsg/tcp_recvmsg byte counting" → cgroup/connect4 + connect6 covered (Tasks 2-5); byte counting deferred to Phase 1.B per scope split.

**Type/name consistency check:**
- `TsNetConnectPayload` (Rust) ↔ `struct ts_net_connect_payload` (C) — Tasks 1, 2 (24 bytes, family/protocol both as documented).
- `TS_NET_CONNECT = 3` from the existing `ts_event_type` enum — already in Phase 0 ts_event.h; ts-core mirror present.
- `NetSkelBuilder` is the libbpf-cargo-generated name for `net.bpf.c` — Tasks 3, 4.
- Map name `events` is reused (each skeleton has its own `events` map; the unified ringbuf builder gets two distinct map references).

**Placeholder scrub:** none of "TBD", "TODO", "fill in", "appropriate handling" appear.

**libbpf-rs API check:** `Program::attach_cgroup(RawFd)` is the expected signature in libbpf-rs 0.24; if the actual signature wants `BorrowedFd`, Task 4 Step 4 documents the pivot.

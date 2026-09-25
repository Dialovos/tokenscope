# TokenScope Phase 0 — Foundations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the TokenScope cargo workspace, the libbpf-rs BPF skeleton build pipeline, and a single end-to-end probe (`sched_process_exec`) that streams events from the kernel to userspace stdout — verified by an integration test and a basic GitHub Actions CI matrix.

**Architecture:** Cargo workspace with five crates (`ts-core`, `ts-bpf-sys`, `tsd`, `tsctl`, `tstop`). BPF programs live in `bpf/*.bpf.c`, compiled by `clang -target bpf` and embedded into Rust binaries via `libbpf-cargo::SkeletonBuilder` invoked from each daemon's `build.rs`. Userspace consumes events from a `BPF_MAP_TYPE_RINGBUF` map. Phase 0 is intentionally minimal: one tracepoint, one event type, stdout sink — Phases 1+ add network probes, TLS uprobes, parsers, exporters.

**Tech Stack:**
- Rust 1.83 (pinned via `rust-toolchain.toml`)
- libbpf-rs 0.24 + libbpf-cargo 0.24 (BPF loader + skeleton generator)
- clang 14+ (BPF target)
- libbpf 1.x (system or vendored)
- bpftool (for skeleton generation, invoked by libbpf-cargo)
- tokio 1.40 (async runtime, future-proofed even though Phase 0 uses sync ringbuf poll)
- tracing 0.1 + tracing-subscriber 0.3 (logging)
- anyhow 1.0 (error handling in binaries)
- thiserror 1.0 (error types in libraries)
- clap 4 (CLI parsing for tsctl/tstop)
- GitHub Actions on `ubuntu-22.04` and `ubuntu-24.04` runners

---

## Scope & Out-of-Scope

**In scope (Phase 0):**
- Repo + workspace scaffolding, .gitignore, LICENSE (Apache-2.0), README, DOC.md
- `ts-core` crate with `TsEventHdr` and `TsEventType` shared types
- `ts-bpf-sys` crate that compiles `bpf/*.bpf.c` and exposes generated skeletons
- `bpf/sched_exec.bpf.c` — single tracepoint program writing to ringbuf
- `tsd` daemon that loads the skeleton, attaches, drains the ringbuf, prints events to stdout
- `tsctl` and `tstop` stub binaries with `--version` only
- BTF fetch script (`vmlinux/fetch-btf.sh`) and a vendored `bpf/vmlinux.h` for the dev box
- GitHub Actions workflow: build + unit tests on Ubuntu 22.04 and 24.04
- Integration test that spawns a child process and asserts `tsd` observes the exec event (root-only, gated by `#[ignore]`)

**Explicitly deferred to later phases:**
- Network/TLS probes (Phases 1-3)
- DuckDB sink (Phase 1)
- Provider parsers (Phase 2)
- TUI (Phase 2)
- Exporters / Prometheus / OTLP (Phase 5)
- vng kernel matrix CI — Phase 0 ships single-kernel CI; full matrix lands in Phase 7
- AppArmor/SELinux profiles, systemd unit, packaging — Phase 7
- `tsd` config file parsing — defaults only in Phase 0
- Provider-specific code, prices.toml — Phase 2

---

## File Structure

```
tokenscope/
├── Cargo.toml                       # workspace root
├── rust-toolchain.toml              # pin to 1.83.0
├── .gitignore
├── README.md
├── LICENSE                          # Apache-2.0
├── DOC.md                           # living project doc per CLAUDE.md
├── .github/
│   └── workflows/
│       └── ci.yml
├── crates/
│   ├── ts-core/                     # shared types + helpers
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       └── event.rs
│   ├── ts-bpf-sys/                  # BPF skeleton compilation
│   │   ├── Cargo.toml
│   │   ├── build.rs
│   │   └── src/
│   │       └── lib.rs               # re-exports skeleton modules
│   ├── tsd/                         # daemon binary
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   └── main.rs
│   │   └── tests/
│   │       └── exec_event.rs        # root-gated integration test
│   ├── tsctl/                       # CLI stub
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── main.rs
│   └── tstop/                       # TUI stub
│       ├── Cargo.toml
│       └── src/
│           └── main.rs
├── bpf/
│   ├── ts_event.h                   # shared event header (C side)
│   ├── sched_exec.bpf.c             # the Phase 0 probe
│   └── vmlinux.h                    # vendored BTF header (gitignored on size? — checked in)
└── vmlinux/
    └── fetch-btf.sh                 # BTFHub fetcher for hosts without /sys/kernel/btf
```

**Files-that-change-together rule applied:**
- BPF C and the Rust skeleton glue live in `ts-bpf-sys` + `bpf/` — always edited together.
- `ts_event.h` (C) and `ts-core::event` (Rust) are mirrored — a struct-size static assertion enforces they stay in sync.
- `tsd`'s integration test lives next to its source so changes to the probe and its consumer ship together.

---

## Task Granularity Note

Each task below is broken into 2-5 minute steps. Some tasks are tagged **(INLINE)** — important enough that the main agent should handle them directly to retain context — and others **(SUBAGENT)** — pure scaffolding that a subagent can do in isolation. The tag is advisory; the executing-plans skill or human can override.

---

## Task 1: Initialize Repo, Workspace, License, Docs **(SUBAGENT)**

**Files:**
- Create: `/home/hoang/code/personal/active/tokenscope/Cargo.toml`
- Create: `/home/hoang/code/personal/active/tokenscope/rust-toolchain.toml`
- Create: `/home/hoang/code/personal/active/tokenscope/.gitignore`
- Create: `/home/hoang/code/personal/active/tokenscope/LICENSE`
- Create: `/home/hoang/code/personal/active/tokenscope/README.md`
- Create: `/home/hoang/code/personal/active/tokenscope/DOC.md`

- [ ] **Step 1: Init git repo**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git init -b main
```
Expected: `Initialized empty Git repository in .../tokenscope/.git/`

- [ ] **Step 2: Write workspace Cargo.toml**

`/home/hoang/code/personal/active/tokenscope/Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = [
    "crates/ts-core",
    "crates/ts-bpf-sys",
    "crates/tsd",
    "crates/tsctl",
    "crates/tstop",
]

[workspace.package]
version       = "0.1.0"
edition       = "2021"
rust-version  = "1.83"
license       = "Apache-2.0"
repository    = "https://github.com/Dialovos/tokenscope"
authors       = ["Hoang Le"]

[workspace.dependencies]
anyhow              = "1.0"
thiserror           = "1.0"
clap                = { version = "4.5", features = ["derive"] }
tracing             = "0.1"
tracing-subscriber  = { version = "0.3", features = ["env-filter", "json"] }
libbpf-rs           = "0.24"
libbpf-cargo        = "0.24"
tokio               = { version = "1.40", features = ["macros", "rt-multi-thread", "signal"] }

# internal
ts-core             = { path = "crates/ts-core" }
ts-bpf-sys          = { path = "crates/ts-bpf-sys" }

[profile.release]
lto             = "thin"
codegen-units   = 1
strip           = true
debug           = false
panic           = "abort"

[profile.dev]
debug = true
```

- [ ] **Step 3: Pin Rust toolchain**

`/home/hoang/code/personal/active/tokenscope/rust-toolchain.toml`:
```toml
[toolchain]
channel    = "1.83.0"
components = ["rustfmt", "clippy"]
profile    = "minimal"
```

- [ ] **Step 4: Write .gitignore**

`/home/hoang/code/personal/active/tokenscope/.gitignore`:
```
/target/
**/*.rs.bk
Cargo.lock.*
.vscode/
.idea/
*.swp
*.swo
*~
# BPF build artifacts
bpf/*.bpf.o
# Local BTF dumps fetched at install time
vmlinux/btf-cache/
# DuckDB / data dirs created at runtime
*.duckdb
*.duckdb.wal
/data/
```

Note: `Cargo.lock` is **checked in** for binary projects — do not gitignore it.

- [ ] **Step 5: Write Apache-2.0 LICENSE**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
curl -sSL https://www.apache.org/licenses/LICENSE-2.0.txt -o LICENSE
```

Verify: `head -1 LICENSE` shows `                                 Apache License`.

- [ ] **Step 6: Write README.md**

`/home/hoang/code/personal/active/tokenscope/README.md`:
```markdown
# TokenScope

Universal LLM observability via eBPF. Zero-instrumentation kernel-level visibility for every LLM workload on a Linux host — local engines, cloud APIs, and agentic frameworks.

> Status: pre-alpha. Phase 0 (foundations) in progress. See `SPEC.md` for the full design.

## Build

Requires: Rust 1.83, clang 14+, libbpf-dev, bpftool, linux-headers for your kernel.

```
cargo build --workspace
```

## Run

```
sudo ./target/debug/tsd
```

You'll see `TsEventHdr { ... }` lines printed for every process exec on the host.

## License

Apache-2.0. See `LICENSE`.
```

- [ ] **Step 7: Write DOC.md**

`/home/hoang/code/personal/active/tokenscope/DOC.md`:
```markdown
# TokenScope — Project Doc

## Overview

TokenScope is a kernel-level eBPF observability platform for LLM workloads on Linux. The full vision and design are in `SPEC.md`. This document tracks what has actually shipped, configuration, and references for contributors.

## Getting Started

See `README.md` for build/run instructions.

## Architecture

Cargo workspace layout:

| Crate          | Purpose |
|----------------|---------|
| `ts-core`      | Shared types (event headers, enums) used by both the daemon and parsers. No I/O. |
| `ts-bpf-sys`   | Compiles `bpf/*.bpf.c` and re-exports `libbpf-cargo`-generated Rust skeletons. Build-time crate; no runtime logic. |
| `tsd`          | Daemon binary. Loads BPF, drains ringbuf, prints events (Phase 0) → routes to pipeline (Phase 1+). |
| `tsctl`        | CLI for ops. Phase 0: `--version` only. |
| `tstop`        | TUI dashboard. Phase 0: stub. |

BPF C code lives in `bpf/` and is compiled by `clang -target bpf`, then `bpftool gen skeleton` produces a Rust-friendly handle that's embedded into the binaries that use it.

## Phases

### Phase 0 — Foundations (in progress, target tag `v0.0.1-phase0`)
Workspace scaffold, libbpf-rs skeleton pipeline, single `sched_process_exec` probe end-to-end, basic GitHub Actions CI on Ubuntu 22.04 + 24.04.

Gate: `cargo test --workspace` green; `sudo ./target/debug/tsd` prints exec events; CI green on both runners.

## Configuration

Phase 0: no config. Future config schema in `SPEC.md` §3.3.

## References

- `SPEC.md` — full design (1300+ lines)
- libbpf-rs docs: https://docs.rs/libbpf-rs
- libbpf-cargo docs: https://docs.rs/libbpf-cargo
- BTFHub: https://github.com/aquasecurity/btfhub
```

- [ ] **Step 8: Verify the workspace parses (no crates yet, expect a specific error)**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
cargo check
```

Expected: error mentioning `crates/ts-core` not found. That is correct — we'll create the member crates in subsequent tasks. The workspace TOML itself parsed without complaint, which is what Step 8 is verifying.

- [ ] **Step 9: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add .gitignore Cargo.toml rust-toolchain.toml LICENSE README.md DOC.md SPEC.md
git commit -m "chore: init workspace scaffold (Phase 0)"
```

Expected: a single commit on `main` with 6+ files.

---

## Task 2: ts-core Crate — Shared Event Types **(INLINE)**

**Files:**
- Create: `crates/ts-core/Cargo.toml`
- Create: `crates/ts-core/src/lib.rs`
- Create: `crates/ts-core/src/event.rs`

**Why inline:** The Rust event types must layout-match the C side exactly. Getting `repr(C)`, alignment, and padding right is foundational; every later parser deserializes through these types.

- [ ] **Step 1: Write the failing struct-layout test**

`crates/ts-core/src/event.rs`:
```rust
//! Wire-format types shared between the BPF programs and userspace.
//! Layout MUST match `bpf/ts_event.h`. The static assertions in this
//! module are tripwires for accidental drift.

use core::mem::{align_of, size_of};

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsEventType {
    NetConnect    = 1,
    NetBytes      = 2,
    TlsPlaintext  = 3,
    LlmReqStart   = 4,
    LlmReqEnd     = 5,
    LlmToken      = 6,
    ProcExec      = 7,
    ProcExit      = 8,
    CgroupNew     = 9,
    CgroupGone    = 10,
    Anomaly       = 11,
    GpuSample     = 12,
}

impl TsEventType {
    /// Convert the on-wire u16 into the typed enum, returning `None` for unknown values.
    /// Unknown values can occur during a rolling upgrade where the daemon is older than
    /// the BPF program — never panic.
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1  => Some(Self::NetConnect),
            2  => Some(Self::NetBytes),
            3  => Some(Self::TlsPlaintext),
            4  => Some(Self::LlmReqStart),
            5  => Some(Self::LlmReqEnd),
            6  => Some(Self::LlmToken),
            7  => Some(Self::ProcExec),
            8  => Some(Self::ProcExit),
            9  => Some(Self::CgroupNew),
            10 => Some(Self::CgroupGone),
            11 => Some(Self::Anomaly),
            12 => Some(Self::GpuSample),
            _  => None,
        }
    }
}

/// Mirror of `struct ts_event_hdr` in `bpf/ts_event.h`.
///
/// Layout (natural alignment, no `packed`):
/// - 0..8   ts_ns      (u64)
/// - 8..12  cpu        (u32)
/// - 12..16 pid        (u32)
/// - 16..20 tgid       (u32)
/// - 20..24 _pad       (u32, padding to 8-byte align cgroup_id)
/// - 24..32 cgroup_id  (u64)
/// - 32..34 ty         (u16)
/// - 34..36 len        (u16)
/// - 36..40 _tail_pad  (u32, padding to round struct size up to 8-byte align)
///
/// Total size: 40 bytes. Alignment: 8.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TsEventHdr {
    pub ts_ns:     u64,
    pub cpu:       u32,
    pub pid:       u32,
    pub tgid:      u32,
    pub cgroup_id: u64,
    pub ty:        u16,
    pub len:       u16,
}

// Tripwires — fail at compile time if layout drifts.
const _: () = assert!(size_of::<TsEventHdr>() == 40);
const _: () = assert!(align_of::<TsEventHdr>() == 8);

/// Errors that can happen while decoding a ringbuf record.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("event too short: got {got} bytes, need at least {need}")]
    Truncated { got: usize, need: usize },
    #[error("declared payload length {declared} exceeds available {available}")]
    BadLength { declared: usize, available: usize },
}

/// Decode a `TsEventHdr` from a ringbuf-delivered byte slice.
///
/// Reads unaligned to be safe regardless of how libbpf-rs hands us the buffer.
pub fn decode_header(buf: &[u8]) -> Result<TsEventHdr, DecodeError> {
    if buf.len() < size_of::<TsEventHdr>() {
        return Err(DecodeError::Truncated {
            got: buf.len(),
            need: size_of::<TsEventHdr>(),
        });
    }
    let hdr = unsafe {
        core::ptr::read_unaligned(buf.as_ptr() as *const TsEventHdr)
    };
    let payload_avail = buf.len() - size_of::<TsEventHdr>();
    if hdr.len as usize > payload_avail {
        return Err(DecodeError::BadLength {
            declared: hdr.len as usize,
            available: payload_avail,
        });
    }
    Ok(hdr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_size_is_forty() {
        assert_eq!(size_of::<TsEventHdr>(), 40);
    }

    #[test]
    fn header_alignment_is_eight() {
        assert_eq!(align_of::<TsEventHdr>(), 8);
    }

    #[test]
    fn decode_truncated() {
        let buf = [0u8; 10];
        let err = decode_header(&buf).unwrap_err();
        assert!(matches!(err, DecodeError::Truncated { got: 10, need: 40 }));
    }

    #[test]
    fn decode_round_trip() {
        let original = TsEventHdr {
            ts_ns: 0xDEAD_BEEF_CAFE_F00D,
            cpu: 3,
            pid: 1234,
            tgid: 1234,
            cgroup_id: 0x4242_4242_4242_4242,
            ty: TsEventType::ProcExec as u16,
            len: 0,
        };
        let bytes: [u8; 40] = unsafe {
            core::mem::transmute(original)
        };
        let decoded = decode_header(&bytes).unwrap();
        assert_eq!(decoded.ts_ns, original.ts_ns);
        assert_eq!(decoded.cpu, original.cpu);
        assert_eq!(decoded.pid, original.pid);
        assert_eq!(decoded.tgid, original.tgid);
        assert_eq!(decoded.cgroup_id, original.cgroup_id);
        assert_eq!(decoded.ty, original.ty);
        assert_eq!(decoded.len, original.len);
        assert_eq!(TsEventType::from_u16(decoded.ty), Some(TsEventType::ProcExec));
    }

    #[test]
    fn unknown_event_type_is_none() {
        assert_eq!(TsEventType::from_u16(255), None);
    }
}
```

- [ ] **Step 2: Write the lib.rs entry point**

`crates/ts-core/src/lib.rs`:
```rust
//! Shared types and helpers for TokenScope.
//!
//! This crate has no I/O, no async, no platform deps — pure data layout
//! plus tiny helpers. It must compile to `no_std` in the future (currently
//! uses `std` for the `thiserror` derives).

pub mod event;

pub use event::{decode_header, DecodeError, TsEventHdr, TsEventType};
```

- [ ] **Step 3: Write the crate manifest**

`crates/ts-core/Cargo.toml`:
```toml
[package]
name          = "ts-core"
version       = { workspace = true }
edition       = { workspace = true }
rust-version  = { workspace = true }
license       = { workspace = true }
repository    = { workspace = true }
authors       = { workspace = true }
description   = "Shared wire-format types for TokenScope"

[dependencies]
thiserror = { workspace = true }
```

- [ ] **Step 4: Run the tests; they should pass**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
cargo test -p ts-core
```

Expected: 4 tests pass. Output ends with `test result: ok. 4 passed; 0 failed`.

If a test fails because `size_of::<TsEventHdr>() != 40`, the layout doc-comment is wrong — re-derive the offsets with `pahole` or by hand and update both the comment and the assertion.

- [ ] **Step 5: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add crates/ts-core
git commit -m "feat(ts-core): shared event types with layout assertions"
```

---

## Task 3: BPF C Program — sched_process_exec → Ringbuf **(INLINE)**

**Files:**
- Create: `bpf/ts_event.h`
- Create: `bpf/sched_exec.bpf.c`
- Create: `bpf/vmlinux.h` (vendored — see Step 5)

**Why inline:** First BPF program in the project. Picking the right header style, helper choice, and ringbuf reservation pattern sets the template for every probe in Phases 1-7.

- [ ] **Step 1: Write the shared event header (C side)**

`bpf/ts_event.h`:
```c
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Wire-format event types shared between BPF programs and userspace.
 * Layout MUST match `crates/ts-core/src/event.rs::TsEventHdr`.
 *
 * Naming: kernel-style `ts_*`. Userspace mirrors as `Ts*` in CamelCase.
 */
#ifndef TS_EVENT_H
#define TS_EVENT_H

enum ts_event_type {
    TS_NET_CONNECT    = 1,
    TS_NET_BYTES      = 2,
    TS_TLS_PLAINTEXT  = 3,
    TS_LLM_REQ_START  = 4,
    TS_LLM_REQ_END    = 5,
    TS_LLM_TOKEN      = 6,
    TS_PROC_EXEC      = 7,
    TS_PROC_EXIT      = 8,
    TS_CGROUP_NEW     = 9,
    TS_CGROUP_GONE    = 10,
    TS_ANOMALY        = 11,
    TS_GPU_SAMPLE     = 12,
};

/*
 * Header for every ringbuf record.
 *
 * Natural alignment (NOT __attribute__((packed)) — packed forces
 * unaligned access in BPF which the verifier dislikes for some helpers).
 * The 4-byte hole at offset 20 and the 4-byte tail padding to 40 are
 * intentional. The Rust mirror has identical size/alignment asserted at
 * compile time.
 */
struct ts_event_hdr {
    __u64 ts_ns;       /* CLOCK_MONOTONIC, kernel time */
    __u32 cpu;
    __u32 pid;         /* userspace PID == kernel TGID */
    __u32 tgid;        /* kernel TGID == thread group leader */
    /* 4-byte implicit padding for 8-byte align of cgroup_id */
    __u64 cgroup_id;
    __u16 type;        /* enum ts_event_type */
    __u16 len;         /* payload bytes following the header */
    /* 4-byte implicit tail padding to align struct size to 8 */
};

#endif /* TS_EVENT_H */
```

- [ ] **Step 2: Write the BPF program**

`bpf/sched_exec.bpf.c`:
```c
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Phase 0 probe. Fires on every successful exec() and emits a TsEventHdr
 * with type=TS_PROC_EXEC. No payload yet (Phase 1 adds cmdline).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "ts_event.h"

/* Required by the BPF verifier — without "GPL" some helpers refuse to load. */
char LICENSE[] SEC("license") = "GPL";

/*
 * 256 KiB ringbuf. Tunable via [daemon].ringbuf_size_kb in later phases.
 * Must be a power of two.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/*
 * Tracepoint format for sched_process_exec:
 *   field:__data_loc char[] filename
 *   field:pid_t pid
 *   field:pid_t old_pid
 *
 * We don't use the filename in Phase 0 (verifier-friendly to keep this
 * program tiny). Phase 1 will use bpf_probe_read_kernel_str against the
 * tracepoint's __data_loc.
 */
SEC("tracepoint/sched/sched_process_exec")
int handle_exec(void *ctx)
{
    struct ts_event_hdr *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        /* Ringbuf full — userspace fell behind. Drop and move on. */
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    e->ts_ns     = bpf_ktime_get_ns();
    e->cpu       = bpf_get_smp_processor_id();
    e->pid       = (__u32)(pid_tgid & 0xFFFFFFFFu);
    e->tgid      = (__u32)(pid_tgid >> 32);
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->type      = TS_PROC_EXEC;
    e->len       = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

- [ ] **Step 3: Generate vmlinux.h for the dev box**

The `vmlinux.h` header is huge (~3MB) and kernel-specific. We vendor a copy for the developer's current kernel and let CI / install scripts regenerate as needed.

Run:
```
cd /home/hoang/code/personal/active/tokenscope
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

If `/sys/kernel/btf/vmlinux` does not exist (e.g., custom kernel), the next task (BTF fetch script) covers it. For Phase 0 we assume the dev box has BTF.

Verify:
```
head -1 bpf/vmlinux.h
wc -l bpf/vmlinux.h
```

Expected: first line is `#ifndef __VMLINUX_H__` (or similar guard); line count > 100,000.

- [ ] **Step 4: Verify the BPF program compiles standalone**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
clang -target bpf -O2 -g -Wall -Werror \
    -I bpf \
    -c bpf/sched_exec.bpf.c \
    -o /tmp/sched_exec.bpf.o
```

Expected: silent success. Verify object exists:
```
file /tmp/sched_exec.bpf.o
```
Should print `ELF 64-bit LSB relocatable, eBPF, version 1 (SYSV)`.

If clang complains about missing headers (`bpf/bpf_helpers.h`), install:
- Ubuntu/Debian: `sudo apt install libbpf-dev`
- Arch: `sudo pacman -S libbpf`
- Fedora: `sudo dnf install libbpf-devel`

Clean up: `rm /tmp/sched_exec.bpf.o`.

- [ ] **Step 5: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add bpf/
git commit -m "feat(bpf): sched_process_exec probe + shared event header"
```

Note: `bpf/vmlinux.h` is checked in despite size — it makes the repo self-contained for the dev box. CI fetches a per-runner copy.

---

## Task 4: BTF Fetch Script for Hosts Without /sys/kernel/btf **(SUBAGENT)**

**Files:**
- Create: `vmlinux/fetch-btf.sh`

- [ ] **Step 1: Write the script**

`vmlinux/fetch-btf.sh`:
```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Fetch a vmlinux BTF dump for the running kernel from BTFHub when
# /sys/kernel/btf/vmlinux is not available (e.g., kernels built without
# CONFIG_DEBUG_INFO_BTF). Writes bpf/vmlinux.h to stdout-friendly C format.
#
# Usage:
#   ./vmlinux/fetch-btf.sh                  # auto-detect distro + kernel
#   ./vmlinux/fetch-btf.sh ubuntu 22.04 5.15.0-91-generic
#
# Exit codes:
#   0 success
#   1 BTF could not be located on BTFHub for this kernel
#   2 missing required tool (curl, tar, bpftool)

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${REPO_ROOT}/bpf/vmlinux.h"
CACHE="${REPO_ROOT}/vmlinux/btf-cache"
mkdir -p "$CACHE"

require() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required tool: $1" >&2
        exit 2
    fi
}
require curl
require tar
require bpftool

# 1. Fast path: kernel exposes BTF directly.
if [[ -r /sys/kernel/btf/vmlinux ]]; then
    echo "kernel exposes BTF; dumping directly" >&2
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$OUT"
    echo "wrote $OUT" >&2
    exit 0
fi

# 2. Otherwise, look up BTFHub.
DISTRO="${1:-}"
RELEASE="${2:-}"
KERNEL="${3:-$(uname -r)}"
ARCH="$(uname -m)"

if [[ -z "$DISTRO" || -z "$RELEASE" ]]; then
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        DISTRO="${ID:-unknown}"
        RELEASE="${VERSION_ID:-unknown}"
    else
        echo "cannot detect distro; pass DISTRO RELEASE as args" >&2
        exit 1
    fi
fi

URL="https://github.com/aquasecurity/btfhub-archive/raw/main/${DISTRO}/${RELEASE}/${ARCH}/${KERNEL}.btf.tar.xz"
TARBALL="${CACHE}/${KERNEL}.btf.tar.xz"

echo "fetching ${URL}" >&2
if ! curl -fLo "$TARBALL" "$URL"; then
    echo "no BTF on BTFHub for ${DISTRO} ${RELEASE} ${KERNEL} ${ARCH}" >&2
    exit 1
fi

tar -xJf "$TARBALL" -C "$CACHE"
BTF_FILE="${CACHE}/${KERNEL}.btf"

if [[ ! -r "$BTF_FILE" ]]; then
    echo "extracted archive missing ${BTF_FILE}" >&2
    exit 1
fi

bpftool btf dump file "$BTF_FILE" format c > "$OUT"
echo "wrote $OUT" >&2
```

- [ ] **Step 2: Make executable + smoke test the help path**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
chmod +x vmlinux/fetch-btf.sh
bash -n vmlinux/fetch-btf.sh   # syntax check only
```

Expected: silent (no syntax errors).

- [ ] **Step 3: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add vmlinux/fetch-btf.sh
git commit -m "tools: add BTF fetch script (BTFHub fallback)"
```

---

## Task 5: ts-bpf-sys Crate — Skeleton Build Pipeline **(INLINE)**

**Files:**
- Create: `crates/ts-bpf-sys/Cargo.toml`
- Create: `crates/ts-bpf-sys/build.rs`
- Create: `crates/ts-bpf-sys/src/lib.rs`

**Why inline:** This is the core build-time machinery. Every other crate depending on a BPF program flows through this skeleton-generation pipeline. Getting the OUT_DIR layout, rerun-if-changed directives, and feature-gating right is fiddly.

- [ ] **Step 1: Write the crate manifest**

`crates/ts-bpf-sys/Cargo.toml`:
```toml
[package]
name          = "ts-bpf-sys"
version       = { workspace = true }
edition       = { workspace = true }
rust-version  = { workspace = true }
license       = { workspace = true }
repository    = { workspace = true }
authors       = { workspace = true }
description   = "Compiles TokenScope BPF programs and exposes libbpf-cargo skeletons"
build         = "build.rs"
links         = "ts-bpf-sys-skel"   # makes cargo enforce single instance

[dependencies]
libbpf-rs = { workspace = true }

[build-dependencies]
libbpf-cargo = { workspace = true }
```

The `links = "ts-bpf-sys-skel"` line prevents two copies of this crate from coexisting in a build graph (would conflict on the BPF map names).

- [ ] **Step 2: Write build.rs**

`crates/ts-bpf-sys/build.rs`:
```rust
//! Compile every `bpf/*.bpf.c` in the repo and emit a libbpf-cargo
//! skeleton into OUT_DIR/<name>.skel.rs. The library entry point
//! re-exports those modules.

use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

/// Each entry: (BPF source filename, generated skeleton filename).
/// Add new probes here as they're written.
const PROGRAMS: &[(&str, &str)] = &[
    ("sched_exec.bpf.c", "sched_exec.skel.rs"),
];

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir.join("..").join("..");
    let bpf_dir = repo_root.join("bpf");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    println!("cargo:rerun-if-changed={}", bpf_dir.display());

    for (src_name, skel_name) in PROGRAMS {
        let src = bpf_dir.join(src_name);
        let skel = out_dir.join(skel_name);

        println!("cargo:rerun-if-changed={}", src.display());

        SkeletonBuilder::new()
            .source(&src)
            .clang_args(["-I", bpf_dir.to_str().unwrap()])
            .build_and_generate(&skel)
            .unwrap_or_else(|e| {
                panic!(
                    "failed to build BPF skeleton for {}: {e}",
                    src.display()
                );
            });
    }
}
```

- [ ] **Step 3: Write the lib.rs that re-exports skeletons**

`crates/ts-bpf-sys/src/lib.rs`:
```rust
//! Generated BPF skeletons.
//!
//! Each `pub mod X` corresponds to a `bpf/X.bpf.c` source and exposes
//! - `XSkelBuilder` (open the program)
//! - `XSkel`        (the loaded skeleton with `maps()` and `progs()`)
//! - `XOpenSkel`    (intermediate stage between open and load)
//!
//! See libbpf-rs docs: https://docs.rs/libbpf-rs

#![allow(clippy::all)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

pub mod sched_exec {
    include!(concat!(env!("OUT_DIR"), "/sched_exec.skel.rs"));
}

// Re-export libbpf-rs so consumers don't have to add it to their own Cargo.toml
// just to satisfy the skeleton's trait bounds.
pub use libbpf_rs;
```

- [ ] **Step 4: Build and verify the skeleton was generated**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
cargo build -p ts-bpf-sys 2>&1 | tail -20
```

Expected: build succeeds. Then verify the skeleton file exists:

```
find target/debug/build -name 'sched_exec.skel.rs' | head -1
```

Expected: a path printed under `target/debug/build/ts-bpf-sys-*/out/sched_exec.skel.rs`.

If the build fails with `clang: command not found`, install clang:
- Ubuntu/Debian: `sudo apt install clang`

If the build fails with `bpftool: command not found`, install:
- Ubuntu/Debian: `sudo apt install linux-tools-common linux-tools-generic`

If the build fails with `vmlinux.h: No such file`, run Task 3 Step 3 first.

- [ ] **Step 5: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add crates/ts-bpf-sys
git commit -m "feat(ts-bpf-sys): build.rs pipeline with libbpf-cargo skeletons"
```

---

## Task 6: tsd Daemon — Load, Attach, Drain, Print **(INLINE)**

**Files:**
- Create: `crates/tsd/Cargo.toml`
- Create: `crates/tsd/src/main.rs`
- Create: `crates/tsd/tests/exec_event.rs`

**Why inline:** This is the end-to-end glue. Getting the libbpf-rs API calls right (open → load → attach → ringbuf builder → poll), wiring the integration test correctly, and choosing the right error-handling pattern is the closest the agent will get to writing the daemon's hot path. Worth keeping in primary context.

- [ ] **Step 1: Write the crate manifest**

`crates/tsd/Cargo.toml`:
```toml
[package]
name          = "tsd"
version       = { workspace = true }
edition       = { workspace = true }
rust-version  = { workspace = true }
license       = { workspace = true }
repository    = { workspace = true }
authors       = { workspace = true }
description   = "TokenScope daemon"

[[bin]]
name = "tsd"
path = "src/main.rs"

[dependencies]
ts-core             = { workspace = true }
ts-bpf-sys          = { workspace = true }
anyhow              = { workspace = true }
clap                = { workspace = true }
tracing             = { workspace = true }
tracing-subscriber  = { workspace = true }

[dev-dependencies]
# Used by the integration test to spawn a child process whose exec we observe.
nix = { version = "0.29", features = ["process"] }
```

- [ ] **Step 2: Write the failing integration test FIRST (TDD)**

`crates/tsd/tests/exec_event.rs`:
```rust
//! Spawn `tsd`, then exec a child process, and assert that tsd's stdout
//! contains a `TsEventHdr` line with the child's PID.
//!
//! Requires CAP_BPF (or root). Marked `#[ignore]` so `cargo test`
//! doesn't fail for unprivileged developers; CI runs with
//! `cargo test -- --include-ignored`.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
#[ignore = "requires CAP_BPF or root; run with --include-ignored under sudo"]
fn captures_exec_event_for_child() {
    // Build the binary explicitly so cargo's debug build is fresh.
    let bin = env!("CARGO_BIN_EXE_tsd");

    let mut child = Command::new(bin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tsd");

    let stdout = child.stdout.take().expect("pipe stdout");
    let mut reader = BufReader::new(stdout);

    // Give tsd a moment to attach the BPF program before triggering exec.
    std::thread::sleep(Duration::from_millis(500));

    // Trigger an exec we can recognize: /bin/true is the smallest exec.
    let triggered = Command::new("/bin/true")
        .status()
        .expect("trigger /bin/true");
    assert!(triggered.success());
    let trigger_pid = std::process::id();

    // Read tsd's stdout for up to 5 seconds, looking for any TsEventHdr line.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut saw_event = false;
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        reader.get_mut().get_ref();   // keep borrow checker happy across loops
        match reader.read_line(&mut line) {
            Ok(0) => break,                          // EOF
            Ok(_) if line.contains("TsEventHdr") => {
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
        "tsd produced no TsEventHdr lines within 5s after triggering /bin/true (pid {trigger_pid})"
    );
}
```

- [ ] **Step 3: Verify the test fails (no main.rs yet)**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
cargo test -p tsd
```

Expected: compilation error — `tsd` has no `main` and no binary. That's the failing-test signal we want.

- [ ] **Step 4: Write the daemon main.rs**

`crates/tsd/src/main.rs`:
```rust
//! TokenScope daemon (Phase 0).
//!
//! Loads the `sched_exec` BPF program, attaches its tracepoint, drains
//! the ringbuf, and prints each event as a debug line on stdout. Phase 1
//! replaces stdout with the in-process pipeline.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use ts_bpf_sys::libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use ts_bpf_sys::libbpf_rs::RingBufferBuilder;
use ts_bpf_sys::sched_exec::SchedExecSkelBuilder;
use ts_core::{decode_header, TsEventType};

#[derive(Parser, Debug)]
#[command(name = "tsd", version, about = "TokenScope daemon")]
struct Args {
    /// Override RUST_LOG-style filter for tracing.
    #[arg(long, default_value = "info")]
    log_filter: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_new(&args.log_filter)
            .unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    info!("tsd starting (Phase 0 — sched_exec only)");

    // 1. Open + load + attach the skeleton.
    let skel_builder = SchedExecSkelBuilder::default();
    let open_skel = skel_builder.open().context("open BPF skeleton")?;
    let mut skel = open_skel.load().context("load BPF skeleton (verifier)")?;
    skel.attach().context("attach BPF programs")?;

    info!("BPF program attached — listening for sched_process_exec");

    // 2. Build the ringbuf consumer.
    let mut builder = RingBufferBuilder::new();
    builder
        .add(&skel.maps.events, handle_event)
        .map_err(|e| anyhow!("add ringbuf consumer: {e}"))?;
    let ringbuf = builder.build().map_err(|e| anyhow!("build ringbuf: {e}"))?;

    // 3. Poll forever (until SIGINT/SIGTERM kills us — Phase 1 wires this up properly).
    loop {
        match ringbuf.poll(Duration::from_millis(200)) {
            Ok(_) => {}
            Err(e) => {
                error!(?e, "ringbuf poll error");
                // Don't exit — transient errors (EINTR) are normal.
            }
        }
    }
}

/// Called by libbpf-rs for each ringbuf record.
///
/// Returns 0 to keep consuming; non-zero would stop the ringbuf entirely.
fn handle_event(data: &[u8]) -> i32 {
    match decode_header(data) {
        Ok(hdr) => {
            let kind = TsEventType::from_u16(hdr.ty)
                .map(|t| format!("{t:?}"))
                .unwrap_or_else(|| format!("Unknown({})", hdr.ty));
            // Phase 0: print to stdout. Phase 1 hands this to the pipeline.
            println!(
                "TsEventHdr {{ kind: {kind}, pid: {pid}, tgid: {tgid}, cpu: {cpu}, cgroup_id: {cgid:#x}, ts_ns: {ts}, len: {len} }}",
                kind = kind,
                pid = hdr.pid,
                tgid = hdr.tgid,
                cpu = hdr.cpu,
                cgid = hdr.cgroup_id,
                ts = hdr.ts_ns,
                len = hdr.len,
            );
            0
        }
        Err(e) => {
            error!(?e, len = data.len(), "failed to decode ringbuf event");
            0   // keep going
        }
    }
}
```

Notes on the libbpf-rs 0.24 API:
- `&skel.maps.events` accesses the field-style maps (the new API; older versions used `skel.maps_mut().events()`).
- If the API differs at the actual pinned version, the compiler error message will be specific — pivot accordingly.

- [ ] **Step 5: Build the workspace**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
cargo build --workspace 2>&1 | tail -20
```

Expected: build succeeds across all crates. If there's an API mismatch on the libbpf-rs side, the error message names the symbol — adjust the call accordingly. Common variants:
- `skel.maps.events` vs `skel.maps().events()` vs `skel.obj.maps().find("events")`
- `RingBufferBuilder::new()` vs `RingBufferBuilder::default()`

- [ ] **Step 6: Run unit tests (no sudo, no integration)**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
cargo test --workspace
```

Expected: ts-core's 4 tests pass. `tsd` integration test is skipped (marked `#[ignore]`). Output ends with `test result: ok` for each crate.

- [ ] **Step 7: Run integration test under sudo**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
sudo -E env "PATH=$PATH" cargo test -p tsd -- --ignored --include-ignored --nocapture captures_exec_event_for_child
```

Expected: test passes; you see `captured: TsEventHdr { ... }` printed.

If the test times out (no event observed in 5s):
1. Check that the BPF program loaded: `sudo dmesg | tail` — verifier rejection lines mention `BPF_PROG_TYPE`.
2. Check the tracepoint exists: `sudo cat /sys/kernel/debug/tracing/events/sched/sched_process_exec/format`.
3. Run tsd manually in one terminal: `sudo ./target/debug/tsd`. In another: `/bin/true`. Lines should appear.

- [ ] **Step 8: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add crates/tsd
git commit -m "feat(tsd): load + drain + print sched_exec events end-to-end"
```

---

## Task 7: tsctl Stub Binary **(SUBAGENT)**

**Files:**
- Create: `crates/tsctl/Cargo.toml`
- Create: `crates/tsctl/src/main.rs`

- [ ] **Step 1: Manifest**

`crates/tsctl/Cargo.toml`:
```toml
[package]
name          = "tsctl"
version       = { workspace = true }
edition       = { workspace = true }
rust-version  = { workspace = true }
license       = { workspace = true }
repository    = { workspace = true }
authors       = { workspace = true }
description   = "TokenScope CLI"

[[bin]]
name = "tsctl"
path = "src/main.rs"

[dependencies]
clap   = { workspace = true }
anyhow = { workspace = true }
```

- [ ] **Step 2: main.rs with version-only subcommand**

`crates/tsctl/src/main.rs`:
```rust
//! TokenScope CLI. Phase 0: `--version` only. Phases 1+ add status, tail,
//! query, etc. — see SPEC.md §6.

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "tsctl", version, about = "TokenScope CLI")]
struct Args {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print build info and exit (Phase 0 has nothing else).
    Version,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    match args.cmd.unwrap_or(Cmd::Version) {
        Cmd::Version => {
            println!("tsctl {}", env!("CARGO_PKG_VERSION"));
        }
    }
    Ok(())
}
```

- [ ] **Step 3: Build and verify**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
cargo build -p tsctl
./target/debug/tsctl version
```

Expected: prints `tsctl 0.1.0`.

- [ ] **Step 4: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add crates/tsctl
git commit -m "feat(tsctl): stub binary with version subcommand"
```

---

## Task 8: tstop Stub Binary **(SUBAGENT)**

**Files:**
- Create: `crates/tstop/Cargo.toml`
- Create: `crates/tstop/src/main.rs`

- [ ] **Step 1: Manifest**

`crates/tstop/Cargo.toml`:
```toml
[package]
name          = "tstop"
version       = { workspace = true }
edition       = { workspace = true }
rust-version  = { workspace = true }
license       = { workspace = true }
repository    = { workspace = true }
authors       = { workspace = true }
description   = "TokenScope live TUI"

[[bin]]
name = "tstop"
path = "src/main.rs"

[dependencies]
clap   = { workspace = true }
anyhow = { workspace = true }
```

- [ ] **Step 2: main.rs placeholder**

`crates/tstop/src/main.rs`:
```rust
//! TokenScope TUI. Phase 0: stub that prints a "coming in Phase 2" notice
//! and exits cleanly. The real ratatui dashboard lands in Phase 2.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "tstop", version, about = "TokenScope live dashboard (stub)")]
struct Args {}

fn main() -> anyhow::Result<()> {
    let _ = Args::parse();
    eprintln!(
        "tstop is a Phase 2 deliverable. For Phase 0, run `sudo tsd` and read the lines on stdout."
    );
    Ok(())
}
```

- [ ] **Step 3: Build and verify**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
cargo build -p tstop
./target/debug/tstop --version
./target/debug/tstop
```

Expected: `tstop 0.1.0` for the first; the second prints the Phase 2 notice and exits 0.

- [ ] **Step 4: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add crates/tstop
git commit -m "feat(tstop): stub binary; full TUI deferred to Phase 2"
```

---

## Task 9: GitHub Actions CI **(SUBAGENT)**

**Files:**
- Create: `.github/workflows/ci.yml`

**Scope note:** Phase 0 CI runs build + unit tests on Ubuntu 22.04 and 24.04. The vng-based kernel matrix from SPEC §11 is deferred to Phase 7 (Hardening) — getting vng wired up cleanly is its own multi-step effort and would expand Phase 0's scope materially.

- [ ] **Step 1: Write the workflow**

`.github/workflows/ci.yml`:
```yaml
# SPDX-License-Identifier: Apache-2.0
name: CI

on:
  push:
    branches: [main]
  pull_request:

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: -D warnings
  RUST_BACKTRACE: 1

jobs:
  build-test:
    name: build + test (${{ matrix.os }})
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-22.04, ubuntu-24.04]
    steps:
      - uses: actions/checkout@v4

      - name: Install BPF toolchain
        run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends \
              clang \
              libbpf-dev \
              linux-tools-common \
              linux-tools-generic \
              "linux-tools-$(uname -r)" || \
            sudo apt-get install -y --no-install-recommends linux-tools-generic
          # bpftool from the linux-tools-generic package may live under a kernel-versioned dir
          if ! command -v bpftool >/dev/null; then
            sudo ln -sf "$(find /usr/lib/linux-tools* -name bpftool | head -1)" /usr/local/bin/bpftool
          fi
          bpftool version

      - name: Generate vmlinux.h for the runner kernel
        run: |
          if [[ -r /sys/kernel/btf/vmlinux ]]; then
              sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
              wc -l bpf/vmlinux.h
          else
              ./vmlinux/fetch-btf.sh
          fi

      - uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: 1.83.0
          components: rustfmt, clippy

      - uses: Swatinem/rust-cache@v2

      - name: cargo fmt
        run: cargo fmt --all -- --check

      - name: cargo clippy
        run: cargo clippy --workspace --all-targets -- -D warnings

      - name: cargo build
        run: cargo build --workspace --all-targets

      - name: cargo test (unit, non-root)
        run: cargo test --workspace --all-targets

      - name: cargo test (integration, root, sched_exec)
        run: |
          sudo -E env "PATH=$PATH" \
              "$(command -v cargo)" test -p tsd \
              -- --ignored --include-ignored --nocapture
```

- [ ] **Step 2: Validate YAML locally**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
python3 -c 'import yaml,sys; yaml.safe_load(open(".github/workflows/ci.yml"))' && echo OK
```

Expected: `OK`.

- [ ] **Step 3: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add .github/workflows/ci.yml
git commit -m "ci: build + unit + root integration test on ubuntu 22.04/24.04"
```

---

## Task 10: Phase 0 Wrap-up — DOC.md, Tag, Smoke Test **(INLINE)**

**Files:**
- Modify: `DOC.md` — flip Phase 0 from "in progress" to "shipped" with concrete gate evidence.

**Why inline:** Final acceptance gate. The agent should personally run the smoke test, look at the actual output, and confirm before declaring Phase 0 done.

- [ ] **Step 1: Run the full local gate**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
sudo -E env "PATH=$PATH" cargo test -p tsd -- --ignored --include-ignored
```

Expected: all four commands exit 0. If clippy complains about something cosmetic, fix it. If a test fails, do NOT proceed — return to the relevant task.

- [ ] **Step 2: Live smoke test (manual eyes-on)**

Terminal A:
```
sudo ./target/debug/tsd
```

Terminal B:
```
/bin/true
ls
date
```

Confirm Terminal A prints `TsEventHdr { kind: ProcExec, pid: ..., ... }` for each child process. Ctrl+C tsd to stop.

- [ ] **Step 3: Update DOC.md Phase 0 entry**

Edit `DOC.md`, replace the existing Phase 0 section with:

```markdown
### Phase 0 — Foundations (shipped, tag `v0.0.1-phase0`)

Workspace scaffold (`ts-core`, `ts-bpf-sys`, `tsd`, `tsctl`, `tstop`); libbpf-cargo skeleton build pipeline; `bpf/sched_exec.bpf.c` tracepoint emitting `TsEventHdr` records through a 256 KiB ringbuf; `tsd` drains and prints them; GitHub Actions CI on Ubuntu 22.04 + 24.04.

**Gate evidence (verified manually 2026-05-02):**
- `cargo fmt --check` clean
- `cargo clippy -D warnings` clean
- `cargo test --workspace` — 4/4 ts-core tests pass
- `sudo cargo test -p tsd -- --ignored --include-ignored` — exec event integration test passes
- `sudo ./target/debug/tsd` prints `TsEventHdr { kind: ProcExec, ... }` lines for live `/bin/true` invocations

**Known gaps left for later phases:**
- vng kernel matrix CI (deferred to Phase 7)
- BPF program does not yet capture `comm`/`cmdline` payload (Phase 1)
- No config file; daemon uses defaults only (Phase 1)
- `tsctl`/`tstop` are stubs (Phase 1+/Phase 2)
```

- [ ] **Step 4: Commit**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git add DOC.md
git commit -m "docs: mark Phase 0 shipped with gate evidence"
```

- [ ] **Step 5: Tag the milestone**

Run:
```
cd /home/hoang/code/personal/active/tokenscope
git tag -a v0.0.1-phase0 -m "Phase 0 — Foundations"
git tag --list
```

Expected: `v0.0.1-phase0` appears in the tag list.

(Skip `git push` — the user has not authorized publishing to a remote yet. Surface the tag in the wrap-up and ask before pushing.)

---

## Definition of Done (Phase 0 acceptance gate)

All must be true:
1. Workspace builds with `cargo build --workspace` from a clean checkout (after running `vmlinux/fetch-btf.sh` if needed).
2. `cargo test --workspace` exits 0 (ts-core layout/decoder tests).
3. `sudo cargo test -p tsd -- --ignored --include-ignored` exits 0 (end-to-end sched_exec capture).
4. `sudo ./target/debug/tsd` prints recognizable `TsEventHdr { kind: ProcExec, ... }` for live process execs.
5. `cargo fmt --check` and `cargo clippy -D warnings` are clean.
6. CI workflow file is valid YAML and contains a build+test job for Ubuntu 22.04 and 24.04.
7. DOC.md reflects Phase 0 shipped with gate evidence.
8. Git tag `v0.0.1-phase0` exists locally.

---

## Self-Review Notes

**Spec coverage check (SPEC §11 Phase 0 line items):**
- "Repo scaffold (cargo workspace: tsd, tsctl, tstop, ts-bpf, ts-core)" → Tasks 1, 2, 5, 6, 7, 8.
- "libbpf-rs + skeleton build pipeline (clang → BPF → embed via build.rs)" → Task 5.
- "vmlinux.h generation + BTFHub fetch script" → Tasks 3 (Step 3) + 4.
- "One trivial probe (sched_process_exec) end-to-end through ringbuf to stdout" → Tasks 3, 5, 6.
- "CI on GitHub Actions with vng kernel matrix" → Task 9 (partial — basic two-runner matrix; full vng matrix deferred to Phase 7 per the scope note in Task 9).

**Type/name consistency check:**
- `TsEventHdr` (Rust) and `struct ts_event_hdr` (C) — consistent across Tasks 2, 3, 6.
- `TsEventType::ProcExec` (Rust) ↔ `TS_PROC_EXEC` (C) — consistent (Tasks 2, 3).
- Map name `events` is the same in `bpf/sched_exec.bpf.c` and the Rust consumer (`skel.maps.events`) — Tasks 3, 6.
- `SchedExecSkelBuilder` is the libbpf-cargo-generated name from `sched_exec.bpf.c` — Tasks 5, 6.

**Placeholders scrubbed:** none of "TBD", "TODO", "fill in", "appropriate handling" appear in any code block above.

**Scope discipline:** the only deferral made beyond what SPEC §11 already deferred is the vng kernel matrix CI; flagged explicitly in Task 9.

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

### Phase 0 — Foundations (shipped 2026-05-02, tag `v0.0.1-phase0`)

Workspace scaffold (`ts-core`, `ts-bpf-sys`, `tsd`, `tsctl`, `tstop`); libbpf-cargo skeleton build pipeline; `bpf/sched_exec.bpf.c` tracepoint emitting `TsEventHdr` records through a 256 KiB ringbuf; `tsd` drains and prints them; GitHub Actions CI on Ubuntu 22.04 + 24.04.

**Gate evidence:**
- `cargo fmt --check` clean
- `cargo clippy --workspace --all-targets -- -D warnings` clean
- `cargo test --workspace` — 5/5 ts-core unit tests pass
- `sudo cargo test -p tsd -- --ignored --nocapture captures_exec_event_for_child` — passes (captured `TsEventHdr { kind: ProcExec, pid: 76682, ... }` after `/bin/true`)
- Plan: `docs/superpowers/plans/2026-05-02-phase-0-foundations.md`

**Toolchain pinned to Rust 1.85** (libbpf-cargo's transitive deps require edition2024).

**Known gaps left for later phases:**
- vng kernel matrix CI (deferred to Phase 7)
- BPF program does not yet capture `comm`/`cmdline` payload (Phase 1)
- No config file; daemon uses defaults only (Phase 1)
- `tsctl`/`tstop` are stubs (Phase 1+/Phase 2)

## Configuration

Phase 0: no config. Future config schema in `SPEC.md` §3.3.

## References

- `SPEC.md` — full design (1300+ lines)
- libbpf-rs docs: https://docs.rs/libbpf-rs
- libbpf-cargo docs: https://docs.rs/libbpf-cargo
- BTFHub: https://github.com/aquasecurity/btfhub

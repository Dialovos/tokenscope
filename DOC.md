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

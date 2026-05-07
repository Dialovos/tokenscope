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

### Phase 1.E — DuckDB Sink (shipped 2026-05-06, tag `v0.0.6-phase1e`)

Every event tsd processes — `ProcExec`, `NetConnect`, `NetBytes` — is now persisted into an embedded DuckDB at `~/.local/share/tokenscope/events.duckdb` (override with `--db-path`). Stdout output stays unchanged unless `--no-stdout` is passed; the database is the queryable system of record. A `ctrlc` handler on `SIGINT`/`SIGTERM` flips an atomic shutdown flag the main loop watches, so the DuckDB connection drops cleanly on scope exit (after the ringbuf releases its closure-borrows) — no torn writes.

Schema: three event tables (`events_proc_exec`, `events_net_connect`, `events_net_bytes`) plus `schema_version`, embedded as a single SQL string in `tsd::store`. Migrations are idempotent (CREATE IF NOT EXISTS) — the second one will move to a file-based runner.

`net_bytes::flush` writes a row per non-zero LRU map entry every flush window, stamped with a wall-clock snapshot ns so queries can correlate against absolute time.

**Toolchain bumped to 1.86.0** — `duckdb 1.10502.0` requires 1.85.1 and an `icu` transitive needs 1.86.

**Gate evidence (verified 2026-05-06):**
- `cargo fmt --check` / `cargo clippy --workspace --all-targets -- -D warnings` clean
- `cargo test --workspace` — ts-core 13 + tsd lib 14 (proc_cache 9 + store 5) = 27 unit tests pass
- `sudo cargo test -p tsd -- --ignored` — five integration tests pass
  - `round_trips_events_through_duckdb` confirms `connect rows: 1, bytes rows: 8, max tx: 1024` after a known 1024-byte loopback transfer through the full pipeline (BPF → ringbuf → store insert → SQL SELECT)
- Plan: `docs/superpowers/plans/2026-05-06-phase-1e-duckdb-sink.md`

**Known gaps:**
- No partitioning / rollup / retention (Phase 2; current schema grows linearly per event)
- Inserts are one-row-at-a-time (no prepared statements, no batching) — fine for hundreds of events/sec; redo when we hit thousands
- No read API yet — query via the `duckdb` CLI or by the integration test path; `tsctl tail` / `tsctl query` lands in Phase 1.F
- Schema doesn't carry exe / uid / gid / start_time (Phase 2)
- First build is slow (~30 min single-threaded) because `duckdb` compiles its bundled C++ amalgamation; incremental rebuilds are seconds. CI will need to cache `target/` aggressively or accept the cold-build cost.

### Phase 1.D — BPF comm Capture (shipped 2026-05-06, tag `v0.0.5-phase1d`)

`bpf_get_current_comm()` is now called at every event emit site (sched_exec, cgroup/connect, fexit/tcp_sendmsg, fexit/tcp_recvmsg). The 16-byte comm string is carried in `ts_event_hdr` (header grew 40 → 56 bytes) and in `ts_net_bytes_value` (32 → 48 bytes). Userspace reads comm directly from the event, eliminating the /proc race that produced `comm: "<gone>"` for short-lived processes in Phase 1.C.

The /proc cache is retained for `cmdline` lookups only — that field still has the race, but seeing `comm: "curl", cmdline: "[<gone>]"` is far more useful than two sentinels.

**Gate evidence (verified 2026-05-06):**
- `cargo fmt --check` / `cargo clippy -D warnings` clean
- `cargo test --workspace` — 13 ts-core + 9 tsd unit tests pass (22 total)
- `sudo cargo test -p tsd -- --ignored` — four integration tests pass, all show real comm values (`"true"`, `"captures_tcp_by"`, etc.)
- Live smoke: `curl example.com` produces `comm: "curl"` lines for both NetConnect and NetBytes

**Wire format break:** This phase changes the on-disk event layout. Pre-1.D ringbuf consumers will see truncated/garbled events. Acceptable pre-1.0; documented for downstream tools.

### Phase 1.C — Process Enrichment via /proc (shipped 2026-05-06, tag `v0.0.4-phase1c`)

Userspace `proc_cache` resolves `pid → {comm, cmdline}` lazily from `/proc/<pid>/comm` and `/proc/<pid>/cmdline`. Both the ringbuf event handler and the periodic net_bytes flush borrow the cache via closures (single-threaded; `RefCell` for interior mutability). Every event line tsd prints — `ProcExec`, `NetConnect`, `NetBytes` — now includes `comm:` and `cmdline:` fields.

Cache: 4096-entry FIFO eviction, sentinel values (`<gone>` / `<denied>` / `<error>`) for unreadable PIDs so a single failed lookup doesn't trigger repeated /proc reads. No BPF or wire-format changes — pure userspace. handle_event looks up by `hdr.tgid` (userspace PID), not `hdr.pid` (kernel TID), so non-leader threads correctly resolve to their parent process's /proc entry.

**Gate evidence (verified 2026-05-06):**
- `cargo fmt --check` / `cargo clippy -D warnings` clean
- `cargo test --workspace` — 13 ts-core + 9 tsd proc_cache unit tests pass (22 total)
- `sudo cargo test -p tsd -- --ignored` — four tests pass: `exec_event`, `connect_event`, `bytes_event`, `netconnect_line_has_enrichment_fields`
- Plan: `docs/superpowers/plans/2026-05-06-phase-1c-proc-enrichment.md`

**Known limitation — short-lived process race:**
For processes that exit and get reaped within ~milliseconds of generating an event (e.g., `curl example.com` finishing before tsd's 200ms ringbuf poll runs), `/proc/<pid>/` disappears before the cache lookup. Affected lines show `comm: "<gone>"`. Long-lived processes (servers, sshd, top, etc.) enrich correctly. **Fix lives in Phase 1.D**, which adds `bpf_get_current_comm()` to the BPF event payloads — captures comm at event time, eliminating the race entirely. This was deliberately scoped out of 1.C to avoid a wire-format change here.

**Other gaps:**
- No PID-reuse detection (cache trusts pid; fix in 1.D using /proc/<pid>/stat start_time)
- No exit-driven invalidation (FIFO eviction handles it eventually)
- exe / uid / gid / cgroup_path not captured (1.D when DuckDB schema needs them)

### Phase 1.B — TCP Byte Counting (shipped 2026-05-06, tag `v0.0.3-phase1b`)

Two fexit programs (`fexit/tcp_sendmsg` + `fexit/tcp_recvmsg`) accumulate per-socket TX/RX bytes into a `BPF_MAP_TYPE_LRU_HASH` keyed by `bpf_get_socket_cookie()`. tsd flushes the map every `--flush-interval-ms` (default 5000 ms) and prints `NetBytes { sock_cookie, pid, tx, rx, last_ns }` lines on stdout. Map is cumulative; LRU eviction at 65k sockets.

**Gate evidence (verified 2026-05-06):**
- `cargo fmt --check` / `cargo clippy -D warnings` clean
- `cargo test --workspace` — 13/13 ts-core unit tests pass (9 from Phase 1.A + 4 net_bytes mirrors)
- `sudo cargo test -p tsd -- --ignored` — three tests pass: `exec_event`, `connect_event`, `bytes_event`
  - Bytes: `NetBytes { sock_cookie: 0x0000000000000001, pid: 47143, tx: 1024, rx: 0, last_ns: 78939495697541 }` (1024-byte payload reflected exactly)
- Plan: `docs/superpowers/plans/2026-05-06-phase-1b-tcp-byte-counting.md`

**Known gaps:**
- UDP byte counting (Phase 2)
- Cumulative counters; subtraction-on-query lands with DuckDB in Phase 1.D
- PID is the FIRST observed PID for a socket; sends from softirq context (TCP retransmits) attribute to ksoftirqd
- IPv6 untested end-to-end (only v4 in `bytes_event.rs`)

### Phase 1.A — Cgroup Connect Probes (shipped 2026-05-06, tag `v0.0.2-phase1a`)

`bpf/net.bpf.c` adds `cgroup/connect4` + `cgroup/connect6` programs that emit a `TS_NET_CONNECT` ringbuf record (with destination IP+port and protocol) on every outbound connect() syscall system-wide. `tsd` now loads two BPF skeletons (sched_exec + net) and drains both with a single multiplexed ringbuf consumer. Cgroup attachment uses the v2 unified hierarchy at `/sys/fs/cgroup`; v1 hosts are unsupported.

**Gate evidence (verified 2026-05-06):**
- `cargo fmt --check` / `cargo clippy -D warnings` clean
- `cargo test --workspace` — 9/9 ts-core unit tests pass (5 from Phase 0 + 4 net_connect)
- `sudo cargo test -p tsd -- --ignored` — both `captures_exec_event_for_child` and `captures_cgroup_connect_v4` pass
  - Connect: `TsEventHdr { kind: NetConnect, pid: 41815, tgid: 41814, cpu: 16, cgroup_id: 0x15, dst: 127.0.0.1:1, proto: 6 }`
  - Exec: `TsEventHdr { kind: ProcExec, pid: 41820, tgid: 41820, cpu: 18, cgroup_id: 0x15, ts_ns: 77551326289437, len: 0 }`
- Plan: `docs/superpowers/plans/2026-05-02-phase-1a-cgroup-connect.md`

**Verifier gotcha hit:** `__builtin_memcpy(dst, ctx->user_ip6, 16)` was rejected because clang compiled it to a u64 load via modified ctx pointer. Reading each `user_ip6[i]` as a u32 individually fixed it. Pattern noted in `bpf/net.bpf.c` for future probes touching `bpf_sock_addr`.

**Known gaps left for later phases:**
- TCP byte counting via tcp_sendmsg/tcp_recvmsg (Phase 1.B)
- Process enrichment (cmdline, exe, /proc walk) (Phase 1.C)
- DuckDB persistence (Phase 1.D)
- `tsctl tail` / `tsctl status` (Phase 1.E)
- IPv6 tested only at compile/load time; no end-to-end v6 integration test

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

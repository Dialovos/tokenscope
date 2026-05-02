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

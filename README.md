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

## History

`main` was rewritten on 2026-09-28 to remove co-author trailers, so clones made
before then hold old copies of those commits. If `git fetch` reports a forced
update and `git cherry origin/main` prints no `+` lines, run
`git reset --hard origin/main` and `git fetch --tags --force`.

## License

Apache-2.0. See `LICENSE`.

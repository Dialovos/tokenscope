# TokenScope

Linux eBPF observability for LLM workloads. The current usage-monitor draft
reconstructs reported token counts from dynamically linked OpenSSL traffic on a
narrow HTTP/1.1 path, alongside process and network metadata.

> Status: pre-alpha. The reported-usage monitor merged on 2026-10-16 (PR #2).
> The unprivileged suite and all ten privileged tests pass on kernel 7.0 locally
> and on the Ubuntu 22.04 and 24.04 CI runners. HTTP/1.1 Chat Completions
> JSON/SSE parsing streams instead of buffering,
> loss is sized by per-direction byte offsets, and recovery keeps keep-alive
> connections useful after a loss. Storage and tail carry metadata and numbers only.
> None of this establishes complete token accounting, HTTP/2 support or billing
> accuracy. See [DOC.md](DOC.md) for the contract and release history, and
> [the implementation record](docs/research/2026-10-08-improvement-implementation.md#completion--2026-10-15)
> for checks and remaining gates. The broader design is in `SPEC.md`.

## Build

Requires Linux x86-64, pinned Rust 1.86.0, clang with BPF support, pkg-config,
libelf/zlib development files and a C++ compiler for bundled DuckDB. The checked-in
`rust-toolchain.toml` selects Rust and its formatting/lint components.

```
cargo build --workspace --locked
```

## Run

```
sudo ./target/debug/tsd --no-stdout
sudo ./target/debug/tsctl status
sudo ./target/debug/tsctl query 'SELECT capture_epoch, tgid, request_ordinal, usage_state, capture_integrity, reports_json FROM events_usage'
```

Live capture needs administrator privileges, cgroup v2, bpffs and compatible
kernel BPF support. TLS observation includes the daemon's cgroup; add
`--track-cgroup <path>` for the workload's cgroup. The default database is
`tokenscope/usage.duckdb` under the data directory selected by `XDG_DATA_HOME`,
then the current account's local share directory, then `/var/lib`. Its immediate
parent must be private. Historical databases are preserved and refused for new
writes. `tsctl tail` exports metadata and numeric reports; `--show-plaintext` is
refused. Numeric usage is an observed report, and capture integrity is recorded
separately.

TLS activation requires entry/return probes for both basic and `_ex` read/write
APIs, plus `SSL_new`, `SSL_free` and `SSL_clear`; an incomplete library is skipped.
The cgroup filter is shared and persistent: configured IDs are added to it,
so stale IDs or another observer can broaden TLS scope. Qualification requires
exclusive use of a fresh filter. Host/path matching identifies OpenAI-compatible
reports; it does not verify the TLS peer or establish authenticated billing.

## Test

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
python3 experiments/test-tls-inflight.py
```

The Rust suite covers replay, recovery, persistence, fault handling and privacy
without root. Privileged tests are ignored by default. The C fixture executes the
actual TLS entry/return code with mocked BPF helpers; it does not test kernel
loading. The privileged tests run as root in a loopback-only scope:

```sh
experiments/qualify-privileged.sh
```

Run it as your normal user; it builds first and asks sudo only for the test
binaries. It refuses to start while another observer owns the pinned cgroup
filter, and removes the pin afterwards only if the run created it.

## Research validation

[Improvement research (2026-10-08)](docs/research/2026-10-08-improvement-research.md)
prioritizes privacy, capture/persistence correctness, usage provenance and
independently qualified HTTP/2 follow-up experiments. The first implementation
is described in the implementation record above.

[Loss-recovery ablation (2026-10-15)](docs/research/2026-10-15-loss-recovery-ablation.md)
answers its main question in replay: does loss evidence prevent falsely complete
usage without discarding too much? Conservative invalidation made no false
claims but kept only 12–62% of undamaged usage under 0.05–1% call loss. Sized gaps
plus response resync made no false claims across 43,200 requests under loss and
kept 94.5–99.8%. Parsers without loss evidence made up to 70 false claims per
7,200 requests. This is a deterministic simulation, not live capture:

```sh
cargo run --release -p ts-core --example usage_ablation -- 100 \
  > experiments/results/2026-10-15-usage-ablation.json
```

[Initial accounting research review and pilot](docs/research/2026-09-29-accounting-validation.md)
checks prior work, HTTP/2 streaming feasibility, and the limits of passive token
accounting. Its replay experiment uses synthetic traffic and runs without root:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r experiments/requirements.txt
.venv/bin/python experiments/accounting-pilot.py \
  --output experiments/results/2026-09-29-accounting-pilot.json
```

The [study protocol](docs/research/accounting-study-protocol.md),
[reproduction guide](docs/research/accounting-reproduction.md), and
[working manuscript](docs/research/accounting-manuscript.md) define the live
comparison. The completed main study contains 1,620 control/observer trial cells
and 24,600 scored synthetic attempts. Pinned OBI matched all 4,100 Python
HTTP/1.1 attempts and recovered all 2,460 emitted usages exactly. Go HTTP/1.1
matched 1,612 attempts and recovered 1,113 usages. Go HTTP/2 failed clean usage
qualification in the main session and remains diagnostic; a preceding qualified
screen contains conflicting count exports. These findings describe one local
workload and kernel. Python HTTP/2 payload capture is documented as unsupported.
Validate the fixture with
`.venv/bin/python experiments/run-study.py --mode smoke`; run the scorer checks
with `.venv/bin/python experiments/test-accounting-score.py`. The host screen
uses `sudo bash experiments/run-screen.sh`. Pinned agtap requires an isolated
test kernel and is not launched by the host script.

`sudo bash experiments/run-confirmation.sh` qualifies Go HTTP/2, then runs
ten-seed Go and Python matrices sequentially. The launchers share a lock to
prevent overlapping observer jobs. Allow about 1.5 hours without GPU inference.

The technical-report PDF (`experiments/results/accounting-manuscript.pdf`) and
main study artifact (`experiments/results/2026-09-29-accounting-main-artifact.tar.gz`)
contain the working report, figures, reproduction scripts, exact measured source
snapshots and portable accounting evidence. Author/Claude review and venue
selection remain pending; nothing has been uploaded. Earlier draft/screen
archives remain as historical snapshots. This evidence supports a scoped
technical report; a new-method paper needs additional mechanism and validation.

Files under `experiments/results/` are generated artifacts and stay out of Git
(repo-guard blocks them), so the result links in the research documents only
resolve in the maintainer's checkout. They are archived separately.

## History

`main` was rewritten on 2026-09-28 to remove co-author trailers, so clones made
before then hold old copies of those commits. If `git fetch` reports a forced
update and `git cherry origin/main` prints no `+` lines, run
`git reset --hard origin/main` and `git fetch --tags --force`.

## License

Apache-2.0. See `LICENSE`.

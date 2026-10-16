# Trustworthy usage implementation

Date: 2026-10-08. Implements the first deliverable recommended by the
[research](2026-10-08-improvement-research.md), including both requirements in
the [independent audit](2026-10-08-improvement-research-audit.md).

## Scope and contract

Support dynamically linked OpenSSL and HTTP/1.1 Chat Completions JSON/SSE.
Libraries must expose every required basic and `_ex` read/write API and lifecycle
symbol; incomplete attachment is refused. Host/path matching identifies an
OpenAI-compatible report without authenticating the TLS peer or billing origin.
Persist only metadata and reported numeric usage. Raw TLS and process arguments
remain ephemeral; reject the old plaintext tail option rather than offer an
unsafe chunk-redaction guarantee. Preserve historical databases, changing the
default filename to `usage.duckdb`. No raw debug mode in this deliverable.
Before opening an existing path for writing, inspect its schema read-only and
refuse legacy databases containing `events_tls_plaintext`; preserve their
original bytes and require a separate new destination. Flushed-row counts mean
successful application flush visibility, not power-loss durability or proof of
complete capture.

Record capture epoch, process start time, SSL lifetime, direction and successful
call sequence. Attach SSL_new/free/clear lifecycle probes; missing lifecycle or
sequence evidence prevents trusted reconstruction. Successful SSL writes mean
library acceptance, not server receipt. Nested invocations are suppressed with
depth bookkeeping; failures always remove completed inflight state. Capture
loss invalidates reconstruction, including whole/final calls; global losses
remain globally scoped. No body hashes establish identity.

The replayable parser accepts complete, sequential chunks, strict HTTP/1.1
length/chunk framing, informational responses, JSON and SSE. Reject ambiguous
framing, compressed bodies, HTTP/2 and unsupported encodings with explicit
reasons. Keep absent and zero distinct, duplicate snapshots idempotent and
conflicts visible. Association uses observed request order, never payload hash.
Do not claim complete transport coverage: stored usage is an observed provider
report and capture integrity is separate. Limit retained bytes, connections,
pending requests and idle lifetime; eviction emits uncertainty.

## Work items and acceptance gates

1. **Privacy:** stop command-line collection/logging/persistence, raw TLS
   persistence and content fingerprints; private database creation; protocol
   version bump and explicit plaintext rejection. Sentinel checks cover all
   event families, database/WAL, tail and split TLS payloads.
2. **Persistence:** stop producers before draining a FIFO shutdown marker;
   bounded queue; flush on a busy deadline and final drain. Surface insert/flush
   failures, writer health and successfully flushed row counts in status.
   Tail observations do not imply persistence. Test shutdown inventory, busy
   flush and injected errors.
3. **Capture:** entry/return write semantics and read cleanup; distinct nested,
   map-failure and missing-state counters. Lifetime and sequence metadata,
   conservative invalidation and final checkpoint reconciliation. Build the BPF
   programs; privileged runtime qualification remains an explicit gate.
4. **Parser and integration:** bounded pure Rust reconstruction and allowlisted
   provider usage, sink integration, accounting table and tail/query output.
   Replay fixtures exercise every split point, chunking, zero/missing usage,
   duplicate/conflicting SSE, partial frames, gaps, reuse, expiry and aggregate
   exhaustion. Unsupported cases produce reasons rather than guessed totals.
5. **Verification and documentation:** format, workspace tests and lint;
   synthetic persistence/privacy fault tests; document support and every
   unverified live gate. Independent review of the implementation and resolve
   substantive findings before handoff.

HTTP/2 diagnosis, new runtime adapters, OTLP, pricing, real-provider calls and
fresh privileged benchmark matrices are the subsequent research tracks E1–E8.
They do not gate the narrowly supported first deliverable and are not implied
by a successful unprivileged test suite.

## Paused checkpoint — 2026-10-09

Paused at the user's request. All changes are uncommitted on
`research/accounting-validation`; source HEAD remains `88b4ccf`. Existing
`experiments/results/` remains untouched and must not be included by a blanket
Git add. Original improvement research and its audit remain historical records.

### Implemented on disk, awaiting verification

- Default database changes to `usage.duckdb`; existing non-usage and legacy
  plaintext databases are inspected read-only and refused before migration or
  permission changes. Private creation and symlink refusal are added.
- Command-line arguments are no longer collected/logged for events and are
  discarded by storage. Raw TLS persistence and fingerprints are removed;
  protocol v2 rejects plaintext tail requests.
- FIFO shutdown marker drains accepted events; flush deadlines run during busy
  ingestion. Persistence errors and writer progress are exposed separately;
  health resets on writer exit/unwind.
- Accepted-byte SSL write return probes, read cleanup, nested-call diagnostics,
  SSL_new/free/clear lifecycle, process start and exec identity, directional
  sequence/loss inventories, and conservative checkpoint invalidation are added.
- Pure Rust HTTP/1.1 JSON/SSE usage reconstruction and writer/table/tail
  integration are drafted. Unsupported compressed/HTTP2/close-delimited bodies
  are refused. Zero/missing/partial/conflicting reports remain distinct;
  duplicate JSON keys are rejected.
- Replay, drain, busy-flush, injected append/flush, database privacy and legacy
  preservation tests are written, but have not completed execution.

The independent reviewer found several gaps during coding. Fixes on disk cover
loss before first admission (a generation barrier), divergent nested operations,
exec identity, legacy v1 preservation, shared capture epochs, reserved-capacity
accounting, duplicate JSON keys and writer health. These still need tests.

### Resume work

1. Finish build setup and execute the Rust tests before treating any code as
   working. Only stable Rust 1.98.1 is installed globally. Project-local Rust
   1.86 installation was stopped while partial. Locked dependency fetch failed
   on registry timeouts (`sync_wrapper`); the cache is incomplete.
2. Resolve the reviewer's remaining classification findings: malformed-only
   payloads and bodyless 204 must not become `reported_partial` without a valid
   report; preserve `conflicting` when malformed events follow distinct valid
   reports. Add fixtures for both.
3. Revisit nested-call trust: buffer/SSL/count equivalence alone does not prove
   that two invocations are wrappers; either qualify the rule or conservatively
   invalidate unqualified nested activity. Check failed/mismatched returns and
   stale inflight entries across exec/exit with realistic fixtures.
4. Add panic, two-capture-epoch, independent checkpoint race, completed-large-
   stream capacity, all-event-family/split sentinel and WAL preservation checks.
   The old ignored enrichment/TLS tests still expect command lines/raw TLS
   tables; update them to the new contract using synthetic local traffic.
5. Document fixed limits: 128 total admitted lifetimes per capture epoch (closed
   and expired identities remain tombstones), 256 KiB per connection, 8 MiB of
   retained parser buffers, 16 KiB headers, 128 KiB bodies, 16 pending requests,
   30 s idle expiry. Admission exhaustion is sticky until restart and exposed in
   status. Queue memory, temporary decoding allocations and DuckDB RSS are
   separate from the retained-buffer quota. Live inventory checkpoints can run
   ahead of queued records and conservatively invalidate healthy connections.
6. Finish README/DOC support and run/query instructions; record exact completed
   checks and compiler. Request the existing independent reviewer to re-audit
   final source and resolve substantive findings. No commit/push/PR was made.

### Checks actually completed

- BPF TLS compilation with project-local clang 21.1.8: exit 0, including the
  exec-identity changes. This is compilation only; no verifier/load/live test.
- Formatting with Rust 1.98.1: exit 0. Final format/diff checks are rerun at
  handoff; this does not establish compilation or behavior.
- Rust tests: not completed. Initial offline resolution failed; network fetch
  failed on timeouts. No passing Rust test result is claimed.
- Privileged OpenSSL qualification, real-provider calls, HTTP/2 studies, fresh
  performance experiments and power-loss durability: not run.

Reusable compiler/headers and incomplete Rust/dependency caches are retained
under ignored `target/`. No system packages were installed: sudo required
interactive authentication. Setup processes were stopped at pause. Historical
research, databases and results are preserved.

## Review handoff — 2026-10-09

The checkpoint above records the state before resuming. The user will run Claude
review themselves; Claude has not been invoked for this implementation. This is
a locally tested draft for review, rather than a qualified live release.
Changes remain uncommitted on `research/accounting-validation`. Preserve the
September study results, manuscript and frozen source archives; they measured
earlier observers and do not validate this implementation.

### Corrections since the paused checkpoint

- Malformed-only JSON/SSE and bodyless 204 responses produce absent usage;
  a malformed event cannot erase conflicts established by valid reports. Valid
  counts followed by malformed events remain partial.
- Nested calls invalidate trust even when SSL/buffer/count arguments match.
  Stale exec/PID state is discarded before fresh entry; a thread-exit tracepoint
  cleans both directional inflight entries and records loss. Failed/retried,
  partial-success, mismatched, map/reservation and output-pointer paths have a
  host C fixture using the actual production functions with mocked BPF helpers.
- Added writer-panic health, separate capture-epoch, checkpoint-ahead-of-queue,
  completed-large-response buffer-release, all-event-family split-sentinel and
  active-WAL preservation tests. The writer fixtures use the same monotonic
  clock as live capture so idle expiry is exercised correctly.
- Fixed database initialization: DuckDB rejects an existing empty placeholder.
  It now creates the file inside an already-private directory, then file mode
  is set before schema/event writes. Test fixtures use private subdirectories;
  a negative fixture still rejects a shared directory without changing it.
  Existing and dangling symlinks are refused before initializing a target.
- Removed the obsolete process-cache dependency from production event paths
  and its remaining argument-reading code. Compatibility argument inputs are
  deliberately discarded. Storage and tail sentinel checks cover every event
  family, including payload splits and a live WAL.
- Updated ignored TLS tests to synthetic loopback HTTP/1.1 traffic with actual
  numeric-usage assertions. Missing prerequisites fail explicitly when selected.
  Ignored storage/control/enrichment fixtures use separate database destinations;
  enrichment expects metadata without arguments. README and DOC now distinguish
  the current draft from historical plaintext behavior. CI's Rust version now
  matches the pinned toolchain and its privileged tests run sequentially; the
  remote workflow has not been executed for this working tree.

### Verification record

Completed checks, all exit 0:

| Check | Result | Local evidence under `target/implementation-checks/` |
| --- | --- | --- |
| `cargo +1.86.0 test --workspace --locked --offline` | 99 passed: 33 core unit, 19 usage replay, 47 daemon unit; 10 privileged tests ignored | `workspace-tests-reviewed.log`, `.exit` |
| `cargo +1.86.0 clippy --workspace --all-targets --locked --offline -- -D warnings` | Clean, including test targets | `clippy.log`, `.exit` |
| `cargo +1.86.0 build --workspace --all-targets --locked --offline` | Workspace binaries and test targets built, including regenerated BPF skeletons | `workspace-build-all-targets.log`, `.exit` |
| `cargo +1.86.0 fmt --all -- --check` | Clean | Completed command output |
| `git diff --check` | Clean | Completed command output |
| `python3 experiments/test-tls-inflight.py` | Host C capture/loss fixtures passed | Completed command output; temporary fixture automatically removed |
| Local documentation links and qualification shell syntax | Existing targets and valid Bash syntax | Completed command output |

Logs and exit files are retained under ignored `target/implementation-checks/`,
including earlier failures. Initial tests exposed the empty-file initialization
bug and non-private fixture directories; the next run exposed synthetic
timestamps causing real writer expiry. Both causes were corrected, and the
reviewed source passed the full rerun. A separate plain workspace binary build
was deliberately terminated (exit 143) when it selected another native dependency
profile; the successful all-target build reused the test profile instead.
Earlier native-link and stale-generated-skeleton compile failures are retained
as diagnostics; final compilation/lint succeeded.

The project-local toolchain is Rust 1.86.0
(`05f9846f8`, 2025-03-31), with clang 21.1.8 for BPF/native builds. Global Rust
1.98.1 and system packages were left unchanged. Locked crates were fetched
successfully; subsequent checks run offline. A dangling cached libelf runtime
link was repaired using the installed matching runtime. Rustup's project-local
auto-self-update was disabled to avoid its incorrect Cargo-home self-update
check; the pinned installation recheck passed.

These checks do not establish privileged verifier/load acceptance, live OpenSSL
capture, HTTP/2 support, real-provider billing, overhead, crash-WAL recovery or
power-loss durability. Release panic=abort does not run unwind cleanup. The
resource limits and checkpoint timing tradeoffs in DOC remain explicit.

### Claude review and live qualification

Review the final working-tree diff and the new untracked usage module/tests,
not only HEAD. Prioritize capture lifetime/loss invariants, delayed checkpoint
ordering, all-channel privacy, read-only legacy refusal, writer shutdown and
reported/partial/conflicting classification. Record actual Claude contribution
only after the review, and resolve findings before claiming the implementation
ready for release. No commit, push, PR or publication upload was performed.

For live qualification, build the binaries and the TLS test executable as the
normal user, then run only the selected executable as root in a dedicated
cgroup. Do not run concurrently with another TokenScope daemon or observer job:
the capture filter uses a shared bpffs pin. The following foreground command is
for attended qualification, not a long benchmark; retain its exit code and log.
Start with a fresh filter: configured IDs are additions to the persistent map,
and stale IDs can broaden scope. The command refuses an existing pin. An
administrator must inspect any existing filter and its owners before arranging
an exclusive fresh run; never clear another observer's active map.

```sh
(
set -euo pipefail
sudo test ! -e /sys/fs/bpf/tokenscope/cgroup_filter
# From the project root. This machine's ignored env.sh selects the local tools.
source target/implementation-checks/env.sh
cargo build --workspace --all-targets --locked --offline
cargo test -p tsd --test tls_e2e --no-run --locked --offline \
  --message-format=json > target/implementation-checks/tls-build.jsonl
tls_test_binary=$(python3 - <<'PY'
import json
from pathlib import Path
paths = []
for line in Path('target/implementation-checks/tls-build.jsonl').read_text().splitlines():
    obj = json.loads(line)
    if (obj.get('reason') == 'compiler-artifact'
            and obj['target']['name'] == 'tls_e2e' and obj.get('executable')):
        paths.append(obj['executable'])
assert len(paths) == 1, paths
print(paths[0])
PY
)
if sudo systemd-run --scope -p IPAddressDeny=any -p IPAddressAllow=localhost \
  systemd-inhibit --what=sleep:idle:handle-lid-switch \
  --why='Synthetic TokenScope usage qualification' \
  "$tls_test_binary" --ignored --test-threads=1 --nocapture \
  > target/implementation-checks/privileged-tls.log 2>&1; then
  qualification_status=0
else
  qualification_status=$?
fi
printf '%s\n' "$qualification_status" > target/implementation-checks/privileged-tls.exit
exit "$qualification_status"
)
```

The three TLS tests require root, cgroup v2, bpffs, curl linked to OpenSSL,
OpenSSL CLI and Python ssl. They require positive attachment/capture and exact
5/3/8 usage for the known client PID, then check content exclusion and explicit
plaintext-tail refusal. The fixture uses loopback, a temporary certificate and
synthetic sentinel data; no provider call or GPU inference is involved. A test
failure is a failed qualification, not a reason to suppress or skip an assert.
The host C fixture is complementary and cannot replace this gate.

Keep the reusable toolchain/native build caches and verification logs. No
disposable fixture data remains after the unprivileged tests; historical
research output is intentionally retained.

## Resume verification — 2026-10-09

The authorized first deliverable is implemented and validated locally. This
record supersedes the earlier verification counts; privileged qualification and
the user's Claude review remain pending. No commit, push, PR or upload was made.

### Final audit fixes

- **Directory privacy:** a bare relative database filename now checks the
  current directory before creation. Subprocess regression fixtures exercise
  both 0700 and 0755 directories, preserving their permissions and refusing
  creation in the shared directory.
- **Complete attachment:** all 11 basic/`_ex` read/write and lifecycle links are
  required. Each attempted library gets a unique attach cookie; all its probes
  remain inert until the readiness map is updated after successful attachment.
  Any failed link or activation drops all owned links and skips the library.
  Older libraries missing required symbols are outside this supported path.
- **Cgroup migration:** calls outside the filter poison a known SSL lifetime
  without retaining their payload. Nested/stale inflight bookkeeping still runs,
  preventing hidden calls from leaving a reusable trusted stream when the thread
  returns to scope. Production-C fixtures cover fully untracked calls, returns
  after reentry, and nesting across scope changes.
- **Shutdown attachment:** all library cookies are disabled before any links
  detach. If any deletion fails, shutdown records conservative capture-control
  loss, skips final ring ingestion, drains already accepted writer events and
  returns the error. The C fixture verifies that a return after disabling cannot
  emit payload and that thread-exit cleanup still marks abandoned inflight loss.
- **Ambiguous accounting inputs:** duplicate Content-Type headers are refused
  in either order, including identical duplicates. Scalar/array usage-details
  parents are malformed; absent/null/empty objects retain their documented
  optional-field semantics. JSON and SSE replay regressions verify no full report
  is invented. The first duplicate-header fixture expected only one invalidation;
  it was corrected to verify both the pending request and connection records.
- **Attribution and scope:** README and DOC explicitly describe Host/path
  attribution and the persistent shared filter. Qualification refuses an existing
  filter pin and requires exclusive use; no running observer's map was cleared.

The same-caliber independent agent reviewed the final source and returned
**PASS as a reviewable implementation draft**, with no unresolved blocking code
defect. It confirmed the attachment, migration, teardown, privacy and parser
fixes. It independently ran `git diff --check` and inspected earlier completed
verification logs; it did not independently execute the full test suites. The
author completed the changed-source reruns below after the review.

### Final completed checks

All checks below finished successfully with exit 0 using the local pinned Rust
1.86.0 environment. Evidence is retained under ignored
`target/implementation-checks/`.

| Check | Result | Evidence |
| --- | --- | --- |
| Workspace tests, locked/offline | **102 passed:** 33 core unit, 21 usage replay, 48 daemon unit; **10 privileged tests ignored** | `resume-final-workspace-tests.log`, `.exit` |
| Workspace/all-target clippy, warnings denied | Passed | `resume-final-clippy.log`, `.exit` |
| Workspace/all-target build, locked/offline | Passed, including BPF compilation and generated skeletons | `resume-final-build-all-targets.log`, `.exit` |
| Production TLS C fixture | Readiness, scope migration, teardown, accepted bytes, retry, nesting, mismatch, exec/PID reuse, exit and loss passed | `resume-final-tls-fixture.log`, `.exit` |
| Rust formatting and `git diff --check` | Passed | Completed command output |
| Local documentation links and qualification Bash syntax | Passed; qualification command was not executed | Completed command output |

`resume-final-source-sha256.txt` identifies the changed source/configuration/test
files checked against source HEAD `88b4ccf`; it excludes historical research
results. Reusable build environments, caches and logs are retained. Workspace
scratch and disposable host-fixture directories are empty.

**Unverified:** live BPF verifier/load acceptance and OpenSSL capture, the remote
CI workflow, real-provider reconciliation, overhead, crash recovery and power-loss
durability. Administrator access was checked: noninteractive sudo requires
interactive authentication, so the live gate was not attempted. The three
synthetic TLS tests and the other seven privileged tests remain unrun. HTTP/2,
new runtime adapters, OTLP, pricing and E1–E8 experiments remain later tracks.

## Completion — 2026-10-15

Claude reviewed the 2026-10-09 working tree on 2026-10-13, then resolved the
findings below and completed the replay ablation on 2026-10-15. Changes remain
uncommitted on `research/accounting-validation` (HEAD `88b4ccf`). No commit,
push, PR or upload was made.

### Review findings and resolution

All four coverage findings were reproduced against the 2026-10-09 tracker
before fixing:

| Finding | Was | Now |
| --- | --- | --- |
| Whole-body buffering | Streams over ~500 tokens and prompts over 128 KiB failed with `body_limit` | Incremental chunked/SSE parsing keeps one line or event; request and other bodies are skipped by length. 5,000-token streams and 2 MB prompts are reported |
| 64 KiB call truncation | Any larger single write was capture loss | An uncaptured tail inside a discarded body is skipped; anywhere else it is reported, never guessed |
| Lifetime cap | 128 lifetimes per daemon run, including every non-provider TLS connection and closed tombstones; then silent | 1,024 live provider lifetimes. Closed lifetimes free their slot; other origins and server-role lifetimes are released; refusal is one explicit row and not sticky |
| Idle expiry | Healthy keep-alive connections expired after 30 s, then every later request was silent | Only lifetimes stuck mid-message expire, after 30 min |
| Checkpoint race | Inventory ahead of consumed records invalidated live streams | Accepted bytes ahead of consumed count as lost only if still missing at the next pass; the shutdown pass is exact |
| Global escalation | A benign `SSL_free` race, nested call or thread exit invalidated every process's open requests | Map lookups that find a closed key are skipped; kernel losses are attributed to their lifetime; only unattributable loss is global |
| Kernel map leak | Lifetimes of processes that exit without `SSL_free` stayed forever | Swept one pass after the process is gone, with an exact final inventory |
| Verifier clamp | `origin/main`'s Ubuntu 22.04 fix (`7d02492`, `7c6191f`) was missing from the rewritten emitter | Ported into `emit()` |

The research question then motivated two recovery rules, measured in the
[loss-recovery ablation](2026-10-15-loss-recovery-ablation.md):

- Each record carries the direction's stream byte offset, so every lost record
  has an exact size. Ring and copy failures no longer bump loss epochs; those
  now mean only unsized activity.
- After an unrecoverable response gap, only the overlapping requests are
  unverified; parsing resumes at the first read entered after the next request
  write. This assumes non-pipelining clients, disables itself when pipelining
  is observed, and labels later rows `observed_after_resync`.

The ablation found one flaw in the first resync version (4 false claims at 1%
loss); it is fixed and covered by a replay test. Contract details are in
[DOC.md](../../DOC.md#current-draft--reported-usage-2026-10-15).

Wire and storage changes in this branch are unreleased. The TLS payload is now
88 bytes (`stream_offset`), and `events_tls_metadata` gains `stream_offset`.
`tsctl status` adds capture-error, closure-loss, unattributed-drop, sweep,
refused and other-origin counters (protocol v2, additive fields).

### Checks — 2026-10-15

All with the project-local Rust 1.86.0 and clang 21.1.8 environment
(`source target/implementation-checks/env.sh`), locked and offline:

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Exit 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | Exit 0 |
| `cargo build --workspace --all-targets` | Exit 0, including BPF objects and skeletons |
| `cargo test --workspace` | Exit 0: 117 passed (33 core unit, 34 usage replay, 50 daemon unit); 10 privileged ignored |
| `python3 experiments/test-tls-inflight.py` | Exit 0: production probe C with mocked helpers, now including offsets, closure loss and reservation failure |
| `git diff --check` | Exit 0 |
| Mutation spot checks | Disabling two-pass unseen inventories, Discard-only skipping, partial-only expiry, partial-only shutdown rows and the resync-time abandonment each fails at least one test |
| Replay ablation, 100 trials | Exit 0; results in the [ablation note](2026-10-15-loss-recovery-ablation.md#results) |

These checks preceded the privileged run below, which found three more
defects. After those fixes every row was rerun with the same results (the
ablation output is byte-identical), except the mutation spot checks, which
cover tracker code the fixes did not touch.

### Privileged qualification — 2026-10-15

Run by the user in a terminal, since sudo needs a password and the assistant
shell has none. Kernel 7.0.0-38-generic, OpenSSL 3.5.5, curl 8.18.0. Synthetic
loopback traffic only, in a `systemd-run` scope that denies non-loopback IP.

| Binary | Tests | Result |
| --- | ---: | --- |
| `tls_e2e` | 3 | Pass: libssl attach; a real curl exchange stored as exactly 5/3/8 with metadata in both directions; no sentinel content in database, WAL, tail or logs; plaintext tail refused |
| `bytes_event`, `connect_event`, `exec_event`, `enrichment` | 4 | Pass |
| `control_e2e`, `control_query`, `store_roundtrip` | 3 | Pass |

The first three runs failed, each exposing a defect the unprivileged suite
could not reach:

1. **`net.bpf.c` failed verification.** Kernel 7.0 removed `tcp_recvmsg`'s
   `addr_len` argument, so the fexit program's fixed return-value slot became
   an invalid context access, and the daemon could not start at all. This is
   also broken on `origin/main`. The program now reads the return value with
   `bpf_get_func_ret` where the kernel has it (5.17+), and otherwise uses the
   pre-5.19 six-argument slot. The previous fixed slot was also wrong on
   5.15–5.18.
2. **`SSL_clear` ended every lifetime before its first byte.** OpenSSL's
   handshake state machine calls `SSL_clear` before every first handshake.
   Treating it as the end of the lifetime left all real traffic untracked
   (`missing_lifecycle`). `SSL_clear` now closes the old generation and opens
   a new one. The host fixture covers handshake clears, reuse after data, and
   clears of untracked objects.
3. **An interrupted ring poll counted as unattributable loss.** The shutdown
   signal interrupted `poll`, which invalidated every open lifetime, though
   nothing had been consumed. EINTR is now ignored, and the final drain uses a
   non-blocking consume.

Two test-side changes made the failures diagnosable. `tsctl tail` now exits
non-zero when the daemon refuses the subscription; it used to print the
refusal and exit 0. The TLS e2e test now reports the daemon's stderr when the
daemon exits early, and a metadata-only summary of stored rows when usage is
missing.

[`experiments/qualify-privileged.sh`](../../experiments/qualify-privileged.sh)
runs every privileged binary this way and supersedes the inline command in
the [review handoff](#claude-review-and-live-qualification).

**Not verified:** the remote CI workflow, other kernels (the CO-RE fallback
for kernels without `bpf_get_func_ret` has not been loaded), real-provider
reconciliation, overhead, crash recovery and power-loss durability. Recovery
under real loss, and the no-pipelining assumption for real SDKs, are open
research items in the
[ablation note](2026-10-15-loss-recovery-ablation.md#next).

### Merging with `origin/main`

`origin/main` is 10 commits ahead of this branch's base (`db648f1`). Its
substantive changes (verifier clamp, upstream bpftool in CI, Rust cache key,
test filter, README history note) are already in this working tree; the rest
are formatting. After committing this work, merge `origin/main`; for
`bpf/tls.bpf.c`, `crates/tsd/tests/tls_e2e.rs`, `.github/workflows/ci.yml`,
`README.md`, `crates/tsd/src/tls.rs`, `crates/tsd/src/control.rs` and
`crates/tsctl/src/main.rs`, keep this branch's version. `bpf/net.bpf.c` merges
cleanly and carries the kernel 7.0 fix to `main`. Then rerun the checks
above. `experiments/results/` stays out of Git: repo-guard blocks result files
as generated artifacts, and the ablation output regenerates deterministically.

## Merged — 2026-10-16

Merged into `main` as PR #2 (`3e983b0`). The remote CI workflow ran on the
Ubuntu 22.04 and 24.04 runners and passed: fmt, clippy, build, 117
unprivileged tests and all 10 privileged tests as root, including the three
TLS tests. That adds two runner kernels to the local 7.0 qualification; the
workflow does not log their versions.

Still not verified: the CO-RE fallback for kernels without `bpf_get_func_ret`
(5.15/5.16), real-provider reconciliation, overhead, crash recovery and
power-loss durability. The open research items are in the
[ablation note](2026-10-15-loss-recovery-ablation.md#next).

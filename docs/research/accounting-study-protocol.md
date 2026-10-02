# Passive LLM usage accounting: study protocol

Protocol v2.0, 2026-09-29. Author: Hoang Le. Venue undecided.
Status: design and implementation; no live eBPF results yet.

## Research target

Where do host-side eBPF observers lose or misassign **provider-reported usage
per network attempt**, and how reliably do their outputs represent insufficient
evidence? Compare pinned OBI and agtap with a server ledger and an application
ledger. The application reference validates the workload; it is not a passive
competitor. TokenScope's raw capture is not yet a complete usage-accounting tool.

Do not claim to infer remote billed totals, untransmitted task identity, or
novelty of HTTP/2 parsing. Missing counts are unknown, not zero. A negative result
is an acceptable answer. The [initial review](2026-09-29-accounting-validation.md)
records related work and information limits.

## Questions and hypotheses

- RQ1: What fraction of attempts with emitted usage have exactly recovered input
  and output counts and the correct response/attempt identity?
- RQ2: How do missing usage, interruptions, retries, body limits, late attachment,
  and capture pressure change coverage and error?
- RQ3: When evidence is insufficient, does an observer omit the value, mark it
  incomplete, report a zero, or assert an incorrect exact value?
- RQ4: What runtime and process CPU/RSS overhead occurs in supported conditions?

Null expectation: complete supported captures recover the emitted usage exactly.
An implementation defect must repeat across seeds and survive configuration
checks. A documented unsupported protocol is a coverage limit, not a discovered
bug. Unknown usage is not an accounting error by itself.

## Independent evidence

Each run stores these separately:

1. Server ledger: received opaque attempt ID, connection/stream ID, HTTP status,
   response ID, synthetic usage, whether final usage was emitted, and termination.
2. Application ledger: task-to-attempt mapping, client-observed completion,
   cancellations and retry decisions. Task IDs never appear in the traffic.
3. Observer output: original JSONL/OTLP exports and startup/error logs.
4. Provenance: protocol/script/dependency hashes, baseline binary/tag/source hashes,
   runtime/kernel, parameters, timing and process resource summaries.

No scorer joins observations by token counts or response arrival order. Join
using an exported response ID; other identity evidence must be documented and
scored separately. An unmatched record is retained, not assigned optimistically.
Duplicate exports of the same response ID must be detected; conflicting duplicates
are errors. Do not sum cumulative stream updates as separate attempts.

The mock endpoint uses loopback TLS with a generated fixture CA, HTTP/1.1 and
HTTP/2 ALPN, OpenAI-compatible SSE shapes, and no external API calls. Synthetic
token counts are assigned by the server, not produced by a model. This evaluates
capture and accounting, not provider tokenizer correctness or real invoices.

## Core matrix

One client process (Python/OpenSSL or Go/net/http), one local mock server and
one observer at a time. The Go client independently validates the supported
OBI HTTP/2 library path; it does not use hyper-h2. HTTP/1.1 uses concurrent
connections; HTTP/2 uses interleaved streams on
one connection. Concurrency: 1, 8 and 32. Seed governs schedules and distinct
usage values. Use 10 fixed seeds (0–9) for the initial comparison; unsupported
cells remain in the coverage table and are excluded from supported-case errors.

| Scenario | Controlled change | Expected observable evidence |
| --- | --- | --- |
| complete | All usage delivered with stream end | Exact per-attempt usage |
| no-usage | Completed SSE response omits usage | Usage unknown despite HTTP success |
| cancel | Client cancels before final usage, including HTTP/2 RST_STREAM | Partial response; usage unknown |
| disconnect | Server closes/reset before final usage | Partial response; usage unknown |
| large-body | 96 KiB response content before usage | Exact if configured capture includes the tail |
| retry | One HTTP 429 attempt followed by a successful attempt in the same task | Separate attempt inventory; final success usage; no guessed retry grouping |
| late-attach | Observer starts after one completed warm-up exchange on a persistent connection | Coverage depends on recoverable protocol state; record documented limits |
| pressure | Bursty responses at the selected concurrency, with bounded large bodies | Measure actual loss/pressure; do not assume dropped BPF events |

Add an explicit reported-zero control to distinguish zero from missing usage.
Run an unobserved control and each baseline, using supported opt-in body capture
and bounded local output. Record configuration and maximum buffers. Disable
unneeded telemetry and select only fixture processes. No public collectors,
credential files, unrelated process payloads, or GPU inference are involved.

Small screen: complete/no-usage/cancel/retry, concurrency 1/8, two seeds and both
protocols. The host launcher runs control and OBI. agtap requires a dedicated
VM/test kernel: pinned v0.1.0 attaches system-wide JSON pipe kprobes even with
`-p`; its PID filtering for pipe events happens after capture in userspace.
See [attachment code](https://github.com/zhebrak/agtap/blob/1ad473cd78d3803a729fb4aa8018ef09a426060c/agtap/src/main.rs)
and [pipe capture](https://github.com/zhebrak/agtap/blob/1ad473cd78d3803a729fb4aa8018ef09a426060c/agtap-ebpf/src/main.rs).
Do not run that release directly on the shared workstation. A container shares
the host kernel and does not provide the necessary isolation. An isolated
comparison must run both baselines in that environment for comparable overhead.
Confirm installation and successful HTTP/1.1 usage capture before
interpreting unsupported HTTP/2 cells. Start-up failures are infrastructure
failures and cannot become zero-coverage measurements.

## Metrics and inference

- Attempt recall: matched unique observed attempts / server-received attempts.
- Exact-usage coverage: correctly matched counts / attempts with emitted usage.
- Incorrect usage: wrong nonmissing counts or conflicting duplicates.
- Unknown usage: absent counts, separately for emitted and nonemitted usage.
- Unmatched and duplicate records: explicit counts, never discarded silently.
- Unsupported cells and observer startup failures: separate statuses.
- Evidence/completeness claims: compare only explicit tool signals; absence of a
  completeness flag is "not exposed", not a fabricated detector result.
- Reported-token aggregation error: observed versus emitted totals, with missing
  attempts disclosed; also report per-attempt absolute error to avoid cancellation.
- Overhead: paired workload duration, observer/client CPU, peak RSS. All process
  resources are scoped to benchmark children. Do not extrapolate from mock token
  counts to a GPU serving workload.

The independent unit for uncertainty is a run/seed, not an individual correlated
stream. Preserve all trial rows. Bootstrap run-level metrics within supported
protocol/scenario/concurrency cells when there are enough repetitions. With only
two screening seeds, show raw outcomes and no confidence interval. A zero observed
error rate does not prove a universal zero error rate.

## Decision and follow-up

Freeze protocol and software hashes before confirmatory trials. Changes after
screening require a protocol revision and a dated explanation; screening rows
stay distinct from confirmation rows. Stop on client/server ledger mismatch,
unsupported privilege/kernel environment, unexpected external traffic, or an
unbounded output/resource condition. Preserve failed-run diagnostics.

Continue toward a paper if a supported-case gap repeats, or if the comparison
produces useful evidence on operational completeness beyond already documented
feature gaps. A new recovery mechanism needs an ablation against the strongest
baseline. If results only confirm ordinary unsupported HTTP/2/body capture,
publish a clearly scoped technical artifact/report rather than claim a new
systems mechanism. Extend to a second client runtime and another kernel before
making broad portability claims.

## Publication and AI disclosure

Prepare a self-contained manuscript, bibliography, raw/derived-data manifest,
figures and reproduction instructions. Select venue after results. Publication
requires a chosen destination and account access; no upload has occurred.

Hoang Le is the human author. Credit GPT and Claude in an AI-assistance statement
that names actual contributions. GPT has assisted with literature triage,
experimental design and harness implementation. Claude's study-specific review
is pending; do not imply it has happened. Human review of final claims and
publication metadata remains pending. AI tools are not listed as human authors.

## Revisions and screening diagnostics

- v1.1: source review found agtap's system-wide pipe capture. Require an isolated
  kernel for that baseline; the shared-host launcher runs control and OBI only.
- v1.2: the first host screen completed both controls and the HTTP/1.1 OBI
  workload, but the collector rejected protobuf while expecting JSON. Retain
  that run as invalid export evidence, not an accuracy result. Add the official
  OTLP protobuf schema, retain original request bodies and normalize decoded
  traces for scoring. Configure `http/protobuf` explicitly and test real HTTP
  acknowledgments, including reported zero and omitted fields.
  OBI's mandatory cloud metadata detectors also attempted link-local lookups;
  place each observer in a transient systemd unit allowing only loopback IP
  traffic and override fixture host identity. This changes transport handling
  and network containment, not hypotheses, scenarios, token assignment or
  identity-matching rules. Preserve startup/configuration logs. The old artifact
  is a dated preliminary fixture snapshot, not confirmation of this revision.
- v2.0: the qualified Python screen recovered all 36 emitted usages exactly
  across 90 HTTP/1.1 attempts, with the other 54 unknown, and no GenAI records
  for Python HTTP/2. The latter is documented as unsupported. Add a Go standard
  library client to test OBI's supported HTTP/2 path before claiming a new gap.
  Strengthen late attachment to follow a full completed warm-up request/response
  in both runtimes; keep warm-ups in the independent ledgers but out of scored
  trial denominators. Export identity/usage attributes without message content
  to bound trace output. Snapshot exact source in each run before execution.
  These are post-screening design revisions; do not pool the earlier two-seed
  screen with ten-seed confirmatory rows or claim that it tested the revised
  late-attachment condition. The first screen's exact source was not snapshotted;
  its recorded hashes and original exports remain engineering diagnostics.

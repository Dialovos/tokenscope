# Loss-recovery ablation (E4)

Date: 2026-10-15. Answers the main question of the
[2026-10-08 research](2026-10-08-improvement-research.md): can connection-level
loss evidence and conservative reconstruction stop confidently wrong usage
without throwing away too much recoverable usage?

**Answer, in replay:** yes, but only with recovery. Loss evidence plus "any
loss invalidates the connection" made no false claims and kept just 12–62% of
the usage whose own bytes were never damaged. Adding exact gap sizes and
response resync kept 94.5–99.8% with no false claims in any cell. Parsers
without loss evidence kept more raw coverage but made up to 70 false claims per
7,200 requests, misattributing up to about a million tokens.

This is a deterministic simulation of the capture stream, not live capture.
The live probes now pass privileged qualification on synthetic loopback
traffic ([record](2026-10-08-improvement-implementation.md#privileged-qualification--2026-10-15)),
but no live run has measured loss rates or exercised recovery.

## Method

[`usage_ablation.rs`](../../crates/ts-core/examples/usage_ablation.rs) builds
synthetic agent traffic and encodes it exactly as `tls.bpf.c` emits it, then
replays it through `UsageTracker`.

- **Workload.** Each trial runs 6 keep-alive HTTP/1.1 connections with 12
  sequential requests each. Prompt bodies are 0.5–4.5 KB (50%), 5–45 KB (30%),
  60–200 KB (15%) or 200–600 KB (5%). Half the connections write a request in
  one call; the rest write 16 KiB at a time. Responses are 70% SSE and 30% JSON.
  SSE completions run 20–600 tokens, one ~245-byte event per read. 10% of
  streams omit usage and 3% of requests get a 429. Every true usage on a
  connection is distinct, so swapped attempts are detectable.
- **Capture model.** 4 KiB chunks and 64 KiB per-call capture, per-direction
  call sequences and byte offsets, entry and return times on one clock, closure
  records at the end. After every round, an inventory pass is inserted up to 3
  records before the round's end, so it races with records still in transit.
- **Faults.** These are the loss kinds the design can size:
  - *Kernel ring:* each call fails reservation with probability *p*, from a
    random chunk onward.
  - *Queue drop:* each record is dropped with probability *p*. A dropped
    closure is signalled up to 64 records early, as the writer can drain that
    signal before older queued records.

  *p* ∈ {0.05%, 0.2%, 1%}, plus a no-fault control.
- **Observers.** Each replays the same stream:
  - *Full recovery:* sequences, offsets and inventories; skips sized gaps in
    discarded bodies and resyncs responses.
  - *Sized-gap skip only:* full recovery without resync.
  - *Conservative invalidation:* any lost record invalidates its lifetime. This
    is the first implementation's rule.
  - *Chunk metadata only:* the pre-improvement metadata. Calls are renumbered in
    arrival order, so whole lost calls are invisible, but missing chunks inside
    a call are not.
  - *Naive:* bytes in arrival order, damaged calls re-formed from whatever
    chunks arrived. It still uses this project's strict HTTP/JSON parser; a
    lenient parser would do worse.
- **Scoring.** An observation claims "request *k* on this connection had usage
  *X*". *Exact* means a `reported` row whose counts equal request *k*'s truth.
  *False complete* means a `reported` row whose counts differ; every one here
  is a misassociation to another request's counts. A request is *undamaged*
  when none of its own records were lost. *Kept of undamaged* = exact undamaged
  / undamaged with usage.
- **Scale.** 100 trials; 7,200 requests and 6,483 true usages per cell. Seeds
  are fixed, so reruns are identical.

## Results

Raw cells: `experiments/results/2026-10-15-usage-ablation.json`, SHA-256
`bf8b47796ab52077ae55bfbdf0d16a4d99e5668b594072659cdb88f29f904ebd`. Result
files are generated artifacts and stay out of Git; the [command
below](#reproduce) regenerates this one byte for byte.
With no faults, every observer was 100% exact, so the racing inventory passes
caused no false invalidations. The table omits the four duplicate no-fault rows.

| Fault | Rate | Observer | Exact (of 6,483) | Kept of undamaged | False complete | Misattributed tokens |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| None | 0% | Full recovery | 6,483 | 100.0% | 0 | 0 |
| Kernel ring | 0.05% | Full recovery | 5,859 | 99.8% | 0 | 0 |
| Kernel ring | 0.05% | Sized-gap skip only | 3,500 | 59.6% | 0 | 0 |
| Kernel ring | 0.05% | Conservative invalidation | 3,471 | 59.2% | 0 | 0 |
| Kernel ring | 0.05% | Chunk metadata only | 6,368 | 98.6% | 2 | 14,446 |
| Kernel ring | 0.05% | Naive | 6,373 | 98.6% | 2 | 14,446 |
| Queue drop | 0.05% | Full recovery | 5,830 | 99.6% | 0 | 0 |
| Queue drop | 0.05% | Sized-gap skip only | 3,650 | 62.4% | 0 | 0 |
| Queue drop | 0.05% | Conservative invalidation | 3,586 | 61.6% | 0 | 0 |
| Queue drop | 0.05% | Chunk metadata only | 6,251 | 97.1% | 0 | 0 |
| Queue drop | 0.05% | Naive | 6,279 | 97.1% | 0 | 0 |
| Kernel ring | 0.2% | Full recovery | 4,478 | 98.5% | 0 | 0 |
| Kernel ring | 0.2% | Sized-gap skip only | 1,204 | 26.5% | 0 | 0 |
| Kernel ring | 0.2% | Conservative invalidation | 1,196 | 26.4% | 0 | 0 |
| Kernel ring | 0.2% | Chunk metadata only | 6,057 | 94.5% | 9 | 75,866 |
| Kernel ring | 0.2% | Naive | 6,071 | 94.5% | 9 | 75,866 |
| Queue drop | 0.2% | Full recovery | 4,478 | 99.0% | 0 | 0 |
| Queue drop | 0.2% | Sized-gap skip only | 1,250 | 27.5% | 0 | 0 |
| Queue drop | 0.2% | Conservative invalidation | 1,194 | 26.7% | 0 | 0 |
| Queue drop | 0.2% | Chunk metadata only | 5,692 | 89.7% | 21 | 95,842 |
| Queue drop | 0.2% | Naive | 5,766 | 89.7% | 22 | 132,859 |
| Kernel ring | 1% | Full recovery | 2,492 | 96.7% | 0 | 0 |
| Kernel ring | 1% | Sized-gap skip only | 332 | 13.0% | 0 | 0 |
| Kernel ring | 1% | Conservative invalidation | 325 | 12.8% | 0 | 0 |
| Kernel ring | 1% | Chunk metadata only | 5,053 | 80.4% | 67 | 906,810 |
| Kernel ring | 1% | Naive | 5,108 | 80.4% | 70 | 1,065,295 |
| Queue drop | 1% | Full recovery | 2,433 | 94.5% | 0 | 0 |
| Queue drop | 1% | Sized-gap skip only | 343 | 13.2% | 0 | 0 |
| Queue drop | 1% | Conservative invalidation | 299 | 12.5% | 0 | 0 |
| Queue drop | 1% | Chunk metadata only | 3,631 | 60.5% | 28 | 798,486 |
| Queue drop | 1% | Naive | 3,878 | 60.5% | 35 | 1,018,875 |

## Findings

1. **Invalidation alone is too expensive.** One lost record ends parsing for
   the rest of a keep-alive connection. Coverage of undamaged usage fell to
   59–62% at 0.05% loss and 13% at 1%. Zero false claims is not enough when
   most usage silently becomes "unverified".
2. **Exact gap sizes alone barely help this workload.** Most calls are SSE
   reads, so most losses land in response streams, where a known length does
   not restore framing. Skipping sized gaps in discarded bodies (mostly
   prompts) moved coverage by about one point.
3. **Response resync recovers almost everything without wrong claims.** After
   a response gap, only requests whose responses may overlap the lost bytes
   are reported unverified. Parsing resumes at the first read that entered
   after the next request's write. It kept 94.5–99.8% of undamaged usage, with
   no false claims across 43,200 requests under loss and 600 trials.
4. **Without loss evidence, framing checks hide most but not all errors.**
   The strict parser caught most corruption, which is why the baselines look
   good at 0.05%. Their remaining errors are all shifted attempts: one
   request's real counts reported for another. These grow with loss (2 → 70
   per cell), and aggregate token totals would not reveal them.
5. **Most of the coverage gap to naive is unprovable.** Naive also reports many
   *damaged* requests correctly, because lost SSE content events rarely change
   the final usage. Claiming those would need an alignment assumption (lost
   reads are whole chunk frames) that this simulation satisfies by
   construction, so it cannot test it.

During this experiment, the first resync version made 4 false claims at 1%
loss. Request *k*'s response was lost entirely while resync was waiting for
it, and the next response was credited to *k*. A gap revealed during resync by
a read that entered after the resume point now abandons the awaited request
too. The replay test `a_response_lost_while_resyncing_moves_the_resume_point`
reproduces the case, and the published table is from the fixed version.

## Limits

- **Simulation, not capture.** The probes load and capture a real exchange,
  but real loss rates, and recovery under real loss, are unmeasured.
- **Assumptions hold by construction.** Clients never pipeline, which response
  resync relies on. Each SSE event arrives in its own read. The in-transit
  window is at most 3 records, well inside one inventory pass.
- **Not every loss kind is injected.** Unsized losses (nested or out-of-scope
  calls) and unattributable losses are absent. Both invalidate by design, so
  the coverage figures are upper bounds for workloads that have them.
- **Truth is exactly knowable.** Every usage on a connection is distinct;
  identical counts on retries would hide swaps from this scorer.
- **Counts are pooled.** Trials are the independent unit; requests within a
  connection are correlated. Zero false claims in 600 faulted trials bounds
  the per-trial false-claim rate below about 0.5% (rule of three) for these
  conditions only.
- **One protocol.** HTTP/1.1, one provider shape, one process per connection.

## Next

- Run fresh-observer repetitions (E1) under load, with injected ring
  pressure, and record live loss counters and recovery outcomes.
- Check the no-pipelining assumption against the actual SDKs (OpenAI Python
  with httpx, curl) with an intact-capture trace per client.
- Decide whether alignment-based recovery of damaged responses is worth an
  explicit, separately labelled claim, and test it with reads that split and
  merge chunk frames.

## Reproduce

```sh
cargo run --release -p ts-core --example usage_ablation -- 100 \
  > experiments/results/2026-10-15-usage-ablation.json
sha256sum experiments/results/2026-10-15-usage-ablation.json
```

Runs in about 40 seconds on one core and needs no root or network.

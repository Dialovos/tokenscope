# Accounting study: execution and analysis notes

2026-09-29. These notes supplement frozen protocol v2.0 without changing the
measured runner, fixture, scorer or Go binary during an experiment.

## Exclusive execution

Two confirmation launchers started 26 seconds apart. Their Go screen and main
executions overlapped; the main directories ending `22-16-13Z-go-main` and
`22-16-39Z-go-main` have exclusion records. All their evidence is retained, and
their corresponding screens are diagnostic only. The targeted stop helper
stopped their runner process trees and observer services. The launchers now
share an exclusive file lock. The run beginning `22-24-26Z` was checked with one
active study runner and the lock held. Its clean Go HTTP/1.1 and HTTP/2 usage
checks passed before the main matrix began.

## Statistical unit and workload history

The frozen runner batches ordinary cases into one observer/client session per
protocol. Its ten seed cells are repeated synthetic workload conditions, not
ten independently restarted observer runs. Ordinary Go commands create a fresh
transport and close its idle connections afterward; the shared observer and
client-process state can carry across earlier cases. Seed-cell means and ranges are descriptive;
ordinary-case confidence intervals are suppressed. Sequential control/observer
timings also do not establish a causal production overhead estimate.

Late-attachment cells each use a fresh worker and observer, following a completed
warm-up exchange on that worker's connection. Ten such repetitions permit the
specified run-level bootstrap, subject to the fixed-workload and one-host limits.
The analysis records this distinction explicitly. A calibrated ordinary-case
uncertainty estimate needs fresh observer/client repetitions. Attributing a
failure specifically to cancellation, retry or connection reuse also needs a
targeted follow-up that controls prior session history.

The reported late-attachment support label inherits the runtime/protocol's
ordinary-batch qualification. It is not a separate positive control for every
fresh late observer. Those observers intentionally begin after the completed
warm-up; an additional independently identifiable control would be needed to
distinguish their individual readiness from late-attachment recovery.

## Go screening finding and possible mechanism

The exclusive Go HTTP/2 screen recovered 27 of 36 emitted usages exactly and
contained four conflicting response identities. Conflicting values are present
in decoded original OTLP spans. One response assigned `(51, 359)` input/output
counts was exported both with that pair and with `(138, 414)`, the assigned pair
of another stream. The scorer joins by identity throughout; comparing values
here is diagnosis, not reassignment of evidence.

The pinned baseline's
[Go payload capture](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/3cc19862cef1abdaaeaa2a6387b462d31822010e/bpf/gotracer/go_large_buffer.h)
reads a stream ID at a fixed offset near the start of a captured buffer and
documents assumptions about read alignment. Its
[OpenAI SSE parser](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/3cc19862cef1abdaaeaa2a6387b462d31822010e/pkg/ebpf/common/http/openai_stream.go)
keeps the first response ID while merging subsequent usage. This suggests a
possible path from an incorrectly associated payload to an incorrect count.
It is an inference from source, not a measured root cause. Demonstrating it
requires observing or controlling TLS read/frame boundaries and an ablation.
An existing documented alignment limitation may explain a symptom; it cannot
be presented as a newly invented stream-disambiguation problem.

The long Go HTTP/2 ordinary batch did not reproduce clean usage capture in its
first ten concurrency-one requests, although generic HTTP spans were exported.
Its fixture/export checks pass, but those rows are labeled diagnostic with
`clean_usage_not_reproduced_in_this_session`; they cannot supply a qualified
baseline error rate. Qualification in an earlier screen does not qualify a new
observer session automatically. The analysis independently checks each session
and suppresses its qualified-case uncertainty claims when that check fails.
This calls for an active clean-usage gate and targeted timing/state checks in
a follow-up, rather than interpreting every missing GenAI record as an error.

## Portable evidence

Original protobuf bodies, decoded exports and host logs remain local. The
artifact builder retains independent synthetic ledgers, scores, measured source
snapshots and original evidence hashes. Portable OTLP JSON keeps accounting
attributes and opaque span IDs and removes resource/scope metadata. A direct
comparison verifies that every normalized accounting observation is unchanged,
including unmatched records and conflicting duplicates. Generic diagnostics
in portable scores are replaced by their count. These transformations are
recorded in artifact provenance; they are not claimed to be original export bytes.

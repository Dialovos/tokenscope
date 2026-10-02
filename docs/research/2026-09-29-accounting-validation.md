# Accounting research question: initial validation

Reviewed and piloted on 2026-09-29. Status: **conditional go for a comparative
measurement study; novelty is not established**.

## Decision

The original question was:

> How accurately can an external observer attribute tokens and cost to individual
> agent requests under concurrent HTTP/2 streams, retries, and cancellations?

It combines three different problems. HTTP/2 request identity is established
protocol machinery. Extracting provider-reported token usage is already
implemented by observability tools. Exact remote billing totals and application
retry/task relationships can be unidentifiable when the necessary evidence never
reaches the observer. A universal exact-accounting claim is therefore unsuitable.

The targeted literature search did not locate a paper evaluating the full
combination against independent attempt, usage, and task ledgers. This is a
provisional search result, not proof that no such paper exists. Existing software
is substantial prior art even without an associated paper.

A narrower candidate question is:

> Across concurrent streaming workloads and controlled capture failures, how much
> provider-reported usage can host-side eBPF tools correctly recover per wire
> attempt, and how reliably do they identify incomplete or ambiguous accounting?

Continue only through a small comparison with existing tools before investing in
the broad platform roadmap. HTTP/2 support, summing token fields, and representing
missing usage as unknown are already known techniques. A publishable contribution
would need useful new measurements or a demonstrated improvement over baselines.

## Prior work checked

These are primary sources. Repository documentation refers to the moving `main`
branch reviewed on the date above, not a pinned release or a reproduced result.
Pin actual baseline versions before collecting comparative measurements.

| Source | What it already answers | What this review did not establish |
| --- | --- | --- |
| [AgentSight, arXiv v2](https://arxiv.org/html/2508.02736v2), August 2025; abstract lists PACMI 2025 | TLS capture, SSE reconstruction, system-event correlation, agent failure case studies. Evaluation measures workflow overhead and detection examples. | A controlled study of per-attempt token accounting under multiplexing, lost usage events, and cancellation. |
| [eInfer](https://jianchang.su/uploads/eInfer.pdf), eBPF workshop 2025 | Distributed inference performance tracing and cross-layer request correlation. | Cloud API token/billing reconciliation under the proposed failure matrix. |
| [ProfInfer](https://arxiv.org/abs/2601.20755), accepted MLSys 2026 | Operator-level profiling of local inference engines. | The cloud streaming accounting question. |
| [eBeeMetrics, arXiv v1](https://arxiv.org/html/2603.25067v1), accepted ISPASS 2026 | gRPC stream disambiguation with transport/stream IDs via library uprobes; latency and throughput accuracy comparisons. | LLM usage-field completeness or bill attribution. This rules out treating multiplexed request disambiguation itself as new. |
| [OpenTelemetry eBPF Instrumentation features](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/devdocs/features.md) | GenAI token extraction; omission of missing usage while preserving reported zero; HTTP/2 tracing. Documentation limits HTTP/2 body capture to Go clients and says streaming counts require captured usage events. | Measured accounting accuracy across our proposed conditions. Generic HTTP/2 span support does not establish generic GenAI response-body coverage. |
| [agtap](https://github.com/zhebrak/agtap) | LLM/MCP tracing, streaming usage extraction, terminal UI and exports. Documents HTTP/1.1-only reconstruction and unsupported TLS runtimes. | HTTP/2 support or a comparative accounting evaluation. An unsupported-protocol result would confirm a known limitation, not discover a new failure. |
| [LLM-SLO-eBPF-Toolkit](https://github.com/ogulcanaydogan/llm-slo-ebpf-toolkit) | Controlled fault injection and accuracy/confidence evaluation for SLO fault attribution using kernel signals and application spans. | Token-to-attempt or token-to-task accounting. Its attribution target is the fault domain, not the owner of token usage. |
| [async-batch-llm token-aware admission](https://github.com/geoff-davis/async-batch-llm/blob/main/docs/token-aware-admission.md) | Application-side retry accounting, known-zero versus unknown usage, and cancellation-aware reconciliation. | Passive capture accuracy. This establishes that distinguishing unknown usage and accounting for retries are existing ideas. |

Additional adjacent work was inspected at abstract or project-description level:

- [Silent-Bench](https://zenodo.org/records/20128451), a May 2026 preprint, audits
  API gateway behavior and reported billing anomalies through active API probes.
  Its description does not establish passive HTTP/2 capture-failure accuracy.
- [Auditing Token Padding and Token Accounting](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=7050418),
  posted July 2026, compares verbosity and provider token counts with a common
  tokenizer. Its abstract addresses a different accounting target.
- [AgentTelemetry](https://github.com/Krishnachaitanyakc/AgentTelemetry) lists an
  AIware 2026 paper and a fault-detection benchmark using application telemetry.
  The inspected project description addresses agent fault classes rather than
  passive stream-to-usage reconstruction. The ACM full text was inaccessible.

[RFC 9113](https://www.rfc-editor.org/rfc/rfc9113.html) defines HTTP/2 framing and
stream identifiers. Decoding stream identity from complete plaintext is a
protocol implementation problem, not a new LLM mechanism.

The generic search families included `eBPF LLM HTTP/2 token attribution retries`,
`LLM token accounting observability accuracy concurrency`, `eBPF HTTP/2 multiplexing
tracing paper`, `LLM eBPF token cancellation benchmark`, and `LLM observability
identifiability tokens`, followed by inspection of the primary sources above.
This was a targeted web search, not an exhaustive systematic review or a survey
of every tool's implementation and test suite.

## Define the target before measuring it

Keep these quantities separate:

1. **Wire attempt:** a protocol request, keyed by connection lifetime and HTTP/2
   stream ID. Retries create additional attempts. Stream IDs and process IDs
   alone are insufficient across connections and process lifetimes.
2. **Reported usage:** counts the provider puts in an observed response. A
   completed response can omit them. Visible text chunks are not necessarily
   tokens, and tokenizing text does not recover hidden reasoning or cache usage.
3. **Logical task:** the application's grouping of attempts into an agent task
   or a retry chain. An application ledger can reveal this; identical requests
   alone cannot establish it. Mark unresolved grouping explicitly.
4. **Billed usage/cost:** authoritative provider accounting. Reported counts with
   a fixed pricing fixture can validate arithmetic, not real invoices. Treat
   cache classes and pricing versions separately when adding cost evaluation.

If two possible executions produce identical observations but have different
target values, no observer using only those observations can always output the
correct target. For example, after a stream is interrupted before final usage,
two remote executions may have different unseen totals. Similarly, two identical
request/response attempts might represent two independent tasks or a validation
retry within one task. These are information limits, not empirical claims about
any provider's cancellation or billing policy.

## Pilot actually run

The runnable experiment is [accounting-pilot.py](../../experiments/accounting-pilot.py).
Its [raw report](../../experiments/results/2026-09-29-accounting-pilot.json) records
the interpreter, pinned dependency versions, script hash, parameters and outcomes.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r experiments/requirements.txt
.venv/bin/python experiments/accounting-pilot.py \
  --output experiments/results/2026-09-29-accounting-pilot.json
```

The generator uses hyper-h2 4.3.0 to create HTTP/2 SSE responses and randomly
interleaves stream DATA frames. An ideal hyper-h2 receiver with complete initial
connection state recovers per-stream bodies. The fixture ledger assigns distinct
usage counts; no model or tokenizer generates them.

The complete-capture matrix uses 1, 8 and 32 simultaneous streams, five scheduling
seeds and 1-, 64- and 4096-byte replay fragments: 45 configurations containing
615 synthetic attempts in total. These are protocol fixtures, not 615 live API
calls or independent performance trials.

| Condition | Attempts | Exact reported usage | Unknown usage |
| --- | ---: | ---: | ---: |
| Complete interleaved capture | 615 | 615 | 0 |
| Explicit reported zero | 2 | 2 | 0 |
| Completed stream without usage | 1 | 0 | 1 |
| Interrupted before final usage | 1 | 0 | 1 |
| One usage DATA frame omitted | 8 | 7 | 1 |
| One modeled plaintext call capped at 64 KiB | 1 | 0 | 1 |

The script checks each observation against its fixture ledger. It also constructs
an interrupted trace compatible with hidden output totals of either 11 or 999,
and a complete two-attempt trace compatible with either one or two logical tasks.
The first pair has identical observed bytes and decoder output despite different
hidden ledgers. The second exposes complete per-attempt usage but no task mapping.

Interpretation: complete framing and usage metadata make transport multiplexing
recoverable in this idealized setting. Missing evidence prevents stronger claims.
Unknown is not zero. These are feasibility controls and counterexamples, not a
novel accounting method or measurements of existing tools.

Limitations: no eBPF probes, TLS encryption, sockets, real cancellation frames,
TokenScope daemon, competitor binaries, cloud APIs, inference, invoices, or
overhead were tested. The decoder receives all initial HTTP/2/HPACK state.
Dropping an entire usage frame models lost evidence, not arbitrary byte loss or
real ring-buffer behavior. The capture-cap fixture deliberately groups a long
response into one modeled plaintext call; it does not establish how a real TLS
library sizes calls. Both generator and reference decoder use hyper-h2, so this
is not independent validation of its protocol implementation. Loss flags in the
report are harness truth, not demonstrated per-stream fault detection by a tool.

## Consequences for TokenScope

The current shipped design captures raw OpenSSL plaintext, capped at 16 chunks
of 4 KiB per call. Provider parsing and HTTP reassembly are deferred. It captures
attempted SSL writes at entry, so failed/retried TLS writes must not automatically
be treated as distinct successful HTTP requests. CLI queries and the DuckDB sink
are useful infrastructure but do not answer this accounting question.

See [DOC.md](../../DOC.md) for the implemented scope,
[TLS capture](../../bpf/tls.bpf.c) for emission/caps, and
[the event schema](../../bpf/ts_event.h) for identifiers. A TLS call ID is not an
HTTP request ID. Aggregate drop counters also do not establish which stream lost
evidence. Any prototype must define connection lifetimes, stream identity and
incompleteness before claiming per-request accuracy.

## Next experiment and decision gate

1. Build a local TLS mock server and real Python/OpenSSL HTTP/2 client with
   independent application-task, server-attempt and provider-usage ledgers. Give
   the observer neither hidden task IDs nor the server ledger. Run HTTP/1.1 controls
   and HTTP/2 multiplexing at 1/8/32 concurrent streams. Observe only fixture PIDs.
2. Pin and run OBI and agtap with supported configurations. Inspect their relevant
   parsing tests/source first. Report documented unsupported combinations separately
   from errors in claimed supported configurations. TokenScope currently has no
   usage parser and is a capture baseline, not a finished accounting competitor.
3. Add real client cancellation (`RST_STREAM`), omitted final usage, body caps,
   late attachment, deliberate capture loss and retry-after-error/validation.
   Keep attempt totals separate from task-grouping accuracy and hidden billing.
4. Measure attempt recall, stream misassignment, exact-usage coverage, incorrect
   values, unknown rate and false assertions of completeness. Show accounting
   error over all attempts as well as over the recoverable subset. Repeated
   schedules must expose uncertainty; fixture success rates are not production
   guarantees. Only the live observer stage can measure latency/CPU overhead.
5. Proceed with a paper direction only if repeated measurements show a material
   unresolved failure in supported cases, or a useful comparative result beyond
   documented feature gaps. A new mechanism then needs an ablation against the
   strongest baseline. If a matching prior study or existing implementation
   already resolves the narrowed target, stop that novelty claim and consider
   contributing the fixtures upstream.

**Current conclusion:** the question is partly answered; the combined empirical
evaluation was not located in this review. The pilot makes a small baseline
comparison worth doing. It does not yet justify a paper claim or a platform build.

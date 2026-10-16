# Independent audit of improvement research

Audit date: 2026-10-08, workspace local date. Reviewer: independent Codex agent
`tokenscope_research_audit`, using the same inherited model configuration as
the research author, with no model override. This is an AI review, not a human
or Claude review.

Subject: [improvement research](2026-10-08-improvement-research.md) and its
[README](../../README.md) link. Reviewed source HEAD: `88b4ccf` on
`research/accounting-validation`. Research document SHA-256 at audit intake:
`22a816a3e2e95701f6c639f4da2611f13b07d53875d07fe778f0ed3df5db9003`.
Line references below identify that 400-line version, which was not changed
during the audit.

## Verdict

**PASS as improvement research.** The independent reviewer found no blocking
factual or methodological error. The report appropriately distinguishes local
source concerns, historical synthetic measurements and proposed experiments.
Its priority on privacy and trustworthy reported-usage accounting is supported.

This verdict does not validate a new accounting method, prove production
reliability or qualify an implementation for deployment. Operational frequency
of the source concerns remains unmeasured. A future implementation plan should
incorporate the following two non-blocking requirements.

## Findings

### Medium: Make the privacy gate cover every event family

Research lines 86–98 propose minimized TLS accounting persistence. Command-line
privacy is mentioned separately at lines 205–210, under F7; the preferred first
implementation scope at lines 398–400 names F1–F6. That separation could leave
command-line handling outside the first privacy change.

The current writer passes command lines into persistence through
[sink.rs](../../crates/tsd/src/sink.rs), around line 219, and
[store.rs](../../crates/tsd/src/store.rs), around line 143. Command lines can
contain credentials and private content. This supports the report's concern;
the finding is a scope clarification rather than a factual contradiction.

Smallest future-plan revision: explicitly apply default minimization to TLS,
process/network metadata, logs and exports. Add synthetic command-line sentinels
to E5 and include this requirement in the first implementation scope. Preserve
historical research evidence through any migration.

### Low: Specify aggregate resource bounds

Research lines 214–217 call for bounded processing stages, and E5 at line 341
includes oversized headers/events and decompression. Those are appropriate, but
per-stage byte limits alone do not define the total state retained across many
connections, unfinished streams and long-lived framing contexts.

Smallest future-plan revision: specify per-connection and global memory/state
quotas, expiry rules, and explicit uncertainty on eviction. Add a control with
many small incomplete streams so individually small objects cannot evade the
aggregate bound. This is a feasibility requirement for a future parser, not an
observed failure of a parser already shipped in this repository.

## Evidence independently checked

The reviewer inspected relevant local source, prior study documentation and
historical summary fields, and checked material external claims against primary
sources. It made no file changes.

| Area | Audit result |
| --- | --- |
| Historical numbers and qualification | Attempts, identity matches, emitted/exact usage, clean-check outcomes and all three summary hashes match the report |
| Privacy and capture source findings | Raw plaintext persistence, entry-only writes, ineffective overwrite counting and unsuccessful-read state retention match the code |
| Identity and loss findings | Missing lifecycle generations and limitations of aggregate loss counters match the inspected schema and capture path |
| Persistence findings | Non-draining shutdown risk, idle-only explicit periodic flush and warning-only persistence failures match the writer |
| Tail metadata and fingerprint | Four-byte digest prefix and missing tail `read_failed` match the renderer |
| Provider/protocol references | OpenSSL writes, OBI usage/coverage limitations, Anthropic cumulative/cache usage, HPACK state, SSE and OTel relocation support the report's scoped claims |
| Experimental controls | Fresh qualification, separate ledgers, independent run units, retained failed qualification runs and ablations are appropriate |
| Documentation | Local links, UTF-8/LF/newline/path checks and `git diff --check` completed with exit 0 |

The Go HTTP/2 main summary also contains 18 conflicting matched attempts and
32 duplicate records. Adding those values to a future diagnostic table would
make that session's evidence easier to compare. They do not qualify the session
or establish a production error rate.

The reviewer clarified that HTTP/2 diagnosis can proceed independently of the
first Python/OpenSSL HTTP/1.1 implementation. Success in the broader experiment
should not gate completion of that narrower deliverable.

Material primary references include
[OBI feature documentation](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/devdocs/features.md),
[OpenSSL write semantics](https://docs.openssl.org/3.0/man3/SSL_write/),
[Anthropic streaming](https://platform.claude.com/docs/en/build-with-claude/streaming),
[Anthropic prompt caching](https://platform.claude.com/docs/en/build-with-claude/prompt-caching),
[HPACK](https://www.rfc-editor.org/rfc/rfc7541.html),
[SSE parsing](https://html.spec.whatwg.org/multipage/server-sent-events.html), and
[OTel's GenAI relocation notice](https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-spans/).
Moving pages are documentation references, not new baseline measurements.
Official OpenAI usage semantics were checked using the OpenAI Docs skill.

## Verification limits and disposition

The independent reviewer did not rerun the scorer or collector, build/test Rust,
run privileged capture, measure overhead, exercise privacy sentinels or reconcile
billing. The six scorer tests and one collector test listed in the original
report remain results of the author's research review, not independent test
execution by this reviewer.

The research report and runtime code remain unchanged. The two findings are
documented requirements for the next implementation plan. No package installation,
live capture, deployment, publication, Git push or PR occurred during this audit.
Existing untracked research results were preserved.

# Accounting study: reproduction and current status

The study evaluates provider-reported usage per network attempt. It does not
evaluate real provider invoices, model tokenizers or GPU inference. Author:
Hoang Le. Publication destination remains undecided; no upload has occurred.

## Evidence available

- The [protocol](accounting-study-protocol.md) defines the comparison and decision
  gate. Protocol v2.0 records revisions after screening and adds a Go reference.
- The [initial review](2026-09-29-accounting-validation.md) covers prior work,
  ideal HTTP/2 replay controls and information limits.
- The TLS fixture was validated across 108 trials and 1,640 network attempts,
  including actual HTTP/2 client resets, server resets, retries, omitted usage,
  large responses and reported zero. This is fixture validation only.
- A live Python OBI screen now matches all 90 HTTP/1.1 attempts, recovers 36
  emitted usages exactly and leaves 54 unknown. Python HTTP/2 produces no GenAI
  records, consistent with pinned documented limits. These are two-seed
  screening results, not confirmation or a new defect. See
  [screen summary](../../experiments/results/2026-09-29-obi-screen.json).
  Local sudo requires interactive authentication. The first OBI screen loaded
  its probes and passed the workload
  ledger checks, but its protobuf exports were rejected by the original
  JSON-only collector. That run is retained as invalid. agtap v0.1.0 additionally
  requires an isolated kernel.
- Both Python and independent Go TLS clients passed the nine-scenario fixture
  checks: 108 trials and 1,640 scored attempts per runtime. Revised late-start
  cases include separate unscored warm-up exchanges. Go uses its standard
  library HTTP/2 implementation, independently of the hyper-h2 server.
- Go clean HTTP/1.1 and HTTP/2 usage checks passed. Two initial confirmation
  launchers overlapped; their screen anomalies and resource records are
  diagnostic only, and both executions are excluded from confirmation.
  The exclusive rerun's screen recovered 16/36 Go HTTP/1.1 usages and 27/36
  Go HTTP/2 usages exactly; HTTP/2 contained four conflicting response identities.
  See [Go screen summary](../../experiments/results/2026-09-29-go-obi-screen.json).
  The launchers share an exclusive lock.
- Ten-seed confirmation completed 1,620 control/observer cells and 24,600 scored
  attempts, with no reference-ledger mismatches. Python HTTP/1.1 matched all
  4,100 attempts and recovered all 2,460 emitted usages exactly; Go HTTP/1.1
  matched 1,612 and recovered 1,113. Go HTTP/2 failed the new main session's clean
  usage check and remains diagnostic despite the preceding qualified screen.
  See the [Go main summary](../../experiments/results/2026-09-29-go-main.json)
  and [Python main summary](../../experiments/results/2026-09-29-python-main.json).
- The [manuscript](accounting-manuscript.md) and
  [PDF](../../experiments/results/accounting-manuscript.pdf) include the completed
  measurements and their limitations. Author review, actual Claude review and
  venue selection remain pending. Earlier archives are historical snapshots;
  the main artifact contains the current report and measured evidence.

## Install and verify

Run commands from the project root. No changes to the Rust application are
required. Use Python 3.11 or newer and OpenSSL with ALPN support; the recorded
validation used Python 3.14.4 and OpenSSL 3.5.5.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r experiments/requirements.txt
python3 experiments/fetch-baselines.py
.venv/bin/python experiments/test-accounting-score.py
.venv/bin/python experiments/test-accounting-collector.py
```

Build the Go reference offline with Go 1.25 or newer (validated with 1.26.0):

```sh
mkdir -p experiments/.cache/go-build
GOCACHE="$PWD/experiments/.cache/go-build" GOMAXPROCS=2 \
  GOTOOLCHAIN=local GOPROXY=off GO111MODULE=off GOWORK=off \
  go build -o experiments/.cache/accounting-client experiments/accounting_client.go
```

The fetcher downloads official public binaries, checks their release SHA256
digests and records source/tag/binary hashes in `experiments/baselines.json`.
It does not claim to verify Sigstore signatures. The selected baselines are
OBI v0.13.0 and agtap v0.1.0. Retain `experiments/.cache/` for reuse.

## Validate the workload without root

```sh
.venv/bin/python experiments/run-study.py --mode smoke
.venv/bin/python experiments/run-study.py --mode smoke --runtime go
```

This uses loopback sockets and a generated fixture certificate. The client
connects to `127.0.0.1`; the provider-shaped Host/SNI are synthetic and do not
trigger DNS resolution or any external API request. Server and client are
separate processes. The generated private key is removed after the run.

Each output directory has `metadata.json`, independent `server.jsonl` and
`application.jsonl`, original observer output, and `score.json`. Failed runs
retain their diagnostics. The runner stops on workload/reference mismatch or
observer startup failure. Control is never scored as a passive observer.

```sh
.venv/bin/python experiments/analyze-study.py experiments/runs/RUN-DIRECTORY \
  --output experiments/results/study-summary.json
```

Replace `RUN-DIRECTORY` with the printed directory. The summary checks the
reference again and hashes its evidence. Do not infer missing counts as zero,
or equate successful fixture decoding with eBPF accuracy.

## Host screen

Review the protocol and runner, then:

```sh
sudo bash experiments/run-screen.sh
```

The launcher runs under `nohup` and `systemd-inhibit`, saves the log and evidence
inside the project, and changes ownership of new run files back to the invoking
user. It runs 64 trial cells: 32 control and 32 OBI. Each observer runs in a
transient systemd unit with non-loopback IP traffic denied; this blocks OBI's
automatic cloud metadata lookups. Only the fixture worker PID
is selected in OBI. Metrics exporters, distributed context propagation and
Kubernetes discovery are disabled; the OTLP collector listens on loopback and
accepts protobuf or JSON, preserving original bytes and decoded records.
Both TLS directions have a 128 KiB body capture budget.

`sudo bash experiments/run-screen.sh go` runs the corresponding Go screen.
Original protobuf export bodies stay in `otlp-raw/`. Each new run saves a source
snapshot before execution; keep these together with its ledgers.

The four observer batches each wait 8 seconds for startup and 45 seconds for
drain. The host screen is expected to take several minutes, rather than the
earlier conservative per-trial estimate. Actual completion and useful capture
still depend on privileges, kernel compatibility and configuration. The main
matrix has 540 cells per observer, including separately attached late-start
cases; those startup/drain periods can dominate its runtime. No GPU is used.

Watch the printed log with `tail -f`. An exit/startup failure is an infrastructure
outcome, never zero accounting coverage. Confirm clean HTTP/1.1 usage exports
before interpreting the HTTP/2 coverage cells. Pinned OBI documents Python
HTTP/2 payload capture as unsupported, although HTTP/2 tracing exists.

## Confirmatory host job

```sh
sudo bash experiments/run-confirmation.sh
```

This launches one background inhibited job, first qualifying clean Go HTTP/1.1
and HTTP/2 usage capture. If qualification passes, it runs the ten-seed Go
matrix for both protocols and the ten-seed Python HTTP/1.1 matrix sequentially.
The launchers take a shared exclusive job lock; a second launch exits. Python
HTTP/2's documented unsupported path
remains in the initial screen; it is not presented as a newly discovered bug.

Expect about 1.5 hours, largely from independent late-attachment startup/drain
periods. The confirmation includes 1,620 trial cells and 24,600 scored network
attempts across controls and OBI; qualification adds 64 cells and 360 attempts.
Warm-up exchanges are retained separately and excluded from these denominators.
No GPU inference or external API requests are used. Review actual source,
configuration, qualification and resource records before drawing conclusions.

For an accidentally duplicated job, inspect its exact run directories with
`python3 experiments/stop-study.py --run experiments/runs/RUN-DIRECTORY`.
The default only reports the selected process tree. Add `sudo` and `--stop`
to stop those jobs and their own transient observer services, retain evidence
and record their exclusion. Confirmation shells are stopped as well so they
cannot launch a subsequent runtime. Do not interpret overlapped runs as
confirmation, even if their reference ledgers pass.

## Isolated comparison

agtap v0.1.0's TLS uprobes accept `-p`, but its JSON pipe kprobes are system-wide
and only filtered later in userspace. The runner therefore refuses agtap on the
shared host. A container shares that kernel; use a dedicated Linux VM or test
machine without unrelated workloads. No such environment has been provisioned.

Run both baselines there to make overhead comparisons within one environment:

```sh
sudo systemd-inhibit --what=sleep:idle:handle-lid-switch \
  --why='Local accounting comparison' \
  .venv/bin/python experiments/run-study.py --mode screen \
  --observers control obi agtap --isolated-kernel
```

For long runs, use `tmux` or `nohup` with a project-local log. The flag attests to
an isolated test kernel; it does not create a VM. The pinned agtap runtime path
must be absent: pre-existing `/tmp/agtap` is left untouched. Study-created
runtime files are moved into the new run directory after shutdown.

Freeze the validated source/protocol before a `--mode main` run. Any changes
needed after screening require a recorded revision. Do not pool host and VM
overhead, or claim portability from a single runtime/kernel. RSS measurements
are process lifetime high-water marks, and short CPU samples have tick resolution;
extended steady workloads are needed for robust performance conclusions.

Ordinary seed cells share one client/observer session per protocol; their
means/ranges describe that workload sequence, with no independent-run interval.
Late-attachment cells restart both processes. The
[execution notes](accounting-execution-notes.md) record this limitation and the
excluded overlapping runs. Inspect those notes alongside the frozen protocol.

## Publication work still required

The current evidence supports a scoped technical report and reproducible
artifact. A new-method paper needs a demonstrated recovery mechanism, ablation,
qualified HTTP/2 follow-up and another implementation/kernel. The human author
must review the claims/citations and select a destination for this report.
GPT assistance is recorded; Claude's study-specific review is pending. Account
access, venue formatting and final upload happen after that concrete package
exists. Local environments, cached binaries and raw research runs are retained.

## Local report and artifact

Install the separate plotting/PDF dependencies without changing the measured
core dependency pins:

```sh
.venv/bin/python -m pip install -r experiments/requirements-report.txt
.venv/bin/python experiments/analyze-study.py \
  experiments/runs/2026-09-29T22-24-26Z-go-main \
  --output experiments/results/2026-09-29-go-main.json
.venv/bin/python experiments/analyze-study.py \
  experiments/runs/2026-09-29T22-24-26Z-python-main \
  --output experiments/results/2026-09-29-python-main.json
.venv/bin/python experiments/render-report.py --summary \
  experiments/results/2026-09-29-go-main.json \
  experiments/results/2026-09-29-python-main.json
```

The analyzer accepts only completed valid runs and excludes recorded overlapping
executions. The PDF/figure provenance records source, summary and output hashes.
The [review prompt](accounting-review.md) is prepared for the author and Claude;
it does not assert that either review has occurred.

The portable archive contains the qualified exclusive Go screen, both main
matrices, exact measured source snapshots, independent synthetic ledgers,
accounting-preserving OTLP exports, source and reporting outputs. Host resources,
generic diagnostic attributes and logs are omitted; original exports remain
local. The earlier Python screen is included as a hashed derived summary,
without its original exports or historical source snapshot. The artifact
manifest hashes every packaged file, and a sidecar hashes the archive.

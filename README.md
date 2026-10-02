# TokenScope

Universal LLM observability via eBPF. Zero-instrumentation kernel-level visibility for every LLM workload on a Linux host — local engines, cloud APIs, and agentic frameworks.

> Status: pre-alpha. Process/network collection, DuckDB storage, CLI queries, and OpenSSL plaintext capture are implemented through Phase 2.A; HTTP reconstruction and LLM usage parsing remain pending. See `DOC.md` for shipped scope and `SPEC.md` for the full design.

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

## Research validation

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

[Technical-report PDF](experiments/results/accounting-manuscript.pdf) and
[main study artifact](experiments/results/2026-09-29-accounting-main-artifact.tar.gz)
contain the working report, figures, reproduction scripts, exact measured source
snapshots and portable accounting evidence. Author/Claude review and venue
selection remain pending; nothing has been uploaded. Earlier draft/screen
archives remain as historical snapshots. This evidence supports a scoped
technical report; a new-method paper needs additional mechanism and validation.

## License

Apache-2.0. See `LICENSE`.

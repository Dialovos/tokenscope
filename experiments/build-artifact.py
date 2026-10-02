#!/usr/bin/env python3
"""Package valid study evidence and a manuscript draft locally; never upload."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
import tempfile

from score_accounting import observations, read_jsonl, validate_reference


ROOT = Path(__file__).resolve().parent.parent
SOURCE = [
    "LICENSE", "DOC.md", "bpf/tls.bpf.c", "bpf/ts_event.h",
    "docs/research/2026-09-29-accounting-validation.md",
    "docs/research/accounting-study-protocol.md", "docs/research/accounting-reproduction.md",
    "docs/research/accounting-manuscript.md", "docs/research/references.bib",
    "docs/research/accounting-execution-notes.md", "docs/research/accounting-review.md",
    "experiments/requirements.txt", "experiments/baselines.json",
    "experiments/requirements-report.txt", "experiments/render-report.py",
    "experiments/accounting-pilot.py", "experiments/accounting_fixture.py",
    "experiments/accounting_client.go", "experiments/score_accounting.py",
    "experiments/run-study.py", "experiments/run-screen.sh",
    "experiments/run-confirmation.sh", "experiments/stop-study.py",
    "experiments/fetch-baselines.py", "experiments/test-accounting-score.py",
    "experiments/test-accounting-collector.py", "experiments/analyze-study.py",
    "experiments/build-artifact.py", "experiments/results/2026-09-29-accounting-pilot.json",
    "experiments/results/2026-09-29-obi-screen.json",
    "experiments/results/2026-09-29-go-obi-screen.json",
]
BINARY_REPORTS = ["experiments/results/accounting-manuscript.pdf",
                  "experiments/results/accounting-coverage.png",
                  "experiments/results/accounting-coverage.pdf"]
TEXT_REPORTS = ["experiments/results/accounting-manuscript.provenance.json",
                "experiments/results/accounting-coverage-data.json",
                "experiments/results/accounting-coverage.svg"]
SPAN_ATTRIBUTES = {
    "gen_ai.provider.name", "gen_ai.operation.name", "gen_ai.response.id",
    "gen_ai.request.model", "gen_ai.response.model", "gen_ai.usage.input_tokens",
    "gen_ai.usage.output_tokens", "http.request.header.x-fixture-attempt-id",
    "http.response.status_code", "error.type",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2) + "\n").encode("utf-8")


def read_regular(path, inside):
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(inside):
        raise RuntimeError("Unexpected evidence file: " + path.name)
    return path.read_bytes()


def portable_otlp(data):
    """Retain accounting attributes and opaque span IDs; omit host resources."""
    payloads = []
    for line in data.decode("utf-8").splitlines():
        if not line.strip():
            continue
        spans = []
        for resource in json.loads(line).get("resourceSpans", []):
            for scope in resource.get("scopeSpans", []):
                for span in scope.get("spans", []):
                    kept = {key: span[key] for key in ("traceId", "spanId", "parentSpanId") if key in span}
                    kept["attributes"] = [a for a in span.get("attributes", []) if a["key"] in SPAN_ATTRIBUTES]
                    spans.append(kept)
        payloads.append({"resourceSpans": [{"scopeSpans": [{"spans": spans}]}]})
    return b"".join((json.dumps(p, separators=(",", ":")) + "\n").encode() for p in payloads)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, nargs="+", required=True)
    parser.add_argument("--summary", type=Path, nargs="+", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--include-report", action="store_true")
    args = parser.parse_args()
    payload = {name: read_regular(ROOT / name, ROOT) for name in SOURCE}
    if args.include_report:
        for name in [*BINARY_REPORTS, *TEXT_REPORTS]:
            payload[name] = read_regular(ROOT / name, ROOT)
        report = json.loads(payload["experiments/results/accounting-manuscript.provenance.json"])
        if report["manuscript_sha256"] != digest(payload["docs/research/accounting-manuscript.md"]):
            parser.error("Rendered PDF does not match the current manuscript")
        if report["pdf_sha256"] != digest(payload["experiments/results/accounting-manuscript.pdf"]):
            parser.error("Rendered PDF changed")
        if report["renderer_sha256"] != digest(payload["experiments/render-report.py"]):
            parser.error("Renderer changed after PDF generation")
        if report["report_requirements_sha256"] != digest(payload["experiments/requirements-report.txt"]):
            parser.error("Reporting dependency pins changed after PDF generation")
        for name, expected in report["figure_sha256"].items():
            if digest(payload["experiments/results/" + name]) != expected:
                parser.error("Rendered figure changed")
    summaries = {}
    for requested in args.summary:
        path = requested.resolve()
        data = read_regular(path, ROOT / "experiments/results")
        summary = json.loads(data)
        if summary.get("analysis_script_sha256") and summary["analysis_script_sha256"] != digest(payload["experiments/analyze-study.py"]):
            parser.error("Analysis source changed after summary generation")
        key = summary["run_metadata_sha256"]
        if key in summaries:
            parser.error("Duplicate summary metadata hash")
        summaries[key] = summary
        payload[path.relative_to(ROOT).as_posix()] = data
    provenance, used_summaries = [], set()
    seen_runs = set()
    for requested in args.run:
        run = requested.resolve()
        if run.parent != ROOT / "experiments/runs" or run in seen_runs:
            parser.error("Each run must be a distinct immediate experiments/runs directory")
        seen_runs.add(run)
        review = run / "execution-review.json"
        if review.exists() and json.loads(read_regular(review, run)).get("decision") == "excluded_from_confirmation":
            parser.error("Overlapping/excluded executions cannot enter the research package")
        raw_metadata = read_regular(run / "metadata.json", run)
        metadata = json.loads(raw_metadata)
        if metadata.get("status") != "ok" or not metadata.get("finished_at_utc"):
            parser.error("Only completed valid runs can be packaged")
        if not set(metadata["observers"]) <= {"control", "obi"}:
            parser.error("Only the reviewed control and OBI evidence formats are supported")
        metadata_hash = digest(raw_metadata)
        summary = summaries.get(metadata_hash)
        if not summary or summary["run_status"] != "ok":
            parser.error("A matching valid summary is required for every run")
        used_summaries.add(metadata_hash)
        prefix = "evidence/" + run.name + "/"
        payload[prefix + "metadata.json"] = raw_metadata
        for name, expected in metadata["hashes"].items():
            if name not in SOURCE:
                raise RuntimeError("Unexpected measured source: " + name)
            frozen = run / "source-snapshot" / name
            data = read_regular(frozen, run) if frozen.exists() else read_regular(ROOT / name, ROOT)
            if digest(data) != expected:
                raise RuntimeError("Measured source unavailable or changed: " + name)
            payload[prefix + "source-snapshot/" + name] = data
        suite_provenance = []
        for suite in metadata["suites"]:
            directory = suite["directory"]
            if Path(directory).name != directory or suite["status"] != "ok" or suite["reference_errors"]:
                raise RuntimeError("Invalid fixture suite")
            path = run / directory
            originals = {}
            for name in ("server.jsonl", "application.jsonl", "score.json", "otlp.jsonl"):
                data = read_regular(path / name, run)
                evidence_name = directory + "/" + name
                if summary["evidence_sha256"].get(evidence_name) != digest(data):
                    raise RuntimeError("Evidence changed: " + evidence_name)
                originals[name] = data
            trials = read_jsonl(path / "application.jsonl")
            errors = validate_reference(read_jsonl(path / "server.jsonl"), [a for t in trials for a in t["attempts"]])
            if errors:
                raise RuntimeError("Reference changed: " + directory)
            for name in ("server.jsonl", "application.jsonl"):
                payload[prefix + directory + "/" + name] = originals[name]
            portable = portable_otlp(originals["otlp.jsonl"])
            # Privacy transformation must preserve every accounting observation,
            # including unmatched IDs, zero, duplicates and incorrect counts.
            with tempfile.TemporaryDirectory(prefix="accounting-export-", dir=ROOT / "experiments/.cache") as tmp:
                temporary = Path(tmp)
                (temporary / "otlp.jsonl").write_bytes(portable)
                if observations(suite["observer"], temporary)[0] != observations(suite["observer"], path)[0]:
                    raise RuntimeError("Portable export changed accounting observations: " + directory)
            payload[prefix + directory + "/otlp.jsonl"] = portable
            score = json.loads(originals["score.json"])
            diagnostic_count = len(score.pop("diagnostics", []))
            score["portable_export_note"] = "Host resources and generic diagnostics omitted; accounting observations preserved exactly"
            score["omitted_generic_diagnostic_count"] = diagnostic_count
            payload[prefix + directory + "/score.json"] = json_bytes(score)
            suite_provenance.append({"suite": directory,
                                     "original_evidence_sha256": {k: digest(v) for k, v in originals.items()},
                                     "transformations": {"otlp.jsonl": "accounting attribute allowlist; no resource/scope metadata",
                                                         "score.json": "generic diagnostics replaced by their count"}})
        provenance.append({"run": run.name, "metadata_sha256": metadata_hash,
                           "mode": metadata["mode"], "runtime": metadata.get("client_runtime", "python"),
                           "suites": suite_provenance})
    if used_summaries != summaries.keys():
        parser.error("Every supplied summary must correspond to a packaged run")
    if args.include_report:
        for name, expected in report["summaries"].items():
            data = payload.get("experiments/results/" + name)
            if data is None or digest(data) != expected:
                parser.error("Rendered report summary is absent or changed")
    payload["evidence/provenance.json"] = json_bytes(provenance)
    payload["README.md"] = (
        "# Accounting-study working artifact\n\n"
        "Human author: Hoang Le. GPT assistance is recorded in the manuscript; "
        "Claude study-specific review and human review remain pending.\n\n"
        "This package contains synthetic replay results, loopback TLS evidence, "
        "source and a working manuscript. Check each run's metadata for its "
        "screen/control/confirmation stage; inclusion does not establish production "
        "accuracy or provider billing. This draft is not ready for submission.\n\n"
        "See docs/research/accounting-reproduction.md. Evidence includes independent "
        "ledgers, exact measured source snapshots and portable OTLP JSON. The "
        "portable export retains accounting attributes and opaque span IDs, with "
        "host resources and generic diagnostics removed. Each transformation is "
        "checked to preserve all scorer observations exactly. Original evidence "
        "hashes are in evidence/provenance.json; original host exports stay local. "
        "Packaged file hashes are in manifest.json.\n\n"
        "The earlier Python screening summary records a prior implementation by "
        "hash; when its run is not listed under evidence/, its original exports "
        "and exact historical source are not included. Third-party binaries, "
        "environments, keys, credentials and host logs are excluded. Nothing "
        "has been uploaded.\n"
    ).encode()
    for name, data in payload.items():
        if name in BINARY_REPORTS:
            continue
        content = data.decode("utf-8")
        if re.search(r"/home/[A-Za-z0-9._-]+/", content) or re.search(r"[A-Za-z]:\\Users\\[^\\\s]+\\", content):
            raise RuntimeError("Local personal path in export: " + name)
    manifest = {"schema_version": 2, "built_at_utc": datetime.now(timezone.utc).isoformat(),
                "stage": "working_research_artifact_not_submission",
                "author": "Hoang Le", "venue": None, "runs": [r["run"] for r in provenance],
                "contents_sha256": {name: digest(data) for name, data in sorted(payload.items())}}
    payload["manifest.json"] = json_bytes(manifest)
    output = args.output.resolve()
    if output.parent != ROOT / "experiments/results":
        parser.error("Artifact must be directly inside experiments/results")
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() or output.with_suffix(output.suffix + ".sha256").exists():
        raise RuntimeError("Existing artifact or checksum was left untouched")
    with tarfile.open(output, "w:gz") as archive:
        for name, data in sorted(payload.items()):
            info = tarfile.TarInfo("accounting-study/" + name)
            info.size = len(data)
            info.mode = 0o755 if name.endswith(".sh") or name in SOURCE and name.startswith("experiments/") and name.endswith(".py") else 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    sidecar = output.with_suffix(output.suffix + ".sha256")
    sidecar.write_text(digest(output.read_bytes()) + "  " + output.name + "\n", encoding="utf-8")
    print(f"Prepared {output.relative_to(ROOT)} ({output.stat().st_size} bytes); no upload")


if __name__ == "__main__":
    main()

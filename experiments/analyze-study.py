#!/usr/bin/env python3
"""Summarize independent fixture ledgers and identity-based observer scores."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import random
import statistics

from score_accounting import read_jsonl, validate_reference


def sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def interval(values, independent):
    if len(values) < 10 or not independent:
        return None
    rng = random.Random(0)
    means = sorted(statistics.mean(rng.choices(values, k=len(values))) for _ in range(2000))
    return {"method": "percentile bootstrap of run/seed means; 2000 resamples, seed 0",
            "lower": means[49], "upper": means[1949], "level": .95,
            "limitation": "fixed synthetic seeds; zero-width intervals do not establish universal correctness"}


def aggregate_report(report):
    emitted = [r for r in report["attempts"] if r["usage_emitted"]]
    assigned = {key: sum(r["expected_usage"][field] for r in emitted)
                for key, field in (("input", "prompt_tokens"), ("output", "completion_tokens"))}
    recovered, absolute_error, component_known = {}, {}, {}
    for key, field in (("input", "prompt_tokens"), ("output", "completion_tokens")):
        known = []
        for row in emitted:
            values = {r.get(key) for r in row["observations"]}
            if len(values) == 1:
                value = next(iter(values))
                if isinstance(value, int) and not isinstance(value, bool):
                    known.append((value, row["expected_usage"][field]))
        recovered[key] = sum(value for value, _ in known)
        absolute_error[key] = sum(abs(value - expected) for value, expected in known)
        component_known[key] = len(known)
    return {"emitted_assigned_totals": assigned, "matched_known_observed_totals": recovered,
            "known_component_attempts": component_known, "known_component_absolute_error": absolute_error,
            "interpretation": "missing values remain unknown; total shortfall is not proof of a wrong reported count"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    metadata = json.loads((args.run / "metadata.json").read_text())
    review = args.run / "execution-review.json"
    if review.exists() and json.loads(review.read_text()).get("decision") == "excluded_from_confirmation":
        parser.error("This execution is excluded from confirmation; retain it for diagnosis")
    if metadata.get("status") != "ok" or not metadata.get("finished_at_utc"):
        parser.error("Analyze only a completed, valid run")
    fixture_groups = defaultdict(lambda: {"trials": 0, "received_attempts": 0,
                                          "usage_emitted_attempts": 0, "reference_errors": []})
    evidence, comparisons = {}, []
    statistical_groups, resource_trials = defaultdict(list), {}
    resource_suites = []
    qualification = {}
    for item in metadata.get("suites", []):
        if item["observer"] == "control" or not item["directory"].endswith("-000"):
            continue
        report = json.loads((args.run / item["directory"] / "score.json").read_text())
        clean = [t for t in report["trials"] if t["parameters"]["scenario"] == "complete"
                 and t["parameters"]["concurrency"] == 1]
        protocol = item["directory"].split("-")[1]
        qualified = any(t["summary"]["exact_attempts"] == 1 for t in clean)
        unsupported = protocol == "http2" and metadata.get("client_runtime", "python") == "python"
        qualification[(item["observer"], protocol)] = {
            "support": "documented_unsupported_python_http2_payload" if unsupported else
                       "qualified_supported_candidate" if qualified else "clean_usage_not_reproduced_in_this_session",
            "clean_checks": len(clean),
            "exact_clean_checks": sum(t["summary"]["exact_attempts"] == 1 for t in clean)}
    for item in metadata.get("suites", []):
        suite = args.run / item["directory"]
        report = json.loads((suite / "score.json").read_text())
        if item["status"] != "ok" or report["status"] != "ok":
            raise RuntimeError("Invalid observer suite: " + item["directory"])
        events = read_jsonl(suite / "server.jsonl")
        trials = read_jsonl(suite / "application.jsonl")
        errors = validate_reference(events, [r for t in trials for r in t["attempts"]])
        if errors or item["reference_errors"]:
            raise RuntimeError("Invalid fixture: " + item["directory"])
        for filename in ("server.jsonl", "application.jsonl", "score.json", "otlp.jsonl"):
            path = suite / filename
            evidence[item["directory"] + "/" + filename] = sha(path)
        for trial in trials:
            if trial.get("phase") == "warmup":
                continue
            command = trial["parameters"]
            resource_trials[(item["observer"], command["protocol"], command["scenario"],
                             command["concurrency"], command["seed"])] = trial
            key = (item["observer"], command["protocol"], command["scenario"])
            group = fixture_groups[key]
            ids = {r["attempt_id"] for r in trial["attempts"]}
            group["trials"] += 1
            group["received_attempts"] += sum(r["event"] == "received" and r["attempt_id"] in ids for r in events)
            group["usage_emitted_attempts"] += sum(r["event"] == "usage_emitted" and r["attempt_id"] in ids for r in events)
        if report.get("observer_final_sample"):
            resource_suites.append({"suite": item["directory"], "observer": item["observer"],
                                    **report["observer_final_sample"]})
        if report["overall"]:
            comparisons.append({"suite": item["directory"], "observer": item["observer"],
                                "status": item["status"], "summary": report["overall"]["summary"],
                                "aggregation": aggregate_report(report["overall"]),
                                **qualification[(item["observer"], item["directory"].split("-")[1])]})
            for trial in report["trials"]:
                p, s = trial["parameters"], trial["summary"]
                errors = sum(s["states"].get(state, 0) for state in
                             ("incorrect", "conflicting_duplicates", "counts_without_emitted_evidence"))
                metrics = {"attempt_recall": s["matched_attempts"] / s["server_attempts"],
                           "incorrect_assertion_attempt_fraction": errors / s["server_attempts"]}
                if s["emitted_usage_attempts"]:
                    metrics["exact_usage_coverage"] = s["exact_attempts"] / s["emitted_usage_attempts"]
                for metric, value in metrics.items():
                    statistical_groups[(item["observer"], p["protocol"], p["scenario"], p["concurrency"], metric)].append(value)
    stats = [{"observer": key[0], "protocol": key[1], "scenario": key[2], "concurrency": key[3],
              "metric": key[4], "run_count": len(values), "mean": statistics.mean(values),
              "minimum": min(values), "maximum": max(values),
              "independent_observer_restarts": key[2] == "late-attach",
              **qualification[(key[0], key[1])],
              "run_level_95_percent_interval": interval(values, key[2] == "late-attach" and
                    qualification[(key[0], key[1])]["support"] == "qualified_supported_candidate")}
             for key, values in sorted(statistical_groups.items())]
    paired_groups, paired_rows = defaultdict(list), []
    for key, trial in sorted(resource_trials.items()):
        observer, protocol, scenario, concurrency, seed = key
        if observer == "control":
            continue
        control = resource_trials.get(("control", protocol, scenario, concurrency, seed))
        if not control:
            continue
        metrics = {"client_duration_difference_seconds": trial["duration_seconds"] - control["duration_seconds"],
                   "client_cpu_difference_seconds": trial["client_cpu_seconds"] - control["client_cpu_seconds"],
                   "client_process_lifetime_peak_rss_difference_kib": trial["client_peak_rss_kib"] - control["client_peak_rss_kib"]}
        if control["duration_seconds"] > 0:
            metrics["client_duration_ratio"] = trial["duration_seconds"] / control["duration_seconds"]
        for field in ("observer_sampled_cpu_seconds_during_workload", "observer_process_lifetime_peak_rss_kib"):
            if field in trial:
                metrics[field] = trial[field]
        paired_rows.append({"observer": observer, "protocol": protocol, "scenario": scenario,
                            "concurrency": concurrency, "seed": seed,
                            **qualification[(observer, protocol)], **metrics})
        for metric, value in metrics.items():
            paired_groups[(observer, protocol, scenario, concurrency, metric)].append(value)
    resources = [{"observer": key[0], "protocol": key[1], "scenario": key[2], "concurrency": key[3],
                  "metric": key[4], "run_count": len(values), "mean": statistics.mean(values),
                  "minimum": min(values), "maximum": max(values),
                  "independent_observer_restarts": key[2] == "late-attach",
                  **qualification[(key[0], key[1])],
                  "run_level_95_percent_interval": interval(values, key[2] == "late-attach" and
                        qualification[(key[0], key[1])]["support"] == "qualified_supported_candidate")}
                 for key, values in sorted(paired_groups.items())]
    result = {"schema_version": 2, "study_stage": metadata["mode"], "run_status": metadata["status"],
              "analysis_script_sha256": sha(Path(__file__)),
              "run_metadata_sha256": sha(args.run / "metadata.json"),
              "client_runtime": metadata.get("client_runtime", "python"),
              "session_qualification": [{"observer": key[0], "protocol": key[1], **value}
                                        for key, value in sorted(qualification.items())],
              "statistical_limit": "ordinary seed cells share an observer/client batch and have no independent-run confidence interval; late-attach cells restart both",
              "provenance": {k: metadata[k] for k in ("started_at_utc", "finished_at_utc", "python", "openssl", "kernel", "machine", "hashes", "limits")},
              "fixture_validation": [{"observer": k[0], "protocol": k[1], "scenario": k[2], **v}
                                     for k, v in sorted(fixture_groups.items())],
              "fixture_trial_count": sum(v["trials"] for v in fixture_groups.values()),
              "fixture_attempt_count": sum(v["received_attempts"] for v in fixture_groups.values()),
              "fixture_usage_emitted_count": sum(v["usage_emitted_attempts"] for v in fixture_groups.values()),
              "live_observer_suites": comparisons, "run_level_statistics": stats,
              "resource_analysis": {"paired_rows": paired_rows, "run_level_statistics": resources,
                                    "observer_whole_process_samples": resource_suites,
                                    "limits": ["short, sequential synthetic cells are diagnostic, not production overhead",
                                               "process lifetime RSS cannot be attributed to one cell",
                                               "observer CPU samples during traffic have scheduler-tick resolution",
                                               "whole-process CPU includes attachment and drain; do not add it to traffic samples"]},
              "evidence_sha256": evidence}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("run_status", "fixture_trial_count", "fixture_attempt_count", "fixture_usage_emitted_count")}, indent=2))


if __name__ == "__main__":
    main()

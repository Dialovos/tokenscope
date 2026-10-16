"""Conservative identity-based scoring; never join by counts or arrival order."""
from collections import defaultdict
import json


def read_jsonl(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def value_of(value):
    for key in ("stringValue", "intValue", "doubleValue", "boolValue"):
        if key in value:
            return value[key]
    return None


def optional_count(value):
    if value is None:
        return None
    # Zero remains a value. Invalid/negative counts are errors, not unknown.
    if isinstance(value, bool):
        return "invalid"
    try:
        n = int(value)
    except (ValueError, TypeError):
        return "invalid"
    return n if n >= 0 and str(n) == str(value) else "invalid"


def observations(observer, suite):
    rows, diagnostics = [], []
    if observer == "control":
        return rows, diagnostics
    if observer == "agtap":
        for line in (suite / "observer.stdout.log").read_text(encoding="utf-8").splitlines():
            try:
                raw = json.loads(line)
            except ValueError:
                diagnostics.append({"unparsed_stdout": line[:200]})
                continue
            if not isinstance(raw, dict) or "id" not in raw:
                diagnostics.append({"unrecognized_json": raw})
                continue
            aid = None
            # agtap error IDs are synthetic. Its captured request headers can
            # provide an explicit attempt ID, without timing/count heuristics.
            body_path = raw.get("body_path")
            if body_path:
                from pathlib import Path
                local = suite / "agtap-runtime" / "bodies" / Path(body_path).name
                if local.is_file():
                    detail = json.loads(local.read_text(encoding="utf-8"))
                    aid = next((v for k, v in detail.get("request_headers", [])
                                if k.lower() == "x-fixture-attempt-id"), None)
            rows.append({"response_id": raw["id"], "attempt_id": aid,
                         "input": optional_count(raw.get("input_tokens")),
                         "output": optional_count(raw.get("output_tokens")),
                         "completeness": "not_exposed", "identity_source": "response_id_or_captured_request_header"})
    elif observer == "obi":
        for payload in read_jsonl(suite / "otlp.jsonl"):
            for resource in payload.get("resourceSpans", []):
                for scope in resource.get("scopeSpans", []):
                    for span in scope.get("spans", []):
                        attrs = {a["key"]: value_of(a.get("value", {})) for a in span.get("attributes", [])}
                        # Retain generic HTTP spans as unmatched inventory when
                        # they lack sufficient identity. Do not count parent and
                        # child spans twice as if they were separate attempts.
                        if any(k.startswith("gen_ai.") for k in attrs):
                            rows.append({"response_id": attrs.get("gen_ai.response.id"),
                                         "attempt_id": attrs.get("http.request.header.x-fixture-attempt-id"),
                                         "input": optional_count(attrs.get("gen_ai.usage.input_tokens")),
                                         "output": optional_count(attrs.get("gen_ai.usage.output_tokens")),
                                         "completeness": "not_exposed", "identity_source": "exported_attributes"})
                        else:
                            diagnostics.append({"generic_span": span.get("name"), "attributes": attrs})
    return rows, diagnostics


def score(server, observed):
    received = {r["attempt_id"]: r for r in server if r["event"] == "received"}
    if sum(r["event"] == "received" for r in server) != len(received):
        raise ValueError("Duplicate server receipt IDs")
    emitted = {r["attempt_id"] for r in server if r["event"] == "usage_emitted"}
    response_ids = {r["response_id"]: aid for aid, r in received.items()}
    buckets, unmatched = defaultdict(list), []
    for row in observed:
        aid_by_response = response_ids.get(row.get("response_id"))
        aid_by_request = row.get("attempt_id") if row.get("attempt_id") in received else None
        if aid_by_response and aid_by_request and aid_by_response != aid_by_request:
            unmatched.append({**row, "reason": "conflicting_identity"})
            continue
        aid = aid_by_response or aid_by_request
        if aid is None:
            unmatched.append({**row, "reason": "no_joinable_identity"})
        else:
            buckets[aid].append(row)
    details = []
    for aid, expected in received.items():
        rows = buckets.get(aid, [])
        pairs = {(r.get("input"), r.get("output")) for r in rows}
        if not rows:
            state = "unobserved"
        elif len(pairs) > 1:
            state = "conflicting_duplicates"
        else:
            counts = next(iter(pairs))
            if counts == (None, None):
                state = "unknown"
            elif aid not in emitted:
                state = "counts_without_emitted_evidence"
            elif "invalid" in counts:
                state = "incorrect"
            elif None in counts:
                state = "partial_usage"
            else:
                state = "exact" if counts == (expected["assigned_usage"]["prompt_tokens"],
                                              expected["assigned_usage"]["completion_tokens"]) else "incorrect"
        details.append({"attempt_id": aid, "response_id": expected["response_id"],
                        "usage_emitted": aid in emitted, "state": state,
                        "expected_usage": expected["assigned_usage"] if aid in emitted else None,
                        "observations": rows, "duplicate_records": max(0, len(rows) - 1)})
    summary = {"server_attempts": len(received), "emitted_usage_attempts": len(emitted),
               "matched_attempts": len(buckets), "exact_attempts": sum(r["state"] == "exact" for r in details),
               "unmatched_records": len(unmatched),
               "duplicate_records": sum(r["duplicate_records"] for r in details)}
    summary["states"] = {state: sum(r["state"] == state for r in details)
                         for state in sorted({r["state"] for r in details})}
    return {"summary": summary, "attempts": details, "unmatched": unmatched}


def validate_reference(server, application):
    receipts = {r["attempt_id"]: r for r in server if r["event"] == "received"}
    emitted = {r["attempt_id"] for r in server if r["event"] == "usage_emitted"}
    app = {r["attempt_id"]: r for r in application}
    errors = []
    if len(receipts) != sum(r["event"] == "received" for r in server):
        errors.append("duplicate_server_receipts")
    if len(app) != len(application) or app.keys() != receipts.keys():
        errors.append("application_server_attempt_inventory_mismatch")
    for aid in app.keys() & receipts.keys():
        row, truth = app[aid], receipts[aid]
        if row["status"] != truth["status"]:
            errors.append(aid + ":status_mismatch")
        expected_usage = truth["assigned_usage"] if aid in emitted else None
        if row["usage"] != expected_usage:
            errors.append(aid + ":usage_mismatch")
        if truth["status"] == 200 and row["response_id"] != truth["response_id"]:
            errors.append(aid + ":response_identity_mismatch")
        if truth["scenario"] not in ("cancel", "disconnect") and truth["status"] == 200 and not row["sse_done"]:
            errors.append(aid + ":missing_completion_sentinel")
    return errors

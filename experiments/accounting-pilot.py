#!/usr/bin/env python3
"""Replay synthetic HTTP/2 SSE responses to check accounting observability.

This uses an ideal hyper-h2 decoder with complete initial connection state.
It does not load eBPF, run TokenScope or competitors, contact providers, or
measure overhead. Token numbers are fixture ledger values, not tokenization
or provider billing measurements. No live network traffic is captured.
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import random
import sys

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, StreamEnded
from h2.settings import SettingCodes


@dataclass
class Exchange:
    decoder: H2Connection
    records: list[tuple[str, bytes]]
    ledger: dict[int, dict[str, int]]


def sse(value: dict | str) -> bytes:
    payload = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return f"data: {payload}\n\n".encode()


def exchange(count: int, seed: int, mode: str = "complete") -> Exchange:
    """Generate standards-library HTTP/2 framing with interleaved SSE bodies."""
    client = H2Connection(config=H2Configuration(client_side=True))
    server = H2Connection(config=H2Configuration(client_side=False))
    client.initiate_connection()
    server.initiate_connection()
    server.receive_data(client.data_to_send())
    client.receive_data(server.data_to_send())
    server.receive_data(client.data_to_send())
    # Enough receive window for the deliberately large capture-cap fixture.
    client.update_settings({SettingCodes.INITIAL_WINDOW_SIZE: 1024 * 1024})
    client.increment_flow_control_window(1024 * 1024)
    server.receive_data(client.data_to_send())
    client.receive_data(server.data_to_send())
    server.receive_data(client.data_to_send())

    ledger = {}
    for index in range(count):
        stream = 2 * index + 1
        # Identical requests intentionally expose no application task/retry ID.
        client.send_headers(stream, [
            (":method", "POST"), (":scheme", "https"),
            (":authority", "mock.invalid"), (":path", "/v1/chat/completions"),
            ("content-type", "application/json"),
        ])
        client.send_data(stream, json.dumps({
            "model": "fixture-model", "stream": True,
            "messages": [{"role": "user", "content": "synthetic prompt"}],
        }).encode(), end_stream=True)
        ledger[stream] = {
            "prompt_tokens": 100 + 7 * index,
            "completion_tokens": 11 + 3 * index,
        }
    server.receive_data(client.data_to_send())
    # The ideal observer is given the state obtained from the whole handshake
    # and all requests; late attach and HPACK state loss are NOT tested here.
    decoder = copy.deepcopy(client)

    records = []
    pending = {}
    for stream, usage in ledger.items():
        server.send_headers(stream, [
            (":status", "200"), ("content-type", "text/event-stream"),
        ])
        records.append(("headers", server.data_to_send()))
        if mode == "zero":
            usage.update(prompt_tokens=0, completion_tokens=0)
        content = "synthetic output π"
        if mode == "capture-cap":
            content = "x" * (96 * 1024)
        delta = sse({"id": f"fixture-{stream}", "choices": [
            {"delta": {"content": content}, "index": 0},
        ]})
        parts = [("delta", delta[i:i + 4096]) for i in range(0, len(delta), 4096)]
        if mode != "interrupted":
            if mode != "no-usage":
                parts.append(("usage", sse({
                    "id": f"fixture-{stream}", "choices": [], "usage": usage,
                })))
            parts.append(("done", sse("[DONE]")))
        pending[stream] = parts

    rng = random.Random(seed)
    while pending:
        stream = rng.choice(list(pending))
        label, body = pending[stream].pop(0)
        end = not pending[stream] and mode != "interrupted"
        server.send_data(stream, body, end_stream=end)
        records.append((f"{label}:{stream}", server.data_to_send()))
        if not pending[stream]:
            del pending[stream]
    return Exchange(decoder, records, ledger)


def observe(sample: Exchange, fragment_size: int, *, drop_usage: bool = False,
            capture_cap: int | None = None) -> tuple[dict, dict]:
    """Recover reported usage per stream; missing counts remain null."""
    raw = b"".join(data for label, data in sample.records
                   if not (drop_usage and label == "usage:1"))
    loss = {
        "dropped_usage_frame": drop_usage,
        "capture_truncated": capture_cap is not None and len(raw) > capture_cap,
    }
    # Model ONE plaintext capture call capped at 16 * 4096 bytes. This is
    # deliberately not a claim about how TLS libraries size real calls.
    if capture_cap is not None:
        raw = raw[:capture_cap]
    bodies = {stream: bytearray() for stream in sample.ledger}
    ended = set()
    for start in range(0, len(raw), fragment_size):
        for event in sample.decoder.receive_data(raw[start:start + fragment_size]):
            if isinstance(event, DataReceived):
                bodies[event.stream_id].extend(event.data)
            elif isinstance(event, StreamEnded):
                ended.add(event.stream_id)

    observed = {}
    for stream, body in bodies.items():
        usage = None
        # Parse only complete SSE records. Fragmentation includes UTF-8 and
        # frame boundaries; incomplete trailing bytes never become evidence.
        for block in bytes(body).split(b"\n\n")[:-1]:
            if not block.startswith(b"data: ") or block == b"data: [DONE]":
                continue
            value = json.loads(block[6:])
            candidate = value.get("usage")
            if candidate is not None:
                usage = {key: candidate[key] for key in (
                    "prompt_tokens", "completion_tokens",
                )}
        observed[stream] = {
            "usage": usage,
            "transport_complete": stream in ended,
        }
    return observed, loss


def evaluate(name: str, count: int, seed: int, fragment: int,
             mode: str = "complete", **faults) -> dict:
    sample = exchange(count, seed, mode)
    observed, loss = observe(sample, fragment, **faults)
    exact = sum(row["usage"] == sample.ledger[stream]
                for stream, row in observed.items())
    unknown = sum(row["usage"] is None for row in observed.values())
    wrong = count - exact - unknown
    if mode in ("complete", "zero") and not faults:
        if exact != count:
            raise RuntimeError(f"complete-capture control failed: {name}")
    elif mode in ("no-usage", "interrupted", "capture-cap"):
        if unknown != count or wrong:
            raise RuntimeError(f"missing-evidence control failed: {name}")
    elif faults.get("drop_usage") and (unknown != 1 or exact != count - 1):
        raise RuntimeError("dropped-usage control failed")
    return {
        "case": name, "streams": count, "seed": seed,
        "fragment_bytes": fragment, "exact_reported_usage": exact,
        "unknown_usage": unknown, "incorrect_usage": wrong,
        "complete_streams": sum(row["transport_complete"] for row in observed.values()),
        "loss": loss,
    }


def information_limits() -> dict:
    """Construct identical observations with different hidden truths.

    These are synthetic counterexamples about the observer's information,
    not evidence that a particular provider bills interrupted calls this way.
    """
    interrupted_a = exchange(1, 0, "interrupted")
    interrupted_b = exchange(1, 0, "interrupted")
    interrupted_b.ledger[1]["completion_tokens"] = 999
    wire_a = b"".join(data for _, data in interrupted_a.records)
    wire_b = b"".join(data for _, data in interrupted_b.records)
    if wire_a != wire_b or interrupted_a.ledger == interrupted_b.ledger:
        raise RuntimeError("hidden-ledger counterexample invalid")
    observed_a, _ = observe(interrupted_a, 64)
    observed_b, _ = observe(interrupted_b, 64)
    if observed_a != observed_b or observed_a[1]["usage"] is not None:
        raise RuntimeError("hidden-ledger observation mismatch")

    attempts = exchange(2, 0)
    attempt_wire = b"".join(data for _, data in attempts.records)
    per_attempt, _ = observe(attempts, 64)
    independent = {1: "task-a", 3: "task-b"}
    retry = {1: "task-a", 3: "task-a"}
    if per_attempt[1]["usage"] is None or per_attempt[3]["usage"] is None:
        raise RuntimeError("retry example needs complete per-attempt usage")
    return {
        "interrupted_hidden_ledger": {
            "same_observed_bytes": wire_a == wire_b,
            "observation_sha256": hashlib.sha256(wire_a).hexdigest(),
            "hidden_output_counts": [11, 999],
            "reported_usage": None,
            "interpretation": "Exact hidden provider-side totals are not identifiable from this trace.",
        },
        "hidden_retry_grouping": {
            "observation_sha256": hashlib.sha256(attempt_wire).hexdigest(),
            "complete_wire_attempts": len(per_attempt),
            "possible_logical_task_counts": [len(set(independent.values())),
                                              len(set(retry.values()))],
            "interpretation": "Wire attempts are identifiable; untransmitted application grouping is not.",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = [evaluate("complete-interleaved", streams, seed, fragment)
            for streams in (1, 8, 32) for seed in range(5)
            for fragment in (1, 64, 4096)]
    controls = list(rows)
    rows.extend([
        evaluate("reported-zero", 2, 0, 64, "zero"),
        evaluate("completed-without-usage", 1, 0, 64, "no-usage"),
        evaluate("interrupted-before-usage", 1, 0, 64, "interrupted"),
        evaluate("usage-frame-dropped", 8, 0, 64, drop_usage=True),
        evaluate("single-capture-call-cap-64k", 1, 0, 4096, "capture-cap",
                 capture_cap=16 * 4096),
    ])
    report = {
        "schema_version": 1,
        "run_at_utc": datetime.now(timezone.utc).isoformat(),
        "experiment": "ideal-decoder synthetic HTTP/2 accounting feasibility pilot",
        "scope": "In-memory replay; no eBPF, TLS encryption, competitors, inference, billing, or overhead measured.",
        "python_version": sys.version.split()[0],
        "dependencies": {name: version(name) for name in ("h2", "hpack", "hyperframe")},
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "complete_capture_summary": {
            "configurations": len(controls),
            "attempts": sum(row["streams"] for row in controls),
            "exact_reported_usage": sum(row["exact_reported_usage"] for row in controls),
            "incorrect_usage": sum(row["incorrect_usage"] for row in controls),
        },
        "rows": rows,
        "information_limits": information_limits(),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"summary": report["complete_capture_summary"],
                      "fault_cases": rows[-5:],
                      "information_limits": report["information_limits"]}, indent=2))


if __name__ == "__main__":
    main()

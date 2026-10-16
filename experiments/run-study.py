#!/usr/bin/env python3
"""Run local TLS accounting trials and preserve separate evidence ledgers.

Control validates the fixture only. Live observers require root and a qualified
HTTP/1.1 capture before any comparative measurement can be interpreted.
"""
import argparse
import asyncio
from datetime import datetime, timezone
import hashlib
import itertools
import json
import os
from pathlib import Path
import platform
import shutil
import ssl
import subprocess
import sys
import time
import uuid

from google.protobuf.json_format import MessageToDict
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

from accounting_fixture import FixtureServer, Ledger, SCENARIOS
from score_accounting import observations, read_jsonl, score, validate_reference


ROOT = Path(__file__).resolve().parent.parent


def sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def cells(mode, protocols):
    scenarios = ("complete", "no-usage", "cancel", "retry") if mode == "screen" else SCENARIOS
    concurrencies = (1, 8) if mode == "screen" else (1, 8, 32)
    seeds = range(10) if mode == "main" else range(2)
    return [{"protocol": p, "scenario": s, "concurrency": c, "seed": seed,
             "prefix": f"{p}-{s}-c{c}-s{seed}"}
            for p, s, c, seed in itertools.product(protocols, scenarios, concurrencies, seeds)]


def clean_env():
    # Never inherit external collectors, credentials or proxy endpoints.
    return {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL", "SUDO_UID", "SUDO_GID")
            if k in os.environ}


def process_sample(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        cpu = (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
        status = Path(f"/proc/{pid}/status").read_text().splitlines()
        rss = next((int(s.split()[1]) for s in status if s.startswith("VmHWM:")), 0)
        return {"cpu_seconds": cpu, "process_lifetime_peak_rss_kib": rss}
    except (FileNotFoundError, ProcessLookupError):
        return None


class Observer:
    def __init__(self, name, suite, pid, collector_port, baselines):
        self.name, self.suite, self.pid = name, suite, pid
        self.collector_port, self.baselines = collector_port, baselines
        self.process, self.stdout, self.stderr = None, None, None
        self.runtime_claimed = False
        self.start_error = None
        self.final_sample = None
        self.unit = None
        self.capture_pid = None

    async def start(self, startup):
        if self.name == "control":
            return
        info = self.baselines[self.name]
        binary = ROOT / info["binary"]
        if sha(binary) != info["binary_sha256"]:
            raise RuntimeError("Baseline binary checksum changed: " + self.name)
        if self.name == "agtap":
            # The pinned release has a fixed runtime path. Refuse to modify a
            # pre-existing directory belonging to any other invocation.
            runtime = Path("/tmp/agtap")
            if runtime.exists():
                raise RuntimeError("agtap runtime already exists; existing files were left untouched")
            runtime.mkdir(mode=0o700)
            self.runtime_claimed = True
            command = [str(binary), "-p", str(self.pid), "--max-body-store", "64",
                       "--max-log-size", "16", "--max-log-files", "2"]
        else:
            config = self.suite / "obi.yaml"
            config.write_text(
                f"target_pids: [{self.pid}]\nlog_level: info\n"
                "attributes:\n  kubernetes:\n    enable: false\n"
                "  instance_id:\n    dns: false\n    override_hostname: accounting-fixture\n"
                "  host_id:\n    override: accounting-fixture\n  select:\n    traces:\n"
                "      include: ['gen_ai.response.id', 'gen_ai.usage.*', 'gen_ai.operation.name', 'gen_ai.provider.name', 'gen_ai.request.model', 'gen_ai.response.model', 'http.response.status_code', 'error.type']\n"
                "discovery:\n  exclude_otel_instrumented_services: false\n"
                "ebpf:\n  context_propagation: disabled\n  wakeup_len: 1\n"
                "  buffer_sizes:\n    http: 131072\n  payload_extraction:\n    http:\n"
                "      genai:\n        openai:\n          enabled: true\n"
                "otel_traces_export:\n"
                f"  endpoint: http://127.0.0.1:{self.collector_port}\n"
                "  protocol: http/protobuf\n  batch_timeout: 1s\n  instrumentations: ['http', 'genai']\n"
                "metrics:\n  features: []\n", encoding="utf-8")
            command = [str(binary), "-config", str(config)]
        self.stdout = (self.suite / "observer.stdout.log").open("wb")
        self.stderr = (self.suite / "observer.stderr.log").open("wb")
        # Pinned OBI always attempts cloud resource detection. A transient unit
        # denies non-loopback IP traffic without changing the baseline binary.
        # systemd applies cgroup BPF network filtering to this observer only.
        self.unit = "accounting-observer-" + uuid.uuid4().hex[:12]
        env_command = ["/usr/bin/env", "-i", *(f"{k}={v}" for k, v in clean_env().items()), *command]
        scoped_command = ["systemd-run", "--quiet", "--collect", "--wait", "--pipe",
                          "--unit=" + self.unit, "--property=IPAddressDeny=any",
                          "--property=IPAddressAllow=localhost", *env_command]
        self.process = await asyncio.create_subprocess_exec(*scoped_command, cwd=ROOT, env=clean_env(),
                                                           stdout=self.stdout, stderr=self.stderr)
        await asyncio.sleep(startup)
        if self.process.returncode is not None:
            self.start_error = {"status": "observer_startup_failed", "exit_code": self.process.returncode}
        else:
            query = await asyncio.create_subprocess_exec("systemctl", "show", self.unit,
                "--property=MainPID", "--value", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            pid_bytes, _ = await query.communicate()
            self.capture_pid = int(pid_bytes.strip() or b"0")
            if self.capture_pid <= 0:
                self.start_error = {"status": "observer_startup_failed", "reason": "No running observer service PID"}

    async def stop(self, drain):
        if self.process:
            if self.process.returncode is None:
                await asyncio.sleep(drain)
                self.final_sample = process_sample(self.capture_pid) if self.capture_pid else None
                stop = await asyncio.create_subprocess_exec("systemctl", "kill", "--signal=SIGINT",
                    "--kill-whom=main", self.unit, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
                await stop.wait()
                try:
                    await asyncio.wait_for(self.process.wait(), 15)
                except asyncio.TimeoutError:
                    kill = await asyncio.create_subprocess_exec("systemctl", "kill", "--signal=SIGKILL", self.unit,
                        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
                    await kill.wait()
                    self.process.kill()
                    await self.process.wait()
            self.stdout.close()
            self.stderr.close()
        if self.runtime_claimed:
            # This directory was created by this invocation, never a prior one.
            shutil.move("/tmp/agtap", self.suite / "agtap-runtime")
            sock = self.suite / "agtap-runtime" / "agtap.sock"
            if sock.is_socket():
                sock.unlink()


class Collector:
    def __init__(self, ledger, raw_dir=None):
        self.ledger = ledger
        self.errors = []
        self.raw_dir = raw_dir
        self.sequence = 0
        self.raw_bytes = 0
        if raw_dir:
            raw_dir.mkdir()

    async def start(self):
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", 0)
        return self.server.sockets[0].getsockname()[1]

    async def handle(self, reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            headers = {k.lower(): v for k, v in (line.decode().split(": ", 1)
                       for line in head.split(b"\r\n")[1:-2])}
            length = int(headers.get("content-length", "0"))
            if length < 1 or length > 16 * 1024 * 1024:
                raise ValueError("Missing or excessive OTLP payload length")
            data = await reader.readexactly(length)
            self.sequence += 1
            if self.raw_dir:
                self.raw_bytes += len(data)
                if self.raw_bytes > 64 * 1024 * 1024:
                    raise ValueError("Raw export budget exceeded")
                (self.raw_dir / f"{self.sequence:05d}.body").write_bytes(data)
                write_json(self.raw_dir / f"{self.sequence:05d}.headers.json", headers)
            if headers.get("content-encoding") == "gzip":
                import gzip
                data = gzip.decompress(data)
            if len(data) > 16 * 1024 * 1024:
                raise ValueError("Excessive uncompressed OTLP payload")
            is_proto = "application/x-protobuf" in headers.get("content-type", "")
            if is_proto:
                request = ExportTraceServiceRequest()
                request.ParseFromString(data)
                self.ledger.write(MessageToDict(request))
                response_body, response_type = b"", "application/x-protobuf"
            elif "application/json" in headers.get("content-type", ""):
                self.ledger.write(json.loads(data))
                response_body, response_type = b"{}", "application/json"
            else:
                raise ValueError("Unsupported OTLP content type")
            writer.write(f"HTTP/1.1 200 OK\r\nContent-Type: {response_type}\r\nContent-Length: {len(response_body)}\r\nConnection: close\r\n\r\n".encode() + response_body)
            await writer.drain()
        except Exception as exc:
            self.errors.append(type(exc).__name__ + ": " + str(exc))
        finally:
            writer.close()
            await writer.wait_closed()

    async def close(self):
        self.server.close()
        await self.server.wait_closed()


async def worker_command(worker, command):
    worker.stdin.write((json.dumps(command) + "\n").encode())
    await worker.stdin.drain()
    line = await asyncio.wait_for(worker.stdout.readline(), 30)
    if not line:
        raise RuntimeError("Application worker exited unexpectedly")
    result = json.loads(line)
    if "error" in result:
        raise RuntimeError("Application worker: " + result["error"])
    return result


async def run_suite(name, batch, suite, cert, key, args, baselines):
    suite.mkdir()
    server_ledger, app_ledger = Ledger(suite / "server.jsonl"), Ledger(suite / "application.jsonl")
    otlp_ledger = Ledger(suite / "otlp.jsonl")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    context.set_alpn_protocols(["h2", "http/1.1"])
    server = FixtureServer(server_ledger, context)
    collector = Collector(otlp_ledger, suite / "otlp-raw")
    port, collector_port = await server.start(), await collector.start()
    worker_log = (suite / "worker.stderr.log").open("wb")
    worker_command_line = [sys.executable, "experiments/accounting_fixture.py"] if args.runtime == "python" else [str(ROOT / "experiments/.cache/accounting-client")]
    worker = await asyncio.create_subprocess_exec(*worker_command_line,
        "--port", str(port), "--cert", str(cert), cwd=ROOT, env=clean_env(),
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=worker_log)
    observer = Observer(name, suite, worker.pid, collector_port, baselines)
    trials, warmups, error = [], [], None
    try:
        ready = json.loads(await asyncio.wait_for(worker.stdout.readline(), 10))
        if ready != {"ready": True}:
            raise RuntimeError("Application worker failed readiness")
        if batch[0]["scenario"] == "late-attach":
            warm_command = {"action": "warm", "protocol": batch[0]["protocol"], "prefix": "warm-" + suite.name,
                            "scenario": "complete", "concurrency": 1, "seed": -1}
            warmed = await worker_command(worker, warm_command)
            app_ledger.write({"parameters": warm_command, "phase": "warmup", **warmed})
            warmups.extend(warmed["attempts"])
        await observer.start(args.startup_seconds)
        if observer.start_error:
            error = observer.start_error
        else:
            for command in batch:
                if observer.process and observer.process.returncode is not None:
                    raise RuntimeError("Observer exited during workload")
                before = process_sample(observer.capture_pid) if observer.capture_pid else None
                result = await worker_command(worker, command)
                after = process_sample(observer.capture_pid) if observer.capture_pid else None
                trial = {"parameters": command, **result}
                if before and after:
                    trial["observer_sampled_cpu_seconds_during_workload"] = after["cpu_seconds"] - before["cpu_seconds"]
                    trial["observer_process_lifetime_peak_rss_kib"] = after["process_lifetime_peak_rss_kib"]
                app_ledger.write(trial)
                trials.append(trial)
            # Allow the server to observe client cancellation before validating.
            await asyncio.sleep(.15)
    except Exception as exc:
        error = {"status": "infrastructure_or_workload_failure", "reason": type(exc).__name__ + ": " + str(exc)}
    finally:
        await observer.stop(args.drain_seconds if not error else 0)
        if worker.returncode is None:
            worker.stdin.write(b'{"action":"stop"}\n')
            try:
                await worker.stdin.drain()
                await asyncio.wait_for(worker.wait(), 5)
            except (asyncio.TimeoutError, BrokenPipeError, ConnectionResetError):
                worker.kill()
                await worker.wait()
        worker_log.close()
        await server.close()
        await collector.close()
        server_ledger.close()
        app_ledger.close()
        otlp_ledger.close()
    raw_server = read_jsonl(suite / "server.jsonl")
    reference_errors = validate_reference(raw_server, warmups + [r for t in trials for r in t["attempts"]])
    if server.errors or collector.errors or reference_errors:
        error = {"status": "invalid_fixture_or_export", "server_errors": server.errors,
                 "collector_errors": collector.errors, "reference_errors": reference_errors}
    observed, diagnostics = observations(name, suite) if not error else ([], [])
    qualification = "fixture_only" if name == "control" else "pending_clean_http1_check"
    if name != "control" and batch[0]["protocol"] == "http1" and batch[0]["scenario"] != "late-attach" and not error:
        if any(r["input"] is not None and r["output"] is not None for r in observed):
            qualification = "usage_export_seen"
        else:
            error = {"status": "observer_not_qualified", "reason": "No clean HTTP/1.1 usage export; diagnose before measuring coverage"}
    derived = []
    if not error and name != "control":
        for trial in trials:
            ids = {r["attempt_id"] for r in trial["attempts"]}
            events = [r for r in raw_server if r["attempt_id"] in ids]
            rids = {r["response_id"] for r in events}
            joined = [r for r in observed if r.get("response_id") in rids or r.get("attempt_id") in ids]
            derived.append({"parameters": trial["parameters"], **score(events, joined)})
        # Suite-level unmatched records are preserved exactly once.
        warm_ids = {r["attempt_id"] for r in warmups}
        overall = score([r for r in raw_server if r["attempt_id"] not in warm_ids], observed)
    else:
        overall = None
    report = {"observer": name, "status": error["status"] if error else "ok",
              "error": error, "qualification": qualification, "trial_count": len(trials),
              "fixture_server_attempts": sum(r["event"] == "received" for r in raw_server) - len(warmups),
              "warmup_attempts": len(warmups), "client_runtime": args.runtime,
              "reference_errors": reference_errors, "observer_final_sample": observer.final_sample,
              "overall": overall, "trials": derived, "diagnostics": diagnostics}
    write_json(suite / "score.json", report)
    return report


async def run(args, output, matrix, baselines):
    cert, key = output / "fixture.pem", output / "fixture.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                    "-keyout", str(key), "-out", str(cert), "-subj", "/CN=api.openai.com",
                    "-addext", "subjectAltName=DNS:api.openai.com"], check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)
    reports = []
    try:
        for name in args.observers:
            qualified = name == "control"
            for protocol in args.protocols:
                ordinary = [c for c in matrix if c["protocol"] == protocol and c["scenario"] != "late-attach"]
                groups = [ordinary] if ordinary else []
                groups += [[c] for c in matrix if c["protocol"] == protocol and c["scenario"] == "late-attach"]
                for index, batch in enumerate(groups):
                    suite = output / f"{name}-{protocol}-{index:03d}"
                    report = await run_suite(name, batch, suite, cert, key, args, baselines)
                    reports.append({"directory": suite.name, **{k: v for k, v in report.items() if k not in ("trials", "diagnostics", "overall")}})
                    print(f"{suite.name}: {report['status']}, {report['trial_count']} trials, {report['fixture_server_attempts']} attempts", flush=True)
                    if report["status"] != "ok":
                        return reports
                    if report["qualification"] == "usage_export_seen":
                        qualified = True
                    if name != "control" and not qualified:
                        raise RuntimeError("No qualified HTTP/1.1 suite before further interpretation")
    finally:
        key.unlink(missing_ok=True)  # Disposable generated fixture key, not a user credential.
    return reports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("screen", "smoke", "main"), default="screen")
    parser.add_argument("--observers", nargs="+", choices=("control", "obi", "agtap"), default=["control"])
    parser.add_argument("--runtime", choices=("python", "go"), default="python")
    parser.add_argument("--protocols", nargs="+", choices=("http1", "http2"), default=["http1", "http2"])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--startup-seconds", type=float, default=8)
    parser.add_argument("--drain-seconds", type=float, default=45)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--isolated-kernel", action="store_true",
                        help="Attest that this is a dedicated VM/test kernel; required for agtap's global pipe probes")
    args = parser.parse_args()
    if Path.cwd().resolve() != ROOT:
        parser.error("Run from the project root")
    if len(set(args.observers)) != len(args.observers) or len(set(args.protocols)) != len(args.protocols):
        parser.error("Duplicate observers or protocols")
    if args.protocols[0] != "http1" and args.observers != ["control"]:
        parser.error("Live comparison must start with HTTP/1.1 qualification")
    if args.startup_seconds < 0 or args.drain_seconds < 0:
        parser.error("Wait times must be nonnegative")
    matrix = cells(args.mode, args.protocols)
    if args.dry_run:
        print(json.dumps({"mode": args.mode, "observers": args.observers,
                          "trials": len(matrix) * len(args.observers),
                          "attempts_per_observer": sum(c["concurrency"] * (2 if c["scenario"] == "retry" else 1) for c in matrix),
                          "root_required": args.observers != ["control"], "matrix": matrix}, indent=2))
        return
    if args.observers != ["control"] and os.geteuid() != 0:
        parser.error("Live eBPF needs administrator access; control runs without root")
    if "agtap" in args.observers and not args.isolated_kernel:
        parser.error("Pinned agtap has system-wide pipe capture even with -p; use a dedicated VM/test kernel and --isolated-kernel")
    go_binary = ROOT / "experiments/.cache/accounting-client"
    if args.runtime == "go" and not go_binary.is_file():
        parser.error("Build experiments/accounting_client.go first; see reproduction guide")
    baselines = json.loads((ROOT / "experiments/baselines.json").read_text())["baselines"]
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    output = args.output or Path("experiments/runs") / (stamp + "-" + args.mode)
    output = output.resolve()
    allowed = (ROOT / "experiments/runs").resolve()
    if not output.is_relative_to(allowed):
        parser.error("Output must be inside experiments/runs")
    output.mkdir(parents=True, exist_ok=False)
    metadata = {"schema_version": 1, "started_at_utc": stamp, "mode": args.mode,
                "observers": args.observers, "protocols": args.protocols,
                "client_runtime": args.runtime,
                "startup_seconds": args.startup_seconds, "drain_seconds": args.drain_seconds,
                "isolated_kernel_attestation": args.isolated_kernel,
                "python": platform.python_version(), "openssl": ssl.OPENSSL_VERSION,
                "kernel": platform.release(), "machine": platform.machine(),
                "available_cpu_count": len(os.sched_getaffinity(0)),
                "hashes": {p.relative_to(ROOT).as_posix(): sha(p) for p in
                           [Path(__file__), ROOT / "experiments/accounting_fixture.py", ROOT / "experiments/score_accounting.py",
                            ROOT / "experiments/requirements.txt", ROOT / "docs/research/accounting-study-protocol.md"]},
                "baselines": baselines, "matrix": matrix,
                "limits": ["synthetic usage; no external model or invoice", "single Python/OpenSSL runtime and kernel",
                           "RSS is a process lifetime high-water mark", "CPU samples have scheduler-tick resolution",
                           "control is fixture validation, not observer accuracy"]}
    if args.runtime == "go":
        metadata["go_version"] = subprocess.check_output(["go", "version"], text=True).strip()
        metadata["go_binary_sha256"] = sha(go_binary)
        metadata["hashes"]["experiments/accounting_client.go"] = sha(ROOT / "experiments/accounting_client.go")
        metadata["limits"][1] = "single Go runtime and kernel; shared Python/hyper-h2 fixture server"
    # Preserve exact measured source before any job starts. Manuscript revisions
    # can then proceed without losing the experiment's implementation snapshot.
    for name, expected in metadata["hashes"].items():
        data = (ROOT / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError("Source changed while freezing: " + name)
        snapshot = output / "source-snapshot" / name
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes(data)
    write_json(output / "metadata.json", metadata)
    try:
        reports = asyncio.run(run(args, output, matrix, baselines))
        metadata["suites"] = reports
        metadata["status"] = "ok" if all(r["status"] == "ok" for r in reports) else "blocked_or_invalid"
    except Exception as exc:
        metadata["status"] = "blocked_or_invalid"
        metadata["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        (output / "fixture.key").unlink(missing_ok=True)
        metadata["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        write_json(output / "metadata.json", metadata)
        # Preserve research files; return newly created output to the sudo user.
        if os.geteuid() == 0 and "SUDO_UID" in os.environ and "SUDO_GID" in os.environ:
            uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
            for path in output.rglob("*"):
                if not path.is_symlink():
                    os.chown(path, uid, gid)
            os.chown(output, uid, gid)
    print("Evidence saved: " + output.relative_to(ROOT).as_posix(), flush=True)
    if metadata["status"] != "ok":
        raise SystemExit(1)


if __name__ == "__main__":
    main()

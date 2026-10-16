"""Loopback TLS/SSE fixture and separate application-reference worker.

Counts are assigned synthetic integers, never actual model tokens. Server
events are independent of the client reference. No logical task ID is on wire.
"""
import asyncio
import hashlib
import json
import resource
import ssl
import sys
import time

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, StreamEnded, StreamReset


SCENARIOS = ("complete", "no-usage", "cancel", "disconnect", "large-body",
             "retry", "late-attach", "pressure", "reported-zero")
MODEL = "gpt-fixture"


def json_bytes(value):
    return json.dumps(value, separators=(",", ":")).encode()


def attempt_id(prefix, index, retry):
    # Opaque IDs do not expose the application's retry/task grouping.
    return hashlib.sha256(f"{prefix}/{index}/{retry}".encode()).hexdigest()[:24]


class Ledger:
    def __init__(self, path):
        self.file = path.open("w", encoding="utf-8")

    def write(self, value):
        self.file.write(json.dumps(value, separators=(",", ":")) + "\n")
        self.file.flush()

    def close(self):
        self.file.close()


def response_plan(headers):
    aid = headers["x-fixture-attempt-id"]
    scenario = headers["x-fixture-scenario"]
    rid = "chatcmpl-fixture-" + aid
    n = int(hashlib.sha256(aid.encode()).hexdigest()[:8], 16)
    usage = {"prompt_tokens": 10 + n % 997, "completion_tokens": 1 + (n // 997) % 499}
    if scenario == "reported-zero":
        usage = {"prompt_tokens": 0, "completion_tokens": 0}
    usage["total_tokens"] = usage["prompt_tokens"] + usage["completion_tokens"]
    status = 429 if scenario == "retry" and headers["x-fixture-retry"] == "0" else 200
    base = {"id": rid, "object": "chat.completion.chunk", "created": 0, "model": MODEL}
    first = {**base, "choices": [{"index": 0, "delta": {"content": "hello"},
                                  "finish_reason": None}], "usage": None}
    pieces = [b"data: " + json_bytes(first) + b"\n\n"]
    if scenario in ("large-body", "pressure"):
        big = {**base, "choices": [{"index": 0, "delta": {"content": "x" * (96 * 1024)},
                                    "finish_reason": None}], "usage": None}
        pieces.append(b"data: " + json_bytes(big) + b"\n\n")
    finish = {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
              "usage": None}
    pieces.append(b"data: " + json_bytes(finish) + b"\n\n")
    emits = scenario not in ("no-usage", "cancel", "disconnect") and status == 200
    if emits:
        pieces.append(b"data: " + json_bytes({**base, "choices": [], "usage": usage}) + b"\n\n")
    pieces.append(b"data: [DONE]\n\n")
    if status == 429:
        pieces = [json_bytes({"id": rid, "error": {"message": "fixture retry", "type": "rate_limit_error"}})]
    return {"attempt_id": aid, "response_id": rid, "scenario": scenario, "status": status,
            "assigned_usage": usage, "usage_planned": emits, "pieces": pieces}


class FixtureServer:
    def __init__(self, ledger, context):
        self.ledger, self.context = ledger, context
        self.connection_count = 0
        self.errors = []
        self.handlers = set()

    def record(self, plan, event, **fields):
        self.ledger.write({"event": event, "time_ns": time.monotonic_ns(),
                           **{k: v for k, v in plan.items() if k != "pieces"}, **fields})

    async def start(self):
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", 0, ssl=self.context)
        return self.server.sockets[0].getsockname()[1]

    async def close(self):
        self.server.close()
        await self.server.wait_closed()
        if self.handlers:
            await asyncio.wait_for(asyncio.gather(*self.handlers, return_exceptions=True), 5)

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        self.handlers.add(task)
        self.connection_count += 1
        cid = self.connection_count
        protocol = writer.get_extra_info("ssl_object").selected_alpn_protocol()
        try:
            if protocol == "h2":
                await self.http2(reader, writer, cid)
            else:
                await self.http1(reader, writer, cid)
        except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError):
            pass  # Expected faults are recorded per attempt below.
        except Exception as exc:
            self.errors.append(type(exc).__name__ + ": " + str(exc))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, ssl.SSLError):
                pass
            self.handlers.discard(task)

    async def http1(self, reader, writer, cid):
        while True:
            try:
                head = await reader.readuntil(b"\r\n\r\n")
            except asyncio.IncompleteReadError:
                return
            headers = dict(line.decode().split(": ", 1) for line in head.split(b"\r\n")[1:-2])
            headers = {k.lower(): v for k, v in headers.items()}
            await reader.readexactly(int(headers["content-length"]))
            plan = response_plan(headers)
            self.record(plan, "received", protocol="http1", connection_id=cid, stream_id=None)
            sent = False
            termination = "connection_closed"
            try:
                status = plan["status"]
                content_type = "text/event-stream" if status == 200 else "application/json"
                writer.write(f"HTTP/1.1 {status} {'OK' if status == 200 else 'Too Many Requests'}\r\n"
                             f"Content-Type: {content_type}\r\nTransfer-Encoding: chunked\r\n"
                             f"Openai-Version: fixture\r\nX-Request-Id: {plan['response_id']}\r\n\r\n".encode())
                for i, piece in enumerate(plan["pieces"]):
                    if i and plan["scenario"] in ("cancel", "disconnect"):
                        await asyncio.sleep(.05)
                        termination = "client_cancel_fixture" if plan["scenario"] == "cancel" else "server_disconnect"
                        return  # Deliberately omit final chunk framing and usage.
                    writer.write(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
                    await writer.drain()
                    if b'"usage":{"prompt_tokens"' in piece:
                        sent = True
                        self.record(plan, "usage_emitted", protocol="http1", connection_id=cid)
                    if plan["scenario"] != "pressure":
                        await asyncio.sleep(.001 + int(plan["attempt_id"][:2], 16) % 3 * .001)
                writer.write(b"0\r\n\r\n")
                await writer.drain()
                termination = "complete"
            finally:
                self.record(plan, "terminated", usage_emitted=sent, termination=termination)

    async def http2(self, reader, writer, cid):
        conn = H2Connection(config=H2Configuration(client_side=False, header_encoding="utf-8"))
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        streams, pending = {}, {}
        while True:
            try:
                data = await asyncio.wait_for(reader.read(65536), .003 if pending else 30)
            except asyncio.TimeoutError:
                data = None
            if data == b"":
                for sid, item in pending.items():
                    self.record(item["plan"], "terminated", termination="connection_closed",
                                usage_emitted=item["sent"], stream_id=sid)
                return
            if data:
                for event in conn.receive_data(data):
                    if isinstance(event, RequestReceived):
                        streams[event.stream_id] = dict(event.headers)
                    elif isinstance(event, DataReceived):
                        conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, StreamEnded):
                        sid = event.stream_id
                        plan = response_plan(streams.pop(sid))
                        self.record(plan, "received", protocol="http2", connection_id=cid, stream_id=sid)
                        conn.send_headers(sid, [(":status", str(plan["status"])),
                                                ("content-type", "text/event-stream" if plan["status"] == 200 else "application/json"),
                                                ("openai-version", "fixture"), ("x-request-id", plan["response_id"])])
                        pending[sid] = {"plan": plan, "piece": 0, "offset": 0, "sent": False,
                                        "resume_at": 0}
                    elif isinstance(event, StreamReset):
                        item = pending.pop(event.stream_id, None)
                        if item:
                            self.record(item["plan"], "terminated", termination="client_reset",
                                        usage_emitted=item["sent"], stream_id=event.stream_id)
            # Distinct opaque IDs (derived from the seed) govern the interleave.
            schedule = sorted(pending.items(), key=lambda pair: pair[1]["plan"]["attempt_id"])
            for sid, item in schedule:
                if time.monotonic() < item["resume_at"]:
                    continue
                plan = item["plan"]
                i = item["piece"]
                if i and plan["scenario"] in ("cancel", "disconnect"):
                    conn.reset_stream(sid, error_code=2)
                    self.record(plan, "terminated", termination="server_reset", usage_emitted=False, stream_id=sid)
                    del pending[sid]
                    continue
                piece = plan["pieces"][i]
                size = min(4096, len(piece) - item["offset"], conn.local_flow_control_window(sid))
                if size <= 0:
                    continue
                chunk = piece[item["offset"]:item["offset"] + size]
                last = item["offset"] + size == len(piece)
                ended = last and i == len(plan["pieces"]) - 1
                conn.send_data(sid, chunk, end_stream=ended)
                # Flush each round-robin stream slice, then record emitted evidence.
                writer.write(conn.data_to_send())
                await writer.drain()
                item["offset"] += size
                if last:
                    if b'"usage":{"prompt_tokens"' in piece:
                        item["sent"] = True
                        self.record(plan, "usage_emitted", protocol="http2", connection_id=cid, stream_id=sid)
                    item["piece"], item["offset"] = i + 1, 0
                    item["resume_at"] = time.monotonic() + (.05 if plan["scenario"] in ("cancel", "disconnect") else .001)
                if ended:
                    self.record(plan, "terminated", termination="complete", usage_emitted=item["sent"], stream_id=sid)
                    del pending[sid]
            writer.write(conn.data_to_send())
            await writer.drain()


def request_headers(attempt, scenario, retry):
    return [("host", "api.openai.com"), ("content-type", "application/json"),
            ("x-fixture-attempt-id", attempt), ("x-fixture-scenario", scenario),
            ("x-fixture-retry", str(retry))]


def extract_usage(body):
    rid, usage, done = None, None, False
    for line in body.splitlines():
        if not line.startswith(b"data: "):
            continue
        value = line[6:]
        if value == b"[DONE]":
            done = True
            continue
        try:
            event = json.loads(value)
        except (ValueError, UnicodeError):
            continue
        rid = event.get("id", rid)
        if isinstance(event.get("usage"), dict):
            usage = event["usage"]
    return rid, usage, done


class FixtureClient:
    def __init__(self, port, cert):
        self.port = port
        self.context = ssl.create_default_context(cafile=cert)
        self.warm = None

    async def connect(self, protocol):
        self.context.set_alpn_protocols(["h2" if protocol == "http2" else "http/1.1"])
        return await asyncio.open_connection("127.0.0.1", self.port, ssl=self.context,
                                              server_hostname="api.openai.com")

    async def close_writer(self, writer):
        writer.close()
        try:
            await writer.wait_closed()
        except (ssl.SSLError, ConnectionError):
            pass

    async def http1_attempt(self, attempt, scenario, retry, warm=None, keep_open=False):
        reader, writer = warm or await self.connect("http1")
        body = json_bytes({"model": MODEL, "messages": [{"role": "user", "content": "fixture"}],
                           "stream": True, "stream_options": {"include_usage": True}})
        headers = request_headers(attempt, scenario, retry) + [("content-length", str(len(body)))]
        writer.write(b"POST /v1/chat/completions HTTP/1.1\r\n" +
                     b"".join(f"{k}: {v}\r\n".encode() for k, v in headers) + b"\r\n" + body)
        await writer.drain()
        head = await reader.readuntil(b"\r\n\r\n")
        status = int(head.split()[1])
        payload = bytearray()
        termination = "complete"
        try:
            while True:
                size = int((await reader.readline()).strip(), 16)
                if size == 0:
                    await reader.readexactly(2)
                    break
                payload.extend(await reader.readexactly(size))
                await reader.readexactly(2)
                if scenario == "cancel":
                    termination = "client_cancel"
                    break
        except (asyncio.IncompleteReadError, ConnectionError, ValueError):
            termination = "server_disconnect"
        if not keep_open:
            await self.close_writer(writer)
        rid, usage, done = extract_usage(bytes(payload))
        return {"attempt_id": attempt, "response_id": rid, "status": status, "usage": usage,
                "sse_done": done, "termination": termination}

    async def h2_session(self):
        reader, writer = await self.connect("http2")
        conn = H2Connection(config=H2Configuration(client_side=True, header_encoding="utf-8"))
        conn.initiate_connection()
        # Increase connection window; stream windows still exercise flow control.
        conn.increment_flow_control_window(16 * 1024 * 1024)
        writer.write(conn.data_to_send())
        await writer.drain()
        return reader, writer, conn

    async def http2_batch(self, command, warm=None, keep_open=False):
        reader, writer, conn = warm or await self.h2_session()
        results, active = [], {}
        scenario = command["scenario"]

        def send(index, retry):
            sid = conn.get_next_available_stream_id()
            aid = attempt_id(command["prefix"], index, retry)
            body = json_bytes({"model": MODEL, "messages": [{"role": "user", "content": "fixture"}],
                               "stream": True, "stream_options": {"include_usage": True}})
            headers = [(":method", "POST"), (":scheme", "https"), (":authority", "api.openai.com"),
                       (":path", "/v1/chat/completions"), *request_headers(aid, scenario, retry),
                       ("content-length", str(len(body)))]
            conn.send_headers(sid, headers)
            conn.send_data(sid, body, end_stream=True)
            active[sid] = {"attempt_id": aid, "index": index, "retry": retry,
                           "status": None, "body": bytearray()}

        for i in range(command["concurrency"]):
            send(i, 0)
        while active:
            writer.write(conn.data_to_send())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(65536), 10)
            if not data:
                raise RuntimeError("Unexpected whole HTTP/2 connection loss")
            for event in conn.receive_data(data):
                # Import here to keep all response event types explicit.
                from h2.events import ResponseReceived
                if isinstance(event, ResponseReceived) and event.stream_id in active:
                    active[event.stream_id]["status"] = int(dict(event.headers)[":status"])
                elif isinstance(event, DataReceived):
                    conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    item = active.get(event.stream_id)
                    if item:
                        item["body"].extend(event.data)
                        if scenario == "cancel":
                            conn.reset_stream(event.stream_id, error_code=8)
                            self.finish_h2(item, results, "client_cancel")
                            del active[event.stream_id]
                elif isinstance(event, (StreamEnded, StreamReset)) and event.stream_id in active:
                    item = active.pop(event.stream_id)
                    self.finish_h2(item, results, "complete" if isinstance(event, StreamEnded) else "server_reset")
                    if scenario == "retry" and item["retry"] == 0:
                        if item["status"] != 429:
                            raise RuntimeError("Retry fixture did not receive HTTP 429")
                        send(item["index"], 1)
        writer.write(conn.data_to_send())
        await writer.drain()
        # Allow RST_STREAM to reach server before closing connection.
        await asyncio.sleep(.01)
        if not keep_open:
            await self.close_writer(writer)
        return results

    @staticmethod
    def finish_h2(item, results, termination):
        rid, usage, done = extract_usage(bytes(item["body"]))
        results.append({"attempt_id": item["attempt_id"], "response_id": rid,
                        "status": item["status"], "usage": usage,
                        "sse_done": done, "termination": termination})

    async def batch(self, command):
        warm, self.warm = self.warm, None
        if command["protocol"] == "http2":
            attempts = await self.http2_batch(command, warm)
        else:
            async def task(i):
                rows = [await self.http1_attempt(attempt_id(command["prefix"], i, 0),
                                                command["scenario"], 0, warm if i == 0 else None)]
                if command["scenario"] == "retry":
                    if rows[0]["status"] != 429:
                        raise RuntimeError("Retry fixture did not receive HTTP 429")
                    rows.append(await self.http1_attempt(attempt_id(command["prefix"], i, 1), "retry", 1))
                return rows
            attempts = [row for rows in await asyncio.gather(*(task(i) for i in range(command["concurrency"]))) for row in rows]
        for row in attempts:
            # Logical grouping is retained only in this application ledger.
            index = next(i for i in range(command["concurrency"])
                         if row["attempt_id"] in (attempt_id(command["prefix"], i, 0),
                                                  attempt_id(command["prefix"], i, 1)))
            row["task_id"] = command["prefix"] + f"-task{index}"
        return attempts


async def worker(port, cert):
    client = FixtureClient(port, cert)
    print(json.dumps({"ready": True}), flush=True)  # SSL library is already loaded.
    while line := await asyncio.to_thread(sys.stdin.readline):
        command = json.loads(line)
        if command.get("action") == "stop":
            if client.warm:
                await client.close_writer(client.warm[1])
            break
        if command.get("action") == "warm":
            client.warm = await client.h2_session() if command["protocol"] == "http2" else await client.connect("http1")
            warm_command = {**command, "scenario": "complete", "concurrency": 1}
            if command["protocol"] == "http2":
                attempts = await client.http2_batch(warm_command, client.warm, keep_open=True)
            else:
                attempts = [await client.http1_attempt(attempt_id(command["prefix"], 0, 0), "complete", 0,
                                                      client.warm, keep_open=True)]
            for row in attempts:
                row["task_id"] = command["prefix"] + "-warmup"
            await asyncio.sleep(.1)
            print(json.dumps({"warm": True, "attempts": attempts}), flush=True)
            continue
        before = resource.getrusage(resource.RUSAGE_SELF)
        started = time.perf_counter()
        try:
            attempts = await client.batch(command)
            result = {"attempts": attempts, "duration_seconds": time.perf_counter() - started}
        except Exception as exc:
            result = {"error": type(exc).__name__ + ": " + str(exc)}
        after = resource.getrusage(resource.RUSAGE_SELF)
        result.update(client_cpu_seconds=(after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime),
                      client_peak_rss_kib=after.ru_maxrss)
        print(json.dumps(result), flush=True)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Separate TLS fixture application worker")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cert", required=True)
    args = parser.parse_args()
    asyncio.run(worker(args.port, args.cert))

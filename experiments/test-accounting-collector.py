#!/usr/bin/env python3
"""Exercise actual OTLP JSON/protobuf HTTP delivery and acknowledgments."""
import asyncio
import gzip
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from google.protobuf.json_format import MessageToDict
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest, ExportTraceServiceResponse

from accounting_fixture import Ledger
from score_accounting import observations, read_jsonl

spec = importlib.util.spec_from_file_location("study", Path(__file__).with_name("run-study.py"))
study = importlib.util.module_from_spec(spec)
spec.loader.exec_module(study)


class CollectorTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_export_formats_preserve_zero_and_missing(self):
        request = ExportTraceServiceRequest()
        scope = request.resource_spans.add().scope_spans.add()
        span = scope.spans.add(name="fixture")
        span.attributes.add(key="gen_ai.response.id").value.string_value = "fixture-id"
        span.attributes.add(key="gen_ai.usage.input_tokens").value.int_value = 0
        payloads = [(request.SerializeToString(), "application/x-protobuf", None),
                    (gzip.compress(request.SerializeToString()), "application/x-protobuf", "gzip"),
                    (json.dumps(MessageToDict(request)).encode(), "application/json", None)]
        with tempfile.TemporaryDirectory(prefix="accounting-collector-") as directory:
            root = Path(directory)
            ledger = Ledger(root / "otlp.jsonl")
            collector = study.Collector(ledger, root / "otlp-raw")
            port = await collector.start()
            try:
                for data, mime, encoding in payloads:
                    reader, writer = await asyncio.open_connection("127.0.0.1", port)
                    head = (f"POST /v1/traces HTTP/1.1\r\nHost: localhost\r\nContent-Type: {mime}\r\n"
                            f"Content-Length: {len(data)}\r\n" + (f"Content-Encoding: {encoding}\r\n" if encoding else "") + "\r\n").encode()
                    writer.write(head + data)
                    await writer.drain()
                    response = await reader.read()
                    header, body = response.split(b"\r\n\r\n", 1)
                    self.assertIn(b"200 OK", header)
                    if mime == "application/x-protobuf":
                        ExportTraceServiceResponse().ParseFromString(body)
                    else:
                        self.assertEqual(json.loads(body), {})
                    writer.close()
                    await writer.wait_closed()
            finally:
                await collector.close()
                ledger.close()
            self.assertEqual(collector.errors, [])
            rows, diagnostics = observations("obi", root)
            self.assertEqual(diagnostics, [])
            self.assertEqual(len(rows), 3)
            self.assertTrue(all(r["response_id"] == "fixture-id" and r["input"] == 0 and r["output"] is None for r in rows))
            self.assertEqual(len(list((root / "otlp-raw").glob("*.body"))), 3)
            self.assertEqual(len(read_jsonl(root / "otlp.jsonl")), 3)


if __name__ == "__main__":
    unittest.main()

"""Tests for the MCP protocol layer: version negotiation, tool annotations,
error reporting, time limits, cancellation and the call trace.

They need no IDA installation:

    python -m unittest discover -s tests -v
"""

import json
import os
import tempfile
import threading
import time
import unittest
from typing import Annotated

from ida_auto_mcp.mcp_server import PROTOCOL_VERSIONS, McpServer


def decompile_thing(address: Annotated[str, "Address"]) -> dict:
    """Pretend to decompile."""
    return {"address": address}


def fail_softly() -> dict:
    """Report a failure in the result."""
    return {"error": "no function here"}


def fail_success_false() -> dict:
    """Report a failure with success: false."""
    return {"success": False}


def succeed() -> dict:
    """Report success."""
    return {"success": True}


def raise_error() -> dict:
    """Raise an exception."""
    raise RuntimeError("broken")


def spin() -> dict:
    """Loop forever in Python code."""
    while True:
        pass


def spin_stubbornly() -> dict:
    """Loop forever, swallowing every Exception."""
    while True:
        try:
            while True:
                pass
        except Exception:
            pass


def nap() -> dict:
    """Run for half a second."""
    deadline = time.monotonic() + 0.5
    while time.monotonic() < deadline:
        pass
    return {"slept": True}


def initialize(server: McpServer, version: str) -> dict:
    return server.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": version,
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
        }
    )["result"]


def call(server: McpServer, name: str, arguments: dict | None = None) -> dict:
    return server.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
    )["result"]


def listed(server: McpServer) -> dict:
    response = server.dispatch({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    return {tool["name"]: tool for tool in response["result"]["tools"]}


class NegotiationTests(unittest.TestCase):
    def test_supported_versions_are_echoed(self):
        server = McpServer("test")
        for version in PROTOCOL_VERSIONS:
            self.assertEqual(initialize(server, version)["protocolVersion"], version)

    def test_unknown_version_gets_the_newest(self):
        result = initialize(McpServer("test"), "1999-01-01")
        self.assertEqual(result["protocolVersion"], PROTOCOL_VERSIONS[0])

    def test_instructions_are_sent_when_set(self):
        self.assertEqual(
            initialize(McpServer("test", instructions="Do X."), "2025-06-18")[
                "instructions"
            ],
            "Do X.",
        )
        self.assertNotIn("instructions", initialize(McpServer("test"), "2025-06-18"))


class AnnotationTests(unittest.TestCase):
    def setUp(self):
        self.server = McpServer("test")
        self.server.tool(decompile_thing, annotations={"readOnlyHint": True})

    def test_new_revisions_get_a_top_level_title(self):
        initialize(self.server, "2025-11-25")
        tool = listed(self.server)["decompile_thing"]
        self.assertEqual(tool["title"], "Decompile thing")
        self.assertEqual(tool["annotations"], {"readOnlyHint": True})

    def test_older_revisions_get_the_title_in_annotations(self):
        initialize(self.server, "2025-03-26")
        tool = listed(self.server)["decompile_thing"]
        self.assertNotIn("title", tool)
        self.assertEqual(
            tool["annotations"], {"readOnlyHint": True, "title": "Decompile thing"}
        )


class ErrorReportingTests(unittest.TestCase):
    def setUp(self):
        self.server = McpServer("test")
        for func in (fail_softly, fail_success_false, succeed, raise_error):
            self.server.tool(func)

    def test_error_results_are_flagged(self):
        self.assertTrue(call(self.server, "fail_softly")["isError"])
        self.assertTrue(call(self.server, "fail_success_false")["isError"])
        self.assertTrue(call(self.server, "raise_error")["isError"])

    def test_successful_results_are_not_flagged(self):
        result = call(self.server, "succeed")
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"], {"success": True})


def list_things(
    filter_str: Annotated[str, "Filter"] = "",
    count: Annotated[int, "How many"] = 3,
    exact: Annotated[bool, "Exact match"] = False,
    ratio: Annotated[float, "A ratio"] = 0.5,
    tags: Annotated[list[str] | None, "Tags"] = None,
) -> dict:
    """Echo the arguments with their types."""
    return {
        "filter_str": filter_str,
        "count": count,
        "count_type": type(count).__name__,
        "exact": exact,
        "ratio": ratio,
        "tags": tags,
    }


class ArgumentValidationTests(unittest.TestCase):
    def setUp(self):
        self.server = McpServer("test")
        self.server.tool(list_things)
        self.server.tool(decompile_thing)

    def refusal(self, name: str, arguments) -> str:
        result = call(self.server, name, arguments)
        self.assertTrue(result["isError"], result)
        return result["content"][0]["text"]

    def test_valid_arguments_pass(self):
        result = call(
            self.server,
            "list_things",
            {"filter_str": "a", "count": 5, "exact": True, "ratio": 2, "tags": ["x"]},
        )
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"]["count"], 5)
        self.assertEqual(result["structuredContent"]["tags"], ["x"])

    def test_misspelled_name_is_refused_with_a_suggestion(self):
        text = self.refusal("list_things", {"filter": "main"})
        self.assertIn("unknown argument 'filter' (did you mean 'filter_str'?)", text)
        self.assertIn("Its arguments: filter_str, count, exact, ratio, tags.", text)

    def test_wrong_types_are_refused(self):
        self.assertIn(
            "'count' must be an integer, not the string \"5\"",
            self.refusal("list_things", {"count": "5"}),
        )
        self.assertIn(
            "'exact' must be true or false, not the string \"false\"",
            self.refusal("list_things", {"exact": "false"}),
        )
        self.assertIn("'count' must be an integer, not true", self.refusal("list_things", {"count": True}))
        self.assertIn("'count' must be an integer", self.refusal("list_things", {"count": 2.5}))
        self.assertIn(
            "'tags' must be an array or null",
            self.refusal("list_things", {"tags": [1]}),
        )

    def test_integral_number_counts_as_integer(self):
        result = call(self.server, "list_things", {"count": 4.0})
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"]["count_type"], "int")

    def test_missing_required_argument(self):
        self.assertIn("missing 'address'", self.refusal("decompile_thing", {}))

    def test_arguments_must_be_an_object(self):
        self.assertIn("expected an object, not an array", self.refusal("decompile_thing", ["0x1"]))

    def test_client_metadata_is_ignored(self):
        result = call(self.server, "decompile_thing", {"address": "0x1", "_meta": {"a": 1}})
        self.assertFalse(result["isError"])

    def test_refusal_is_traced(self):
        with tempfile.TemporaryDirectory() as directory:
            self.server.trace_path = os.path.join(directory, "trace.jsonl")
            call(self.server, "list_things", {"cnt": 1})
            with open(self.server.trace_path, encoding="utf-8") as f:
                record = json.loads(f.readline())
        self.assertTrue(record["is_error"])
        self.assertIn("unknown argument 'cnt'", record["error"])


class TimeLimitTests(unittest.TestCase):
    def setUp(self):
        self.server = McpServer("test")
        self.server.tool_timeout = 0.2
        self.server.tool(spin)
        self.server.tool(spin_stubbornly)
        self.server.tool(succeed)
        self.server.tool(nap, interruptible=False)

    def test_python_loop_is_stopped(self):
        started = time.monotonic()
        result = call(self.server, "spin")
        self.assertLess(time.monotonic() - started, 5)
        self.assertTrue(result["isError"])
        self.assertIn("timed out", result["content"][0]["text"])
        # Nothing is left pending for the next call
        self.assertFalse(call(self.server, "succeed")["isError"])
        time.sleep(0.3)
        self.assertFalse(call(self.server, "succeed")["isError"])

    def test_except_exception_does_not_swallow_the_interrupt(self):
        result = call(self.server, "spin_stubbornly")
        self.assertTrue(result["isError"])
        self.assertIn("timed out", result["content"][0]["text"])

    def test_uninterruptible_tool_runs_to_completion(self):
        result = call(self.server, "nap")
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"], {"slept": True})


class CancellationTests(unittest.TestCase):
    def test_cancelled_call_is_stopped_and_gets_no_response(self):
        server = McpServer("test")
        server.tool(spin)

        read_fd, write_fd = os.pipe()
        stdin = os.fdopen(read_fd, "rb")
        writer = os.fdopen(write_fd, "wb")
        output = []

        class Out:
            def write(self, data):
                output.append(data)

            def flush(self):
                pass

        thread = threading.Thread(target=server.stdio, args=(stdin, Out()), daemon=True)
        thread.start()

        def send(message):
            writer.write(json.dumps(message).encode() + b"\n")
            writer.flush()

        send(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": "spin", "arguments": {}},
            }
        )
        time.sleep(0.3)
        send(
            {
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": 7, "reason": "user pressed stop"},
            }
        )
        send({"jsonrpc": "2.0", "id": 8, "method": "ping"})
        writer.close()
        thread.join(timeout=10)
        self.assertFalse(thread.is_alive())
        stdin.close()

        replies = [json.loads(data) for data in output]
        self.assertEqual(replies, [{"jsonrpc": "2.0", "result": {}, "id": 8}])


class IdleTaskTests(unittest.TestCase):
    """idle_task: background work (IDA analysis) between messages."""

    def start(self, server: McpServer):
        read_fd, write_fd = os.pipe()
        self.stdin = os.fdopen(read_fd, "rb")
        self.writer = os.fdopen(write_fd, "wb")
        self.output = []
        output = self.output

        class Out:
            def write(self, data):
                output.append(data)

            def flush(self):
                pass

        self.thread = threading.Thread(
            target=server.stdio, args=(self.stdin, Out()), daemon=True
        )
        self.thread.start()

    def ping(self, request_id) -> float:
        """Send a ping; returns the seconds until its reply arrived."""
        count = len(self.output)
        started = time.monotonic()
        message = {"jsonrpc": "2.0", "id": request_id, "method": "ping"}
        self.writer.write(json.dumps(message).encode() + b"\n")
        self.writer.flush()
        while len(self.output) == count and time.monotonic() - started < 10:
            time.sleep(0.005)
        self.assertEqual(
            json.loads(self.output[-1]), {"jsonrpc": "2.0", "result": {}, "id": request_id}
        )
        return time.monotonic() - started

    def stop(self):
        self.writer.close()
        self.thread.join(timeout=10)
        self.assertFalse(self.thread.is_alive())
        self.stdin.close()

    def wait_for(self, condition, seconds=5):
        deadline = time.monotonic() + seconds
        while not condition() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(condition())

    def test_idle_task_runs_while_no_message_waits(self):
        server = McpServer("test")
        calls = []
        server.idle_task = lambda: calls.append(1) or len(calls) < 5
        self.start(server)
        self.wait_for(lambda: len(calls) >= 5)
        self.ping(1)
        self.stop()

    def test_requests_are_answered_while_idle_work_remains(self):
        server = McpServer("test")

        def endless_work():
            time.sleep(0.01)
            return True

        server.idle_task = endless_work
        self.start(server)
        time.sleep(0.1)
        for request_id in range(3):
            self.assertLess(self.ping(request_id), 1)
        # End of input still stops the server
        self.stop()

    def test_failing_idle_task_is_retried_after_the_next_message(self):
        server = McpServer("test")
        calls = []

        def broken():
            calls.append(1)
            raise RuntimeError("broken")

        server.idle_task = broken
        with self.assertLogs("ida_auto_mcp.mcp_server", level="WARNING"):
            self.start(server)
            self.wait_for(lambda: len(calls) == 1)
            time.sleep(0.6)
            self.assertEqual(len(calls), 1)
            self.ping(1)
            self.wait_for(lambda: len(calls) == 2)
            self.stop()

    def test_deferred_work_waits_until_the_client_is_quiet(self):
        server = McpServer("test")
        ran = []
        server.defer(lambda: ran.append(time.monotonic()))
        self.start(server)
        time.sleep(0.3)
        self.assertEqual(ran, [])  # nothing before the client's first message
        # A startup exchange: messages in quick succession
        for request_id in range(4):
            self.ping(request_id)
            time.sleep(0.2)
        self.assertEqual(ran, [])
        last = time.monotonic()
        self.wait_for(lambda: len(ran) == 1)
        self.assertGreaterEqual(ran[0] - last, 0.5)
        self.ping(9)
        self.assertEqual(len(ran), 1)
        self.stop()

    def test_deferred_work_runs_before_a_tool_call(self):
        server = McpServer("test")
        order = []
        server.defer(lambda: order.append("deferred"))

        def record() -> dict:
            """Record the call."""
            order.append("tool")
            return {}

        server.tool(record)
        call(server, "record")
        call(server, "record")
        self.assertEqual(order, ["deferred", "tool", "tool"])

    def test_failing_deferred_work_is_logged(self):
        server = McpServer("test")
        server.tool(succeed)

        def broken():
            raise RuntimeError("cannot open")

        server.defer(broken)
        with self.assertLogs("ida_auto_mcp.mcp_server", level="WARNING"):
            result = call(server, "succeed")
        self.assertFalse(result["isError"])

    def test_http_server_runs_the_idle_task_between_requests(self):
        server = McpServer("test")
        calls = []
        server.idle_task = lambda: calls.append(1) or len(calls) < 3
        httpd = server.http_server("127.0.0.1", 0, "test-token-123")
        try:
            httpd.service_actions()
        finally:
            httpd.server_close()
        self.assertEqual(len(calls), 3)


class TraceTests(unittest.TestCase):
    def test_each_call_is_appended(self):
        server = McpServer("test")
        server.tool(decompile_thing)
        server.tool(fail_softly)
        with tempfile.TemporaryDirectory() as directory:
            server.trace_path = os.path.join(directory, "trace.jsonl")
            call(server, "decompile_thing", {"address": "0x401000"})
            call(server, "fail_softly")
            with open(server.trace_path, encoding="utf-8") as f:
                records = [json.loads(line) for line in f]
        self.assertEqual([r["tool"] for r in records], ["decompile_thing", "fail_softly"])
        self.assertEqual(records[0]["arguments"], {"address": "0x401000"})
        self.assertFalse(records[0]["is_error"])
        self.assertTrue(records[1]["is_error"])
        self.assertEqual(records[1]["error"], "no function here")
        self.assertIn("duration_ms", records[0])


if __name__ == "__main__":
    unittest.main()

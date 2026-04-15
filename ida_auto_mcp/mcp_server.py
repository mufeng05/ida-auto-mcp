"""Minimal MCP (Model Context Protocol) server implementation.

Supports stdio and HTTP Streamable transports.
Automatic tool schema generation from Python type hints.
"""

import json
import sys
import inspect
import traceback
from typing import (
    Any,
    BinaryIO,
    Callable,
    Annotated,
    Union,
    get_origin,
    get_args,
    get_type_hints,
    is_typeddict,
)
from types import UnionType
from http.server import BaseHTTPRequestHandler, HTTPServer


MAX_OUTPUT_CHARS = 50_000


class McpServer:
    """MCP server with stdio and HTTP transports."""

    def __init__(self, name: str, version: str = "1.0.0"):
        self.name = name
        self.version = version
        self._tools: dict[str, Callable] = {}

        self._handlers: dict[str, Callable] = {
            "initialize": self._handle_initialize,
            "notifications/initialized": lambda **kw: None,
            "notifications/cancelled": lambda **kw: None,
            "ping": lambda **kw: {},
            "tools/list": self._handle_tools_list,
            "tools/call": self._handle_tools_call,
            "resources/list": lambda **kw: {"resources": []},
            "resources/templates/list": lambda **kw: {"resourceTemplates": []},
            "resources/read": self._handle_resources_read,
            "prompts/list": lambda **kw: {"prompts": []},
        }

    def tool(self, func: Callable) -> Callable:
        """Register a function as an MCP tool."""
        self._tools[func.__name__] = func
        return func

    def dispatch(self, request: bytes | str | dict) -> dict | None:
        """Dispatch a JSON-RPC 2.0 request and return response or None for notifications."""
        if isinstance(request, (bytes, str)):
            try:
                request = json.loads(request)
            except json.JSONDecodeError as e:
                return {
                    "jsonrpc": "2.0",
                    "error": {"code": -32700, "message": f"Parse error: {e}"},
                    "id": None,
                }

        method = request.get("method", "")
        params = request.get("params") or {}
        request_id = request.get("id")

        handler = self._handlers.get(method)
        if handler is None:
            if request_id is None:
                return None
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": f"Method not found: {method}"},
                "id": request_id,
            }

        try:
            if isinstance(params, list):
                result = handler(*params)
            else:
                result = self._call_with_params(handler, params)

            if request_id is None:
                return None  # Notification - no response
            return {"jsonrpc": "2.0", "result": result, "id": request_id}
        except Exception as e:
            if request_id is None:
                return None
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": str(e),
                    "data": traceback.format_exc(),
                },
                "id": request_id,
            }

    def _call_with_params(self, func: Callable, params: dict) -> Any:
        """Call a function mapping dict params to its signature."""
        sig = inspect.signature(func)
        kwargs = {}
        for name, param in sig.parameters.items():
            if name in params:
                kwargs[name] = params[name]
            elif name.startswith("_"):
                continue
            elif param.kind == inspect.Parameter.VAR_KEYWORD:
                continue
        return func(**kwargs)

    # === MCP Protocol Handlers ===

    def _handle_initialize(
        self,
        protocolVersion="2024-11-05",
        capabilities=None,
        clientInfo=None,
        **kw,
    ):
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": self.name, "version": self.version},
        }

    def _handle_tools_list(self, **kw):
        return {
            "tools": [
                self._build_tool_schema(name, func)
                for name, func in self._tools.items()
            ]
        }

    def _handle_tools_call(self, name: str, arguments: dict | None = None, **kw):
        func = self._tools.get(name)
        if func is None:
            return {
                "content": [{"type": "text", "text": f"Unknown tool: {name}"}],
                "isError": True,
            }
        try:
            result = self._call_with_params(func, arguments or {})
            text = json.dumps(result, indent=2, ensure_ascii=False, default=str)
            total_len = len(text)
            if total_len > MAX_OUTPUT_CHARS:
                text = (
                    text[:MAX_OUTPUT_CHARS]
                    + f"\n\n... [truncated: {total_len} chars total,"
                    f" showing first {MAX_OUTPUT_CHARS}]"
                )
            return {
                "content": [{"type": "text", "text": text}],
                "structuredContent": (
                    result if isinstance(result, dict) else {"result": result}
                ),
                "isError": False,
            }
        except Exception as e:
            return {
                "content": [
                    {"type": "text", "text": f"Error: {e}\n{traceback.format_exc()}"}
                ],
                "isError": True,
            }

    def _handle_resources_read(self, uri: str, **kw):
        return {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": json.dumps({"error": f"Resource not found: {uri}"}),
                }
            ],
            "isError": True,
        }

    # === Tool Schema Generation ===

    def _build_tool_schema(self, name: str, func: Callable) -> dict:
        """Generate MCP tool schema from function type hints."""
        hints = get_type_hints(func, include_extras=True)
        hints.pop("return", None)
        sig = inspect.signature(func)

        properties = {}
        required = []

        for param_name, param_type in hints.items():
            properties[param_name] = self._type_to_json_schema(param_type)
            param = sig.parameters.get(param_name)
            if not param or param.default is inspect.Parameter.empty:
                required.append(param_name)

        return {
            "name": name,
            "description": (func.__doc__ or f"Tool: {name}").strip(),
            "inputSchema": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        }

    def _type_to_json_schema(self, py_type: Any) -> dict:
        """Convert Python type hint to JSON Schema."""
        origin = get_origin(py_type)

        if origin is Annotated:
            args = get_args(py_type)
            schema = self._type_to_json_schema(args[0])
            if len(args) > 1 and isinstance(args[-1], str):
                schema["description"] = args[-1]
            return schema

        if origin in (Union, UnionType):
            return {
                "anyOf": [self._type_to_json_schema(t) for t in get_args(py_type)]
            }

        if origin is list:
            args = get_args(py_type)
            items = self._type_to_json_schema(args[0]) if args else {}
            return {"type": "array", "items": items}

        if origin is dict:
            return {"type": "object"}

        if is_typeddict(py_type):
            return self._typed_dict_to_schema(py_type)

        TYPE_MAP = {
            str: "string",
            int: "integer",
            float: "number",
            bool: "boolean",
            list: "array",
            dict: "object",
            type(None): "null",
        }
        return {"type": TYPE_MAP.get(py_type, "object")}

    def _typed_dict_to_schema(self, td_cls) -> dict:
        hints = get_type_hints(td_cls, include_extras=True)
        required_keys = getattr(td_cls, "__required_keys__", set(hints.keys()))
        return {
            "type": "object",
            "properties": {
                k: self._type_to_json_schema(v) for k, v in hints.items()
            },
            "required": [k for k in hints if k in required_keys],
        }

    # === Transports ===

    def stdio(self, stdin: BinaryIO | None = None, stdout: BinaryIO | None = None):
        """Run MCP server over stdio (one JSON-RPC message per line)."""
        stdin = stdin or sys.stdin.buffer
        stdout = stdout or sys.stdout.buffer

        while True:
            try:
                line = stdin.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                response = self.dispatch(line)
                if response is not None:
                    stdout.write(json.dumps(response).encode("utf-8") + b"\n")
                    stdout.flush()
            except (BrokenPipeError, KeyboardInterrupt, EOFError):
                break

    def serve(self, host: str = "127.0.0.1", port: int = 8765):
        """Run MCP server over HTTP (Streamable HTTP transport on /mcp)."""
        server = _McpHttpServer((host, port), _McpHttpHandler)
        server.mcp = self
        server.allow_reuse_address = True
        print(
            f"[ida-auto-mcp] HTTP server: http://{host}:{port}/mcp", file=sys.stderr
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()


class _McpHttpServer(HTTPServer):
    mcp: McpServer


class _McpHttpHandler(BaseHTTPRequestHandler):
    server: _McpHttpServer

    def do_POST(self):
        path = self.path.split("?")[0]
        if path != "/mcp":
            self.send_error(404, "Not Found")
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        response = self.server.mcp.dispatch(body)

        if response is None:
            self.send_response(202)
            self.send_header("Content-Type", "text/plain")
            self._send_cors()
            self.end_headers()
            self.wfile.write(b"Accepted")
        else:
            data = json.dumps(response).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self._send_cors()
            self.end_headers()
            self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers", "Content-Type, Mcp-Session-Id"
        )
        self.end_headers()

    def _send_cors(self):
        origin = self.headers.get("Origin", "")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)

    def log_message(self, format, *args):
        pass

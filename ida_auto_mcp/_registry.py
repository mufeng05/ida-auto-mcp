"""Global MCP server instance and tool decorator."""

from .mcp_server import McpServer

mcp = McpServer("ida-auto-mcp", version="1.0.0")


def tool(func):
    """Register a function as an MCP tool."""
    return mcp.tool(func)

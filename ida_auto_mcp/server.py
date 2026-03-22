"""Main entry point for ida-auto-mcp server.

Usage:
    # stdio mode (default, for MCP clients like Claude Desktop / Claude Code)
    python -m ida_auto_mcp

    # Open a binary on startup
    python -m ida_auto_mcp /path/to/binary.dll

    # HTTP mode (for debugging with MCP Inspector)
    python -m ida_auto_mcp --transport http --port 8765

MCP Client Configuration (Claude Desktop / claude_desktop_config.json):
    {
        "mcpServers": {
            "ida": {
                "command": "python",
                "args": ["-m", "ida_auto_mcp"]
            }
        }
    }
"""

import argparse
import logging
import os
import signal
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="IDA Auto MCP - Headless IDA Pro analysis server for AI agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m ida_auto_mcp                          # Start in stdio mode\n"
            "  python -m ida_auto_mcp /path/to/file.exe        # Open file on startup\n"
            "  python -m ida_auto_mcp --transport http          # HTTP mode for debugging\n"
            "  python -m ida_auto_mcp --ida-dir /opt/ida        # Specify IDA installation\n"
        ),
    )
    parser.add_argument(
        "input_path",
        nargs="?",
        type=Path,
        help="Binary file to open on startup (optional, can also use open_binary tool)",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="Transport mode: stdio (default) for MCP clients, http for debugging",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="HTTP server host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="HTTP server port (default: 8765)",
    )
    parser.add_argument(
        "--ida-dir",
        type=str,
        default=None,
        help="Path to IDA Pro installation directory (sets IDADIR env var)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose/debug logging",
    )
    args = parser.parse_args()

    # Setup logging (to stderr so it doesn't interfere with stdio transport)
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        stream=sys.stderr,
        format="[ida-auto-mcp] %(levelname)s: %(message)s",
    )

    # Set IDADIR before importing idapro
    if args.ida_dir:
        os.environ["IDADIR"] = args.ida_dir

    # Initialize idalib
    try:
        import idapro
    except ImportError:
        print(
            "Error: 'idapro' package not found.\n"
            "\n"
            "This server requires IDA Pro's idalib (headless analysis library).\n"
            "To install it:\n"
            "  1. Locate your IDA Pro installation directory\n"
            "  2. Run: pip install <IDA_DIR>/idalib/python/idapro-*.whl\n"
            "  3. Or set IDADIR and try again: --ida-dir /path/to/ida\n"
            "\n"
            "See: https://docs.hex-rays.com/release-notes/9_0#idalib",
            file=sys.stderr,
        )
        sys.exit(1)

    idapro.enable_console_messages(args.verbose)

    # Now safe to import modules that use IDA APIs
    from ._registry import mcp
    from . import tools  # noqa: F401 - triggers @tool registration
    from .session import get_manager

    # Open initial binary if specified
    if args.input_path:
        if not args.input_path.exists():
            print(
                f"Error: File not found: {args.input_path}", file=sys.stderr
            )
            sys.exit(1)

        manager = get_manager()
        try:
            session = manager.open_binary(args.input_path)
            logging.info(
                "Opened: %s (session: %s)",
                args.input_path.name,
                session.session_id,
            )
        except Exception as e:
            print(
                f"Error opening {args.input_path}: {e}", file=sys.stderr
            )
            sys.exit(1)

    # Cleanup on exit
    def cleanup(signum=None, frame=None):
        try:
            get_manager().close_all()
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # Start server
    if args.transport == "stdio":
        mcp.stdio()
    else:
        mcp.serve(args.host, args.port)

    # Cleanup after server stops
    try:
        get_manager().close_all()
    except Exception:
        pass


if __name__ == "__main__":
    main()

"""Main entry point for ida-auto-mcp server.

Usage:
    # stdio mode (default, for MCP clients like Claude Desktop / Claude Code)
    python -m ida_auto_mcp

    # Open a binary on startup
    python -m ida_auto_mcp /path/to/binary.dll

    # Also enable tools that modify the database / run arbitrary code
    python -m ida_auto_mcp --allow-write --allow-script

    # HTTP mode (for debugging with MCP Inspector); requires a bearer token,
    # taken from IDA_AUTO_MCP_TOKEN or generated and printed on startup
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
            "  python -m ida_auto_mcp --allow-write            # Allow renaming, comments, patching...\n"
            "  python -m ida_auto_mcp --timeout 600            # Stop tool calls after 10 minutes\n"
            "  python -m ida_auto_mcp --analysis-wait 0        # open_binary returns once loaded\n"
            "  python -m ida_auto_mcp --transport http          # HTTP mode for debugging\n"
            "  python -m ida_auto_mcp --ida-dir /opt/ida        # Specify IDA installation\n"
        ),
    )
    parser.add_argument(
        "input_path",
        nargs="?",
        type=Path,
        help=(
            "Binary file to open once the server has started (optional, can "
            "also use open_binary tool)"
        ),
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
        "--allow-write",
        action="store_true",
        help=(
            "Enable tools that modify the IDA database or save it to disk "
            "(renaming, comments, types, code definition, patching, save_database)"
        ),
    )
    parser.add_argument(
        "--allow-script",
        action="store_true",
        help="Enable run_script, which executes arbitrary Python in this process",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=300,
        metavar="SECONDS",
        help=(
            "Stop a tool call that runs longer than this (default: 300; 0 for "
            "no limit). A call busy inside one IDA function stops when that "
            "function returns; on IDA 9.5+ decompilation stops in time too. "
            "Opening, switching, closing and saving databases are never stopped."
        ),
    )
    parser.add_argument(
        "--analysis-wait",
        type=float,
        default=30,
        metavar="SECONDS",
        help=(
            "How long open_binary waits for IDA's auto-analysis before it "
            "returns (default: 30; 0 to return once the file is loaded). "
            "Analysis then continues in the background between tool calls."
        ),
    )
    parser.add_argument(
        "--trace",
        metavar="FILE",
        default=None,
        help="Append a JSON line per tool call (arguments, duration, errors) to FILE",
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
    except ModuleNotFoundError:
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
    except ImportError as e:
        # idapro is installed but could not find or start idalib
        print(
            f"Error: cannot load IDA's idalib: {e}\n"
            "Point IDADIR (or --ida-dir) at an IDA Pro 9.x installation.",
            file=sys.stderr,
        )
        sys.exit(1)

    idapro.enable_console_messages(args.verbose)

    # Now safe to import modules that use IDA APIs
    from ._registry import mcp
    from . import tools  # noqa: F401 - triggers @tool registration
    from .session import get_manager

    if args.allow_write:
        mcp.enabled_groups.add("write")
    if args.allow_script:
        mcp.enabled_groups.add("script")
    mcp.tool_timeout = args.timeout if args.timeout > 0 else None
    mcp.trace_path = args.trace
    get_manager().analysis_wait = max(args.analysis_wait, 0)
    # Analyze the active database while no request is waiting
    mcp.idle_task = get_manager().background_step

    # Open initial binary if specified
    if args.input_path:
        if not args.input_path.exists():
            print(
                f"Error: File not found: {args.input_path}", file=sys.stderr
            )
            sys.exit(1)
        input_path = args.input_path

        def open_input_binary():
            # Only load it; analysis then continues in the background
            try:
                session = get_manager().open_binary(input_path, wait_seconds=0)
                logging.info(
                    "Opened: %s (session: %s)", input_path.name, session.session_id
                )
            except Exception as e:
                print(f"Error opening {input_path}: {e}", file=sys.stderr)

        # Loaded once the server answers: a large binary takes longer to
        # load than clients wait for a server to start. A tool call that
        # comes first waits for it.
        mcp.defer(open_input_binary)

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
        mcp.serve(args.host, args.port, token=os.environ.get("IDA_AUTO_MCP_TOKEN"))

    # Cleanup after server stops
    try:
        get_manager().close_all()
    except Exception:
        pass


if __name__ == "__main__":
    main()

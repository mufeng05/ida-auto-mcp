"""IDA analysis tools exposed as MCP tools.

All tools operate on the currently active IDA database session.
Use open_binary / switch_binary to manage which database is active.

IDA modules are imported inside each function to ensure they are
only accessed after idapro has been initialized.

Tools that modify the database or write files use @write_tool, and
run_script uses @script_tool; both stay disabled unless the server is
started with --allow-write / --allow-script. Tools that open, switch or
close databases use @session_tool.
"""

import ast
import fnmatch
import io
import json
import linecache
import re
import sys
import time
import traceback
from pathlib import Path
from typing import Annotated, Optional

from . import analysis, idb_files
from ._registry import mcp, script_tool, session_tool, tool, write_tool
from .mcp_server import ToolInterrupted
from .session import LoadOptions, get_manager


# ============================================================================
# Session Management Tools
# ============================================================================


@session_tool
def open_binary(
    input_path: Annotated[str, "Absolute path to the binary file to analyze"],
    auto_analysis: Annotated[
        bool,
        "Run IDA auto-analysis, in the background once this returns "
        "(recommended); false analyzes nothing until wait_analysis",
    ] = True,
    processor: Annotated[
        str, "Raw blobs: IDA processor module, e.g. 'arm', 'mipsl' (empty = detect)"
    ] = "",
    file_type: Annotated[
        str, "Raw blobs: start of an IDA loader's file type, e.g. 'Binary file'"
    ] = "",
    base_address: Annotated[
        str, "Raw blobs: load address, e.g. '0x8000000' (16-byte aligned)"
    ] = "",
    entry_point: Annotated[str, "Raw blobs: entry point address, e.g. '0x8000100'"] = "",
) -> dict:
    """Open a binary file for analysis. Creates a new IDA session or reuses an existing one for the same file. This is the first tool you should call to start analyzing a binary.

    IDA's auto-analysis finds functions, cross-references and types. This tool waits for it up to a time set by the server (30 seconds by default), and analysis continues in the background between tool calls, so a binary whose analysis takes hours can be queried right away. Until `analysis.complete` is true, function lists, xrefs and pseudocode can be incomplete and may change; call wait_analysis when you need the finished analysis.

    The loader options (processor, file_type, base_address, entry_point) apply only when IDA creates the file's database, such as for raw firmware."""
    try:
        options = LoadOptions(
            processor=processor.strip(),
            file_type=file_type.strip(),
            base_address=_parse_number(base_address),
            entry_point=_parse_number(entry_point),
        )
        path = Path(input_path).resolve()
        has_database = idb_files.probe(path).state != "missing"
        session = get_manager().open_binary(
            path, auto_analysis=auto_analysis, options=options
        )
        status = analysis.status()
        message = f"Opened {session.input_path.name} (session: {session.session_id})."
        if not status["complete"]:
            message += (
                " IDA is still analyzing it in the background: results can be "
                "incomplete until analysis.complete is true."
                if auto_analysis
                else " It is not analyzed: call wait_analysis to analyze it."
            )
        result = {
            "success": True,
            "session": session.to_dict(active=True),
            "analysis": status,
            "message": message,
        }
        if options and has_database:
            result["warning"] = (
                "The loader options were ignored: the file already has an IDA "
                "database. Delete it to load the file again with them."
            )
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


@session_tool
def close_binary(
    session_id: Annotated[str, "Session ID to close"],
) -> dict:
    """Close an analysis session and free its resources."""
    if get_manager().close_session(session_id):
        return {"success": True, "message": f"Session {session_id} closed"}
    return {"success": False, "error": f"Session not found: {session_id}"}


@session_tool
def switch_binary(
    session_id: Annotated[str, "Session ID to switch to"],
) -> dict:
    """Switch the active analysis to a different open session. All subsequent analysis tools will operate on this session's database."""
    try:
        session = get_manager().switch_session(session_id)
        return {
            "success": True,
            "session": session.to_dict(active=True),
            "message": f"Switched to {session.input_path.name}",
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@tool
def list_sessions() -> dict:
    """List all open analysis sessions. Shows which session is currently active."""
    sessions = get_manager().list_sessions()
    return {"sessions": sessions, "count": len(sessions)}


@tool
def get_current_session() -> dict:
    """Get information about the currently active analysis session."""
    session = get_manager().get_current()
    if session is None:
        return {"error": "No active session. Use open_binary() to open a file first."}
    return {"is_active": True, **session.to_dict(active=True)}


# ============================================================================
# Database Info
# ============================================================================


@tool
def get_database_info() -> dict:
    """Get metadata about the currently loaded binary (filename, architecture, image base, hashes, etc.)."""
    import idaapi
    import ida_funcs
    import ida_nalt
    import idc
    import idautils

    info = idaapi.get_inf_structure() if hasattr(idaapi, "get_inf_structure") else None
    status = analysis.status()

    result = {
        "filename": ida_nalt.get_root_filename(),
        "input_path": ida_nalt.get_input_file_path(),
        "idb_path": idc.get_idb_path(),
        "imagebase": hex(idaapi.get_imagebase()),
        "processor": idaapi.get_idp_name(),
        "auto_analysis_done": status["complete"],
        "analysis": status,
    }

    # Determine bitness
    if hasattr(idaapi, "inf_is_64bit"):
        result["bits"] = 64 if idaapi.inf_is_64bit() else 32
    elif info:
        result["bits"] = 64 if info.is_64bit() else 32

    # File hashes
    md5 = ida_nalt.retrieve_input_file_md5()
    if md5:
        result["md5"] = md5.hex() if isinstance(md5, bytes) else str(md5)
    sha256 = ida_nalt.retrieve_input_file_sha256()
    if sha256:
        result["sha256"] = sha256.hex() if isinstance(sha256, bytes) else str(sha256)

    # File size
    try:
        result["input_file_size"] = ida_nalt.retrieve_input_file_size()
    except Exception:
        pass

    # Min/max addresses
    segs = list(idautils.Segments())
    if segs:
        min_ea = segs[0]
        max_ea = 0
        for seg_ea in segs:
            seg = _get_segment(seg_ea)
            if seg and seg["end"] > max_ea:
                max_ea = seg["end"]
        result["min_address"] = hex(min_ea)
        result["max_address"] = hex(max_ea)

    result["function_count"] = ida_funcs.get_func_qty()

    return result


@tool
def wait_analysis(
    timeout: Annotated[
        float,
        "Seconds to wait at most (default 60); 0 waits until analysis finishes, "
        "within the server's time limit",
    ] = 60,
) -> dict:
    """Run IDA's auto-analysis of the current binary until it finishes or `timeout` seconds pass, then report its progress. Analysis also continues in the background between tool calls, unless the binary was opened with auto_analysis=false (open it again with auto_analysis=true to change that). Call this when you need complete results: a large or obfuscated binary can take hours to analyze, so prefer a timeout and check `complete`."""
    manager = get_manager()
    if manager.get_current() is None:
        return {"error": "No active session. Use open_binary() to open a file first."}

    limit = timeout if timeout > 0 else None
    if mcp.tool_timeout:
        # Stop in time to report the progress, before the time limit stops the call
        limit = min(limit or mcp.tool_timeout, mcp.tool_timeout * 0.9)
    started = time.monotonic()
    while True:
        remaining = None if limit is None else limit - (time.monotonic() - started)
        if remaining is not None and remaining <= 0:
            break
        if manager.advance_analysis(1.0 if remaining is None else min(remaining, 1.0)):
            break

    status = analysis.status()
    result = {
        "success": True,
        "complete": status["complete"],
        "waited_seconds": round(time.monotonic() - started, 1),
        "analysis": status,
    }
    session = manager.get_current()
    if status["complete"]:
        pass
    elif session is not None and session.analysis_stalled_at is not None:
        result["message"] = (
            "IDA has analysis queued that it does not process; results can "
            "stay incomplete."
        )
    else:
        result["message"] = (
            "Analysis is not finished yet. Results can still be incomplete; "
            "call wait_analysis again to wait longer."
        )
    return result


@write_tool(interruptible=False)
def save_database(
    path: Annotated[str, "Save path (empty = current IDB path)"] = "",
) -> dict:
    """Save the current IDA database to disk."""
    import ida_loader
    import idc

    save_path = path.strip() if path else ""
    if not save_path:
        save_path = idc.get_idb_path()
    if not save_path:
        return {"success": False, "error": "Could not determine save path"}

    ok = bool(ida_loader.save_database(save_path, 0))
    return {"success": ok, "path": save_path}


# ============================================================================
# Function Tools
# ============================================================================


@tool
def list_functions(
    filter_str: Annotated[
        str, "Glob pattern to filter names (e.g. 'main*', '*init*')"
    ] = "",
    offset: Annotated[int, "Starting index for pagination"] = 0,
    count: Annotated[int, "Maximum number of results (default 100)"] = 100,
) -> dict:
    """List functions in the binary with optional name filtering and pagination."""
    import idautils
    import ida_funcs

    all_funcs = []
    for ea in idautils.Functions():
        fn = _get_func(ea)
        if not fn:
            continue
        name = ida_funcs.get_func_name(ea) or f"sub_{ea:X}"
        all_funcs.append(
            {
                "address": hex(ea),
                "name": name,
                "size": fn.end_ea - fn.start_ea,
            }
        )

    if filter_str:
        pattern = (
            filter_str
            if "*" in filter_str or "?" in filter_str
            else f"*{filter_str}*"
        )
        all_funcs = [
            f
            for f in all_funcs
            if fnmatch.fnmatch(f["name"].lower(), pattern.lower())
        ]

    total = len(all_funcs)
    page = all_funcs[offset : offset + count]
    return {
        "functions": page,
        "total": total,
        "offset": offset,
        "has_more": offset + count < total,
    }


@tool
def get_function_info(
    address: Annotated[str, "Function address (hex like 0x401000) or name"],
) -> dict:
    """Get detailed information about a specific function (address, size, prototype, etc.)."""
    import ida_funcs
    import ida_nalt
    import ida_typeinf

    ea = _resolve_address(address)
    fn = _get_func(ea)
    if not fn:
        return {"error": f"No function at {address}"}

    name = ida_funcs.get_func_name(fn.start_ea)
    tif = ida_typeinf.tinfo_t()
    has_type = ida_nalt.get_tinfo(tif, fn.start_ea)
    prototype = str(tif) if has_type else None

    return {
        "address": hex(fn.start_ea),
        "end_address": hex(fn.end_ea),
        "name": name,
        "size": fn.end_ea - fn.start_ea,
        "prototype": prototype,
    }


@tool
def decompile_function(
    address: Annotated[str, "Function address (hex) or name to decompile"],
) -> dict:
    """Decompile a function to C pseudocode using Hex-Rays decompiler. Requires Hex-Rays license."""
    import ida_hexrays
    import ida_funcs

    if not ida_hexrays.init_hexrays_plugin():
        return {"error": "Hex-Rays decompiler not available"}

    ea = _resolve_address(address)
    fn = _get_func(ea)
    if not fn:
        return {"error": f"No function at {address}"}

    try:
        cfunc, failure = _decompile(fn.start_ea)
        if cfunc is None:
            return {"error": f"Decompilation failed for {address}: {failure}"}

        return {
            "address": hex(fn.start_ea),
            "name": ida_funcs.get_func_name(fn.start_ea),
            "pseudocode": str(cfunc),
        }
    except ida_hexrays.DecompilationFailure as e:
        return {"error": f"Decompilation failed: {e}"}
    except Exception as e:
        return {"error": f"Decompilation error: {e}"}


@tool
def disassemble_function(
    address: Annotated[str, "Function address (hex) or name"],
    count: Annotated[int, "Max number of instructions (default 200)"] = 200,
) -> dict:
    """Get assembly disassembly for a function or address range. A function's instructions come chunk by chunk: the entry chunk first, then the parts of the function located elsewhere (listed in `chunks`)."""
    import idaapi
    import idc

    ea = _resolve_address(address)
    fn = _get_func(ea)

    lines = []
    chunks = None
    if fn:
        chunks = _func_chunks(fn)
        for head in _func_heads(fn):
            if len(lines) >= count:
                break
            size = idc.get_item_size(head)
            raw = idc.get_bytes(head, size) if size > 0 else b""
            lines.append(
                {
                    "address": hex(head),
                    "disasm": idc.GetDisasm(head),
                    "bytes": raw.hex() if raw else "",
                }
            )
    else:
        # No function at address - disassemble linearly
        current = ea
        for _ in range(count):
            size = idc.get_item_size(current)
            if size <= 0:
                break
            raw = idc.get_bytes(current, size)
            lines.append(
                {
                    "address": hex(current),
                    "disasm": idc.GetDisasm(current),
                    "bytes": raw.hex() if raw else "",
                }
            )
            current = idc.next_head(current)
            if current == idaapi.BADADDR:
                break

    result = {
        "address": hex(ea),
        "is_function": fn is not None,
        "instructions": lines,
        "count": len(lines),
    }
    if chunks is not None:
        result["chunks"] = [{"start": hex(s), "end": hex(e)} for s, e in chunks]
    return result


# ============================================================================
# Cross References
# ============================================================================


@tool
def get_xrefs_to(
    address: Annotated[str, "Target address (hex) or name"],
    max_results: Annotated[int, "Maximum number of results"] = 50,
) -> dict:
    """Get cross-references TO an address - shows what code references this location."""
    import idautils
    import ida_funcs
    import ida_xref

    ea = _resolve_address(address)
    xrefs = []
    for xref in idautils.XrefsTo(ea):
        if len(xrefs) >= max_results:
            break
        fn = _get_func(xref.frm)
        xrefs.append(
            {
                "from_address": hex(xref.frm),
                "type": _xref_type_name(xref.type),
                "from_function": (
                    ida_funcs.get_func_name(fn.start_ea) if fn else None
                ),
            }
        )
    return {"address": hex(ea), "xrefs": xrefs, "count": len(xrefs)}


@tool
def get_xrefs_from(
    address: Annotated[str, "Source address (hex) or name"],
    max_results: Annotated[int, "Maximum number of results"] = 50,
) -> dict:
    """Get cross-references FROM an address - shows what this code references."""
    import idautils
    import ida_funcs

    ea = _resolve_address(address)
    xrefs = []
    for xref in idautils.XrefsFrom(ea):
        if len(xrefs) >= max_results:
            break
        fn = _get_func(xref.to)
        xrefs.append(
            {
                "to_address": hex(xref.to),
                "type": _xref_type_name(xref.type),
                "to_function": (
                    ida_funcs.get_func_name(fn.start_ea) if fn else None
                ),
            }
        )
    return {"address": hex(ea), "xrefs": xrefs, "count": len(xrefs)}


# ============================================================================
# Strings
# ============================================================================


@tool
def list_strings(
    filter_str: Annotated[str, "Substring filter for string content"] = "",
    offset: Annotated[int, "Starting index for pagination"] = 0,
    count: Annotated[int, "Maximum results (default 100)"] = 100,
) -> dict:
    """List strings found in the binary with optional filtering. Strings marked synthetic (IDA 9.5+) exist only in the code, e.g. built from immediates, so their text is not stored at their address."""
    offset = max(offset, 0)
    count = max(count, 0)
    size = _string_list_size()
    if not filter_str:
        page = [
            _string_entry(s)
            for s in _string_items(range(offset, min(offset + count, size)))
        ]
        total = size
    else:
        pattern = filter_str.lower()
        page = []
        total = 0
        for s in _string_items(range(size)):
            text = str(s)
            if pattern not in text.lower():
                continue
            if offset <= total < offset + count:
                page.append(_string_entry(s, text))
            total += 1
    return {
        "strings": page,
        "total": total,
        "offset": offset,
        "has_more": offset + count < total,
    }


@tool
def search_strings(
    pattern: Annotated[str, "Regex pattern to search in strings"],
    max_results: Annotated[int, "Maximum results (default 50)"] = 50,
) -> dict:
    """Search strings by regex pattern (case-insensitive)."""
    compiled = re.compile(pattern, re.IGNORECASE)
    matches = []
    for s in _string_items(range(_string_list_size())):
        if len(matches) >= max_results:
            break
        text = str(s)
        if compiled.search(text):
            match = {"address": hex(s.ea), "text": text}
            if _is_synthetic_string(s):
                match["synthetic"] = True
            matches.append(match)

    return {"pattern": pattern, "matches": matches, "count": len(matches)}


# IDA keeps the string list it built last. Building it scans the whole
# database (seconds for a large binary), so it is kept for the database it was
# built for, and refreshed after analysis changed the database: at once when
# analysis has finished, at most once a minute while it is still running.
_strlist_state: Optional[tuple] = None  # (generation, analysis epoch)
_strlist_built_at = 0.0
_STRLIST_REFRESH_SECONDS = 60.0


def _string_list_size() -> int:
    """Number of items in IDA's string list, after (re)building it if stale."""
    import ida_strlist

    global _strlist_state, _strlist_built_at
    manager = get_manager()
    state = (manager.generation, manager.analysis_epoch)
    now = time.monotonic()
    stale = (
        _strlist_state is None
        or _strlist_state[0] != state[0]
        or (
            _strlist_state[1] != state[1]
            and (
                analysis.is_complete()
                or now - _strlist_built_at >= _STRLIST_REFRESH_SECONDS
            )
        )
    )
    if stale:
        # As idautils.Strings() does: build with the options saved in the database
        ida_strlist.get_strlist_options()
        ida_strlist.build_strlist()
        _strlist_state = state
        _strlist_built_at = now
    return ida_strlist.get_strlist_qty()


def _string_items(indices):
    """String list items (idautils.Strings.StringItem) at the given indices."""
    import ida_strlist
    import idautils

    if hasattr(ida_strlist, "string_info_ex_t"):  # IDA 9.5+, with synthetic strings
        info = ida_strlist.string_info_ex_t()
        get_item = ida_strlist.get_strlist_item_ex
    else:
        info = ida_strlist.string_info_t()
        get_item = ida_strlist.get_strlist_item
    for index in indices:
        if get_item(info, index):
            # StringItem copies the fields, so info can be reused
            yield idautils.Strings.StringItem(info)


def _string_entry(s, text: Optional[str] = None) -> dict:
    """A string list item as list_strings reports it."""
    entry = {
        "address": hex(s.ea),
        "text": str(s) if text is None else text,
        "length": s.length,
    }
    if _is_synthetic_string(s):
        entry["synthetic"] = True
    return entry


# ============================================================================
# Imports / Exports / Segments
# ============================================================================


@tool
def list_imports(
    filter_str: Annotated[str, "Filter pattern for import names"] = "",
    module_filter: Annotated[str, "Filter by module/DLL name"] = "",
    offset: Annotated[int, "Starting index for pagination"] = 0,
    count: Annotated[int, "Maximum results (default 100)"] = 100,
) -> dict:
    """List imported functions from external libraries."""
    import ida_nalt

    all_imports = []
    nimps = ida_nalt.get_import_module_qty()

    for i in range(nimps):
        module = ida_nalt.get_import_module_name(i) or "<unknown>"

        def cb(ea, name, ordinal, _module=module):
            if not name:
                name = f"#{ordinal}"
            all_imports.append(
                {
                    "address": hex(ea),
                    "name": name,
                    "module": _module,
                    "ordinal": ordinal,
                }
            )
            return True

        ida_nalt.enum_import_names(i, cb)

    if filter_str:
        p = filter_str.lower()
        all_imports = [i for i in all_imports if p in i["name"].lower()]
    if module_filter:
        p = module_filter.lower()
        all_imports = [i for i in all_imports if p in i["module"].lower()]

    total = len(all_imports)
    page = all_imports[offset : offset + count]
    return {
        "imports": page,
        "total": total,
        "offset": offset,
        "has_more": offset + count < total,
    }


@tool
def list_exports() -> dict:
    """List exported functions/symbols of the binary."""
    import idautils

    exports = []
    for idx, ordinal, ea, name in idautils.Entries():
        exports.append(
            {"address": hex(ea), "name": name, "ordinal": ordinal}
        )
    return {"exports": exports, "count": len(exports)}


@tool
def list_segments() -> dict:
    """List memory segments/sections of the binary."""
    import idautils

    segments = []
    for ea in idautils.Segments():
        seg = _get_segment(ea)
        if not seg:
            continue
        segments.append(
            {
                "start": hex(seg["start"]),
                "end": hex(seg["end"]),
                "name": seg["name"],
                "size": seg["end"] - seg["start"],
                "permissions": seg["permissions"],
                "class": seg["class"],
            }
        )
    return {"segments": segments, "count": len(segments)}


# ============================================================================
# Search
# ============================================================================


@tool
def search_bytes(
    pattern: Annotated[
        str,
        "Hex byte pattern with optional wildcards, e.g. '48 89 5C 24 ?? 57'",
    ],
    start_address: Annotated[
        str, "Start address (hex). Defaults to binary start."
    ] = "",
    max_results: Annotated[int, "Maximum matches (default 10)"] = 10,
) -> dict:
    """Search for a byte pattern in the binary. Supports wildcard bytes (??)."""
    import idaapi
    import ida_bytes
    import idautils

    # Determine search range
    if start_address:
        start_ea = _resolve_address(start_address)
    else:
        segs = list(idautils.Segments())
        start_ea = segs[0] if segs else 0

    max_ea = 0
    for seg_ea in idautils.Segments():
        seg = _get_segment(seg_ea)
        if seg and seg["end"] > max_ea:
            max_ea = seg["end"]

    if max_ea == 0:
        return {"error": "No segments found", "matches": [], "count": 0}

    tokens = pattern.strip().split()
    if not tokens:
        return {"error": "Empty byte pattern", "matches": [], "count": 0}

    results = []
    ea = start_ea

    # Pre-build search data once before the loop
    use_modern = hasattr(ida_bytes, "find_bytes")
    normalized = None
    pat_bytes = None
    mask_bytes = None

    if use_modern:
        normalized = " ".join(
            "?" if t in ("??", "?") else t for t in tokens
        )
    else:
        pat = bytearray()
        mask = bytearray()
        for t in tokens:
            if t in ("??", "?"):
                pat.append(0)
                mask.append(0)
            else:
                pat.append(int(t, 16))
                mask.append(0xFF)
        pat_bytes = bytes(pat)
        mask_bytes = bytes(mask)

    while len(results) < max_results and ea < max_ea:
        if use_modern:
            try:
                found = ida_bytes.find_bytes(normalized, ea, range_end=max_ea)
            except Exception:
                # Fall back to legacy API
                use_modern = False
                pat = bytearray()
                mask = bytearray()
                for t in tokens:
                    if t in ("??", "?"):
                        pat.append(0)
                        mask.append(0)
                    else:
                        pat.append(int(t, 16))
                        mask.append(0xFF)
                pat_bytes = bytes(pat)
                mask_bytes = bytes(mask)
                continue

        if not use_modern:
            found = ida_bytes.bin_search(
                ea,
                max_ea,
                pat_bytes,
                mask_bytes,
                len(pat_bytes),
                ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW,
            )

        if found == idaapi.BADADDR:
            break
        results.append({"address": hex(found)})
        ea = found + 1

    return {"pattern": pattern, "matches": results, "count": len(results)}


# ============================================================================
# Modifications
# ============================================================================


@write_tool
def rename_address(
    address: Annotated[str, "Address (hex) or current name"],
    new_name: Annotated[str, "New name to assign"],
) -> dict:
    """Rename a function or address in the database."""
    import idaapi

    ea = _resolve_address(address)
    ok = idaapi.set_name(ea, new_name, idaapi.SN_NOWARN | idaapi.SN_NOCHECK)
    if ok:
        _invalidate_decompiler_cache(ea)
        return {"success": True, "address": hex(ea), "new_name": new_name}
    return {
        "success": False,
        "error": f"Failed to rename {address} to {new_name}",
    }


@write_tool
def set_comment(
    address: Annotated[str, "Address (hex) to set comment on"],
    comment: Annotated[str, "Comment text"],
    is_repeatable: Annotated[
        bool, "If true, comment appears at every reference to this address"
    ] = False,
) -> dict:
    """Set a comment at an address in the disassembly."""
    import idc

    ea = _resolve_address(address)
    ok = idc.set_cmt(ea, comment, 1 if is_repeatable else 0)
    return {"success": bool(ok), "address": hex(ea)}


@write_tool
def set_function_type(
    address: Annotated[str, "Function address (hex) or name"],
    type_str: Annotated[
        str,
        "C-style function prototype, e.g. 'int __fastcall foo(int a, char *b)'",
    ],
) -> dict:
    """Set the type/prototype of a function."""
    import idc

    ea = _resolve_address(address)
    ok = idc.SetType(ea, type_str)
    if ok:
        _invalidate_decompiler_cache(ea)
    return {"success": bool(ok), "address": hex(ea), "type": type_str}


# ============================================================================
# Memory
# ============================================================================


@tool
def read_bytes(
    address: Annotated[str, "Address (hex) to read from"],
    size: Annotated[int, "Number of bytes to read (default 256)"] = 256,
) -> dict:
    """Read raw bytes at an address. Returns hex-encoded data."""
    import idc

    if size > 4096:
        size = 4096

    ea = _resolve_address(address)
    data = idc.get_bytes(ea, size)
    if data is None:
        return {"error": f"Cannot read {size} bytes at {address}"}

    return {
        "address": hex(ea),
        "size": len(data),
        "hex": data.hex(),
        "hex_spaced": " ".join(f"{b:02x}" for b in data),
    }


# ============================================================================
# Control Flow (inspired by ida-mcp-rs)
# ============================================================================


@tool
def get_callers(
    address: Annotated[str, "Function address (hex) or name"],
    max_results: Annotated[int, "Maximum results (default 50)"] = 50,
) -> dict:
    """Find all functions that CALL this function. Essential for understanding who uses a function."""
    import idautils
    import ida_funcs
    import ida_xref

    ea = _resolve_address(address)
    fn = _get_func(ea)
    if not fn:
        return {"error": f"No function at {address}"}

    callers = []
    seen = set()
    for xref in idautils.XrefsTo(fn.start_ea):
        if len(callers) >= max_results:
            break
        if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
            caller_fn = _get_func(xref.frm)
            if caller_fn and caller_fn.start_ea not in seen:
                seen.add(caller_fn.start_ea)
                callers.append(
                    {
                        "address": hex(caller_fn.start_ea),
                        "name": ida_funcs.get_func_name(caller_fn.start_ea),
                        "call_site": hex(xref.frm),
                    }
                )

    return {
        "target": hex(fn.start_ea),
        "target_name": ida_funcs.get_func_name(fn.start_ea),
        "callers": callers,
        "count": len(callers),
    }


@tool
def get_callees(
    address: Annotated[str, "Function address (hex) or name"],
    max_results: Annotated[int, "Maximum results (default 50)"] = 50,
) -> dict:
    """Find all functions CALLED BY this function. Shows what a function depends on."""
    import idautils
    import ida_funcs
    import ida_xref

    ea = _resolve_address(address)
    fn = _get_func(ea)
    if not fn:
        return {"error": f"No function at {address}"}

    callees = []
    seen = set()
    for head in _func_heads(fn):
        if len(callees) >= max_results:
            break
        for xref in idautils.XrefsFrom(head):
            if len(callees) >= max_results:
                break
            if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                target_fn = _get_func(xref.to)
                if target_fn and target_fn.start_ea not in seen:
                    seen.add(target_fn.start_ea)
                    callees.append(
                        {
                            "address": hex(target_fn.start_ea),
                            "name": ida_funcs.get_func_name(target_fn.start_ea),
                            "call_site": hex(head),
                        }
                    )

    return {
        "source": hex(fn.start_ea),
        "source_name": ida_funcs.get_func_name(fn.start_ea),
        "callees": callees,
        "count": len(callees),
    }


@tool
def get_callgraph(
    address: Annotated[str, "Root function address (hex) or name"],
    max_depth: Annotated[int, "Maximum traversal depth (default 2)"] = 2,
    max_nodes: Annotated[int, "Maximum nodes in graph (default 100)"] = 100,
) -> dict:
    """Build a call graph starting from a function, exploring callees up to max_depth. Returns nodes and edges for visualization."""
    import idautils
    import ida_funcs
    import ida_xref
    from collections import deque

    ea = _resolve_address(address)
    fn = _get_func(ea)
    if not fn:
        return {"error": f"No function at {address}"}

    nodes = {}
    edges = []
    queue = deque()

    root_ea = fn.start_ea
    root_name = ida_funcs.get_func_name(root_ea)
    nodes[root_ea] = {"address": hex(root_ea), "name": root_name}
    queue.append((root_ea, 0))

    while queue:
        cur_ea, depth = queue.popleft()
        if depth >= max_depth or len(nodes) >= max_nodes:
            continue

        cur_fn = _get_func(cur_ea)
        if not cur_fn:
            continue

        for head in _func_heads(cur_fn):
            for xref in idautils.XrefsFrom(head):
                if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                    target_fn = _get_func(xref.to)
                    if target_fn:
                        t_ea = target_fn.start_ea
                        edges.append({"from": hex(cur_ea), "to": hex(t_ea)})
                        if t_ea not in nodes and len(nodes) < max_nodes:
                            nodes[t_ea] = {
                                "address": hex(t_ea),
                                "name": ida_funcs.get_func_name(t_ea),
                            }
                            queue.append((t_ea, depth + 1))

    return {
        "root": hex(root_ea),
        "nodes": list(nodes.values()),
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
    }


@tool
def get_basic_blocks(
    address: Annotated[str, "Function address (hex) or name"],
) -> dict:
    """Get the basic blocks (control flow graph) of a function. Each block has start/end addresses and successor/predecessor relationships."""
    import ida_funcs
    import ida_gdl

    ea = _resolve_address(address)
    fn = _get_func(ea)
    if not fn:
        return {"error": f"No function at {address}"}

    _BLOCK_TYPES = {
        ida_gdl.fcb_normal: "normal",
        ida_gdl.fcb_indjump: "indjump",
        ida_gdl.fcb_ret: "ret",
        ida_gdl.fcb_cndret: "cndret",
        ida_gdl.fcb_noret: "noret",
        ida_gdl.fcb_enoret: "enoret",
        ida_gdl.fcb_extern: "extern",
        ida_gdl.fcb_error: "error",
    }

    fc = _flow_chart(fn.start_ea)
    blocks = []
    for i in range(fc.size()):
        block = fc[i]
        block_type = fc.calc_block_type(i)
        succs = [hex(fc[fc.succ(i, j)].start_ea) for j in range(fc.nsucc(i))]
        preds = [hex(fc[fc.pred(i, j)].start_ea) for j in range(fc.npred(i))]
        blocks.append(
            {
                "start": hex(block.start_ea),
                "end": hex(block.end_ea),
                "size": block.end_ea - block.start_ea,
                "type": _BLOCK_TYPES.get(block_type, f"unknown_{block_type}"),
                "successors": succs,
                "predecessors": preds,
            }
        )

    return {
        "function": hex(fn.start_ea),
        "name": ida_funcs.get_func_name(fn.start_ea),
        "blocks": blocks,
        "block_count": len(blocks),
    }


@tool
def get_address_info(
    address: Annotated[str, "Address (hex) to resolve"],
) -> dict:
    """Resolve an address to its context: which segment, function, and nearest symbol it belongs to."""
    import idaapi
    import ida_funcs
    import ida_name
    import idc

    ea = _resolve_address(address)

    result = {"address": hex(ea)}

    seg = _get_segment(ea)
    if seg:
        result["segment"] = {
            "name": seg["name"],
            "start": hex(seg["start"]),
            "end": hex(seg["end"]),
            "permissions": seg["permissions"],
        }

    fn = _get_func(ea)
    if fn:
        result["function"] = {
            "address": hex(fn.start_ea),
            "name": ida_funcs.get_func_name(fn.start_ea),
            "offset_in_func": ea - fn.start_ea,
        }

    name = ida_name.get_name(ea)
    if name:
        result["name"] = name

    flags = idaapi.get_flags(ea)
    result["is_code"] = idaapi.is_code(flags)
    result["is_data"] = idaapi.is_data(flags)

    return result


# ============================================================================
# Types & Structs (inspired by ida-mcp-rs)
# ============================================================================


@tool
def list_structs(
    filter_str: Annotated[str, "Filter struct names by substring"] = "",
    offset: Annotated[int, "Starting index for pagination"] = 0,
    count: Annotated[int, "Maximum results (default 100)"] = 100,
) -> dict:
    """List structs/unions defined in the database."""
    import ida_typeinf

    til = ida_typeinf.get_idati()
    limit = ida_typeinf.get_ordinal_limit(til)

    all_structs = []
    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(til, ordinal):
            continue
        if not (tif.is_struct() or tif.is_union()):
            continue
        # None for an unnamed type (IDA 9.5 documents the None return)
        name = tif.get_type_name()
        if filter_str and filter_str.lower() not in (name or "").lower():
            continue

        udt = ida_typeinf.udt_type_data_t()
        tif.get_udt_details(udt)
        all_structs.append(
            {
                "ordinal": ordinal,
                "name": name,
                "size": tif.get_size(),
                "is_union": tif.is_union(),
                "member_count": len(udt),
            }
        )

    total = len(all_structs)
    page = all_structs[offset : offset + count]
    return {"structs": page, "total": total, "offset": offset, "has_more": offset + count < total}


@tool
def get_struct_info(
    name: Annotated[str, "Struct name to look up"],
) -> dict:
    """Get detailed struct/union info including all member fields, offsets, and types."""
    import ida_typeinf

    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(ida_typeinf.get_idati(), name):
        return {"error": f"Struct not found: {name}"}

    if not (tif.is_struct() or tif.is_union()):
        return {"error": f"{name} is not a struct/union"}

    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return {"error": f"Cannot get details for {name}"}

    members = []
    for member in udt:
        members.append(
            {
                "name": member.name,
                "offset": member.offset // 8,
                "size": member.size // 8,
                "type": str(member.type),
            }
        )

    return {
        "name": name,
        "size": tif.get_size(),
        "is_union": tif.is_union(),
        "member_count": len(udt),
        "members": members,
    }


@tool
def get_stack_frame(
    address: Annotated[str, "Function address (hex) or name"],
) -> dict:
    """Get the stack frame layout of a function, showing local variables and arguments. Each member has its offset in the frame structure and its fp_offset, the frame-pointer-relative offset that declare_stack_var and delete_stack_var take."""
    import ida_funcs
    import ida_typeinf

    ea = _resolve_address(address)
    fn = _get_func(ea)
    if not fn:
        return {"error": f"No function at {address}"}

    frame_tif = _get_frame(fn)
    if frame_tif is None:
        return {
            "function": hex(fn.start_ea),
            "name": ida_funcs.get_func_name(fn.start_ea),
            "error": "No stack frame",
        }

    udt = ida_typeinf.udt_type_data_t()
    if not frame_tif.get_udt_details(udt):
        return {
            "function": hex(fn.start_ea),
            "name": ida_funcs.get_func_name(fn.start_ea),
            "error": "Cannot read frame details",
        }

    members = []
    for member in udt:
        offset = member.offset // 8
        members.append(
            {
                "name": member.name,
                "offset": offset,
                "fp_offset": _fp_offset(fn, offset),
                "size": member.size // 8,
            }
        )

    return {
        "function": hex(fn.start_ea),
        "name": ida_funcs.get_func_name(fn.start_ea),
        "frame_size": frame_tif.get_size(),
        "members": members,
        "member_count": len(members),
    }


@tool
def list_entrypoints() -> dict:
    """List all entry points of the binary (main, DllMain, TLS callbacks, etc.)."""
    import ida_entry

    entries = []
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal) or ""
        entries.append(
            {"address": hex(ea), "name": name, "ordinal": ordinal}
        )

    return {"entrypoints": entries, "count": len(entries)}


@write_tool
def patch_bytes(
    address: Annotated[str, "Address (hex) to patch at"],
    hex_bytes: Annotated[str, "Hex string of bytes to write (e.g. '90 90 90' or '909090')"],
) -> dict:
    """Patch bytes in the database at a given address. Use for binary patching (e.g. NOP out instructions)."""
    import ida_bytes

    ea = _resolve_address(address)

    cleaned = hex_bytes.replace(" ", "")
    if len(cleaned) % 2 != 0:
        return {"error": "Hex string must have even length"}

    try:
        data = bytes.fromhex(cleaned)
    except ValueError:
        return {"error": f"Invalid hex string: {hex_bytes}"}

    ida_bytes.patch_bytes(ea, data)
    return {
        "success": True,
        "address": hex(ea),
        "size": len(data),
        "patched": " ".join(f"{b:02x}" for b in data),
    }


@tool
def get_globals(
    filter_str: Annotated[str, "Filter global names by substring"] = "",
    offset: Annotated[int, "Starting index for pagination"] = 0,
    count: Annotated[int, "Maximum results (default 100)"] = 100,
) -> dict:
    """List global variables/named data items (excludes functions)."""
    import idautils

    all_globals = []
    for ea, name in idautils.Names():
        if _get_func(ea):
            continue
        if filter_str and filter_str.lower() not in name.lower():
            continue
        all_globals.append({"address": hex(ea), "name": name})

    total = len(all_globals)
    page = all_globals[offset : offset + count]
    return {"globals": page, "total": total, "offset": offset, "has_more": offset + count < total}


# ============================================================================
# Type System
# ============================================================================


@tool
def list_local_types(
    filter_str: Annotated[str, "Filter type names by substring"] = "",
    kind: Annotated[
        str, "Filter by kind: 'struct', 'union', 'enum', 'typedef', or '' for all"
    ] = "",
    offset: Annotated[int, "Starting index for pagination"] = 0,
    count: Annotated[int, "Maximum results (default 100)"] = 100,
) -> dict:
    """List all local types (structs, unions, enums, typedefs) in the type library."""
    import ida_typeinf

    til = ida_typeinf.get_idati()
    limit = ida_typeinf.get_ordinal_limit(til)

    all_types = []
    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(til, ordinal):
            continue
        name = tif.get_type_name()
        if not name:
            continue

        if tif.is_struct():
            t_kind = "struct"
        elif tif.is_union():
            t_kind = "union"
        elif tif.is_enum():
            t_kind = "enum"
        else:
            t_kind = "typedef"

        if kind and t_kind != kind:
            continue
        if filter_str and filter_str.lower() not in name.lower():
            continue

        all_types.append(
            {
                "ordinal": ordinal,
                "name": name,
                "kind": t_kind,
                "size": tif.get_size(),
                "declaration": str(tif),
            }
        )

    total = len(all_types)
    page = all_types[offset : offset + count]
    return {"types": page, "total": total, "offset": offset, "has_more": offset + count < total}


@write_tool
def declare_type(
    declaration: Annotated[
        str,
        "C type declaration, e.g. 'struct MyStruct { int x; char *name; };' or 'typedef unsigned int DWORD;'",
    ],
) -> dict:
    """Declare a C type definition in the local type library. Supports structs, unions, enums, and typedefs."""
    import ida_typeinf
    import idaapi

    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()

    result = ida_typeinf.parse_decl(tif, til, declaration, ida_typeinf.PT_TYP)
    if result is None:
        return {"error": f"Failed to parse type declaration: {declaration}"}

    # parse_decl returns the type name as a string
    name = result if isinstance(result, str) else tif.get_type_name()
    ordinal = tif.get_ordinal()

    # If no ordinal assigned, create one and save with the parsed name
    if ordinal == 0:
        ordinal = ida_typeinf.alloc_type_ordinal(til)
        tif.set_numbered_type(til, ordinal, ida_typeinf.NTF_REPLACE, name)

    return {
        "success": True,
        "name": name or "<anonymous>",
        "ordinal": ordinal,
        "declaration": str(tif),
    }


@write_tool
def apply_type(
    address: Annotated[str, "Address (hex) or function/symbol name"],
    type_str: Annotated[
        str,
        "C type declaration to apply, e.g. 'int __fastcall(int a, char *b)' or a named type",
    ],
) -> dict:
    """Apply a type to an address (function, global variable, etc.). Works for both function prototypes and data types."""
    import idc
    import idaapi
    import ida_typeinf

    ea = _resolve_address(address)

    # Try setting as function type first
    if idc.SetType(ea, type_str):
        _invalidate_decompiler_cache(ea)
        return {"success": True, "address": hex(ea), "type": type_str}

    # Try parsing and applying manually
    tif = ida_typeinf.tinfo_t()
    til = ida_typeinf.get_idati()
    result = ida_typeinf.parse_decl(tif, til, type_str, ida_typeinf.PT_TYP)
    if result is not None:
        if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
            _invalidate_decompiler_cache(ea)
            return {"success": True, "address": hex(ea), "type": str(tif)}

    return {"success": False, "error": f"Failed to apply type '{type_str}' at {address}"}


# ============================================================================
# Code Definition
# ============================================================================


@write_tool
def define_function(
    address: Annotated[str, "Start address (hex) for the new function"],
    end_address: Annotated[str, "End address (hex), empty for auto-detect"] = "",
) -> dict:
    """Define a function at an address. IDA will analyze the code to determine function boundaries unless end_address is specified."""
    import idaapi
    import ida_funcs

    ea = _resolve_address(address)
    end_ea = _resolve_address(end_address) if end_address else idaapi.BADADDR

    ok = idaapi.add_func(ea, end_ea)
    if not ok:
        existing = _get_func(ea)
        if existing:
            return {
                "success": False,
                "error": f"Function already exists at {hex(existing.start_ea)}",
            }
        return {"success": False, "error": f"Failed to define function at {address}"}

    fn = _get_func(ea)
    return {
        "success": True,
        "address": hex(fn.start_ea),
        "end_address": hex(fn.end_ea),
        "name": ida_funcs.get_func_name(fn.start_ea),
        "size": fn.end_ea - fn.start_ea,
    }


@write_tool
def define_code(
    address: Annotated[str, "Address (hex) to convert to code"],
) -> dict:
    """Convert bytes at an address to code instructions. Useful for areas IDA didn't auto-analyze."""
    import idc

    ea = _resolve_address(address)
    length = idc.create_insn(ea)
    if length == 0:
        return {"success": False, "error": f"Failed to create instruction at {address}"}

    return {
        "success": True,
        "address": hex(ea),
        "size": length,
        "disasm": idc.GetDisasm(ea),
    }


@write_tool
def undefine_code(
    address: Annotated[str, "Address (hex) to undefine"],
    size: Annotated[int, "Number of bytes to undefine (default 1)"] = 1,
) -> dict:
    """Undefine items at an address, converting them back to raw bytes. Useful for re-analysis."""
    import idc

    ea = _resolve_address(address)
    ok = idc.del_items(ea, 0, size)
    return {"success": bool(ok), "address": hex(ea), "size": size}


# ============================================================================
# Assembly Patching & String Reading & Number Conversion
# ============================================================================


@write_tool
def patch_asm(
    address: Annotated[str, "Address (hex) to patch at"],
    assembly: Annotated[str, "Assembly instruction to assemble and patch, e.g. 'nop' or 'xor eax, eax'"],
) -> dict:
    """Assemble an instruction and patch it at the given address. Combines assembly + patching in one step."""
    import idaapi
    import idc
    import ida_bytes
    import ida_idp

    ea = _resolve_address(address)
    is_64 = idaapi.inf_is_64bit() if hasattr(idaapi, "inf_is_64bit") else True

    # AssembleLine returns raw bytes without modifying the database
    code = ida_idp.AssembleLine(ea, 0, ea, is_64, assembly)
    if not code:
        return {"success": False, "error": f"Failed to assemble: {assembly}"}

    ida_bytes.patch_bytes(ea, code)
    # Re-analyze so disassembly is correct
    idc.create_insn(ea)

    return {
        "success": True,
        "address": hex(ea),
        "size": len(code),
        "bytes": code.hex(),
        "disasm": idc.GetDisasm(ea),
    }


@tool
def get_string_at(
    address: Annotated[str, "Address (hex) to read string from"],
    max_length: Annotated[int, "Maximum string length (default 1024)"] = 1024,
) -> dict:
    """Read a null-terminated string at an address. Useful for reading string data referenced by code."""
    import idc

    ea = _resolve_address(address)
    s = idc.get_strlit_contents(ea, max_length, idc.STRTYPE_C)
    if s is None:
        # Try reading raw bytes until null
        data = idc.get_bytes(ea, max_length)
        if data:
            null_pos = data.find(b"\x00")
            if null_pos >= 0:
                s = data[:null_pos]
            else:
                s = data

    if s is None:
        return {"error": f"No string at {address}"}

    text = s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s)
    return {
        "address": hex(ea),
        "string": text,
        "length": len(text),
        "raw_hex": s.hex() if isinstance(s, bytes) else "",
    }


# ============================================================================
# Instruction Search
# ============================================================================


@tool
def find_insns(
    pattern: Annotated[
        str,
        "Mnemonic pattern to search for (e.g. 'call', 'mov.*rax', 'xor eax, eax'). Regex supported.",
    ],
    address: Annotated[str, "Function address to search within (empty = all functions, EXPENSIVE)"] = "",
    max_results: Annotated[int, "Maximum results (default 50)"] = 50,
) -> dict:
    """Find instructions matching a mnemonic/operand pattern.

    Strongly prefer passing `address` to scope the search to one function. Leaving
    address empty walks every instruction in every function and can take many
    minutes on large binaries — only do that when you genuinely need a global
    sweep and have no narrower scope."""
    import idautils
    import idaapi
    import idc
    import ida_funcs

    compiled = re.compile(pattern, re.IGNORECASE)
    results = []

    if address:
        ea = _resolve_address(address)
        fn = _get_func(ea)
        if not fn:
            return {"error": f"No function at {address}"}
        ranges = _func_chunks(fn)
    else:
        ranges = []
        seen = set()  # a tail can belong to several functions
        for func_ea in idautils.Functions():
            fn = _get_func(func_ea)
            if fn:
                for chunk in _func_chunks(fn):
                    if chunk not in seen:
                        seen.add(chunk)
                        ranges.append(chunk)

    for start, end in ranges:
        if len(results) >= max_results:
            break
        for head in idautils.Heads(start, end):
            if len(results) >= max_results:
                break
            if not idaapi.is_code(idaapi.get_flags(head)):
                continue
            disasm = idc.GetDisasm(head)
            mnem = idc.print_insn_mnem(head)
            if compiled.search(disasm) or compiled.search(mnem):
                fn = _get_func(head)
                results.append(
                    {
                        "address": hex(head),
                        "disasm": disasm,
                        "mnemonic": mnem,
                        "function": ida_funcs.get_func_name(fn.start_ea) if fn else None,
                    }
                )

    return {"pattern": pattern, "matches": results, "count": len(results)}


# ============================================================================
# Stack Variable Management
# ============================================================================


@write_tool
def declare_stack_var(
    address: Annotated[str, "Function address (hex) or name"],
    var_offset: Annotated[
        int,
        "Frame-pointer-relative offset (fp_offset in get_stack_frame); usually negative for local variables, positive for arguments",
    ],
    var_name: Annotated[str, "Name for the stack variable"],
    var_type: Annotated[str, "C type declaration (e.g. 'int', 'char *')"] = "",
) -> dict:
    """Create or rename a stack variable in a function's stack frame."""
    import ida_frame
    import ida_typeinf

    ea = _resolve_address(address)
    fn = _get_func(ea)
    if not fn:
        return {"error": f"No function at {address}"}

    # Build type info
    tif = ida_typeinf.tinfo_t()
    if var_type:
        til = ida_typeinf.get_idati()
        parsed = ida_typeinf.parse_decl(tif, til, f"{var_type} x;", ida_typeinf.PT_VAR)
        if parsed is None:
            tif.create_simple_type(ida_typeinf.BT_INT8)
    else:
        tif.create_simple_type(ida_typeinf.BT_INT8)

    if hasattr(ida_frame, "define_stkvar_ea"):  # IDA 9.5+
        ok = ida_frame.define_stkvar_ea(fn.start_ea, var_name, var_offset, tif)
    else:
        ok = ida_frame.define_stkvar(fn, var_name, var_offset, tif)
    if not ok:
        return {"success": False, "error": f"Failed to define stack variable at offset {var_offset}"}

    return {"success": True, "address": hex(ea), "offset": var_offset, "name": var_name}


@write_tool
def delete_stack_var(
    address: Annotated[str, "Function address (hex) or name"],
    var_offset: Annotated[
        int,
        "Frame-pointer-relative offset of the variable (fp_offset in get_stack_frame), as passed to declare_stack_var",
    ],
    size: Annotated[
        int, "Bytes to delete from var_offset (default 1: the variable starting there)"
    ] = 1,
) -> dict:
    """Delete a stack variable from a function's stack frame."""
    import ida_frame
    import ida_typeinf

    ea = _resolve_address(address)
    fn = _get_func(ea)
    if not fn:
        return {"error": f"No function at {address}"}

    frame_tif = _get_frame(fn)
    udt = ida_typeinf.udt_type_data_t()
    if frame_tif is None or not frame_tif.get_udt_details(udt):
        return {"success": False, "error": f"No stack frame at {address}"}

    # delete_frame_members() takes offsets in the frame structure
    start = var_offset - _fp_offset(fn, 0)
    var_name = next((m.name for m in udt if m.offset // 8 == start), None)
    if var_name is None:
        return {
            "success": False,
            "error": f"No stack variable at fp_offset {var_offset}; see get_stack_frame",
        }

    end = start + size
    if hasattr(ida_frame, "delete_frame_members_ea"):  # IDA 9.5+
        ok = ida_frame.delete_frame_members_ea(fn.start_ea, start, end)
    else:
        ok = ida_frame.delete_frame_members(fn, start, end)
    return {"success": bool(ok), "address": hex(ea), "offset": var_offset, "name": var_name}


# ============================================================================
# Enhanced Type System
# ============================================================================


@write_tool
def enum_upsert(
    name: Annotated[str, "Enum type name"],
    members: Annotated[
        list[dict],
        "List of {name, value} dicts, e.g. [{'name':'FLAG_A','value':1},{'name':'FLAG_B','value':2}]",
    ],
    bitfield: Annotated[
        bool, "Create a bitmask enum (bit flags); only applies when the enum is created"
    ] = False,
) -> dict:
    """Create or extend an enum type. Idempotent - existing members are preserved, new ones are added."""
    import ida_typeinf

    til = ida_typeinf.get_idati()

    # Check if enum already exists
    tif = ida_typeinf.tinfo_t()
    existing = tif.get_named_type(til, name)

    if existing and not tif.is_enum():
        # Saving an enum under this name would replace the existing type
        return {"success": False, "error": f"Type {name} already exists and is not an enum"}

    if existing:
        # Extend existing enum. add_edm() updates the stored type in place
        # and keeps the bitmask groups of a bitmask enum valid.
        edt = ida_typeinf.enum_type_data_t()
        if not tif.get_enum_details(edt):
            return {"error": f"Cannot read existing enum {name}"}

        existing_names = {m.name for m in edt}
        total_before = len(edt)
        added = []
        for m in members:
            m_name = m.get("name", "")
            m_value = m.get("value", 0)
            if m_name and m_name not in existing_names:
                try:
                    tif.add_edm(m_name, m_value)
                except ValueError as e:
                    return {
                        "success": False,
                        "name": name,
                        "error": f"Cannot add {m_name}: {e}",
                        "added_members": added,
                    }
                existing_names.add(m_name)
                added.append(m_name)

        return {
            "success": True,
            "name": name,
            "action": "extended",
            "added_members": added,
            "total_members": total_before + len(added),
        }
    else:
        # Create new enum
        edt = ida_typeinf.enum_type_data_t()
        added_count = 0
        for m in members:
            m_name = m.get("name", "")
            m_value = m.get("value", 0)
            if m_name:
                em = ida_typeinf.edm_t()
                em.name = m_name
                em.value = m_value
                edt.push_back(em)
                added_count += 1

        tif_new = ida_typeinf.tinfo_t()
        if not tif_new.create_enum(edt):
            return {"success": False, "error": f"Failed to create enum {name}"}
        if bitfield:
            # IDA builds the bitmask groups itself; BTE_BITMASK must not
            # be set by hand
            code = tif_new.set_enum_is_bitmask(ida_typeinf.tinfo_t.ENUMBM_ON)
            if code != ida_typeinf.TERR_OK:
                return {
                    "success": False,
                    "error": f"Cannot make {name} a bitmask enum: {ida_typeinf.tinfo_errstr(code)}",
                }
        ordinal = ida_typeinf.alloc_type_ordinal(til)
        code = tif_new.set_numbered_type(til, ordinal, ida_typeinf.NTF_REPLACE, name)
        if code != ida_typeinf.TERR_OK:
            return {
                "success": False,
                "error": f"Failed to save enum {name}: {ida_typeinf.tinfo_errstr(code)}",
            }

        return {
            "success": True,
            "name": name,
            "action": "created",
            "ordinal": ordinal,
            "member_count": added_count,
        }


@tool
def type_inspect(
    name: Annotated[str, "Type name to inspect"],
    include_members: Annotated[
        bool, "Include member/field details"
    ] = True,
) -> dict:
    """Inspect a named type in detail: size, kind, full declaration, and members. Works for structs, unions, enums, and typedefs."""
    import ida_typeinf

    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(ida_typeinf.get_idati(), name):
        return {"error": f"Type not found: {name}"}

    if tif.is_struct():
        t_kind = "struct"
    elif tif.is_union():
        t_kind = "union"
    elif tif.is_enum():
        t_kind = "enum"
    elif tif.is_func():
        t_kind = "func"
    else:
        t_kind = "typedef"

    result = {
        "name": name,
        "kind": t_kind,
        "size": tif.get_size(),
        "ordinal": tif.get_ordinal(),
        "declaration": str(tif),
    }

    if include_members:
        if t_kind in ("struct", "union"):
            udt = ida_typeinf.udt_type_data_t()
            if tif.get_udt_details(udt):
                result["members"] = [
                    {
                        "name": m.name,
                        "offset": m.offset // 8,
                        "size": m.size // 8,
                        "type": str(m.type),
                    }
                    for m in udt
                ]
                result["member_count"] = len(udt)
        elif t_kind == "enum":
            edt = ida_typeinf.enum_type_data_t()
            if tif.get_enum_details(edt):
                result["members"] = [
                    {"name": m.name, "value": m.value} for m in edt
                ]
                result["member_count"] = len(edt)

    return result


@tool
def xrefs_to_field(
    struct_name: Annotated[str, "Name of the struct"],
    field_name: Annotated[str, "Name of the field/member to find references to"],
    max_results: Annotated[int, "Maximum results (default 50)"] = 50,
) -> dict:
    """Get cross-references to a specific struct field member. Finds code that accesses this particular field."""
    import ida_typeinf
    import idaapi
    import idautils
    import ida_funcs

    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(til, struct_name):
        return {"error": f"Struct not found: {struct_name}"}

    if not (tif.is_struct() or tif.is_union()):
        return {"error": f"{struct_name} is not a struct/union"}

    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return {"error": f"Cannot get details for {struct_name}"}

    # Find the target field
    target_offset = None
    target_size = None
    for member in udt:
        if member.name == field_name:
            target_offset = member.offset // 8
            target_size = member.size // 8
            break

    if target_offset is None:
        return {
            "error": f"Field '{field_name}' not found in {struct_name}",
            "available_fields": [m.name for m in udt],
        }

    # Get struct member xrefs via IDA 9.3 tinfo_t API
    xrefs = []
    udm = ida_typeinf.udm_t()
    udm.name = field_name
    idx = tif.find_udm(udm, ida_typeinf.STRMEM_NAME)
    if idx >= 0:
        member_tid = tif.get_udm_tid(idx)
        if member_tid != idaapi.BADADDR:
            for xref in idautils.XrefsTo(member_tid):
                if len(xrefs) >= max_results:
                    break
                fn = _get_func(xref.frm)
                xrefs.append({
                    "from_address": hex(xref.frm),
                    "type": _xref_type_name(xref.type),
                    "function": ida_funcs.get_func_name(fn.start_ea) if fn else None,
                })

    return {
        "struct": struct_name,
        "field": field_name,
        "field_offset": target_offset,
        "field_size": target_size,
        "xrefs": xrefs,
        "count": len(xrefs),
    }


# ============================================================================
# Advanced Analysis
# ============================================================================


@tool
def find_paths(
    start_address: Annotated[str, "Start address (hex) or name - must be within a function"],
    end_address: Annotated[str, "End address (hex) or name - must be in the same function"],
    max_paths: Annotated[int, "Maximum number of paths to find (default 5)"] = 5,
    max_depth: Annotated[int, "Maximum path length in basic blocks (default 20)"] = 20,
) -> dict:
    """Find control-flow paths between two addresses within the same function using DFS on the CFG."""
    import ida_funcs

    start_ea = _resolve_address(start_address)
    end_ea = _resolve_address(end_address)

    fn = _get_func(start_ea)
    if not fn:
        return {"error": f"No function at {start_address}"}

    fn2 = _get_func(end_ea)
    if not fn2 or fn.start_ea != fn2.start_ea:
        return {"error": "Both addresses must be in the same function"}

    fc = _flow_chart(fn.start_ea)

    # Map addresses to block indices
    start_block = None
    end_block = None
    for i in range(fc.size()):
        block = fc[i]
        if block.start_ea <= start_ea < block.end_ea:
            start_block = i
        if block.start_ea <= end_ea < block.end_ea:
            end_block = i

    if start_block is None:
        return {"error": f"Address {start_address} not in any basic block"}
    if end_block is None:
        return {"error": f"Address {end_address} not in any basic block"}

    # DFS to find paths
    paths = []

    def dfs(current, target, path, visited):
        if len(paths) >= max_paths:
            return
        if len(path) > max_depth:
            return
        if current == target:
            paths.append(
                [{"start": hex(fc[b].start_ea), "end": hex(fc[b].end_ea)} for b in path]
            )
            return
        for j in range(fc.nsucc(current)):
            succ = fc.succ(current, j)
            if succ not in visited:
                visited.add(succ)
                path.append(succ)
                dfs(succ, target, path, visited)
                path.pop()
                visited.discard(succ)

    dfs(start_block, end_block, [start_block], {start_block})

    return {
        "function": ida_funcs.get_func_name(fn.start_ea),
        "start": hex(start_ea),
        "end": hex(end_ea),
        "paths": paths,
        "path_count": len(paths),
    }


@tool
def export_function(
    address: Annotated[str, "Function address (hex) or name"],
    format: Annotated[
        str, "Export format: 'c_header' for prototype, 'full' for decompiled code"
    ] = "c_header",
) -> dict:
    """Export a function as a C header prototype or full decompiled code."""
    import ida_funcs
    import ida_nalt
    import ida_typeinf
    import ida_hexrays

    ea = _resolve_address(address)
    fn = _get_func(ea)
    if not fn:
        return {"error": f"No function at {address}"}

    name = ida_funcs.get_func_name(fn.start_ea)
    tif = ida_typeinf.tinfo_t()
    has_type = ida_nalt.get_tinfo(tif, fn.start_ea)
    prototype = str(tif) if has_type else None

    result = {
        "address": hex(fn.start_ea),
        "name": name,
        "prototype": prototype,
    }

    if format == "full":
        if not ida_hexrays.init_hexrays_plugin():
            result["error"] = "Hex-Rays decompiler not available for full export"
        else:
            try:
                cfunc, failure = _decompile(fn.start_ea)
                if cfunc:
                    result["code"] = str(cfunc)
                else:
                    result["error"] = f"Decompilation failed: {failure}"
            except Exception as e:
                result["error"] = f"Decompilation failed: {e}"

    return result


# ============================================================================
# Script Execution
# ============================================================================


# run_script's variables, kept until the open database changes
_script_globals: dict = {}
_script_generation: Optional[int] = None
_SCRIPT_FILENAME = "<script>"
_INTERRUPT_NAME = "__ida_auto_mcp_interrupt__"


@script_tool
def run_script(
    script: Annotated[
        str,
        "IDAPython code. Variables persist between calls until another database is opened; the value of a final expression is returned as result.",
    ],
) -> dict:
    """Execute arbitrary IDAPython code. The script can use all IDA APIs (import idaapi, idc, etc). Returns captured stdout/stderr, the value of a final expression, and the traceback if it fails."""
    global _script_generation

    generation = get_manager().generation
    if generation != _script_generation:
        # IDA objects from a database that has been closed must not be reused
        _script_globals.clear()
        _script_generation = generation
    _script_globals.setdefault("__builtins__", __builtins__)
    _script_globals.setdefault("__name__", "__main__")
    _script_globals[_INTERRUPT_NAME] = ToolInterrupted

    old_stdout = sys.stdout
    old_stderr = sys.stderr
    captured_out = io.StringIO()
    captured_err = io.StringIO()
    sys.stdout = captured_out
    sys.stderr = captured_err

    result = None
    error = None
    try:
        tree = ast.parse(script, filename=_SCRIPT_FILENAME)
        _reraise_interrupts(tree)
        final = None
        if tree.body and isinstance(tree.body[-1], ast.Expr):
            final = ast.Expression(tree.body.pop().value)
        # Lets tracebacks show the script's source lines
        linecache.cache[_SCRIPT_FILENAME] = (
            len(script),
            None,
            script.splitlines(True),
            _SCRIPT_FILENAME,
        )
        exec(compile(tree, _SCRIPT_FILENAME, "exec"), _script_globals)
        if final is not None:
            result = eval(compile(final, _SCRIPT_FILENAME, "eval"), _script_globals)
    except SystemExit as e:
        error = f"SystemExit({e.code!r}): the script called exit()"
    except Exception as e:
        error = _script_traceback(e)
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr

    return {
        "output": captured_out.getvalue(),
        "errors": captured_err.getvalue(),
        "error": error,
        "result": _json_safe(result),
    }


def _reraise_interrupts(tree: ast.Module) -> None:
    """Give every try statement of a script a first handler that re-raises
    ToolInterrupted, so a bare except cannot swallow a timeout."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Try) and node.handlers:
            anchor = node.handlers[0]
            handler = ast.ExceptHandler(
                type=ast.Name(id=_INTERRUPT_NAME, ctx=ast.Load()),
                name=None,
                body=[ast.Raise(exc=None, cause=None)],
            )
            node.handlers.insert(0, ast.copy_location(handler, anchor))
    ast.fix_missing_locations(tree)


def _script_traceback(error: BaseException) -> str:
    """The error's traceback, from the script's first frame on."""
    tb = traceback.TracebackException.from_exception(error)
    frames = list(tb.stack)
    first = next(
        (i for i, f in enumerate(frames) if f.filename == _SCRIPT_FILENAME),
        len(frames),
    )
    tb.stack = traceback.StackSummary.from_list(frames[first:])
    return "".join(tb.format()).rstrip()


def _json_safe(value):
    """value itself if it serializes to JSON, else its repr()."""
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError, OverflowError, RecursionError):
        return repr(value)


# ============================================================================
# Type Inference
# ============================================================================


@write_tool
def infer_types(
    address: Annotated[str, "Address (hex) or function/symbol name"],
) -> dict:
    """Infer and apply the most likely type at an address using Hex-Rays decompiler and IDA heuristics."""
    import idaapi
    import ida_typeinf
    import ida_hexrays
    import ida_nalt
    import idc

    ea = _resolve_address(address)
    tif = ida_typeinf.tinfo_t()
    status = "failed"

    # Try 1: Hex-Rays guess_type
    if ida_hexrays.init_hexrays_plugin():
        try:
            if _get_func(ea):
                cfunc, _ = _decompile(ea)
                if cfunc and cfunc.type:
                    tif = cfunc.type
                    status = "decompiler"
        except Exception:
            pass

    # Try 2: existing tinfo
    if status == "failed":
        if ida_nalt.get_tinfo(tif, ea):
            status = "existing"

    # Try 3: guess_tinfo
    if status == "failed":
        if idaapi.guess_tinfo(tif, ea) != idaapi.GUESS_FUNC_FAILED:
            status = "guessed"

    if status == "failed":
        return {"address": hex(ea), "status": "failed", "error": "Could not infer type"}

    # Apply the inferred type
    ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)

    return {
        "address": hex(ea),
        "status": status,
        "type": str(tif),
        "size": tif.get_size(),
    }


# ============================================================================
# Data Flow & Cross-Reference Analysis
# ============================================================================


@tool
def trace_data_flow(
    address: Annotated[str, "Starting address (hex) or name"],
    direction: Annotated[str, "Direction: 'forward' (xrefs from) or 'backward' (xrefs to)"] = "forward",
    max_depth: Annotated[int, "Maximum traversal depth (default 5)"] = 5,
    max_nodes: Annotated[int, "Maximum nodes to visit (default 50)"] = 50,
) -> dict:
    """Trace data flow by following cross-references forward or backward from an address via BFS. Returns a graph of nodes and edges."""
    import idaapi
    import idautils
    import ida_funcs
    import ida_xref
    from collections import deque

    ea = _resolve_address(address)

    nodes = {}
    edges = []
    queue = deque()

    # Build initial node
    fn = _get_func(ea)
    nodes[ea] = {
        "address": hex(ea),
        "name": ida_funcs.get_func_name(fn.start_ea) if fn else idaapi.get_name(ea) or "",
        "depth": 0,
    }
    queue.append((ea, 0))

    while queue and len(nodes) < max_nodes:
        cur_ea, depth = queue.popleft()
        if depth >= max_depth:
            continue

        if direction == "forward":
            xrefs = idautils.XrefsFrom(cur_ea)
        else:
            xrefs = idautils.XrefsTo(cur_ea)

        for xref in xrefs:
            target = xref.to if direction == "forward" else xref.frm
            # Skip flow xrefs (consecutive instructions)
            if xref.type == ida_xref.fl_F:
                continue

            edge = {"from": hex(cur_ea), "to": hex(target), "type": _xref_type_name(xref.type)}
            edges.append(edge)

            if target not in nodes and len(nodes) < max_nodes:
                t_fn = _get_func(target)
                nodes[target] = {
                    "address": hex(target),
                    "name": ida_funcs.get_func_name(t_fn.start_ea) if t_fn else idaapi.get_name(target) or "",
                    "depth": depth + 1,
                }
                queue.append((target, depth + 1))

    return {
        "root": hex(ea),
        "direction": direction,
        "nodes": list(nodes.values()),
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
    }


# ============================================================================
# Comment Utilities
# ============================================================================


@write_tool
def append_comment(
    address: Annotated[str, "Address (hex) to append comment to"],
    comment: Annotated[str, "Comment text to append"],
    is_repeatable: Annotated[bool, "If true, use repeatable comment"] = False,
) -> dict:
    """Append a comment at an address without overwriting existing comments. Automatically deduplicates."""
    import idc

    ea = _resolve_address(address)
    existing = idc.get_cmt(ea, 1 if is_repeatable else 0) or ""

    # Dedup: don't add if already present
    if comment in existing:
        return {"success": True, "address": hex(ea), "comment": existing, "note": "already present"}

    if existing:
        new_comment = existing + "\n" + comment
    else:
        new_comment = comment

    ok = idc.set_cmt(ea, new_comment, 1 if is_repeatable else 0)
    return {"success": bool(ok), "address": hex(ea), "comment": new_comment}


# ============================================================================
# Helpers (not exposed as tools)
# ============================================================================


def _invalidate_decompiler_cache(ea: int):
    """Mark decompiler cache dirty so pseudocode is refreshed after modifications."""
    try:
        import ida_hexrays

        if ida_hexrays.init_hexrays_plugin():
            fn = _get_func(ea)
            if fn:
                ida_hexrays.mark_cfunc_dirty(fn.start_ea)
    except Exception:
        pass


# (database generation, analysis epoch) of the decompiler's cached results
_decompiled_state: Optional[tuple] = None


def _decompile(ea: int) -> tuple:
    """Decompile the function at ea: (cfunc, None), or (None, reason).

    Call init_hexrays_plugin() first. The tool time limit cannot interrupt
    the decompiler's native code, so on IDA 9.5+ the decompiler is given the
    same limit and stops itself. Once analysis changed the database, the
    decompiler's cached results are dropped: they may show functions as they
    were before (cut short, missing calls).
    """
    import ida_hexrays

    global _decompiled_state
    manager = get_manager()
    state = (manager.generation, manager.analysis_epoch)
    if state != _decompiled_state:
        ida_hexrays.clear_cached_cfuncs()
        _decompiled_state = state

    if hasattr(ida_hexrays, "set_decompiler_timeout"):  # IDA 9.5+
        limit = mcp.tool_timeout
        ida_hexrays.set_decompiler_timeout(int(limit * 1000) if limit else 0)
    failure = ida_hexrays.hexrays_failure_t()
    cfunc = ida_hexrays.decompile(ea, failure)
    if cfunc is None:
        return None, failure.desc() or "unknown error"
    return cfunc, None


def _get_func(ea: int):
    """Function containing ea, or None.

    The result has start_ea/end_ea, the bounds of the function's entry
    chunk. IDA 9.5 deprecates get_func() in favor of EA-based lookups and
    gets a func_entry_info_t here; earlier versions get the func_t itself,
    which is what their pointer-based APIs (frames, flow charts) expect.
    """
    import ida_funcs

    if hasattr(ida_funcs, "get_func_entry_info"):  # IDA 9.5+
        fn = ida_funcs.func_entry_info_t()
        return fn if ida_funcs.get_func_entry_info(fn, ea) else None
    return ida_funcs.get_func(ea)


def _func_chunks(fn) -> list:
    """(start, end) of each chunk of a function from _get_func().

    The entry chunk comes first, then the tails in address order: parts of
    the function that IDA found elsewhere in the binary, common in optimized
    and obfuscated code. start_ea/end_ea cover the entry chunk only.
    """
    import ida_funcs

    if hasattr(ida_funcs, "get_func_tails"):  # IDA 9.5+
        import ida_range

        tails = ida_range.rangevec_t()
        ida_funcs.get_func_tails(tails, fn.start_ea)
        ranges = [(r.start_ea, r.end_ea) for r in tails]
    else:
        ranges = [(c.start_ea, c.end_ea) for c in ida_funcs.func_tail_iterator_t(fn)]
    entry = (fn.start_ea, fn.end_ea)
    return [entry] + sorted(r for r in set(ranges) if r[0] != fn.start_ea)


def _func_heads(fn):
    """Addresses of the items of a function from _get_func(), in all its chunks."""
    import idautils

    for start, end in _func_chunks(fn):
        yield from idautils.Heads(start, end)


def _flow_chart(func_ea: int):
    """Flow chart (basic blocks) of the function starting at func_ea.

    A qflow_chart_ea_t on IDA 9.5+, a qflow_chart_t before; both offer
    size(), [n], nsucc()/succ(), npred()/pred() and calc_block_type().
    """
    import ida_gdl
    import idaapi

    if hasattr(ida_gdl, "qflow_chart_ea_t"):  # IDA 9.5+
        return ida_gdl.qflow_chart_ea_t(
            "", func_ea, idaapi.BADADDR, idaapi.BADADDR, 0
        )
    return ida_gdl.qflow_chart_t(
        "", _get_func(func_ea), idaapi.BADADDR, idaapi.BADADDR, 0
    )


def _get_frame(fn):
    """Frame structure (tinfo_t) of a function from _get_func(), or None."""
    import ida_frame
    import ida_typeinf

    frame_tif = ida_typeinf.tinfo_t()
    if hasattr(ida_frame, "get_func_frame_ea"):  # IDA 9.5+
        ok = ida_frame.get_func_frame_ea(frame_tif, fn.start_ea)
    else:
        ok = ida_frame.get_func_frame(frame_tif, fn)
    return frame_tif if ok else None


def _fp_offset(fn, soff: int) -> int:
    """Frame-pointer-relative offset of frame structure offset soff.

    This is the offset define_stkvar() takes, so stack variable tools use
    it; frame structure offsets differ from it by a per-function constant.
    """
    import ida_frame

    if hasattr(ida_frame, "soff_to_fpoff_ea"):  # IDA 9.5+
        return ida_frame.soff_to_fpoff_ea(fn.start_ea, soff)
    return ida_frame.soff_to_fpoff(fn, soff)


def _parse_number(text: str) -> Optional[int]:
    """An optional number such as "0x8000000" or "4096"; None when empty."""
    text = text.strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        raise ValueError(f"Invalid number: {text!r} (use hex like 0x8000000)") from None


def _resolve_address(addr_or_name: str) -> int:
    """Resolve a hex address string or symbol name to an integer EA."""
    import idaapi

    s = addr_or_name.strip()

    # Hex address: 0x401000
    if s.startswith(("0x", "0X")):
        return int(s, 16)

    # IDA auto-name: sub_401000
    if s.startswith("sub_"):
        try:
            return int(s[4:], 16)
        except ValueError:
            pass

    # Pure decimal number
    try:
        val = int(s)
        if val >= 0:
            return val
    except ValueError:
        pass

    # Symbol name lookup
    ea = idaapi.get_name_ea(idaapi.BADADDR, s)
    if ea != idaapi.BADADDR:
        return ea

    raise ValueError(f"Cannot resolve address or name: {addr_or_name}")


def _xref_type_name(xtype: int) -> str:
    """Convert xref type constant to readable string."""
    import ida_xref

    NAMES = {
        ida_xref.fl_U: "unknown",
        ida_xref.fl_CF: "call_far",
        ida_xref.fl_CN: "call_near",
        ida_xref.fl_JF: "jump_far",
        ida_xref.fl_JN: "jump_near",
        ida_xref.fl_F: "flow",
        ida_xref.dr_O: "data_offset",
        ida_xref.dr_W: "data_write",
        ida_xref.dr_R: "data_read",
    }
    return NAMES.get(xtype, f"type_{xtype}")


def _get_segment(ea: int) -> Optional[dict]:
    """Bounds, name, class and rwx permissions of the segment containing ea.

    IDA 9.5 deprecates getseg() and the segment_t accessors in favor of
    EA-based ones (get_segment_info, get_segment_name, ...).
    """
    import ida_segment

    if hasattr(ida_segment, "get_segment_info"):  # IDA 9.5+
        seg = ida_segment.segment_info_t()
        if not ida_segment.get_segment_info(seg, ea):
            return None
        perm = seg.get_perm()
        name = ida_segment.get_segment_name(seg.start_ea)
        sclass = ida_segment.get_segment_class(seg.start_ea)
    else:
        seg = ida_segment.getseg(ea)
        if not seg:
            return None
        perm = seg.perm
        name = ida_segment.get_segm_name(seg)
        sclass = ida_segment.get_segm_class(seg)
    return {
        "start": seg.start_ea,
        "end": seg.end_ea,
        "name": name,
        "class": sclass,
        "permissions": _seg_perms(perm),
    }


def _seg_perms(perm: int) -> str:
    """Format segment permissions as rwx string."""
    import idaapi

    r = "r" if perm & idaapi.SEGPERM_READ else "-"
    w = "w" if perm & idaapi.SEGPERM_WRITE else "-"
    x = "x" if perm & idaapi.SEGPERM_EXEC else "-"
    return r + w + x


def _is_synthetic_string(s) -> bool:
    """Whether a string list item is synthetic (IDA 9.5+): reported by a
    provider such as the decompiler, its text is not in the bytes at s.ea."""
    is_synthetic = getattr(s, "is_synthetic_string", None)
    return bool(is_synthetic and is_synthetic())

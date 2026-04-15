"""IDA analysis tools exposed as MCP tools.

All tools operate on the currently active IDA database session.
Use open_binary / switch_binary to manage which database is active.

IDA modules are imported inside each function to ensure they are
only accessed after idapro has been initialized.
"""

import fnmatch
import io
import re
import sys
from typing import Annotated, Optional

from ._registry import tool
from .session import get_manager


# ============================================================================
# Session Management Tools
# ============================================================================


@tool
def open_binary(
    input_path: Annotated[str, "Absolute path to the binary file to analyze"],
    auto_analysis: Annotated[bool, "Run IDA auto-analysis (recommended)"] = True,
) -> dict:
    """Open a binary file for analysis. Creates a new IDA session or reuses an existing one for the same file. This is the first tool you should call to start analyzing a binary."""
    try:
        session = get_manager().open_binary(input_path, auto_analysis=auto_analysis)
        return {
            "success": True,
            "session": session.to_dict(),
            "message": f"Opened {session.input_path.name} (session: {session.session_id})",
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@tool
def close_binary(
    session_id: Annotated[str, "Session ID to close"],
) -> dict:
    """Close an analysis session and free its resources."""
    if get_manager().close_session(session_id):
        return {"success": True, "message": f"Session {session_id} closed"}
    return {"success": False, "error": f"Session not found: {session_id}"}


@tool
def switch_binary(
    session_id: Annotated[str, "Session ID to switch to"],
) -> dict:
    """Switch the active analysis to a different open session. All subsequent analysis tools will operate on this session's database."""
    try:
        session = get_manager().switch_session(session_id)
        return {
            "success": True,
            "session": session.to_dict(),
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
    return {"is_active": True, **session.to_dict()}


# ============================================================================
# Server Management
# ============================================================================


@tool
def server_health() -> dict:
    """Health check for the MCP server. Reports server status, active session, IDA analysis state, and available subsystems."""
    import ida_auto

    result = {
        "status": "ok",
        "server": "ida-auto-mcp",
    }

    session = get_manager().get_current()
    if session:
        result["session"] = session.to_dict()
        result["auto_analysis_done"] = bool(ida_auto.auto_is_ok())
    else:
        result["session"] = None
        result["auto_analysis_done"] = None

    # Check Hex-Rays availability
    try:
        import ida_hexrays

        result["hexrays_available"] = bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        result["hexrays_available"] = False

    result["open_sessions"] = len(get_manager().list_sessions())
    return result


@tool
def server_warmup(
    init_hexrays: Annotated[
        bool, "Initialize Hex-Rays decompiler plugin"
    ] = True,
    build_string_cache: Annotated[
        bool, "Pre-build the string list cache"
    ] = True,
) -> dict:
    """Warm up IDA subsystems to reduce first-call latency. Call after open_binary to speed up subsequent tool calls."""
    warmed = []

    if init_hexrays:
        try:
            import ida_hexrays

            if ida_hexrays.init_hexrays_plugin():
                warmed.append("hexrays")
        except Exception:
            pass

    if build_string_cache:
        try:
            import idautils

            count = sum(1 for _ in idautils.Strings())
            warmed.append(f"strings({count})")
        except Exception:
            pass

    # Warm up function list
    try:
        import idautils

        count = sum(1 for _ in idautils.Functions())
        warmed.append(f"functions({count})")
    except Exception:
        pass

    return {"success": True, "warmed": warmed}


# ============================================================================
# Database Info
# ============================================================================


@tool
def get_database_info() -> dict:
    """Get metadata about the currently loaded binary (filename, architecture, image base, hashes, etc.)."""
    import idaapi
    import ida_nalt
    import idc
    import ida_auto
    import idautils

    info = idaapi.get_inf_structure() if hasattr(idaapi, "get_inf_structure") else None

    result = {
        "filename": ida_nalt.get_root_filename(),
        "input_path": ida_nalt.get_input_file_path(),
        "idb_path": idc.get_idb_path(),
        "imagebase": hex(idaapi.get_imagebase()),
        "processor": idaapi.get_idp_name(),
        "auto_analysis_done": bool(ida_auto.auto_is_ok()),
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
            seg = idaapi.getseg(seg_ea)
            if seg and seg.end_ea > max_ea:
                max_ea = seg.end_ea
        result["min_address"] = hex(min_ea)
        result["max_address"] = hex(max_ea)

    # Function count
    result["function_count"] = sum(1 for _ in idautils.Functions())

    return result


@tool
def wait_analysis() -> dict:
    """Wait for IDA auto-analysis to complete. Call this after open_binary if you want to ensure analysis is finished."""
    import ida_auto

    ida_auto.auto_wait()
    return {"success": True, "message": "Auto-analysis completed"}


@tool
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
    import idaapi

    all_funcs = []
    for ea in idautils.Functions():
        fn = idaapi.get_func(ea)
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
    import idaapi
    import ida_funcs
    import ida_nalt
    import ida_typeinf

    ea = _resolve_address(address)
    fn = idaapi.get_func(ea)
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
    import idaapi
    import ida_hexrays
    import ida_funcs

    if not ida_hexrays.init_hexrays_plugin():
        return {"error": "Hex-Rays decompiler not available"}

    ea = _resolve_address(address)
    fn = idaapi.get_func(ea)
    if not fn:
        return {"error": f"No function at {address}"}

    try:
        cfunc = ida_hexrays.decompile(fn.start_ea)
        if cfunc is None:
            return {"error": f"Decompilation failed for {address}"}

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
    """Get assembly disassembly for a function or address range."""
    import idaapi
    import idc
    import idautils

    ea = _resolve_address(address)
    fn = idaapi.get_func(ea)

    lines = []
    if fn:
        for head in idautils.Heads(fn.start_ea, fn.end_ea):
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

    return {
        "address": hex(ea),
        "is_function": fn is not None,
        "instructions": lines,
        "count": len(lines),
    }


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
    import idaapi
    import ida_funcs
    import ida_xref

    ea = _resolve_address(address)
    xrefs = []
    for xref in idautils.XrefsTo(ea):
        if len(xrefs) >= max_results:
            break
        fn = idaapi.get_func(xref.frm)
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
    import idaapi
    import ida_funcs

    ea = _resolve_address(address)
    xrefs = []
    for xref in idautils.XrefsFrom(ea):
        if len(xrefs) >= max_results:
            break
        fn = idaapi.get_func(xref.to)
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
    """List strings found in the binary with optional filtering."""
    import idautils

    all_strings = []
    for s in idautils.Strings():
        if s is None:
            continue
        text = str(s)
        all_strings.append(
            {"address": hex(s.ea), "text": text, "length": s.length}
        )

    if filter_str:
        pattern = filter_str.lower()
        all_strings = [s for s in all_strings if pattern in s["text"].lower()]

    total = len(all_strings)
    page = all_strings[offset : offset + count]
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
    import idautils

    compiled = re.compile(pattern, re.IGNORECASE)
    matches = []
    for s in idautils.Strings():
        if s is None:
            continue
        text = str(s)
        if compiled.search(text):
            matches.append({"address": hex(s.ea), "text": text})
            if len(matches) >= max_results:
                break

    return {"pattern": pattern, "matches": matches, "count": len(matches)}


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
    import idaapi

    segments = []
    for ea in idautils.Segments():
        seg = idaapi.getseg(ea)
        if not seg:
            continue
        segments.append(
            {
                "start": hex(seg.start_ea),
                "end": hex(seg.end_ea),
                "name": idaapi.get_segm_name(seg),
                "size": seg.end_ea - seg.start_ea,
                "permissions": _seg_perms(seg),
                "class": idaapi.get_segm_class(seg),
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
        seg = idaapi.getseg(seg_ea)
        if seg and seg.end_ea > max_ea:
            max_ea = seg.end_ea

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


@tool
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


@tool
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


@tool
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
    import idaapi
    import ida_funcs
    import ida_xref

    ea = _resolve_address(address)
    fn = idaapi.get_func(ea)
    if not fn:
        return {"error": f"No function at {address}"}

    callers = []
    seen = set()
    for xref in idautils.XrefsTo(fn.start_ea):
        if len(callers) >= max_results:
            break
        if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
            caller_fn = idaapi.get_func(xref.frm)
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
    import idaapi
    import ida_funcs
    import ida_xref

    ea = _resolve_address(address)
    fn = idaapi.get_func(ea)
    if not fn:
        return {"error": f"No function at {address}"}

    callees = []
    seen = set()
    for head in idautils.Heads(fn.start_ea, fn.end_ea):
        for xref in idautils.XrefsFrom(head):
            if len(callees) >= max_results:
                break
            if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                target_fn = idaapi.get_func(xref.to)
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
    import idaapi
    import ida_funcs
    import ida_xref
    from collections import deque

    ea = _resolve_address(address)
    fn = idaapi.get_func(ea)
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

        cur_fn = idaapi.get_func(cur_ea)
        if not cur_fn:
            continue

        for head in idautils.Heads(cur_fn.start_ea, cur_fn.end_ea):
            for xref in idautils.XrefsFrom(head):
                if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                    target_fn = idaapi.get_func(xref.to)
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
    import idaapi
    import ida_funcs
    import ida_gdl

    ea = _resolve_address(address)
    fn = idaapi.get_func(ea)
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

    cfg = ida_gdl.FlowChart(fn)
    blocks = []
    for block in cfg:
        succs = [hex(s.start_ea) for s in block.succs()]
        preds = [hex(p.start_ea) for p in block.preds()]
        blocks.append(
            {
                "start": hex(block.start_ea),
                "end": hex(block.end_ea),
                "size": block.end_ea - block.start_ea,
                "type": _BLOCK_TYPES.get(block.type, f"unknown_{block.type}"),
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

    seg = idaapi.getseg(ea)
    if seg:
        result["segment"] = {
            "name": idaapi.get_segm_name(seg),
            "start": hex(seg.start_ea),
            "end": hex(seg.end_ea),
            "permissions": _seg_perms(seg),
        }

    fn = idaapi.get_func(ea)
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
        name = tif.get_type_name()
        if filter_str and filter_str.lower() not in name.lower():
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
    """Get the stack frame layout of a function, showing local variables and arguments."""
    import idaapi
    import ida_funcs
    import ida_typeinf
    import ida_frame

    ea = _resolve_address(address)
    fn = idaapi.get_func(ea)
    if not fn:
        return {"error": f"No function at {address}"}

    frame_tif = ida_typeinf.tinfo_t()
    if not ida_frame.get_func_frame(frame_tif, fn):
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
        members.append(
            {
                "name": member.name,
                "offset": member.offset // 8,
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


@tool
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
    import idaapi

    all_globals = []
    for ea, name in idautils.Names():
        if idaapi.get_func(ea):
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


@tool
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


@tool
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


@tool
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
        existing = idaapi.get_func(ea)
        if existing:
            return {
                "success": False,
                "error": f"Function already exists at {hex(existing.start_ea)}",
            }
        return {"success": False, "error": f"Failed to define function at {address}"}

    fn = idaapi.get_func(ea)
    return {
        "success": True,
        "address": hex(fn.start_ea),
        "end_address": hex(fn.end_ea),
        "name": ida_funcs.get_func_name(fn.start_ea),
        "size": fn.end_ea - fn.start_ea,
    }


@tool
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


@tool
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


@tool
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


@tool
def int_convert(
    value: Annotated[str, "Number to convert (hex: 0x1A, decimal: 26, binary: 0b11010)"],
    size: Annotated[int, "Size in bytes for display (1, 2, 4, 8). Default 4."] = 4,
) -> dict:
    """Convert a number between decimal, hexadecimal, binary, and ASCII representations."""
    s = value.strip()

    try:
        if s.startswith(("0x", "0X")):
            n = int(s, 16)
        elif s.startswith(("0b", "0B")):
            n = int(s, 2)
        elif s.startswith(("0o", "0O")):
            n = int(s, 8)
        else:
            n = int(s)
    except ValueError:
        return {"error": f"Cannot parse number: {value}"}

    mask = (1 << (size * 8)) - 1
    unsigned = n & mask
    signed = unsigned if unsigned < (1 << (size * 8 - 1)) else unsigned - (1 << (size * 8))

    # Build byte representation
    byte_vals = [(unsigned >> (i * 8)) & 0xFF for i in range(size)]
    ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in byte_vals)

    return {
        "decimal": n,
        "unsigned": unsigned,
        "signed": signed,
        "hex": hex(unsigned),
        "binary": bin(unsigned),
        "octal": oct(unsigned),
        "size": size,
        "bytes_le": " ".join(f"{b:02x}" for b in byte_vals),
        "bytes_be": " ".join(f"{b:02x}" for b in reversed(byte_vals)),
        "ascii": ascii_repr,
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
    address: Annotated[str, "Function address to search within (empty = all functions)"] = "",
    max_results: Annotated[int, "Maximum results (default 50)"] = 50,
) -> dict:
    """Find instructions matching a mnemonic/operand pattern. Searches within a function or across all functions."""
    import idautils
    import idaapi
    import idc
    import ida_funcs

    compiled = re.compile(pattern, re.IGNORECASE)
    results = []

    if address:
        ea = _resolve_address(address)
        fn = idaapi.get_func(ea)
        if not fn:
            return {"error": f"No function at {address}"}
        ranges = [(fn.start_ea, fn.end_ea)]
    else:
        ranges = []
        for func_ea in idautils.Functions():
            fn = idaapi.get_func(func_ea)
            if fn:
                ranges.append((fn.start_ea, fn.end_ea))

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
                fn = idaapi.get_func(head)
                results.append(
                    {
                        "address": hex(head),
                        "disasm": disasm,
                        "mnemonic": mnem,
                        "function": ida_funcs.get_func_name(fn.start_ea) if fn else None,
                    }
                )

    return {"pattern": pattern, "matches": results, "count": len(results)}


@tool
def find_immediate(
    value: Annotated[str, "Immediate value to search for (hex or decimal)"],
    max_results: Annotated[int, "Maximum results (default 50)"] = 50,
) -> dict:
    """Search for an immediate value in all instructions. Useful for finding constants, magic numbers, or error codes."""
    import idaapi
    import idc
    import ida_search
    import ida_funcs
    import idautils

    s = value.strip()
    if s.startswith(("0x", "0X")):
        imm_val = int(s, 16)
    else:
        imm_val = int(s)

    results = []

    # Use IDA's find_imm API
    ea = 0
    while len(results) < max_results:
        ea, _ = ida_search.find_imm(ea, ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT, imm_val)
        if ea == idaapi.BADADDR:
            break
        fn = idaapi.get_func(ea)
        results.append(
            {
                "address": hex(ea),
                "disasm": idc.GetDisasm(ea),
                "function": ida_funcs.get_func_name(fn.start_ea) if fn else None,
            }
        )
        ea = idc.next_head(ea)
        if ea == idaapi.BADADDR:
            break

    return {"value": value, "matches": results, "count": len(results)}


# ============================================================================
# Stack Variable Management
# ============================================================================


@tool
def declare_stack_var(
    address: Annotated[str, "Function address (hex) or name"],
    var_offset: Annotated[int, "Stack frame offset for the variable"],
    var_name: Annotated[str, "Name for the stack variable"],
    var_type: Annotated[str, "C type declaration (e.g. 'int', 'char *')"] = "",
) -> dict:
    """Create or rename a stack variable in a function's stack frame."""
    import idaapi
    import ida_frame
    import ida_typeinf

    ea = _resolve_address(address)
    fn = idaapi.get_func(ea)
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

    # IDA 9.3 API: define_stkvar(pfn, name, off, tif)
    ok = ida_frame.define_stkvar(fn, var_name, var_offset, tif)
    if not ok:
        return {"success": False, "error": f"Failed to define stack variable at offset {var_offset}"}

    return {"success": True, "address": hex(ea), "offset": var_offset, "name": var_name}


@tool
def delete_stack_var(
    address: Annotated[str, "Function address (hex) or name"],
    var_offset: Annotated[int, "Stack frame offset of the variable to delete"],
    size: Annotated[int, "Size of the variable in bytes (default 1)"] = 1,
) -> dict:
    """Delete a stack variable from a function's stack frame."""
    import idaapi
    import ida_frame

    ea = _resolve_address(address)
    fn = idaapi.get_func(ea)
    if not fn:
        return {"error": f"No function at {address}"}

    # IDA 9.3 API: delete_frame_members(pfn, start_offset, end_offset)
    ok = ida_frame.delete_frame_members(fn, var_offset, var_offset + size)
    return {"success": bool(ok), "address": hex(ea), "offset": var_offset}


# ============================================================================
# Enhanced Type System
# ============================================================================


@tool
def enum_upsert(
    name: Annotated[str, "Enum type name"],
    members: Annotated[
        list[dict],
        "List of {name, value} dicts, e.g. [{'name':'FLAG_A','value':1},{'name':'FLAG_B','value':2}]",
    ],
    bitfield: Annotated[bool, "Treat as a bitfield enum"] = False,
) -> dict:
    """Create or extend an enum type. Idempotent - existing members are preserved, new ones are added."""
    import ida_typeinf

    til = ida_typeinf.get_idati()

    # Check if enum already exists
    tif = ida_typeinf.tinfo_t()
    existing = tif.get_named_type(til, name)

    if existing and tif.is_enum():
        # Extend existing enum
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
                em = ida_typeinf.edm_t()
                em.name = m_name
                em.value = m_value
                edt.push_back(em)
                added.append(m_name)

        total_after = total_before + len(added)
        if added:
            tif2 = ida_typeinf.tinfo_t()
            tif2.create_enum(edt)
            ordinal = tif.get_ordinal()
            tif2.set_numbered_type(til, ordinal, ida_typeinf.NTF_REPLACE, name)

        return {
            "success": True,
            "name": name,
            "action": "extended",
            "added_members": added,
            "total_members": total_after,
        }
    else:
        # Create new enum
        edt = ida_typeinf.enum_type_data_t()
        if bitfield:
            edt.bte = ida_typeinf.BTE_HEX | ida_typeinf.BTE_BITFIELD

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
        tif_new.create_enum(edt)
        ordinal = ida_typeinf.alloc_type_ordinal(til)
        tif_new.set_numbered_type(til, ordinal, ida_typeinf.NTF_REPLACE, name)

        return {
            "success": True,
            "name": name,
            "action": "created",
            "ordinal": ordinal,
            "member_count": added_count,
        }


@tool
def type_query(
    filter_str: Annotated[str, "Filter type names by substring"] = "",
    kind: Annotated[
        str,
        "Filter by kind: 'struct', 'union', 'enum', 'typedef', 'func', or '' for all",
    ] = "",
    include_members: Annotated[
        bool, "Include member details for structs/unions/enums"
    ] = False,
    offset: Annotated[int, "Starting index for pagination"] = 0,
    count: Annotated[int, "Maximum results (default 50)"] = 50,
) -> dict:
    """Advanced query over the local type library with optional member inspection. More powerful than list_local_types."""
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
        elif tif.is_func():
            t_kind = "func"
        else:
            t_kind = "typedef"

        if kind and t_kind != kind:
            continue
        if filter_str and filter_str.lower() not in name.lower():
            continue

        entry = {
            "ordinal": ordinal,
            "name": name,
            "kind": t_kind,
            "size": tif.get_size(),
            "declaration": str(tif),
        }

        if include_members and t_kind in ("struct", "union"):
            udt = ida_typeinf.udt_type_data_t()
            if tif.get_udt_details(udt):
                entry["members"] = [
                    {
                        "name": m.name,
                        "offset": m.offset // 8,
                        "size": m.size // 8,
                        "type": str(m.type),
                    }
                    for m in udt
                ]
        elif include_members and t_kind == "enum":
            edt = ida_typeinf.enum_type_data_t()
            if tif.get_enum_details(edt):
                entry["members"] = [
                    {"name": m.name, "value": m.value} for m in edt
                ]

        all_types.append(entry)

    total = len(all_types)
    page = all_types[offset: offset + count]
    return {
        "types": page,
        "total": total,
        "offset": offset,
        "has_more": offset + count < total,
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
                fn = idaapi.get_func(xref.frm)
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
# Struct Reading
# ============================================================================


@tool
def read_struct_at(
    address: Annotated[str, "Memory address (hex) to overlay struct on"],
    struct_name: Annotated[str, "Name of the struct to overlay"],
) -> dict:
    """Read struct field values from memory at a given address. Overlays the struct definition on raw memory and reads each field."""
    import idc
    import ida_typeinf

    ea = _resolve_address(address)

    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(ida_typeinf.get_idati(), struct_name):
        return {"error": f"Struct not found: {struct_name}"}

    if not (tif.is_struct() or tif.is_union()):
        return {"error": f"{struct_name} is not a struct/union"}

    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return {"error": f"Cannot get details for {struct_name}"}

    struct_size = tif.get_size()
    members = []
    for member in udt:
        m_offset = member.offset // 8
        m_size = member.size // 8
        if m_size <= 0:
            continue
        raw = idc.get_bytes(ea + m_offset, m_size)
        members.append(
            {
                "name": member.name,
                "offset": m_offset,
                "size": m_size,
                "type": str(member.type),
                "raw_hex": raw.hex() if raw else "",
                "value": int.from_bytes(raw, "little") if raw and m_size <= 8 else None,
            }
        )

    return {
        "address": hex(ea),
        "struct": struct_name,
        "struct_size": struct_size,
        "members": members,
    }


# ============================================================================
# Advanced Analysis
# ============================================================================


@tool
def xrefs_to_string(
    query: Annotated[str, "Substring to search for in strings"],
    max_strings: Annotated[int, "Maximum strings to return (default 20)"] = 20,
    max_xrefs_per_string: Annotated[int, "Maximum xrefs per string (default 10)"] = 10,
) -> dict:
    """Find strings matching a query and return cross-references to each. Combines string search + xref lookup in one call."""
    import idautils
    import idaapi
    import ida_funcs

    pattern = query.lower()
    results = []

    for s in idautils.Strings():
        if len(results) >= max_strings:
            break
        if s is None:
            continue
        text = str(s)
        if pattern not in text.lower():
            continue

        xrefs = []
        for xref in idautils.XrefsTo(s.ea):
            if len(xrefs) >= max_xrefs_per_string:
                break
            fn = idaapi.get_func(xref.frm)
            xrefs.append(
                {
                    "from_address": hex(xref.frm),
                    "type": _xref_type_name(xref.type),
                    "function": ida_funcs.get_func_name(fn.start_ea) if fn else None,
                }
            )

        results.append(
            {
                "address": hex(s.ea),
                "string": text,
                "xref_count": len(xrefs),
                "xrefs": xrefs,
            }
        )

    return {"query": query, "strings": results, "count": len(results)}


@tool
def find_paths(
    start_address: Annotated[str, "Start address (hex) or name - must be within a function"],
    end_address: Annotated[str, "End address (hex) or name - must be in the same function"],
    max_paths: Annotated[int, "Maximum number of paths to find (default 5)"] = 5,
    max_depth: Annotated[int, "Maximum path length in basic blocks (default 20)"] = 20,
) -> dict:
    """Find control-flow paths between two addresses within the same function using DFS on the CFG."""
    import idaapi
    import ida_funcs
    import ida_gdl

    start_ea = _resolve_address(start_address)
    end_ea = _resolve_address(end_address)

    fn = idaapi.get_func(start_ea)
    if not fn:
        return {"error": f"No function at {start_address}"}

    fn2 = idaapi.get_func(end_ea)
    if not fn2 or fn.start_ea != fn2.start_ea:
        return {"error": "Both addresses must be in the same function"}

    cfg = ida_gdl.FlowChart(fn)

    # Map addresses to block indices
    start_block = None
    end_block = None
    block_map = {}
    for block in cfg:
        block_map[block.id] = block
        if block.start_ea <= start_ea < block.end_ea:
            start_block = block
        if block.start_ea <= end_ea < block.end_ea:
            end_block = block

    if start_block is None:
        return {"error": f"Address {start_address} not in any basic block"}
    if end_block is None:
        return {"error": f"Address {end_address} not in any basic block"}

    # DFS to find paths
    paths = []

    def dfs(current, target_id, path, visited):
        if len(paths) >= max_paths:
            return
        if len(path) > max_depth:
            return
        if current.id == target_id:
            paths.append(
                [{"start": hex(b.start_ea), "end": hex(b.end_ea)} for b in path]
            )
            return
        for succ in current.succs():
            if succ.id not in visited:
                visited.add(succ.id)
                path.append(succ)
                dfs(succ, end_block.id, path, visited)
                path.pop()
                visited.discard(succ.id)

    dfs(start_block, end_block.id, [start_block], {start_block.id})

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
    import idaapi
    import ida_funcs
    import ida_nalt
    import ida_typeinf
    import ida_hexrays

    ea = _resolve_address(address)
    fn = idaapi.get_func(ea)
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
                cfunc = ida_hexrays.decompile(fn.start_ea)
                if cfunc:
                    result["code"] = str(cfunc)
            except Exception as e:
                result["error"] = f"Decompilation failed: {e}"

    return result


# ============================================================================
# Script Execution
# ============================================================================


@tool
def run_script(
    script: Annotated[str, "IDAPython script code to execute"],
) -> dict:
    """Execute arbitrary IDAPython code. The script can use all IDA APIs (import idaapi, idc, etc). Stdout output is captured and returned."""
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    captured_out = io.StringIO()
    captured_err = io.StringIO()
    sys.stdout = captured_out
    sys.stderr = captured_err

    error = None
    try:
        exec_globals = {"__builtins__": __builtins__}
        exec(script, exec_globals)
    except Exception as e:
        error = f"{type(e).__name__}: {e}"
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr

    return {
        "output": captured_out.getvalue(),
        "errors": captured_err.getvalue(),
        "error": error,
    }


# ============================================================================
# Composite Analysis
# ============================================================================


@tool
def survey_binary() -> dict:
    """One-call binary triage: metadata, segments, entry points, top functions/strings by xref count, and import categories. Ideal as a first call after opening a binary."""
    import idaapi
    import ida_nalt
    import idc
    import idautils
    import ida_funcs
    import ida_xref

    # Metadata
    info = {
        "filename": ida_nalt.get_root_filename(),
        "imagebase": hex(idaapi.get_imagebase()),
        "processor": idaapi.get_idp_name(),
        "bits": 64 if (hasattr(idaapi, "inf_is_64bit") and idaapi.inf_is_64bit()) else 32,
    }
    md5 = ida_nalt.retrieve_input_file_md5()
    if md5:
        info["md5"] = md5.hex() if isinstance(md5, bytes) else str(md5)

    # Segments
    segments = []
    for ea in idautils.Segments():
        seg = idaapi.getseg(ea)
        if seg:
            segments.append({
                "name": idaapi.get_segm_name(seg),
                "start": hex(seg.start_ea),
                "size": seg.end_ea - seg.start_ea,
                "permissions": _seg_perms(seg),
            })

    # Entry points
    import ida_entry
    entries = []
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal) or ""
        entries.append({"address": hex(ea), "name": name})

    # Functions sorted by xref count (top 15)
    func_xrefs = []
    for func_ea in idautils.Functions():
        xcount = sum(1 for _ in idautils.XrefsTo(func_ea))
        name = ida_funcs.get_func_name(func_ea)
        func_xrefs.append((xcount, func_ea, name))
    func_xrefs.sort(reverse=True)
    top_functions = [
        {"address": hex(ea), "name": name, "xref_count": xc}
        for xc, ea, name in func_xrefs[:15]
    ]

    # Strings sorted by xref count (top 15)
    str_xrefs = []
    for s in idautils.Strings():
        if s is None:
            continue
        xcount = sum(1 for _ in idautils.XrefsTo(s.ea))
        str_xrefs.append((xcount, s.ea, str(s)))
    str_xrefs.sort(reverse=True)
    top_strings = [
        {"address": hex(ea), "string": text[:80], "xref_count": xc}
        for xc, ea, text in str_xrefs[:15]
    ]

    # Import categories
    categories = {
        "crypto": [], "network": [], "file_io": [], "process": [],
        "registry": [], "memory": [], "thread": [], "debug": [],
    }
    CATEGORY_KEYWORDS = {
        "crypto": ["crypt", "aes", "hash", "sha", "md5", "rsa", "bcrypt", "cert"],
        "network": ["socket", "connect", "send", "recv", "http", "url", "internet", "wsa", "dns"],
        "file_io": ["createfile", "readfile", "writefile", "deletefile", "findfile", "copyfile", "movefile"],
        "process": ["createprocess", "openprocess", "terminateprocess", "shellexecute", "winexec"],
        "registry": ["regopen", "regquery", "regset", "regcreate", "regdelete", "regclose"],
        "memory": ["virtualalloc", "virtualprotect", "heapalloc", "mapview", "writeprocessmemory"],
        "thread": ["createthread", "createremotethread", "resumethread", "suspendthread"],
        "debug": ["isdebuggerpresent", "checkremotedebugger", "outputdebugstring", "ntqueryinformation"],
    }

    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        def cb(ea, name, ordinal):
            if not name:
                return True
            low = name.lower()
            for cat, keywords in CATEGORY_KEYWORDS.items():
                if any(kw in low for kw in keywords):
                    categories[cat].append(name)
                    break
            return True
        ida_nalt.enum_import_names(i, cb)

    # Only include non-empty categories
    import_categories = {k: v for k, v in categories.items() if v}

    # Statistics
    func_count = sum(1 for _ in idautils.Functions())
    string_count = sum(1 for _ in idautils.Strings())

    return {
        "info": info,
        "statistics": {
            "function_count": func_count,
            "string_count": string_count,
            "segment_count": len(segments),
            "import_module_count": nimps,
        },
        "segments": segments,
        "entrypoints": entries,
        "top_functions_by_xrefs": top_functions,
        "top_strings_by_xrefs": top_strings,
        "import_categories": import_categories,
    }


@tool
def analyze_function(
    address: Annotated[str, "Function address (hex) or name"],
    include_asm: Annotated[bool, "Include disassembly (default false)"] = False,
) -> dict:
    """Comprehensive single-function analysis: pseudocode, strings, constants, callers, callees, basic block count, and cyclomatic complexity."""
    import idaapi
    import ida_funcs
    import ida_hexrays
    import ida_gdl
    import ida_xref
    import idc
    import idautils

    ea = _resolve_address(address)
    fn = idaapi.get_func(ea)
    if not fn:
        return {"error": f"No function at {address}"}

    name = ida_funcs.get_func_name(fn.start_ea)
    result = {
        "address": hex(fn.start_ea),
        "name": name,
        "size": fn.end_ea - fn.start_ea,
    }

    # Pseudocode
    if ida_hexrays.init_hexrays_plugin():
        try:
            cfunc = ida_hexrays.decompile(fn.start_ea)
            if cfunc:
                code = str(cfunc)
                # Cap at 100 lines
                lines = code.split("\n")
                if len(lines) > 100:
                    result["pseudocode"] = "\n".join(lines[:100]) + "\n// ... truncated ..."
                    result["pseudocode_lines"] = len(lines)
                else:
                    result["pseudocode"] = code
        except Exception:
            pass

    # Disassembly (optional)
    if include_asm:
        asm_lines = []
        for head in idautils.Heads(fn.start_ea, fn.end_ea):
            asm_lines.append({"address": hex(head), "disasm": idc.GetDisasm(head)})
            if len(asm_lines) >= 200:
                break
        result["assembly"] = asm_lines

    # Strings referenced
    strings = []
    for head in idautils.Heads(fn.start_ea, fn.end_ea):
        for xref in idautils.XrefsFrom(head):
            s = idc.get_strlit_contents(xref.to, -1, idc.STRTYPE_C)
            if s:
                text = s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s)
                if text and len(text) > 1:
                    strings.append({"address": hex(xref.to), "string": text[:120]})
    # Deduplicate
    seen = set()
    unique_strings = []
    for s in strings:
        if s["address"] not in seen:
            seen.add(s["address"])
            unique_strings.append(s)
    result["strings"] = unique_strings[:20]

    # Constants (non-trivial immediate values)
    constants = set()
    for head in idautils.Heads(fn.start_ea, fn.end_ea):
        if not idaapi.is_code(idaapi.get_flags(head)):
            continue
        for i in range(2):
            val = idc.get_operand_value(head, i)
            if val is not None and val not in (0, 1, -1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
                if 0xFF < val < 0xFFFFFFFF:
                    constants.add(val)
    result["constants"] = [hex(c) for c in sorted(constants)][:20]

    # Callers
    callers = []
    seen_callers = set()
    for xref in idautils.XrefsTo(fn.start_ea):
        if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
            caller_fn = idaapi.get_func(xref.frm)
            if caller_fn and caller_fn.start_ea not in seen_callers:
                seen_callers.add(caller_fn.start_ea)
                callers.append({
                    "address": hex(caller_fn.start_ea),
                    "name": ida_funcs.get_func_name(caller_fn.start_ea),
                })
    result["callers"] = callers[:20]

    # Callees
    callees = []
    seen_callees = set()
    for head in idautils.Heads(fn.start_ea, fn.end_ea):
        for xref in idautils.XrefsFrom(head):
            if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                target_fn = idaapi.get_func(xref.to)
                if target_fn and target_fn.start_ea not in seen_callees:
                    seen_callees.add(target_fn.start_ea)
                    callees.append({
                        "address": hex(target_fn.start_ea),
                        "name": ida_funcs.get_func_name(target_fn.start_ea),
                    })
    result["callees"] = callees[:20]

    # CFG metrics
    cfg = ida_gdl.FlowChart(fn)
    block_count = 0
    edge_count = 0
    for block in cfg:
        block_count += 1
        edge_count += sum(1 for _ in block.succs())
    result["block_count"] = block_count
    result["edge_count"] = edge_count
    result["cyclomatic_complexity"] = edge_count - block_count + 2

    return result


# ============================================================================
# Enhanced Analysis
# ============================================================================


@tool
def func_profile(
    addresses: Annotated[
        list[str],
        "List of function addresses (hex) or names to profile",
    ],
) -> dict:
    """Profile one or more functions with summary metrics: caller/callee count, string references, block count, size, and cyclomatic complexity."""
    import idaapi
    import ida_funcs
    import ida_gdl
    import ida_xref
    import idc
    import idautils

    results = []
    for addr in addresses:
        try:
            ea = _resolve_address(addr)
            fn = idaapi.get_func(ea)
            if not fn:
                results.append({"address": addr, "error": f"No function at {addr}"})
                continue

            name = ida_funcs.get_func_name(fn.start_ea)
            size = fn.end_ea - fn.start_ea

            # Count callers
            caller_count = 0
            seen_callers = set()
            for xref in idautils.XrefsTo(fn.start_ea):
                if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                    caller_fn = idaapi.get_func(xref.frm)
                    if caller_fn and caller_fn.start_ea not in seen_callers:
                        seen_callers.add(caller_fn.start_ea)
                        caller_count += 1

            # Count callees
            callee_count = 0
            seen_callees = set()
            for head in idautils.Heads(fn.start_ea, fn.end_ea):
                for xref in idautils.XrefsFrom(head):
                    if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                        target_fn = idaapi.get_func(xref.to)
                        if target_fn and target_fn.start_ea not in seen_callees:
                            seen_callees.add(target_fn.start_ea)
                            callee_count += 1

            # Count strings
            string_count = 0
            for head in idautils.Heads(fn.start_ea, fn.end_ea):
                for xref in idautils.XrefsFrom(head):
                    s = idc.get_strlit_contents(xref.to, -1, idc.STRTYPE_C)
                    if s:
                        string_count += 1

            # CFG metrics
            cfg = ida_gdl.FlowChart(fn)
            block_count = 0
            edge_count = 0
            for block in cfg:
                block_count += 1
                edge_count += sum(1 for _ in block.succs())

            results.append({
                "address": hex(fn.start_ea),
                "name": name,
                "size": size,
                "caller_count": caller_count,
                "callee_count": callee_count,
                "string_count": string_count,
                "block_count": block_count,
                "edge_count": edge_count,
                "cyclomatic_complexity": edge_count - block_count + 2,
            })
        except Exception as e:
            results.append({"address": addr, "error": str(e)})

    return {"results": results, "count": len(results)}


@tool
def analyze_batch(
    addresses: Annotated[list[str], "List of function addresses (hex) or names"],
    include_decompile: Annotated[bool, "Include Hex-Rays pseudocode"] = True,
    include_disasm: Annotated[bool, "Include assembly disassembly"] = False,
    include_xrefs: Annotated[bool, "Include callers and callees"] = True,
    include_strings: Annotated[bool, "Include referenced strings"] = True,
    include_cfg: Annotated[bool, "Include basic block / CFG info"] = False,
) -> dict:
    """Comprehensive per-function analysis with selectable sections. More flexible than analyze_function - choose exactly what data you need."""
    import idaapi
    import ida_funcs
    import ida_hexrays
    import ida_gdl
    import ida_xref
    import idc
    import idautils

    hexrays_ok = False
    if include_decompile:
        try:
            hexrays_ok = bool(ida_hexrays.init_hexrays_plugin())
        except Exception:
            pass

    results = []
    for addr in addresses:
        try:
            ea = _resolve_address(addr)
            fn = idaapi.get_func(ea)
            if not fn:
                results.append({"address": addr, "error": f"No function at {addr}"})
                continue

            entry = {
                "address": hex(fn.start_ea),
                "name": ida_funcs.get_func_name(fn.start_ea),
                "size": fn.end_ea - fn.start_ea,
            }

            if include_decompile and hexrays_ok:
                try:
                    cfunc = ida_hexrays.decompile(fn.start_ea)
                    entry["pseudocode"] = str(cfunc) if cfunc else None
                except Exception as e:
                    entry["pseudocode_error"] = str(e)

            if include_disasm:
                lines = []
                for head in idautils.Heads(fn.start_ea, fn.end_ea):
                    lines.append({"address": hex(head), "disasm": idc.GetDisasm(head)})
                    if len(lines) >= 300:
                        break
                entry["disassembly"] = lines

            if include_xrefs:
                callers = []
                seen = set()
                for xref in idautils.XrefsTo(fn.start_ea):
                    if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                        cfn = idaapi.get_func(xref.frm)
                        if cfn and cfn.start_ea not in seen:
                            seen.add(cfn.start_ea)
                            callers.append({
                                "address": hex(cfn.start_ea),
                                "name": ida_funcs.get_func_name(cfn.start_ea),
                            })
                entry["callers"] = callers[:30]

                callees = []
                seen = set()
                for head in idautils.Heads(fn.start_ea, fn.end_ea):
                    for xref in idautils.XrefsFrom(head):
                        if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                            tfn = idaapi.get_func(xref.to)
                            if tfn and tfn.start_ea not in seen:
                                seen.add(tfn.start_ea)
                                callees.append({
                                    "address": hex(tfn.start_ea),
                                    "name": ida_funcs.get_func_name(tfn.start_ea),
                                })
                entry["callees"] = callees[:30]

            if include_strings:
                strings = []
                seen_addrs = set()
                for head in idautils.Heads(fn.start_ea, fn.end_ea):
                    for xref in idautils.XrefsFrom(head):
                        if xref.to in seen_addrs:
                            continue
                        s = idc.get_strlit_contents(xref.to, -1, idc.STRTYPE_C)
                        if s:
                            seen_addrs.add(xref.to)
                            text = s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s)
                            strings.append({"address": hex(xref.to), "string": text[:120]})
                entry["strings"] = strings[:30]

            if include_cfg:
                cfg = ida_gdl.FlowChart(fn)
                blocks = []
                edge_count = 0
                for block in cfg:
                    edge_count += sum(1 for _ in block.succs())
                    blocks.append({
                        "start": hex(block.start_ea),
                        "end": hex(block.end_ea),
                        "successors": [hex(s.start_ea) for s in block.succs()],
                    })
                entry["blocks"] = blocks
                entry["block_count"] = len(blocks)
                entry["cyclomatic_complexity"] = edge_count - len(blocks) + 2

            results.append(entry)
        except Exception as e:
            results.append({"address": addr, "error": str(e)})

    return {"results": results, "count": len(results)}


@tool
def analyze_component(
    addresses: Annotated[
        list[str],
        "List of related function addresses (hex) or names to analyze as a group",
    ],
) -> dict:
    """Analyze related functions as a group: per-function summaries, internal call graph, and shared data references. Useful for understanding a subsystem or module."""
    import idaapi
    import ida_funcs
    import ida_xref
    import idc
    import idautils

    eas = []
    ea_set = set()
    for addr in addresses:
        try:
            ea = _resolve_address(addr)
            fn = idaapi.get_func(ea)
            if fn:
                eas.append(fn.start_ea)
                ea_set.add(fn.start_ea)
        except Exception:
            pass

    if not eas:
        return {"error": "No valid functions found"}

    # Per-function summaries
    summaries = []
    all_strings = {}  # address -> text
    for func_ea in eas:
        fn = idaapi.get_func(func_ea)
        name = ida_funcs.get_func_name(func_ea)

        # Strings referenced
        for head in idautils.Heads(fn.start_ea, fn.end_ea):
            for xref in idautils.XrefsFrom(head):
                s = idc.get_strlit_contents(xref.to, -1, idc.STRTYPE_C)
                if s:
                    text = s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s)
                    all_strings[xref.to] = text

        summaries.append({
            "address": hex(func_ea),
            "name": name,
            "size": fn.end_ea - fn.start_ea,
        })

    # Internal call graph (only edges between component functions)
    internal_edges = []
    external_callees = {}  # address -> name
    for func_ea in eas:
        fn = idaapi.get_func(func_ea)
        for head in idautils.Heads(fn.start_ea, fn.end_ea):
            for xref in idautils.XrefsFrom(head):
                if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                    tfn = idaapi.get_func(xref.to)
                    if tfn:
                        if tfn.start_ea in ea_set:
                            internal_edges.append({
                                "from": hex(func_ea),
                                "to": hex(tfn.start_ea),
                            })
                        else:
                            external_callees[tfn.start_ea] = ida_funcs.get_func_name(tfn.start_ea)

    # Deduplicate edges
    seen_edges = set()
    unique_edges = []
    for e in internal_edges:
        key = (e["from"], e["to"])
        if key not in seen_edges:
            seen_edges.add(key)
            unique_edges.append(e)

    # Shared strings (referenced by more than one function)
    string_refs = {}
    for func_ea in eas:
        fn = idaapi.get_func(func_ea)
        for head in idautils.Heads(fn.start_ea, fn.end_ea):
            for xref in idautils.XrefsFrom(head):
                if xref.to in all_strings:
                    string_refs.setdefault(xref.to, set()).add(func_ea)

    shared_strings = [
        {"address": hex(addr), "string": all_strings[addr][:100],
         "referenced_by": [hex(ea) for ea in funcs]}
        for addr, funcs in string_refs.items()
        if len(funcs) > 1
    ]

    return {
        "functions": summaries,
        "function_count": len(summaries),
        "internal_call_graph": unique_edges,
        "external_callees": [
            {"address": hex(ea), "name": name}
            for ea, name in list(external_callees.items())[:30]
        ],
        "shared_strings": shared_strings[:20],
    }


@tool
def analyze_strings(
    filter_str: Annotated[str, "Substring filter for string content"] = "",
    offset: Annotated[int, "Starting index for pagination"] = 0,
    count: Annotated[int, "Maximum results (default 50)"] = 50,
    max_xrefs: Annotated[int, "Maximum xrefs per string (default 10)"] = 10,
) -> dict:
    """List strings with their cross-references combined. More efficient than calling list_strings + get_xrefs_to separately."""
    import idautils
    import idaapi
    import ida_funcs

    all_results = []
    for s in idautils.Strings():
        if s is None:
            continue
        text = str(s)
        if filter_str and filter_str.lower() not in text.lower():
            continue

        xrefs = []
        for xref in idautils.XrefsTo(s.ea):
            if len(xrefs) >= max_xrefs:
                break
            fn = idaapi.get_func(xref.frm)
            xrefs.append({
                "from_address": hex(xref.frm),
                "type": _xref_type_name(xref.type),
                "function": ida_funcs.get_func_name(fn.start_ea) if fn else None,
            })

        all_results.append({
            "address": hex(s.ea),
            "text": text,
            "length": s.length,
            "xref_count": len(xrefs),
            "xrefs": xrefs,
        })

    total = len(all_results)
    page = all_results[offset: offset + count]
    return {
        "strings": page,
        "total": total,
        "offset": offset,
        "has_more": offset + count < total,
    }


@tool
def diff_before_after(
    address: Annotated[str, "Function address (hex) or name"],
    action: Annotated[
        str,
        "Action to perform: 'rename', 'set_type', or 'set_comment'",
    ],
    new_name: Annotated[str, "New name (for action='rename')"] = "",
    new_type: Annotated[str, "New type string (for action='set_type')"] = "",
    comment: Annotated[str, "Comment text (for action='set_comment')"] = "",
) -> dict:
    """Apply a modification and return before/after decompilation so you can immediately see the effect. Supported actions: rename, set_type, set_comment."""
    import idaapi
    import ida_hexrays
    import ida_funcs
    import idc

    ea = _resolve_address(address)
    fn = idaapi.get_func(ea)
    if not fn:
        return {"error": f"No function at {address}"}

    if not ida_hexrays.init_hexrays_plugin():
        return {"error": "Hex-Rays decompiler not available"}

    # Capture BEFORE
    try:
        cfunc = ida_hexrays.decompile(fn.start_ea)
        before = str(cfunc) if cfunc else "<decompilation failed>"
    except Exception as e:
        before = f"<decompilation failed: {e}>"

    # Apply action
    action_result = {}
    if action == "rename":
        if not new_name:
            return {"error": "new_name is required for rename action"}
        ok = idaapi.set_name(ea, new_name, idaapi.SN_NOWARN | idaapi.SN_NOCHECK)
        action_result = {"success": bool(ok), "new_name": new_name}
    elif action == "set_type":
        if not new_type:
            return {"error": "new_type is required for set_type action"}
        ok = idc.SetType(ea, new_type)
        action_result = {"success": bool(ok), "new_type": new_type}
    elif action == "set_comment":
        if not comment:
            return {"error": "comment is required for set_comment action"}
        ok = idc.set_cmt(ea, comment, 0)
        action_result = {"success": bool(ok), "comment": comment}
    else:
        return {"error": f"Unknown action: {action}. Use 'rename', 'set_type', or 'set_comment'"}

    # Invalidate cache and capture AFTER
    _invalidate_decompiler_cache(ea)
    try:
        cfunc = ida_hexrays.decompile(fn.start_ea)
        after = str(cfunc) if cfunc else "<decompilation failed>"
    except Exception as e:
        after = f"<decompilation failed: {e}>"

    return {
        "address": hex(fn.start_ea),
        "function": ida_funcs.get_func_name(fn.start_ea),
        "action": action,
        "action_result": action_result,
        "before": before,
        "after": after,
    }


# ============================================================================
# Type Inference
# ============================================================================


@tool
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
            if idaapi.get_func(ea):
                cfunc = ida_hexrays.decompile(ea)
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
    fn = idaapi.get_func(ea)
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
                t_fn = idaapi.get_func(target)
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


@tool
def xref_matrix(
    addresses: Annotated[list[str], "List of addresses (hex) or names to build matrix for"],
) -> dict:
    """Build a boolean cross-reference matrix showing which addresses reference which. Useful for understanding relationships between functions/data."""
    import idautils

    eas = [_resolve_address(a) for a in addresses]
    ea_set = set(eas)

    matrix = {}
    for ea in eas:
        key = hex(ea)
        row = {}
        for xref in idautils.XrefsFrom(ea):
            if xref.to in ea_set:
                row[hex(xref.to)] = True
        # Also check all instructions within function
        import idaapi
        fn = idaapi.get_func(ea)
        if fn:
            for head in idautils.Heads(fn.start_ea, fn.end_ea):
                for xref in idautils.XrefsFrom(head):
                    if xref.to in ea_set and xref.to != ea:
                        row[hex(xref.to)] = True
        matrix[key] = row

    return {
        "addresses": [hex(ea) for ea in eas],
        "matrix": matrix,
    }


@tool
def pseudocode_at(
    address: Annotated[str, "Address (hex) within a function"],
    context_lines: Annotated[int, "Number of context lines around the target (default 5)"] = 5,
) -> dict:
    """Get decompiled pseudocode lines around a specific address. Uses Hex-Rays eamap to find which pseudocode lines correspond to the given address."""
    import idaapi
    import ida_hexrays
    import ida_funcs
    import ida_lines

    ea = _resolve_address(address)
    fn = idaapi.get_func(ea)
    if not fn:
        return {"error": f"No function at {address}"}

    if not ida_hexrays.init_hexrays_plugin():
        return {"error": "Hex-Rays decompiler not available"}

    try:
        cfunc = ida_hexrays.decompile(fn.start_ea)
        if not cfunc:
            return {"error": f"Decompilation failed"}
    except Exception as e:
        return {"error": f"Decompilation failed: {e}"}

    # Build line text list from pseudocode with tag removal
    pscode = cfunc.get_pseudocode()
    all_lines = [ida_lines.tag_remove(sl.line) for sl in pscode]

    # Map target address to pseudocode line using proportional position
    # This is reliable across IDA versions unlike eamap/find_item_coords
    func_size = fn.end_ea - fn.start_ea
    target_line_nums = set()

    if func_size > 0:
        ratio = (ea - fn.start_ea) / func_size
        # Pseudocode typically: ~20% declarations, ~80% code body
        # Find where code body starts (first line with no '//' comment-only)
        body_start = 0
        for i, line in enumerate(all_lines):
            stripped = line.strip()
            if stripped and not stripped.startswith("//") and stripped not in ("{", "}") and "//" not in stripped.split("=")[0] if "=" not in stripped else True:
                if "(" in stripped or "=" in stripped or "if" in stripped or "for" in stripped or "while" in stripped or "return" in stripped or "goto" in stripped:
                    body_start = i
                    break

        code_range = len(all_lines) - body_start - 1  # -1 for closing brace
        if code_range > 0:
            estimated_line = body_start + int(ratio * code_range)
        else:
            estimated_line = len(all_lines) // 2
        target_line_nums.add(max(0, min(estimated_line, len(all_lines) - 1)))

    center = min(target_line_nums)
    start = max(0, center - context_lines)
    end = min(len(all_lines), center + context_lines + 1)

    lines = []
    for i in range(start, end):
        lines.append({
            "line_number": i,
            "text": all_lines[i],
            "is_target": i in target_line_nums,
        })

    return {
        "function": hex(fn.start_ea),
        "function_name": ida_funcs.get_func_name(fn.start_ea),
        "target_address": hex(ea),
        "lines": lines,
        "total_lines": len(all_lines),
    }


# ============================================================================
# Enhanced Memory Reading
# ============================================================================


@tool
def get_int(
    address: Annotated[str, "Address (hex) to read from"],
    int_type: Annotated[
        str,
        "Integer type: u8, i8, u16, i16, u32, i32, u64, i64 (default u32)",
    ] = "u32",
) -> dict:
    """Read a typed integer value from memory. Supports signed/unsigned 8/16/32/64-bit reads."""
    import idc

    ea = _resolve_address(address)

    TYPE_SIZES = {
        "u8": 1, "i8": 1,
        "u16": 2, "i16": 2,
        "u32": 4, "i32": 4,
        "u64": 8, "i64": 8,
    }
    size = TYPE_SIZES.get(int_type)
    if size is None:
        return {"error": f"Unknown type: {int_type}. Use: u8, i8, u16, i16, u32, i32, u64, i64"}

    data = idc.get_bytes(ea, size)
    if data is None:
        return {"error": f"Cannot read {size} bytes at {address}"}

    unsigned = int.from_bytes(data, "little")
    bits = size * 8
    if int_type.startswith("i"):
        signed = unsigned if unsigned < (1 << (bits - 1)) else unsigned - (1 << bits)
    else:
        signed = None

    return {
        "address": hex(ea),
        "type": int_type,
        "value": signed if signed is not None else unsigned,
        "unsigned": unsigned,
        "hex": hex(unsigned),
        "raw_bytes": data.hex(),
    }


@tool
def get_global_value(
    name_or_address: Annotated[
        str,
        "Global variable name or address (hex)",
    ],
) -> dict:
    """Read a global variable's value by name or address. Reads 8 bytes and shows as multiple integer interpretations."""
    import idc
    import idaapi
    import ida_name

    ea = _resolve_address(name_or_address)
    name = ida_name.get_name(ea) or ""
    data = idc.get_bytes(ea, 8)
    if data is None:
        return {"error": f"Cannot read at {name_or_address}"}

    result = {
        "address": hex(ea),
        "name": name,
        "raw_hex": data.hex(),
    }

    # Show interpretations
    result["as_u8"] = data[0]
    result["as_u16"] = int.from_bytes(data[:2], "little")
    result["as_u32"] = int.from_bytes(data[:4], "little")
    result["as_u32_hex"] = hex(int.from_bytes(data[:4], "little"))
    result["as_u64"] = int.from_bytes(data[:8], "little")
    result["as_u64_hex"] = hex(int.from_bytes(data[:8], "little"))

    # Check if it might be a pointer
    if idaapi.inf_is_64bit() if hasattr(idaapi, "inf_is_64bit") else False:
        ptr = int.from_bytes(data[:8], "little")
    else:
        ptr = int.from_bytes(data[:4], "little")
    ptr_name = ida_name.get_name(ptr) if ptr else ""
    if ptr_name:
        result["as_pointer"] = {"address": hex(ptr), "name": ptr_name}

    return result


# ============================================================================
# Enhanced Cross-Reference Query
# ============================================================================


@tool
def xref_query(
    address: Annotated[str, "Target address (hex) or name"],
    direction: Annotated[
        str, "Direction: 'to' (references TO this address) or 'from' (references FROM)"
    ] = "to",
    xref_type: Annotated[
        str,
        "Filter by type: 'call', 'data', 'jump', or '' for all",
    ] = "",
    offset: Annotated[int, "Starting index for pagination"] = 0,
    count: Annotated[int, "Maximum results (default 50)"] = 50,
) -> dict:
    """Generic cross-reference query with direction, type filtering, and pagination. More flexible than get_xrefs_to/get_xrefs_from."""
    import idautils
    import idaapi
    import ida_funcs
    import ida_xref

    ea = _resolve_address(address)

    TYPE_FILTER = {
        "call": {ida_xref.fl_CN, ida_xref.fl_CF},
        "jump": {ida_xref.fl_JN, ida_xref.fl_JF},
        "data": {ida_xref.dr_O, ida_xref.dr_W, ida_xref.dr_R},
    }
    allowed_types = TYPE_FILTER.get(xref_type)

    all_xrefs = []
    xref_iter = idautils.XrefsTo(ea) if direction == "to" else idautils.XrefsFrom(ea)
    for xref in xref_iter:
        if xref.type == ida_xref.fl_F:
            continue  # Skip flow xrefs
        if allowed_types and xref.type not in allowed_types:
            continue

        ref_addr = xref.frm if direction == "to" else xref.to
        fn = idaapi.get_func(ref_addr)
        all_xrefs.append({
            "address": hex(ref_addr),
            "type": _xref_type_name(xref.type),
            "function": ida_funcs.get_func_name(fn.start_ea) if fn else None,
        })

    total = len(all_xrefs)
    page = all_xrefs[offset: offset + count]
    return {
        "target": hex(ea),
        "direction": direction,
        "xref_type_filter": xref_type or "all",
        "xrefs": page,
        "total": total,
        "offset": offset,
        "has_more": offset + count < total,
    }


# ============================================================================
# Enhanced Script Execution
# ============================================================================


@tool
def py_exec_file(
    file_path: Annotated[str, "Absolute path to Python script file to execute"],
) -> dict:
    """Execute a Python script file in the IDA context. The script can use all IDA APIs. Stdout/stderr are captured."""
    from pathlib import Path

    path = Path(file_path)
    if not path.exists():
        return {"error": f"Script file not found: {file_path}"}

    script = path.read_text(encoding="utf-8")

    old_stdout = sys.stdout
    old_stderr = sys.stderr
    captured_out = io.StringIO()
    captured_err = io.StringIO()
    sys.stdout = captured_out
    sys.stderr = captured_err

    error = None
    error_type = None
    try:
        exec_globals = {"__builtins__": __builtins__, "__file__": str(path)}
        exec(script, exec_globals)
    except Exception as e:
        error_type = type(e).__name__
        error = f"{error_type}: {e}"
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr

    return {
        "file": str(path),
        "output": captured_out.getvalue(),
        "errors": captured_err.getvalue(),
        "error": error,
        "error_type": error_type,
    }


# ============================================================================
# Debug Info Loading
# ============================================================================


@tool
def load_debug_info(
    path: Annotated[
        str,
        "Path to debug symbol file (PDB, dSYM, DWARF). Empty to auto-detect.",
    ] = "",
) -> dict:
    """Load external debug symbols (PDB, dSYM, DWARF) into the current database. Enhances type information and function names."""
    import ida_dbg
    import ida_auto
    import idautils
    import ida_funcs

    func_count_before = sum(1 for _ in idautils.Functions())

    try:
        if path:
            # Load from specific path
            ok = ida_dbg.load_debugger_symbols(path) if hasattr(ida_dbg, "load_debugger_symbols") else False
            if not ok:
                # Try via auto-analysis with PDB
                import ida_pdb

                if hasattr(ida_pdb, "pdb_set_remote_path"):
                    ida_pdb.pdb_set_remote_path(path)
                ok = True
        else:
            # Auto-detect: trigger PDB/dSYM loading
            ok = True

        # Wait for analysis to settle
        ida_auto.auto_wait()
    except Exception as e:
        return {"error": f"Failed to load debug info: {e}"}

    func_count_after = sum(1 for _ in idautils.Functions())
    new_named = 0
    for func_ea in idautils.Functions():
        name = ida_funcs.get_func_name(func_ea)
        if name and not name.startswith("sub_"):
            new_named += 1

    return {
        "success": True,
        "path": path or "<auto-detect>",
        "functions_before": func_count_before,
        "functions_after": func_count_after,
        "named_functions": new_named,
    }


# ============================================================================
# Resolve & Comment Utilities
# ============================================================================


@tool
def resolve_function(
    query: Annotated[str, "Function name or partial name to search for"],
    max_results: Annotated[int, "Maximum results (default 10)"] = 10,
) -> dict:
    """Find functions by partial name match (case-insensitive). Useful when you don't know the exact function name."""
    import idautils
    import idaapi
    import ida_funcs

    pattern = query.lower()
    matches = []
    for func_ea in idautils.Functions():
        name = ida_funcs.get_func_name(func_ea)
        if pattern in name.lower():
            fn = idaapi.get_func(func_ea)
            matches.append({
                "address": hex(func_ea),
                "name": name,
                "size": fn.end_ea - fn.start_ea if fn else 0,
            })
            if len(matches) >= max_results:
                break

    return {"query": query, "matches": matches, "count": len(matches)}


@tool
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
# Batch Operations
# ============================================================================


@tool
def batch_decompile(
    addresses: Annotated[list[str], "List of function addresses (hex) or names to decompile"],
) -> dict:
    """Decompile multiple functions in one call. Returns results for each function."""
    import idaapi
    import ida_hexrays
    import ida_funcs

    if not ida_hexrays.init_hexrays_plugin():
        return {"error": "Hex-Rays decompiler not available"}

    results = []
    for addr in addresses:
        try:
            ea = _resolve_address(addr)
            fn = idaapi.get_func(ea)
            if not fn:
                results.append({"address": addr, "error": f"No function at {addr}"})
                continue
            cfunc = ida_hexrays.decompile(fn.start_ea)
            if cfunc:
                results.append({
                    "address": hex(fn.start_ea),
                    "name": ida_funcs.get_func_name(fn.start_ea),
                    "pseudocode": str(cfunc),
                })
            else:
                results.append({"address": hex(fn.start_ea), "error": "Decompilation failed"})
        except Exception as e:
            results.append({"address": addr, "error": str(e)})

    return {"results": results, "count": len(results)}


@tool
def batch_rename(
    renames: Annotated[
        list[dict],
        "List of {address, new_name} objects, e.g. [{'address':'0x401000','new_name':'main'}]",
    ],
) -> dict:
    """Rename multiple addresses in one call. Each item needs 'address' and 'new_name' fields."""
    import idaapi

    results = []
    for item in renames:
        addr = item.get("address", "")
        new_name = item.get("new_name", "")
        if not addr or not new_name:
            results.append({"address": addr, "success": False, "error": "Missing address or new_name"})
            continue
        try:
            ea = _resolve_address(addr)
            ok = idaapi.set_name(ea, new_name, idaapi.SN_NOWARN | idaapi.SN_NOCHECK)
            if ok:
                _invalidate_decompiler_cache(ea)
            results.append({"address": hex(ea), "new_name": new_name, "success": bool(ok)})
        except Exception as e:
            results.append({"address": addr, "new_name": new_name, "success": False, "error": str(e)})

    succeeded = sum(1 for r in results if r.get("success"))
    return {"results": results, "total": len(results), "succeeded": succeeded}


# ============================================================================
# Helpers (not exposed as tools)
# ============================================================================


def _invalidate_decompiler_cache(ea: int):
    """Mark decompiler cache dirty so pseudocode is refreshed after modifications."""
    try:
        import ida_hexrays

        if ida_hexrays.init_hexrays_plugin():
            import idaapi

            fn = idaapi.get_func(ea)
            if fn:
                ida_hexrays.mark_cfunc_dirty(fn.start_ea)
    except Exception:
        pass


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


def _seg_perms(seg) -> str:
    """Format segment permissions as rwx string."""
    import idaapi

    r = "r" if seg.perm & idaapi.SEGPERM_READ else "-"
    w = "w" if seg.perm & idaapi.SEGPERM_WRITE else "-"
    x = "x" if seg.perm & idaapi.SEGPERM_EXEC else "-"
    return r + w + x

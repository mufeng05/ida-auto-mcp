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
# Database Info
# ============================================================================


@tool
def get_database_info() -> dict:
    """Get metadata about the currently loaded binary (filename, architecture, image base, etc.)."""
    import idaapi
    import ida_nalt
    import idc
    import ida_auto

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
    import ida_struct
    import idaapi

    all_structs = []
    idx = ida_struct.get_first_struc_idx()
    while idx != idaapi.BADADDR:
        sid = ida_struct.get_struc_by_idx(idx)
        sptr = ida_struct.get_struc(sid)
        if sptr:
            name = ida_struct.get_struc_name(sid)
            if not filter_str or filter_str.lower() in name.lower():
                all_structs.append(
                    {
                        "id": sid,
                        "name": name,
                        "size": ida_struct.get_struc_size(sptr),
                        "is_union": ida_struct.is_union(sid),
                        "member_count": sptr.memqty,
                    }
                )
        idx = ida_struct.get_next_struc_idx(idx)

    total = len(all_structs)
    page = all_structs[offset : offset + count]
    return {"structs": page, "total": total, "offset": offset, "has_more": offset + count < total}


@tool
def get_struct_info(
    name: Annotated[str, "Struct name to look up"],
) -> dict:
    """Get detailed struct/union info including all member fields, offsets, and types."""
    import ida_struct

    sid = ida_struct.get_struc_id(name)
    if sid == -1:
        return {"error": f"Struct not found: {name}"}

    sptr = ida_struct.get_struc(sid)
    if not sptr:
        return {"error": f"Cannot load struct: {name}"}

    members = []
    for i in range(sptr.memqty):
        member = sptr.get_member(i)
        if member:
            mname = ida_struct.get_member_name(member.id)
            msize = ida_struct.get_member_size(member)
            members.append(
                {
                    "name": mname,
                    "offset": member.soff,
                    "size": msize,
                }
            )

    return {
        "name": name,
        "id": sid,
        "size": ida_struct.get_struc_size(sptr),
        "is_union": ida_struct.is_union(sid),
        "member_count": sptr.memqty,
        "members": members,
    }


@tool
def get_stack_frame(
    address: Annotated[str, "Function address (hex) or name"],
) -> dict:
    """Get the stack frame layout of a function, showing local variables and arguments."""
    import idaapi
    import ida_funcs
    import ida_struct
    import ida_frame

    ea = _resolve_address(address)
    fn = idaapi.get_func(ea)
    if not fn:
        return {"error": f"No function at {address}"}

    frame = ida_frame.get_frame(fn)
    if not frame:
        return {
            "function": hex(fn.start_ea),
            "name": ida_funcs.get_func_name(fn.start_ea),
            "error": "No stack frame",
        }

    members = []
    for i in range(frame.memqty):
        member = frame.get_member(i)
        if member:
            mname = ida_struct.get_member_name(member.id)
            msize = ida_struct.get_member_size(member)
            members.append(
                {
                    "name": mname,
                    "offset": member.soff,
                    "size": msize,
                }
            )

    return {
        "function": hex(fn.start_ea),
        "name": ida_funcs.get_func_name(fn.start_ea),
        "frame_size": ida_struct.get_struc_size(frame),
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
# Helpers (not exposed as tools)
# ============================================================================


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

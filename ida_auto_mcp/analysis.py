"""Running IDA's auto-analysis in bounded steps.

idalib analyzes only when asked, and ida_auto.auto_wait() returns only once
the whole analysis queue is drained. For a large or obfuscated binary that
takes hours, and nothing can interrupt it. The server instead advances the
queue with ida_auto.auto_make_step(), which handles one queued address per
call: in short slices while no request is waiting (background analysis), and
up to a deadline in open_binary and wait_analysis. Between two steps the
database is consistent, so tool calls and interruptions can come in between.
The approach follows Hex-Rays' ida-nexus.
"""

import time

# One background slice. A request that arrives meanwhile waits for the rest
# of the slice, plus the current step, which on rare addresses takes seconds.
SLICE_SECONDS = 0.05

# Steps between two looks at the clock; a step usually takes microseconds
_STEPS_PER_CHECK = 16

# auto_make_step() at times processes nothing although work is still queued,
# and goes on at the next call. This many such calls in a row count as stuck.
_MAX_IDLE_STEPS = 100

# What IDA does while working through each of its queues (ida_auto.AU_*)
_STAGES = {
    "AU_UNK": "undefining items",
    "AU_CODE": "creating instructions",
    "AU_WEAK": "creating instructions",
    "AU_PROC": "creating functions",
    "AU_TAIL": "adding function tails",
    "AU_FCHUNK": "finding function chunks",
    "AU_USED": "reanalyzing",
    "AU_USD2": "reanalyzing",
    "AU_TYPE": "applying types",
    "AU_LIBF": "applying library signatures",
    "AU_LBF2": "applying library signatures",
    "AU_LBF3": "applying library signatures",
    "AU_CHLB": "loading signature files",
    "AU_FINAL": "final pass",
}


def advance(seconds: float) -> bool:
    """Advance the open database's analysis for about `seconds`.

    Returns True once nothing is left to process, or nothing can be: then
    is_complete() tells which. A call may overrun by the duration of one step.
    """
    import ida_auto
    import ida_idaapi

    # Opening a database without analysis leaves the analyzer enabled, but a
    # database saved with analysis switched off would ignore the steps
    if not ida_auto.is_auto_enabled():
        ida_auto.enable_auto(True)

    make_step = ida_auto.auto_make_step
    end = ida_idaapi.BADADDR
    deadline = time.monotonic() + seconds
    idle = 0
    while True:
        for _ in range(_STEPS_PER_CHECK):
            if make_step(0, end):
                idle = 0
            elif ida_auto.auto_is_ok():
                return True
            else:
                idle += 1
                if idle >= _MAX_IDLE_STEPS:
                    return True
        if time.monotonic() >= deadline:
            return False


def is_complete() -> bool:
    """Whether the open database's analysis queues are empty."""
    import ida_auto

    return bool(ida_auto.auto_is_ok())


def status() -> dict:
    """The open database's analysis progress, for tool results.

    complete is True once IDA's queues are empty. Until then, stage says
    which kind of work IDA is doing and address where it last worked;
    functions counts the functions found so far.
    """
    import ida_auto
    import ida_funcs
    import ida_idaapi

    complete = bool(ida_auto.auto_is_ok())
    result = {"complete": complete, "functions": ida_funcs.get_func_qty()}
    if complete or not hasattr(ida_auto, "get_auto_display"):
        return result
    display = ida_auto.auto_display_t()
    if ida_auto.get_auto_display(display):
        for name, stage in _STAGES.items():
            if getattr(ida_auto, name, None) == display.type:
                result["stage"] = stage
                if display.ea != ida_idaapi.BADADDR:
                    result["address"] = hex(display.ea)
                break
    return result

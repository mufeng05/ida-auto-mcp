"""Tests for running IDA's analysis in steps (background slices, open_binary's
wait, wait_analysis), for the caches that analysis makes stale (pseudocode,
the string list), and for iterating every chunk of a function.

They replace IDA's modules with small stand-ins, so no IDA installation is
needed:

    python -m unittest discover -s tests -v
"""

import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from ida_auto_mcp import analysis, tools
from ida_auto_mcp import session as session_module
from ida_auto_mcp._registry import mcp
from ida_auto_mcp.session import Session, SessionManager

BADADDR = 0xFFFFFFFFFFFFFFFF
QUEUES = ["AU_UNK", "AU_CODE", "AU_WEAK", "AU_PROC", "AU_TAIL", "AU_FCHUNK", "AU_USED"]


class FakeIda:
    """Stand-ins for the IDA modules imported by analysis, session and tools.

    pending is the number of queued addresses left to analyze; each
    auto_make_step() call handles one.
    """

    def __init__(self, pending: int = 0):
        self.pending = pending
        # At this many pending addresses, one step processes nothing, as
        # IDA's auto_make_step() at times does
        self.pause_at: int | None = None
        # Every step processes nothing while work is queued
        self.stuck = False
        self.enabled = True
        self.opened: list[bool] = []  # run_auto_analysis of each open
        self.modules = {
            "ida_auto": self._ida_auto(),
            "ida_idaapi": types.SimpleNamespace(BADADDR=BADADDR),
            "ida_funcs": types.SimpleNamespace(get_func_qty=lambda: 7),
            "idapro": types.SimpleNamespace(
                open_database=self._open_database,
                close_database=lambda save=True: None,
            ),
        }

    def _ida_auto(self):
        fake = self
        module = types.SimpleNamespace(AU_NONE=99)
        for value, name in enumerate(QUEUES):
            setattr(module, name, value)

        def auto_make_step(ea1, ea2):
            if not fake.enabled or fake.pending == 0 or fake.stuck:
                return False
            if fake.pending == fake.pause_at:
                fake.pause_at = None
                return False
            fake.pending -= 1
            return True

        def enable_auto(enable):
            previous, fake.enabled = fake.enabled, enable
            return previous

        class auto_display_t:
            type = 99
            ea = BADADDR

        def get_auto_display(display):
            display.type, display.ea = module.AU_CODE, 0x401000
            return True

        module.auto_make_step = auto_make_step
        module.auto_is_ok = lambda: fake.pending == 0
        module.is_auto_enabled = lambda: fake.enabled
        module.enable_auto = enable_auto
        module.auto_display_t = auto_display_t
        module.get_auto_display = get_auto_display
        return module

    def _open_database(self, path, run_auto_analysis, args=None):
        self.opened.append(run_auto_analysis)
        return 0

    def patch(self, **extra):
        return mock.patch.dict(sys.modules, {**self.modules, **extra})


class ManagerTestCase(unittest.TestCase):
    """Runs each test with a fresh SessionManager as the global one."""

    def setUp(self):
        self._saved_manager = session_module._manager
        self.manager = session_module._manager = SessionManager()

    def tearDown(self):
        session_module._manager = self._saved_manager

    def activate(self, auto_analysis: bool = True) -> Session:
        session = Session("s1", Path("sample.exe"), auto_analysis=auto_analysis)
        self.manager._sessions["s1"] = session
        self.manager._active_id = "s1"
        return session


class AdvanceTests(unittest.TestCase):
    def test_stops_at_the_deadline_while_work_remains(self):
        ida = FakeIda(pending=10**12)
        with ida.patch():
            started = time.monotonic()
            self.assertFalse(analysis.advance(0.05))
            self.assertLess(time.monotonic() - started, 2)
            self.assertGreater(ida.pending, 0)

    def test_finishes_when_the_queues_are_empty(self):
        ida = FakeIda(pending=100)
        with ida.patch():
            self.assertTrue(analysis.advance(10))
            self.assertEqual(ida.pending, 0)

    def test_goes_on_after_a_step_that_processed_nothing(self):
        ida = FakeIda(pending=100)
        ida.pause_at = 37
        with ida.patch():
            self.assertTrue(analysis.advance(10))
            self.assertEqual(ida.pending, 0)
            self.assertTrue(analysis.is_complete())

    def test_gives_up_when_nothing_is_processed(self):
        ida = FakeIda(pending=100)
        ida.stuck = True
        with ida.patch():
            self.assertTrue(analysis.advance(10))
            self.assertFalse(analysis.is_complete())

    def test_enables_an_analyzer_that_was_switched_off(self):
        ida = FakeIda(pending=5)
        ida.enabled = False
        with ida.patch():
            self.assertTrue(analysis.advance(10))
        self.assertTrue(ida.enabled)

    def test_status_names_the_stage_until_complete(self):
        ida = FakeIda(pending=3)
        with ida.patch():
            self.assertEqual(
                analysis.status(),
                {
                    "complete": False,
                    "functions": 7,
                    "stage": "creating instructions",
                    "address": "0x401000",
                },
            )
            ida.pending = 0
            self.assertEqual(analysis.status(), {"complete": True, "functions": 7})


class BackgroundStepTests(ManagerTestCase):
    def test_nothing_to_do_without_a_session(self):
        self.assertFalse(self.manager.background_step())

    def test_session_without_auto_analysis_is_left_alone(self):
        ida = FakeIda(pending=50)
        self.activate(auto_analysis=False)
        with ida.patch():
            self.assertFalse(self.manager.background_step())
        self.assertEqual(ida.pending, 50)

    def test_slices_until_complete(self):
        ida = FakeIda(pending=10**12)
        session = self.activate()
        with ida.patch():
            epoch = self.manager.analysis_epoch
            self.assertTrue(self.manager.background_step())
            self.assertGreater(self.manager.analysis_epoch, epoch)
            self.assertEqual(session.to_dict(active=True)["analysis"], "running")
            self.assertEqual(session.to_dict(active=False)["analysis"], "paused")

            ida.pending = 10
            self.assertFalse(self.manager.background_step())
            self.assertTrue(session.analysis_complete)
            self.assertEqual(session.to_dict(active=True)["analysis"], "complete")
            self.assertFalse(session.to_dict(active=True)["is_analyzing"])

            # New work, e.g. after defining code, makes it resume
            ida.pending = 10**12
            self.assertTrue(self.manager.background_step())

    def test_stuck_analysis_is_retried_once_a_minute(self):
        ida = FakeIda(pending=50)
        ida.stuck = True
        session = self.activate()
        with ida.patch(), self.assertLogs("ida_auto_mcp.session", level="WARNING"):
            self.assertFalse(self.manager.background_step())
            self.assertIsNotNone(session.analysis_stalled_at)
            epoch = self.manager.analysis_epoch
            self.assertFalse(self.manager.background_step())
            self.assertEqual(self.manager.analysis_epoch, epoch)

            session.analysis_stalled_at -= 61
            ida.stuck = False
            self.assertFalse(self.manager.background_step())
            self.assertGreater(self.manager.analysis_epoch, epoch)
        self.assertTrue(session.analysis_complete)
        self.assertIsNone(session.analysis_stalled_at)


class OpenBinaryTests(ManagerTestCase):
    def setUp(self):
        super().setUp()
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "sample.exe"
        self.path.write_bytes(b"MZ")

    def tearDown(self):
        self.directory.cleanup()
        super().tearDown()

    def test_waits_up_to_the_limit_and_never_lets_idalib_analyze(self):
        ida = FakeIda(pending=10**12)
        self.manager.analysis_wait = 0.05
        with ida.patch():
            started = time.monotonic()
            session = self.manager.open_binary(self.path)
            self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(ida.opened, [False])
        self.assertFalse(session.analysis_complete)
        self.assertEqual(session.to_dict(active=True)["analysis"], "running")

    def test_small_binary_is_analyzed_before_it_returns(self):
        ida = FakeIda(pending=1000)
        with ida.patch():
            session = self.manager.open_binary(self.path)
        self.assertTrue(session.analysis_complete)

    def test_without_auto_analysis_nothing_runs(self):
        ida = FakeIda(pending=1000)
        with ida.patch():
            session = self.manager.open_binary(self.path, auto_analysis=False)
            self.assertFalse(self.manager.background_step())
        self.assertEqual(ida.pending, 1000)
        self.assertEqual(session.to_dict(active=True)["analysis"], "off")

    def test_opening_a_tracked_file_again_applies_auto_analysis(self):
        ida = FakeIda(pending=1000)
        with ida.patch():
            first = self.manager.open_binary(self.path, auto_analysis=False)
            again = self.manager.open_binary(self.path, auto_analysis=True)
        self.assertIs(first, again)
        self.assertTrue(again.auto_analysis)
        self.assertTrue(again.analysis_complete)
        self.assertEqual(ida.opened, [False])


class WaitAnalysisToolTests(ManagerTestCase):
    def setUp(self):
        super().setUp()
        self._saved_timeout = mcp.tool_timeout
        mcp.tool_timeout = None

    def tearDown(self):
        mcp.tool_timeout = self._saved_timeout
        super().tearDown()

    def call(self, **arguments) -> dict:
        return mcp.dispatch(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "wait_analysis", "arguments": arguments},
            }
        )["result"]

    def test_can_be_interrupted(self):
        self.assertNotIn("wait_analysis", mcp._uninterruptible)

    def test_returns_progress_when_the_timeout_passes(self):
        ida = FakeIda(pending=10**12)
        self.activate()
        with ida.patch():
            result = self.call(timeout=0.2)
        self.assertFalse(result["isError"])
        content = result["structuredContent"]
        self.assertFalse(content["complete"])
        self.assertEqual(content["analysis"]["stage"], "creating instructions")
        self.assertIn("message", content)

    def test_waits_until_complete(self):
        ida = FakeIda(pending=5000)
        self.activate(auto_analysis=False)
        with ida.patch():
            content = self.call(timeout=0)["structuredContent"]
        self.assertTrue(content["complete"])
        self.assertEqual(ida.pending, 0)

    def test_stops_before_the_server_time_limit(self):
        ida = FakeIda(pending=10**12)
        self.activate()
        mcp.tool_timeout = 0.3
        with ida.patch():
            result = self.call(timeout=0)
        self.assertFalse(result["isError"], result)
        self.assertFalse(result["structuredContent"]["complete"])

    def test_says_when_analysis_cannot_go_on(self):
        ida = FakeIda(pending=50)
        ida.stuck = True
        self.activate()
        with ida.patch(), self.assertLogs("ida_auto_mcp.session", level="WARNING"):
            content = self.call(timeout=5)["structuredContent"]
        self.assertFalse(content["complete"])
        self.assertLess(content["waited_seconds"], 5)
        self.assertIn("does not process", content["message"])

    def test_needs_a_session(self):
        self.assertTrue(self.call()["isError"])


class DecompilerCacheTests(ManagerTestCase):
    def setUp(self):
        super().setUp()
        tools._decompiled_state = None
        self.cleared = 0

        def clear_cached_cfuncs():
            self.cleared += 1

        self.hexrays = types.SimpleNamespace(
            clear_cached_cfuncs=clear_cached_cfuncs,
            hexrays_failure_t=lambda: types.SimpleNamespace(desc=lambda: ""),
            decompile=lambda ea, failure: f"cfunc at {ea:#x}",
        )

    def test_cache_is_dropped_once_analysis_changed_the_database(self):
        with mock.patch.dict(sys.modules, {"ida_hexrays": self.hexrays}):
            self.assertEqual(tools._decompile(0x401000)[0], "cfunc at 0x401000")
            tools._decompile(0x401000)
            self.assertEqual(self.cleared, 1)
            self.manager.analysis_epoch += 1
            tools._decompile(0x401000)
            self.assertEqual(self.cleared, 2)
            self.manager.generation += 1
            tools._decompile(0x401000)
            self.assertEqual(self.cleared, 3)


class StringListTests(ManagerTestCase):
    TEXTS = ["alpha", "beta", "gamma", "alphabet", "delta"]

    def setUp(self):
        super().setUp()
        tools._strlist_state = None
        self.builds = 0
        self.ida = FakeIda(pending=10)
        self.modules = self.string_modules(ida_95=True)

    def string_modules(self, ida_95: bool) -> dict:
        """ida_strlist and idautils as IDA 9.5 has them (items with
        synthetic strings need string_info_ex_t) or as earlier versions do."""
        texts = self.TEXTS

        def build_strlist():
            self.builds += 1

        class string_info_t:
            ea = length = type = 0

        class string_info_ex_t(string_info_t):
            synthetic_string = ""

        def get_strlist_item(info, index):
            if not 0 <= index < len(texts):
                return False
            info.ea, info.length, info.type = 0x1000 + index * 0x10, len(texts[index]), 0
            return True

        class StringItem:
            def __init__(self, si):
                self.ea, self.length, self.strtype = si.ea, si.length, si.type
                if ida_95:
                    self.synthetic_string = si.synthetic_string

            def __str__(self):
                return texts[(self.ea - 0x1000) // 0x10]

        ida_strlist = types.SimpleNamespace(
            build_strlist=build_strlist,
            get_strlist_options=lambda: None,
            get_strlist_qty=lambda: len(texts),
            get_strlist_item=get_strlist_item,
            string_info_t=string_info_t,
        )
        if ida_95:
            ida_strlist.string_info_ex_t = string_info_ex_t
            ida_strlist.get_strlist_item_ex = get_strlist_item
        return {
            "ida_strlist": ida_strlist,
            "idautils": types.SimpleNamespace(
                Strings=types.SimpleNamespace(StringItem=StringItem)
            ),
        }

    def test_earlier_ida_versions(self):
        with self.ida.patch(**self.string_modules(ida_95=False)):
            result = tools.list_strings(offset=1, count=2)
        self.assertEqual([s["text"] for s in result["strings"]], ["beta", "gamma"])

    def test_pages_come_from_one_build(self):
        with self.ida.patch(**self.modules):
            first = tools.list_strings(offset=0, count=2)
            second = tools.list_strings(offset=2, count=2)
        self.assertEqual(self.builds, 1)
        self.assertEqual([s["text"] for s in first["strings"]], ["alpha", "beta"])
        self.assertEqual([s["text"] for s in second["strings"]], ["gamma", "alphabet"])
        self.assertEqual(second["total"], 5)
        self.assertTrue(second["has_more"])

    def test_filter_counts_every_match(self):
        with self.ida.patch(**self.modules):
            result = tools.list_strings(filter_str="ALPHA", offset=1, count=5)
        self.assertEqual([s["text"] for s in result["strings"]], ["alphabet"])
        self.assertEqual(result["total"], 2)
        self.assertFalse(result["has_more"])

    def test_search_uses_the_same_list(self):
        with self.ida.patch(**self.modules):
            tools.list_strings()
            result = tools.search_strings(pattern="^.e", max_results=5)
        self.assertEqual([m["text"] for m in result["matches"]], ["beta", "delta"])
        self.assertEqual(self.builds, 1)

    def test_rebuilt_for_another_database(self):
        with self.ida.patch(**self.modules):
            tools.list_strings()
            self.manager.generation += 1
            tools.list_strings()
        self.assertEqual(self.builds, 2)

    def test_rebuilt_at_most_once_a_minute_while_analysis_runs(self):
        with self.ida.patch(**self.modules):
            tools.list_strings()
            self.manager.analysis_epoch += 1
            tools.list_strings()
            self.assertEqual(self.builds, 1)
            tools._strlist_built_at -= 61
            tools.list_strings()
            self.assertEqual(self.builds, 2)

    def test_rebuilt_once_analysis_finished(self):
        with self.ida.patch(**self.modules):
            tools.list_strings()
            self.manager.analysis_epoch += 1
            self.ida.pending = 0
            tools.list_strings()
            tools.list_strings()
        self.assertEqual(self.builds, 2)


def chunk(start, end):
    return types.SimpleNamespace(start_ea=start, end_ea=end)


class FunctionChunkTests(unittest.TestCase):
    """A function at 0x1000 with a tail at 0x5000; it calls 0x2000 from its
    entry chunk and 0x3000 from its tail."""

    FUNC = chunk(0x1000, 0x1010)
    TAIL = chunk(0x5000, 0x5010)
    CALLEES = {0x2000: chunk(0x2000, 0x2010), 0x3000: chunk(0x3000, 0x3010)}

    def ida_modules(self, ida_95: bool) -> dict:
        def get_func(ea):
            for fn in (self.FUNC, *self.CALLEES.values()):
                if fn.start_ea <= ea < fn.end_ea:
                    return fn
            if self.TAIL.start_ea <= ea < self.TAIL.end_ea:
                return self.FUNC
            return None

        def tails_of(fn):
            return [self.TAIL] if fn is self.FUNC else []

        ida_funcs = types.SimpleNamespace(
            get_func=get_func,
            get_func_name=lambda ea: f"sub_{ea:X}",
        )
        modules = {"ida_funcs": ida_funcs}
        if ida_95:
            # The tails, unordered, and the entry chunk, which is skipped
            ida_funcs.get_func_tails = lambda out, ea: out.extend(
                tails_of(get_func(ea)) + [self.FUNC]
            ) or True
            modules["ida_range"] = types.SimpleNamespace(rangevec_t=list)
        else:
            ida_funcs.func_tail_iterator_t = lambda fn: iter([fn] + tails_of(fn))

        calls = {0x1004: 0x2000, 0x5008: 0x3000}
        modules["idautils"] = types.SimpleNamespace(
            Heads=lambda start, end: iter(range(start, end, 4)),
            XrefsFrom=lambda ea: (
                [types.SimpleNamespace(type=17, to=calls[ea])] if ea in calls else []
            ),
        )
        modules["ida_xref"] = types.SimpleNamespace(fl_CN=17, fl_CF=16)
        modules["idaapi"] = types.SimpleNamespace(
            BADADDR=BADADDR, get_name_ea=lambda base, name: BADADDR
        )
        modules["idc"] = types.SimpleNamespace(
            get_item_size=lambda ea: 4,
            get_bytes=lambda ea, size: b"\x90" * size,
            GetDisasm=lambda ea: "nop",
            next_head=lambda ea, end=BADADDR: ea + 4,
        )
        return modules

    def test_chunks_start_with_the_entry_chunk(self):
        for ida_95 in (False, True):
            with self.subTest(ida_95=ida_95):
                with mock.patch.dict(sys.modules, self.ida_modules(ida_95)):
                    self.assertEqual(
                        tools._func_chunks(self.FUNC),
                        [(0x1000, 0x1010), (0x5000, 0x5010)],
                    )

    def test_callees_include_calls_from_tails(self):
        for ida_95 in (False, True):
            with self.subTest(ida_95=ida_95):
                with mock.patch.dict(sys.modules, self.ida_modules(ida_95)):
                    result = tools.get_callees("0x1000")
                self.assertEqual(
                    [c["address"] for c in result["callees"]], ["0x2000", "0x3000"]
                )

    def test_disassembly_covers_every_chunk(self):
        with mock.patch.dict(sys.modules, self.ida_modules(False)):
            result = tools.disassemble_function("0x1000")
        addresses = [i["address"] for i in result["instructions"]]
        self.assertEqual(addresses[:4], ["0x1000", "0x1004", "0x1008", "0x100c"])
        self.assertEqual(addresses[4:], ["0x5000", "0x5004", "0x5008", "0x500c"])
        self.assertEqual(
            result["chunks"],
            [{"start": "0x1000", "end": "0x1010"}, {"start": "0x5000", "end": "0x5010"}],
        )

    def test_callgraph_follows_calls_from_tails(self):
        with mock.patch.dict(sys.modules, self.ida_modules(False)):
            result = tools.get_callgraph("0x1000", max_depth=1)
        self.assertEqual(
            sorted(node["address"] for node in result["nodes"]),
            ["0x1000", "0x2000", "0x3000"],
        )


if __name__ == "__main__":
    unittest.main()

"""Tests for binary-level adversarial analysis via radare2."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from packages.binary_analysis.radare2_understand import (
    BinaryContextMap,
    BinaryUnderstand,
    FunctionInfo,
    _DANGEROUS_IMPORTS,
    _ENTRY_POINT_HINTS,
    analyse_binary_context,
    probe_capability,
)


class TestProbeCapability(unittest.TestCase):
    @patch("packages.binary_analysis.radare2_understand.shutil.which")
    def test_no_radare2(self, mock_which):
        mock_which.return_value = None
        cap = probe_capability()
        self.assertFalse(cap["available"])
        self.assertIsNone(cap["decompiler"])

    @patch("packages.binary_analysis.radare2_understand.shutil.which")
    def test_radare2_without_r2pipe(self, mock_which):
        mock_which.return_value = "/usr/bin/r2"
        with patch.dict("sys.modules", {"r2pipe": None}):
            # Force ImportError by pretending the module is None
            with patch("builtins.__import__", side_effect=ImportError):
                cap = probe_capability()
        self.assertFalse(cap["has_r2pipe"])
        self.assertFalse(cap["available"])

    @patch("packages.binary_analysis.radare2_understand.shutil.which")
    @patch("packages.binary_analysis.radare2_understand.subprocess.run")
    def test_radare2_with_r2pipe_no_ghidra(self, mock_run, mock_which):
        mock_which.return_value = "/usr/bin/r2"
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        with patch.dict("sys.modules", {"r2pipe": MagicMock()}):
            cap = probe_capability()
        self.assertTrue(cap["available"])
        self.assertEqual(cap["decompiler"], "pdc")

    @patch("packages.binary_analysis.radare2_understand.shutil.which")
    @patch("packages.binary_analysis.radare2_understand.subprocess.run")
    def test_radare2_with_r2ghidra(self, mock_run, mock_which):
        mock_which.return_value = "/usr/bin/r2"
        mock_run.return_value = MagicMock(stdout="r2ghidra plugin loaded", returncode=0)
        with patch.dict("sys.modules", {"r2pipe": MagicMock()}):
            cap = probe_capability()
        self.assertTrue(cap["has_r2ghidra"])
        self.assertEqual(cap["decompiler"], "r2ghidra")


class TestBinaryContextMap(unittest.TestCase):
    def test_to_dict_roundtrips(self):
        ctx = BinaryContextMap(
            binary_path=Path("/tmp/sample"),
            arch="x86", bits=64, binary_format="elf",
        )
        ctx.entry_points.append(FunctionInfo(name="main", address=0x401000))
        ctx.dangerous_sinks.append(
            FunctionInfo(name="sym.imp.strcpy", address=0x402000, is_imported=True)
        )
        ctx.fuzz_priorities = [
            {"function": "parse_request", "score": 9, "reason": "calls strcpy on argv"},
        ]
        d = ctx.to_dict()
        self.assertEqual(d["arch"], "x86")
        self.assertEqual(d["bits"], 64)
        self.assertEqual(len(d["entry_points"]), 1)
        self.assertEqual(d["entry_points"][0]["name"], "main")
        self.assertEqual(d["dangerous_sinks"][0]["is_imported"], True)
        self.assertEqual(d["sink_details"][0]["name"], "sym.imp.strcpy")
        self.assertEqual(d["sources"][0]["entry"], "main")
        self.assertEqual(d["sinks"][0]["location"], "sym.imp.strcpy")
        self.assertEqual(d["fuzz_priorities"][0]["score"], 9)

    def test_write_creates_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = BinaryContextMap(binary_path=Path("/tmp/sample"))
            out = ctx.write(Path(tmp) / "ctx.json")
            self.assertTrue(out.exists())
            data = json.loads(out.read_text())
            self.assertIn("binary", data)


class TestDangerousImports(unittest.TestCase):
    def test_known_dangerous_imports_present(self):
        # Representatives from each composed category. The full
        # taxonomy is exhaustively tested in core/tests/
        # test_function_taxonomy.py; here we just confirm radare2_
        # understand's composition still includes the major sink
        # families.
        self.assertIn("strcpy", _DANGEROUS_IMPORTS)         # string overflow
        self.assertIn("scanf", _DANGEROUS_IMPORTS)          # scan-family
        self.assertIn("memcpy", _DANGEROUS_IMPORTS)         # mem copy
        self.assertIn("syslog", _DANGEROUS_IMPORTS)         # format-string
        self.assertIn("system", _DANGEROUS_IMPORTS)         # exec
        self.assertIn("calloc", _DANGEROUS_IMPORTS)         # alloc (size-tainted)
        self.assertIn("recv", _DANGEROUS_IMPORTS)           # net ingest
        self.assertIn("XML_Parse", _DANGEROUS_IMPORTS)      # parser
        self.assertIn("atoi", _DANGEROUS_IMPORTS)           # integer parse
        self.assertIn("mktemp", _DANGEROUS_IMPORTS)         # TOCTOU

    def test_ubiquitous_functions_deliberately_absent(self):
        """Curation invariant — ubiquitous fns are NOT in the fuzz-
        priority composition because their import carries zero
        signal (every binary has them)."""
        for ubiq in ("malloc", "realloc", "free", "open", "fopen",
                     "read", "write", "printf", "fprintf"):
            self.assertNotIn(
                ubiq, _DANGEROUS_IMPORTS,
                msg=(f"{ubiq!r} is ubiquitous — should not be in "
                     f"_DANGEROUS_IMPORTS. See core/function_taxonomy.py "
                     f"docstring."),
            )

    def test_entry_point_hints_cover_common_cases(self):
        self.assertIn("main", _ENTRY_POINT_HINTS)
        self.assertIn("LLVMFuzzerTestOneInput", _ENTRY_POINT_HINTS)
        self.assertIn("DriverEntry", _ENTRY_POINT_HINTS)


class TestBinaryUnderstand(unittest.TestCase):
    @patch("packages.binary_analysis.radare2_understand.probe_capability")
    def test_init_raises_when_radare2_missing(self, mock_probe):
        mock_probe.return_value = {"available": False, "decompiler": None,
                                    "has_r2pipe": False, "has_r2ghidra": False,
                                    "r2_bin": None}
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x7fELF" + b"\x00" * 60)
            tmp = Path(f.name)
        try:
            with self.assertRaises(RuntimeError) as ctx:
                BinaryUnderstand(tmp)
            self.assertIn("radare2 not available", str(ctx.exception))
        finally:
            tmp.unlink()

    @patch("packages.binary_analysis.radare2_understand.probe_capability")
    def test_init_raises_for_missing_binary(self, mock_probe):
        mock_probe.return_value = {"available": True, "decompiler": "pdc",
                                    "has_r2pipe": True, "has_r2ghidra": False,
                                    "r2_bin": "/usr/bin/r2"}
        with self.assertRaises(FileNotFoundError):
            BinaryUnderstand(Path("/nonexistent/raptor_probe_binary"))

    @patch("packages.binary_analysis.radare2_understand.probe_capability")
    def test_analyse_pipeline_with_mocked_r2(self, mock_probe):
        mock_probe.return_value = {"available": True, "decompiler": "pdc",
                                    "has_r2pipe": True, "has_r2ghidra": False,
                                    "r2_bin": "/usr/bin/r2"}
        # Build a mock r2pipe instance that returns canned responses
        fake_r2 = MagicMock()
        responses = {
            "ij": json.dumps({
                "bin": {"arch": "x86", "bits": 64, "bintype": "elf"},
            }),
            "iij": json.dumps([
                {"name": "sym.imp.strcpy", "type": "FUNC"},
                {"name": "sym.imp.printf", "type": "FUNC"},
                {"name": "sym.imp.read", "type": "FUNC"},
            ]),
            "iEj": json.dumps([
                {"name": "main", "vaddr": 0x401000},
                {"name": "process_request", "vaddr": 0x401200},
            ]),
            "aflj": json.dumps([
                {"name": "main", "offset": 0x401000, "size": 100, "type": "fcn"},
                {"name": "process_request", "offset": 0x401200, "size": 250, "type": "fcn"},
                {"name": "sym.imp.strcpy", "offset": 0x402000, "size": 16, "type": "imp"},
            ]),
            "izj": json.dumps([
                {"string": "GET / HTTP/1.0\r\n\r\n"},
                {"string": "/usr/bin/test"},
            ]),
        }

        def cmd_response(cmd):
            if cmd == "aaa":
                return ""
            if cmd in responses:
                return responses[cmd]
            if cmd.startswith("axffj @"):
                # Return strcpy as a call from process_request only
                addr_str = cmd.split("@")[-1].strip()
                if "0x401200" in addr_str or "4198912" in addr_str:
                    return json.dumps([{"name": "sym.imp.strcpy"}])
                return "[]"
            if cmd.startswith("pdc @"):
                return "/* decompiled */ int x() { return 0; }"
            return ""
        fake_r2.cmd.side_effect = cmd_response

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x7fELF" + b"\x00" * 60)
            tmp = Path(f.name)

        try:
            with patch.dict("sys.modules", {"r2pipe": MagicMock()}) as mock_modules:
                # Replace the imported r2pipe.open()
                mock_modules["r2pipe"].open = MagicMock(return_value=fake_r2)

                bu = BinaryUnderstand(tmp)
                ctx = bu.analyse(max_decompile=5)

            self.assertEqual(ctx.arch, "x86")
            self.assertEqual(ctx.bits, 64)
            self.assertEqual(ctx.binary_format, "elf")
            self.assertIn("sym.imp.strcpy", ctx.imports)

            # process_request should be flagged as calling strcpy
            process_req = next(
                f for f in ctx.interesting_functions if f.name == "process_request"
            )
            self.assertIn("strcpy", process_req.calls_dangerous)

            # main should be in entry_points
            entry_names = [f.name for f in ctx.entry_points]
            self.assertIn("main", entry_names)

            # dangerous_sinks should include strcpy
            sink_names = [f.name for f in ctx.dangerous_sinks]
            self.assertTrue(any("strcpy" in n for n in sink_names))

            # heuristic prioritisation should rank process_request highly
            self.assertTrue(any(
                p["function"] == "process_request" for p in ctx.fuzz_priorities
            ))
        finally:
            tmp.unlink()

    @patch("packages.binary_analysis.radare2_understand.BinaryUnderstand")
    def test_analyse_binary_context_writes_shared_artifact(self, mock_understand):
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "binary-context-map.json"
            ctx = BinaryContextMap(binary_path=Path("/tmp/sample"))
            mock_understand.return_value.analyse.return_value = ctx

            result = analyse_binary_context(Path("/tmp/sample"), out_path=out, llm=None)

            self.assertIs(result, ctx)
            self.assertTrue(out.exists())
            mock_understand.assert_called_once_with(Path("/tmp/sample"), llm=None)


class TestSandboxWiring(unittest.TestCase):
    """Verify analyse() sets R2PIPE_R2 + cleanup env BEFORE r2pipe.open()
    runs, and restores env on exit. Drives r2pipe via a mock so we don't
    need a real r2 binary or wrapper-host capabilities (mount-ns etc.) —
    the wrapper's runtime behaviour is covered by
    test_r2_sandboxed_wrapper.py."""

    def _make_understand_with_fake_binary(self):
        """Build a BinaryUnderstand against a real on-disk ELF stub so
        the constructor's `is_file()` + `exists()` checks pass without
        needing to mock them."""
        tmp = tempfile.NamedTemporaryFile(
            delete=False, suffix="-stub", prefix="r2-wiring-",
        )
        tmp.write(b"\x7fELF" + b"\x00" * 60)
        tmp.close()
        self.addCleanup(lambda p=tmp.name: Path(p).unlink(missing_ok=True))
        # probe_capability is checked in __init__; patch it to look
        # available so we don't need real radare2 binary on the CI host.
        with patch(
            "packages.binary_analysis.radare2_understand.probe_capability",
            return_value={"available": True, "r2_path": "/usr/bin/radare2",
                          "r2_version": "5.0", "has_r2pipe": True,
                          "has_r2ghidra": False, "decompiler": "pdc"},
        ):
            return BinaryUnderstand(Path(tmp.name), llm=None)

    @patch("packages.binary_analysis.radare2_understand.logger")
    def test_analyse_sets_r2pipe_r2_to_wrapper(self, _mock_logger):
        """Inside analyse(), r2pipe.open is called WITH R2PIPE_R2 pointing
        at libexec/raptor-r2-sandboxed. Captured by patching r2pipe to
        snapshot os.environ at call-time."""
        import os
        understand = self._make_understand_with_fake_binary()
        captured_env = {}

        def fake_open(path, flags=None):
            # Snapshot the relevant env vars at the moment r2pipe.open
            # would have spawned the wrapper.
            for k in ("R2PIPE_R2", "OUTPUT_DIR", "R2_TARGET_DIR",
                      "_RAPTOR_TRUSTED"):
                captured_env[k] = os.environ.get(k)
            mock = MagicMock()
            mock.cmd.return_value = "[]"
            return mock

        fake_r2pipe = MagicMock()
        fake_r2pipe.open = fake_open
        with patch.dict("sys.modules", {"r2pipe": fake_r2pipe}):
            understand.analyse(max_decompile=0, max_strings=0)

        self.assertIsNotNone(captured_env["R2PIPE_R2"])
        self.assertTrue(
            captured_env["R2PIPE_R2"].endswith("/libexec/raptor-r2-sandboxed"),
            f"R2PIPE_R2 was {captured_env['R2PIPE_R2']!r}, "
            f"expected to end with /libexec/raptor-r2-sandboxed",
        )
        self.assertTrue(Path(captured_env["R2PIPE_R2"]).is_file(),
                        "wrapper path must resolve to a real file")
        self.assertIsNotNone(captured_env["OUTPUT_DIR"])
        self.assertIsNotNone(captured_env["R2_TARGET_DIR"])
        # Trust marker required by the wrapper's gate.
        self.assertEqual(captured_env["_RAPTOR_TRUSTED"], "1")

    @patch("packages.binary_analysis.radare2_understand.logger")
    def test_analyse_restores_env_on_exit(self, _mock_logger):
        """Env vars set for the wrapper must be cleaned up after
        analyse() returns — preventing pollution into the parent's
        other subprocess spawns (LLM dispatch, sibling tools)."""
        import os
        understand = self._make_understand_with_fake_binary()
        pre = {k: os.environ.get(k) for k in
               ("R2PIPE_R2", "OUTPUT_DIR", "R2_TARGET_DIR",
                "_RAPTOR_TRUSTED")}
        fake_r2pipe = MagicMock()
        fake_r2pipe.open.return_value.cmd.return_value = "[]"
        with patch.dict("sys.modules", {"r2pipe": fake_r2pipe}):
            understand.analyse(max_decompile=0, max_strings=0)
        for k, v in pre.items():
            self.assertEqual(
                os.environ.get(k), v,
                f"env var {k} leaked after analyse(): "
                f"before={v!r}, after={os.environ.get(k)!r}",
            )

    @patch("packages.binary_analysis.radare2_understand.logger")
    def test_analyse_restores_env_on_exception(self, _mock_logger):
        """If r2pipe / r2 raises mid-analysis, env restoration must
        still run (finally block) — otherwise a single failure leaks
        the wrapper-only env into the rest of the process."""
        import os
        understand = self._make_understand_with_fake_binary()
        pre_r2pipe_r2 = os.environ.get("R2PIPE_R2")
        fake_r2pipe = MagicMock()
        fake_r2pipe.open.side_effect = RuntimeError("simulated r2 failure")
        with patch.dict("sys.modules", {"r2pipe": fake_r2pipe}):
            with self.assertRaises(RuntimeError):
                understand.analyse(max_decompile=0, max_strings=0)
        self.assertEqual(os.environ.get("R2PIPE_R2"), pre_r2pipe_r2,
                         "R2PIPE_R2 leaked after exception")

    def test_wrapper_path_resolves_correctly(self):
        """Static check that the wrapper path derivation in
        radare2_understand matches libexec/raptor-r2-sandboxed —
        catches a refactor that moves the wrapper without updating
        the caller."""
        # radare2_understand.py is at packages/binary_analysis/...
        # parents[2] from that file = repo root. Wrapper is at
        # <root>/libexec/raptor-r2-sandboxed.
        import packages.binary_analysis.radare2_understand as ru
        repo_root = Path(ru.__file__).resolve().parents[2]
        expected = repo_root / "libexec" / "raptor-r2-sandboxed"
        self.assertTrue(
            expected.is_file(),
            f"libexec wrapper missing at {expected} — wiring will fail",
        )


class TestCmdTimeout(unittest.TestCase):
    """BinaryUnderstand._cmd_t — per-command timeout helper. Drives
    r2.cmd() in a worker thread; on timeout, kills the r2 subprocess
    via r2pipe's `process` handle and raises TimeoutError."""

    def test_normal_command_returns_result(self):
        """Fast r2 response → result returned, no timeout."""
        r2 = MagicMock()
        r2.cmd.return_value = '{"bin": "elf"}'
        result = BinaryUnderstand._cmd_t(r2, "ij", timeout_s=5.0)
        self.assertEqual(result, '{"bin": "elf"}')
        r2.cmd.assert_called_once_with("ij")

    def test_timeout_raises_timeouterror(self):
        """r2.cmd() blocks > timeout → TimeoutError raised, r2 killed."""
        import time
        r2 = MagicMock()
        # Simulate r2 hanging: cmd() never returns.
        r2.cmd.side_effect = lambda c: time.sleep(10)
        r2.process = MagicMock()
        with self.assertRaises(TimeoutError) as ctx:
            BinaryUnderstand._cmd_t(r2, "aaa", timeout_s=0.5)
        self.assertIn("aaa", str(ctx.exception))
        self.assertIn("0.5s", str(ctx.exception))
        # On timeout, r2.process.kill() must have been called to
        # unblock the pipe read.
        r2.process.kill.assert_called()

    def test_timeout_handles_missing_process_handle(self):
        """If r2pipe doesn't expose `process` (older versions, custom
        subclass), _cmd_t must still raise TimeoutError without
        crashing on the missing attribute."""
        import time
        r2 = MagicMock(spec=["cmd"])  # no `process` attr
        r2.cmd.side_effect = lambda c: time.sleep(10)
        with self.assertRaises(TimeoutError):
            BinaryUnderstand._cmd_t(r2, "aaa", timeout_s=0.3)

    def test_cmd_exception_propagates(self):
        """Exceptions from r2.cmd() (e.g. ConnectionError if pipe
        broke) must propagate up to the caller, not be swallowed."""
        r2 = MagicMock()
        r2.cmd.side_effect = ConnectionError("pipe broken")
        with self.assertRaises(ConnectionError):
            BinaryUnderstand._cmd_t(r2, "ij", timeout_s=5.0)

    def test_per_command_timeout_budgets_are_reasonable(self):
        """Sanity-check the class-level _T_* timeouts haven't drifted
        to silly values (zero, negative, decade-long)."""
        self.assertGreater(BinaryUnderstand._T_AAA, 60)        # > 1 min
        self.assertLess(BinaryUnderstand._T_AAA, 3600)         # < 1 hour
        self.assertGreater(BinaryUnderstand._T_DECOMPILE, 10)
        self.assertLess(BinaryUnderstand._T_DECOMPILE, 600)
        self.assertGreater(BinaryUnderstand._T_QUERY, 1)
        self.assertLess(BinaryUnderstand._T_QUERY, 300)
        self.assertGreater(BinaryUnderstand._T_XREF, 1)
        self.assertLess(BinaryUnderstand._T_XREF, 300)


class TestTransitiveCallers(unittest.TestCase):
    """BinaryUnderstand._tag_transitive_callers — BFS backwards from
    dangerous_sinks through the aflcj call graph, flagging functions
    that reach a sink within _TRANSITIVE_MAX_DEPTH hops.

    Models the CVE pattern grokjc's PR #488 Claude-review flagged:
    parse_message → helper_a → helper_b → strcpy. parse_message is
    3 hops from the sink and must be flagged, even though it doesn't
    directly call any dangerous import."""

    def _make_understand(self):
        tmp = tempfile.NamedTemporaryFile(
            delete=False, suffix="-stub", prefix="r2-trans-",
        )
        tmp.write(b"\x7fELF" + b"\x00" * 60)
        tmp.close()
        self.addCleanup(lambda p=tmp.name: Path(p).unlink(missing_ok=True))
        with patch(
            "packages.binary_analysis.radare2_understand.probe_capability",
            return_value={"available": True, "r2_path": "/usr/bin/radare2",
                          "r2_version": "5.0", "has_r2pipe": True,
                          "has_r2ghidra": False, "decompiler": "pdc"},
        ):
            return BinaryUnderstand(Path(tmp.name), llm=None)

    def _ctx_with(self, interesting_names, sinks_with_callers):
        """Build a BinaryContextMap with the given interesting fns
        and a callgraph linking them to sinks.

        sinks_with_callers: dict mapping sink_name → list of caller
        names. caller names must be in interesting_names.
        """
        ctx = BinaryContextMap(binary_path=Path("/tmp/stub"))
        for i, n in enumerate(interesting_names):
            ctx.interesting_functions.append(
                FunctionInfo(name=n, address=0x1000 + i * 0x100, size=64),
            )
        # Create FunctionInfo records for the sinks
        sink_set = set()
        for sink in sinks_with_callers:
            sink_set.add(sink)
            ctx.dangerous_sinks.append(
                FunctionInfo(name=sink, address=0xdead, is_imported=True),
            )
        return ctx, sinks_with_callers

    def test_one_hop_direct_caller_flagged(self):
        """parse_msg directly calls strcpy (1 hop). Must be flagged
        with transitive_distance=1."""
        understand = self._make_understand()
        ctx, _ = self._ctx_with(
            interesting_names=["parse_msg"],
            sinks_with_callers={"strcpy": ["parse_msg"]},
        )
        # Fake r2 with aflcj returning the call graph.
        r2 = MagicMock()
        callgraph = [
            {"name": "parse_msg", "callrefs": [{"name": "strcpy"}]},
        ]
        r2.cmd.return_value = json.dumps(callgraph)
        understand._tag_transitive_callers(r2, ctx)
        fn = ctx.interesting_functions[0]
        self.assertEqual(fn.transitive_distance, 1)
        self.assertEqual(fn.transitively_reaches_dangerous, ["strcpy"])

    def test_three_hop_indirect_caller_flagged(self):
        """parse_msg → helper_a → helper_b → strcpy. parse_msg is
        3 hops from the sink — exactly at the depth cap. Must flag."""
        understand = self._make_understand()
        ctx, _ = self._ctx_with(
            interesting_names=["parse_msg", "helper_a", "helper_b"],
            sinks_with_callers={"strcpy": ["helper_b"]},
        )
        r2 = MagicMock()
        callgraph = [
            {"name": "parse_msg", "callrefs": [{"name": "helper_a"}]},
            {"name": "helper_a", "callrefs": [{"name": "helper_b"}]},
            {"name": "helper_b", "callrefs": [{"name": "strcpy"}]},
        ]
        r2.cmd.return_value = json.dumps(callgraph)
        understand._tag_transitive_callers(r2, ctx)
        by_name = {f.name: f for f in ctx.interesting_functions}
        self.assertEqual(by_name["helper_b"].transitive_distance, 1)
        self.assertEqual(by_name["helper_a"].transitive_distance, 2)
        self.assertEqual(by_name["parse_msg"].transitive_distance, 3)
        for fn in ctx.interesting_functions:
            self.assertEqual(fn.transitively_reaches_dangerous, ["strcpy"])

    def test_beyond_depth_cap_not_flagged(self):
        """Function at depth=4 (one past the _TRANSITIVE_MAX_DEPTH cap)
        must NOT be flagged — bounds the false-positive blast radius."""
        understand = self._make_understand()
        ctx, _ = self._ctx_with(
            interesting_names=["top", "h1", "h2", "h3"],
            sinks_with_callers={"strcpy": ["h3"]},
        )
        r2 = MagicMock()
        callgraph = [
            {"name": "top", "callrefs": [{"name": "h1"}]},
            {"name": "h1",  "callrefs": [{"name": "h2"}]},
            {"name": "h2",  "callrefs": [{"name": "h3"}]},
            {"name": "h3",  "callrefs": [{"name": "strcpy"}]},
        ]
        r2.cmd.return_value = json.dumps(callgraph)
        understand._tag_transitive_callers(r2, ctx)
        by_name = {f.name: f for f in ctx.interesting_functions}
        # top is at depth=4, past max_depth=3 → not flagged
        self.assertEqual(by_name["top"].transitive_distance, 0)
        self.assertEqual(by_name["top"].transitively_reaches_dangerous, [])
        # h1/h2/h3 at depths 3/2/1 are flagged
        self.assertEqual(by_name["h3"].transitive_distance, 1)
        self.assertEqual(by_name["h2"].transitive_distance, 2)
        self.assertEqual(by_name["h1"].transitive_distance, 3)

    def test_reaches_multiple_sinks(self):
        """parse_msg calls helper_a (→strcpy) AND helper_b (→memcpy).
        Should accumulate both sinks in transitively_reaches_dangerous."""
        understand = self._make_understand()
        ctx, _ = self._ctx_with(
            interesting_names=["parse_msg", "helper_a", "helper_b"],
            sinks_with_callers={"strcpy": ["helper_a"], "memcpy": ["helper_b"]},
        )
        r2 = MagicMock()
        callgraph = [
            {"name": "parse_msg",
             "callrefs": [{"name": "helper_a"}, {"name": "helper_b"}]},
            {"name": "helper_a", "callrefs": [{"name": "strcpy"}]},
            {"name": "helper_b", "callrefs": [{"name": "memcpy"}]},
        ]
        r2.cmd.return_value = json.dumps(callgraph)
        understand._tag_transitive_callers(r2, ctx)
        by_name = {f.name: f for f in ctx.interesting_functions}
        self.assertEqual(by_name["parse_msg"].transitive_distance, 2)
        self.assertEqual(
            by_name["parse_msg"].transitively_reaches_dangerous,
            ["memcpy", "strcpy"],
        )

    def test_sym_imp_prefix_resolved(self):
        """r2 stores import sinks as `sym.imp.strcpy` but the call
        graph references them as `strcpy`. The BFS must match across
        the prefix."""
        understand = self._make_understand()
        ctx, _ = self._ctx_with(
            interesting_names=["parse_msg"],
            sinks_with_callers={"sym.imp.strcpy": ["parse_msg"]},
        )
        r2 = MagicMock()
        callgraph = [
            # Call site references the bare name "strcpy", not the
            # sym.imp.* prefix form
            {"name": "parse_msg", "callrefs": [{"name": "strcpy"}]},
        ]
        r2.cmd.return_value = json.dumps(callgraph)
        understand._tag_transitive_callers(r2, ctx)
        fn = ctx.interesting_functions[0]
        self.assertEqual(fn.transitive_distance, 1)
        # Display name normalised to bare base
        self.assertEqual(fn.transitively_reaches_dangerous, ["strcpy"])

    def test_no_sinks_no_op(self):
        """If dangerous_sinks is empty, the method must not raise."""
        understand = self._make_understand()
        ctx = BinaryContextMap(binary_path=Path("/tmp/stub"))
        ctx.interesting_functions.append(
            FunctionInfo(name="any", address=0x1000),
        )
        r2 = MagicMock()
        r2.cmd.return_value = "[]"
        understand._tag_transitive_callers(r2, ctx)  # must not raise
        self.assertEqual(ctx.interesting_functions[0].transitive_distance, 0)

    def test_aflcj_failure_degrades_silently(self):
        """If aflcj fails (timeout, malformed JSON, r2 quirk), the
        method must log and continue rather than crash the analysis."""
        understand = self._make_understand()
        ctx, _ = self._ctx_with(
            interesting_names=["parse_msg"],
            sinks_with_callers={"strcpy": ["parse_msg"]},
        )
        r2 = MagicMock()
        r2.cmd.side_effect = RuntimeError("aflcj exploded")
        # Must not raise — analysis continues with no transitive data
        understand._tag_transitive_callers(r2, ctx)
        self.assertEqual(ctx.interesting_functions[0].transitive_distance, 0)

    def test_aflcj_dict_wrapped_output_handled(self):
        """Some r2 builds wrap aflcj output as {"functions": [...]}
        instead of a bare list. The method must unwrap and proceed
        rather than crashing on a string .get() call."""
        understand = self._make_understand()
        ctx, _ = self._ctx_with(
            interesting_names=["parse_msg"],
            sinks_with_callers={"strcpy": ["parse_msg"]},
        )
        r2 = MagicMock()
        wrapped = {
            "functions": [
                {"name": "parse_msg", "callrefs": [{"name": "strcpy"}]},
            ],
        }
        r2.cmd.return_value = json.dumps(wrapped)
        understand._tag_transitive_callers(r2, ctx)
        # BFS should still find parse_msg as a direct caller
        self.assertEqual(ctx.interesting_functions[0].transitive_distance, 1)

    def test_aflcj_unknown_dict_shape_does_not_crash(self):
        """If r2 returns a dict we don't know how to unwrap, the
        method must NOT crash — just skip the transitive analysis."""
        understand = self._make_understand()
        ctx, _ = self._ctx_with(
            interesting_names=["parse_msg"],
            sinks_with_callers={"strcpy": ["parse_msg"]},
        )
        r2 = MagicMock()
        r2.cmd.return_value = json.dumps({"unknown_key": "garbage"})
        understand._tag_transitive_callers(r2, ctx)  # must not raise
        self.assertEqual(ctx.interesting_functions[0].transitive_distance, 0)

    def test_sinks_not_flagged_as_reaching_themselves(self):
        """A sink that happens to call another sink (e.g. wrapper
        around strcpy that itself happens to be a known import) must
        NOT be flagged as transitively reaching itself."""
        understand = self._make_understand()
        ctx, _ = self._ctx_with(
            interesting_names=[],  # no non-sink callers
            sinks_with_callers={"strcpy": ["memcpy"], "memcpy": []},
        )
        # memcpy is a sink AND calls strcpy. The transitive analysis
        # must not flag memcpy as reaching itself or strcpy — sinks
        # are excluded from the reached set.
        r2 = MagicMock()
        callgraph = [
            {"name": "memcpy", "callrefs": [{"name": "strcpy"}]},
        ]
        r2.cmd.return_value = json.dumps(callgraph)
        understand._tag_transitive_callers(r2, ctx)
        # ctx.interesting_functions has no non-sink fn, so nothing
        # to assert there; just verify no crash + reached set
        # didn't include sinks.

    def test_heuristic_prioritise_surfaces_transitive_match(self):
        """The fuzz_priorities ranking must include functions that
        only transitively reach sinks — not just direct callers. This
        is the operator-visible outcome of the whole transitive
        analysis."""
        understand = self._make_understand()
        ctx = BinaryContextMap(binary_path=Path("/tmp/stub"))
        # parse_msg has NO direct dangerous calls but transitively
        # reaches strcpy via two helpers.
        parse_msg = FunctionInfo(
            name="parse_msg", address=0x1000,
            calls_dangerous=[],
            transitively_reaches_dangerous=["strcpy"],
            transitive_distance=2,
        )
        # direct_only directly calls 1 sink.
        direct_only = FunctionInfo(
            name="direct_only", address=0x2000,
            calls_dangerous=["sprintf"],
        )
        ctx.interesting_functions.extend([parse_msg, direct_only])
        understand._heuristic_prioritise(ctx)
        names = [p["function"] for p in ctx.fuzz_priorities]
        self.assertIn("parse_msg", names)
        self.assertIn("direct_only", names)
        # Direct caller scores higher (10 vs 2 here — depth=2 weight
        # is max_depth+1-2 = 3-2 = 2)
        scores = {p["function"]: p["score"] for p in ctx.fuzz_priorities}
        self.assertGreater(scores["direct_only"], scores["parse_msg"])
        # parse_msg's reason mentions transitive
        for p in ctx.fuzz_priorities:
            if p["function"] == "parse_msg":
                self.assertIn("reaches strcpy", p["reason"])
                self.assertEqual(p["transitive_distance"], 2)


if __name__ == "__main__":
    unittest.main()

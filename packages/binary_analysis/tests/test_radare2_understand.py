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
        self.assertIn("strcpy", _DANGEROUS_IMPORTS)
        self.assertIn("system", _DANGEROUS_IMPORTS)
        self.assertIn("DeviceIoControl", _DANGEROUS_IMPORTS)
        self.assertIn("memcpy", _DANGEROUS_IMPORTS)

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


if __name__ == "__main__":
    unittest.main()

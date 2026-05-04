"""Tests for binary-level adversarial analysis via radare2."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from packages.fuzzing.binary_understand import (
    BinaryContextMap,
    BinaryUnderstand,
    FunctionInfo,
    _DANGEROUS_IMPORTS,
    _ENTRY_POINT_HINTS,
    probe_capability,
)


class TestProbeCapability(unittest.TestCase):
    @patch("packages.fuzzing.binary_understand.shutil.which")
    def test_no_radare2(self, mock_which):
        mock_which.return_value = None
        cap = probe_capability()
        self.assertFalse(cap["available"])
        self.assertIsNone(cap["decompiler"])

    @patch("packages.fuzzing.binary_understand.shutil.which")
    def test_radare2_without_r2pipe(self, mock_which):
        mock_which.return_value = "/usr/bin/r2"
        with patch.dict("sys.modules", {"r2pipe": None}):
            # Force ImportError by pretending the module is None
            with patch("builtins.__import__", side_effect=ImportError):
                cap = probe_capability()
        self.assertFalse(cap["has_r2pipe"])
        self.assertFalse(cap["available"])

    @patch("packages.fuzzing.binary_understand.shutil.which")
    @patch("packages.fuzzing.binary_understand.subprocess.run")
    def test_radare2_with_r2pipe_no_ghidra(self, mock_run, mock_which):
        mock_which.return_value = "/usr/bin/r2"
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        with patch.dict("sys.modules", {"r2pipe": MagicMock()}):
            cap = probe_capability()
        self.assertTrue(cap["available"])
        self.assertEqual(cap["decompiler"], "pdc")

    @patch("packages.fuzzing.binary_understand.shutil.which")
    @patch("packages.fuzzing.binary_understand.subprocess.run")
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
    @patch("packages.fuzzing.binary_understand.probe_capability")
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

    @patch("packages.fuzzing.binary_understand.probe_capability")
    def test_init_raises_for_missing_binary(self, mock_probe):
        mock_probe.return_value = {"available": True, "decompiler": "pdc",
                                    "has_r2pipe": True, "has_r2ghidra": False,
                                    "r2_bin": "/usr/bin/r2"}
        with self.assertRaises(FileNotFoundError):
            BinaryUnderstand(Path("/nonexistent/raptor_probe_binary"))

    @patch("packages.fuzzing.binary_understand.probe_capability")
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


if __name__ == "__main__":
    unittest.main()

"""Tests for target detection."""

import os
import platform
import tempfile
import unittest
from pathlib import Path

from packages.fuzzing.target_detector import detect, TargetInfo


# Magic byte fixtures
ELF_MAGIC = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00" + b"\x3e\x00" + b"\x00" * 32
MACHO_64_LE_MAGIC = b"\xcf\xfa\xed\xfe" + b"\x00" * 60
PE_MAGIC = b"MZ" + b"\x00" * 60


class TestDetect(unittest.TestCase):
    def test_nonexistent_path_returns_unknown(self):
        info = detect(Path("/this/path/does/not/exist/raptor_probe"))
        self.assertEqual(info.kind, "unknown")
        self.assertIn("does not exist", info.description)

    def test_elf_binary_detection(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(ELF_MAGIC)
            f.write(b"\x00" * 1024)
            tmp = Path(f.name)
        try:
            tmp.chmod(0o755)
            info = detect(tmp)
            self.assertEqual(info.kind, "elf-linux")
            self.assertEqual(info.arch, "x86_64")
            if platform.system() == "Linux":
                self.assertTrue(info.can_fuzz_here)
            else:
                self.assertFalse(info.can_fuzz_here)
                self.assertTrue(any("do not run on" in b for b in info.blockers))
        finally:
            os.unlink(tmp)

    def test_macho_binary_detection(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(MACHO_64_LE_MAGIC)
            f.write(b"\x00" * 1024)
            tmp = Path(f.name)
        try:
            tmp.chmod(0o755)
            info = detect(tmp)
            self.assertEqual(info.kind, "macho")
            self.assertEqual(info.arch, "64-bit")
        finally:
            os.unlink(tmp)

    def test_pe_executable_detection(self):
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(PE_MAGIC)
            tmp = Path(f.name)
        try:
            info = detect(tmp)
            self.assertEqual(info.kind, "pe-exe")
            self.assertEqual(info.recommended_fuzzer, "winafl")
            if platform.system() != "Windows":
                self.assertFalse(info.can_fuzz_here)
        finally:
            os.unlink(tmp)

    def test_pe_dll_detection(self):
        with tempfile.NamedTemporaryFile(suffix=".dll", delete=False) as f:
            f.write(PE_MAGIC)
            tmp = Path(f.name)
        try:
            info = detect(tmp)
            self.assertEqual(info.kind, "pe-dll")
        finally:
            os.unlink(tmp)

    def test_pe_sys_detection_provides_kernel_fuzzing_hints(self):
        """Windows kernel drivers must produce clear, actionable guidance."""
        with tempfile.NamedTemporaryFile(suffix=".sys", delete=False) as f:
            f.write(PE_MAGIC)
            tmp = Path(f.name)
        try:
            info = detect(tmp)
            self.assertEqual(info.kind, "pe-sys")
            self.assertIn("kernel driver", info.description.lower())
            # Must mention the available approaches
            text = " ".join(info.hints + info.blockers).lower()
            self.assertTrue("kafl" in text or "snapchange" in text or "ioctl" in text)
        finally:
            os.unlink(tmp)

    def test_c_source_file_detected(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
            f.write("int main(void){ return 0; }\n")
            tmp = Path(f.name)
        try:
            info = detect(tmp)
            self.assertEqual(info.kind, "source-c")
            self.assertFalse(info.can_fuzz_here)
            self.assertTrue(any("harness" in h.lower() for h in info.hints))
        finally:
            os.unlink(tmp)

    def test_cpp_header_detected(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".hpp", delete=False) as f:
            f.write("#pragma once\nvoid foo(int x);\n")
            tmp = Path(f.name)
        try:
            info = detect(tmp)
            self.assertEqual(info.kind, "source-cpp")
        finally:
            os.unlink(tmp)

    def test_unknown_file_format(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\xde\xad\xbe\xef" * 16)
            tmp = Path(f.name)
        try:
            info = detect(tmp)
            self.assertEqual(info.kind, "unknown")
        finally:
            os.unlink(tmp)

    def test_directory_with_no_markers_returns_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            info = detect(Path(tmp))
            self.assertEqual(info.kind, "unknown")

    def test_target_info_summary(self):
        info = TargetInfo(
            path=Path("/tmp/test"), kind="elf-linux", arch="x86_64",
            description="Linux ELF binary", can_fuzz_here=True,
            recommended_fuzzer="afl",
            hints=["use --understand for context"],
        )
        text = info.summary()
        self.assertIn("Target: /tmp/test", text)
        self.assertIn("Kind: elf-linux", text)
        self.assertIn("Recommended fuzzer: afl", text)
        self.assertIn("use --understand", text)


if __name__ == "__main__":
    unittest.main()

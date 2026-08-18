"""Tests for target detection."""

import os
import platform
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from packages.fuzzing.target_detector import detect, TargetInfo


# Magic byte fixtures
ELF_MAGIC = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00" + b"\x3e\x00" + b"\x00" * 32
MACHO_64_LE_MAGIC = b"\xcf\xfa\xed\xfe" + b"\x00" * 60
PE_MAGIC = b"MZ" + b"\x00" * 60


def _fat_macho_fixture(magic: bytes, *, is_64: bool) -> bytes:
    endian = ">" if magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf") else "<"
    entry_size = 32 if is_64 else 20
    payload = bytearray(b"\x00" * 0x140)
    payload[:8] = magic + struct.pack(f"{endian}I", 1)
    if is_64:
        payload[8:8 + entry_size] = struct.pack(f"{endian}IIQQII", 0x0100000C, 0, 0x100, 0x20, 0, 0)
    else:
        payload[8:8 + entry_size] = struct.pack(f"{endian}IIIII", 0x0100000C, 0, 0x100, 0x20, 0)
    payload[0x100:0x120] = b"arm64-slice" + b"\x00" * 21
    return bytes(payload)


def _elf_bytes(*, ei_class: int, machine: int) -> bytes:
    header = bytearray(b"\x00" * 64)
    header[:4] = b"\x7fELF"
    header[4] = ei_class
    header[18:20] = machine.to_bytes(2, "little")
    return bytes(header)


def _write(tmp: str, name: str, data: bytes) -> Path:
    path = Path(tmp) / name
    path.write_bytes(data)
    return path


def _pe_fixture(machine: int) -> bytes:
    data = bytearray(b"\x00" * 256)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"
    data[0x84:0x86] = machine.to_bytes(2, "little")
    return bytes(data)


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

    def test_macho_non_executable_on_darwin_gets_chmod_blocker(self):
        # Parity with _detect_elf: a Mach-O without the execute bit
        # must surface a chmod blocker so plan() rejects cleanly
        # instead of execute() failing mid-run.
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(MACHO_64_LE_MAGIC)
            f.write(b"\x00" * 1024)
            tmp = Path(f.name)
        try:
            tmp.chmod(0o644)
            with patch("packages.fuzzing.target_detector.platform.system",
                       return_value="Darwin"):
                info = detect(tmp)
            self.assertEqual(info.kind, "macho")
            self.assertFalse(info.can_fuzz_here)
            self.assertTrue(any("chmod +x" in b for b in info.blockers))
            # On the native platform the missing execute bit is the
            # only blocker — no cross-platform message.
            self.assertFalse(any("do not run on" in b for b in info.blockers))
        finally:
            os.unlink(tmp)

    def test_macho_executable_on_darwin_has_no_blockers(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(MACHO_64_LE_MAGIC)
            f.write(b"\x00" * 1024)
            tmp = Path(f.name)
        try:
            tmp.chmod(0o755)
            with patch("packages.fuzzing.target_detector.platform.system",
                       return_value="Darwin"):
                info = detect(tmp)
            self.assertTrue(info.can_fuzz_here)
            self.assertEqual(info.blockers, [])
        finally:
            os.unlink(tmp)

    def test_all_fat_macho_variants_are_detected(self):
        for magic, is_64 in (
            (b"\xca\xfe\xba\xbe", False),
            (b"\xbe\xba\xfe\xca", False),
            (b"\xca\xfe\xba\xbf", True),
            (b"\xbf\xba\xfe\xca", True),
        ):
            with self.subTest(magic=magic.hex()):
                with tempfile.NamedTemporaryFile(delete=False) as f:
                    f.write(_fat_macho_fixture(magic, is_64=is_64))
                    tmp = Path(f.name)
                try:
                    tmp.chmod(0o755)
                    info = detect(tmp)
                    self.assertEqual(info.kind, "macho")
                    self.assertEqual(info.arch, "fat")
                finally:
                    os.unlink(tmp)

    def test_java_class_magic_is_not_mislabelled_as_fat_macho(self):
        with tempfile.NamedTemporaryFile(suffix=".class", delete=False) as f:
            f.write(b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 64)
            tmp = Path(f.name)
        try:
            info = detect(tmp)
            self.assertEqual(info.kind, "java-class")
            self.assertIn("java", info.description.lower())
        finally:
            os.unlink(tmp)

    def test_jar_and_apk_archives_are_recognised_for_binary_intake(self):
        for suffix, members, expected in (
            (".jar", {"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n", "Demo.class": b"\xca\xfe\xba\xbe"}, "java-archive"),
            (".apk", {"AndroidManifest.xml": b"<manifest/>", "classes.dex": b"dex\n035\x00"}, "apk"),
        ):
            with self.subTest(suffix=suffix):
                with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
                    tmp = Path(f.name)
                try:
                    with zipfile.ZipFile(tmp, "w") as zf:
                        for name, body in members.items():
                            zf.writestr(name, body)
                    info = detect(tmp)
                    self.assertEqual(info.kind, expected)
                finally:
                    os.unlink(tmp)

    def test_pe_executable_detection(self):
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(_pe_fixture(0x014C))
            tmp = Path(f.name)
        try:
            info = detect(tmp)
            self.assertEqual(info.kind, "pe-exe")
            self.assertEqual(info.arch, "i386")
            self.assertEqual(info.recommended_fuzzer, "winafl")
            if platform.system() != "Windows":
                self.assertFalse(info.can_fuzz_here)
        finally:
            os.unlink(tmp)

    def test_pe_dll_detection(self):
        with tempfile.NamedTemporaryFile(suffix=".dll", delete=False) as f:
            f.write(_pe_fixture(0x8664))
            tmp = Path(f.name)
        try:
            info = detect(tmp)
            self.assertEqual(info.kind, "pe-dll")
            self.assertEqual(info.arch, "x86_64")
        finally:
            os.unlink(tmp)

    def test_pe_sys_detection_provides_kernel_fuzzing_hints(self):
        """Windows kernel drivers must produce clear, actionable guidance."""
        with tempfile.NamedTemporaryFile(suffix=".sys", delete=False) as f:
            f.write(_pe_fixture(0xAA64))
            tmp = Path(f.name)
        try:
            info = detect(tmp)
            self.assertEqual(info.kind, "pe-sys")
            self.assertEqual(info.arch, "arm64")
            self.assertIn("kernel driver", info.description.lower())
            # Must mention the available approaches
            text = " ".join(info.hints + info.blockers).lower()
            self.assertTrue("kafl" in text or "snapchange" in text or "ioctl" in text)
        finally:
            os.unlink(tmp)

    def test_linux_kernel_module_is_not_treated_as_a_user_mode_campaign(self):
        with tempfile.NamedTemporaryFile(suffix=".ko", delete=False) as f:
            f.write(ELF_MAGIC)
            f.write(b"\x00" * 1024)
            tmp = Path(f.name)
        try:
            tmp.chmod(0o755)
            info = detect(tmp)
            self.assertEqual(info.kind, "elf-kmod")
            self.assertFalse(info.can_fuzz_here)
            self.assertIn("kernel module", info.description.lower())
            self.assertTrue(any("harness" in item.lower() for item in info.hints))
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

    def test_unknown_machine_32bit_relabelled(self):
        # A dict-lookup default made arch never equal "unknown", so the
        # 32-bit relabel branch was dead.
        with tempfile.TemporaryDirectory() as tmp:
            info = detect(_write(tmp, "t32", _elf_bytes(ei_class=1, machine=0x1234)))
        self.assertEqual(info.kind, "elf-linux")
        self.assertEqual(info.arch, "32-bit")

    def test_unknown_machine_64bit_keeps_descriptor(self):
        with tempfile.TemporaryDirectory() as tmp:
            info = detect(_write(tmp, "t64", _elf_bytes(ei_class=2, machine=0x1234)))
        self.assertEqual(info.arch, "machine_0x1234")

    def test_known_machine_wins_over_bitness(self):
        with tempfile.TemporaryDirectory() as tmp:
            info = detect(_write(tmp, "t386", _elf_bytes(ei_class=1, machine=0x03)))
        self.assertEqual(info.arch, "i386")

    def test_truncated_header_reports_unknown_arch(self):
        # 19 bytes covers only half of the 2-byte machine field; the
        # guard must not read a partial value.
        with tempfile.TemporaryDirectory() as tmp:
            info = detect(
                _write(tmp, "trunc", _elf_bytes(ei_class=1, machine=0x03)[:19])
            )
        self.assertEqual(info.kind, "elf-linux")
        self.assertEqual(info.arch, "unknown")

    def test_target_info_summary(self):
        info = TargetInfo(
            path=Path("./test"), kind="elf-linux", arch="x86_64",
            description="Linux ELF binary", can_fuzz_here=True,
            recommended_fuzzer="afl",
            hints=["use --understand for context"],
        )
        text = info.summary()
        self.assertIn("Target: test", text)
        self.assertIn("Kind: elf-linux", text)
        self.assertIn("Recommended fuzzer: afl", text)
        self.assertIn("use --understand", text)


class TestRecommendedFuzzerPopulation(unittest.TestCase):
    """Directly orchestratable kinds (rust-crate, python-pkg) null
    recommended_fuzzer when the tool cannot run here, matching
    elf-linux/macho; cross-host handoff kinds (elf-kmod, pe-sys) keep
    naming the external tool."""

    def test_rust_crate_nulls_fuzzer_when_toolchain_missing(self):
        # rust-crate hard-coded "cargo-fuzz" even when the crate cannot
        # be fuzzed on this host.
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "Cargo.toml").write_text("[package]\n")
            with patch("packages.fuzzing.target_detector.shutil.which",
                       return_value=None):
                info = detect(Path(tmp))
        self.assertEqual(info.kind, "rust-crate")
        self.assertFalse(info.can_fuzz_here)
        self.assertIsNone(info.recommended_fuzzer)

    def test_rust_crate_recommends_when_toolchain_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "Cargo.toml").write_text("[package]\n")
            with patch("packages.fuzzing.target_detector.shutil.which",
                       return_value="/x/tool"):
                info = detect(Path(tmp))
        self.assertTrue(info.can_fuzz_here)
        self.assertEqual(info.recommended_fuzzer, "cargo-fuzz")

    def test_python_pkg_nulls_fuzzer_when_atheris_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "pyproject.toml").write_text("[project]\n")
            # None entry in sys.modules makes `import atheris` raise
            # ImportError even if the package is installed.
            with patch.dict(sys.modules, {"atheris": None}):
                info = detect(Path(tmp))
        self.assertEqual(info.kind, "python-pkg")
        self.assertFalse(info.can_fuzz_here)
        self.assertIsNone(info.recommended_fuzzer)

    def test_kernel_module_keeps_cross_host_tool_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            info = detect(
                _write(tmp, "mod.ko", _elf_bytes(ei_class=2, machine=0x3E))
            )
        self.assertEqual(info.kind, "elf-kmod")
        self.assertFalse(info.can_fuzz_here)
        self.assertEqual(info.recommended_fuzzer, "kafl-or-snapchange")


if __name__ == "__main__":
    unittest.main()

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

    def test_big_endian_elf_machine_read_in_file_byte_order(self):
        # e_machine uses the file's own byte order (EI_DATA=2 → MSB).
        # An unconditional little-endian read byte-swapped every
        # big-endian ELF's arch label (s390x 0x16 read as 0x1600).
        be_magic = (
            b"\x7fELF\x02\x02\x01\x00" + b"\x00" * 8   # EI_DATA = 2
            + b"\x00\x02"                              # e_type (BE)
            + b"\x00\x16"                              # e_machine s390x (BE)
        )
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(be_magic)
            f.write(b"\x00" * 1024)
            tmp = Path(f.name)
        try:
            tmp.chmod(0o755)
            info = detect(tmp)
            self.assertEqual(info.kind, "elf-linux")
            self.assertEqual(info.arch, "machine_0x16")
        finally:
            os.unlink(tmp)

    def test_little_endian_elf_machine_unchanged(self):
        # Direction two: the LE read stays correct.
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(ELF_MAGIC)
            f.write(b"\x00" * 1024)
            tmp = Path(f.name)
        try:
            tmp.chmod(0o755)
            self.assertEqual(detect(tmp).arch, "x86_64")
        finally:
            os.unlink(tmp)

    def test_directory_c_detection_single_walk(self):
        # Nested C sources are still recognised through the
        # single-walk scan (the per-extension '**' globs it replaced
        # cost up to five full traversals on non-C trees).
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            deep = root / "src" / "lib"
            deep.mkdir(parents=True)
            (deep / "parser.c").write_text("int main(void){return 0;}\n")
            self.assertEqual(detect(root).kind, "source-c")

    def test_directory_without_c_sources_is_unknown(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "docs").mkdir()
            (root / "docs" / "readme.md").write_text("hi\n")
            self.assertEqual(detect(root).kind, "unknown")

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


class TestSourceTreeWithoutHeaders:
    """S5.5: a C/C++ repo whose sources are all .c/.cc (no headers at
    the top of the tree) must classify as source-c, not unknown —
    env build-on-demand plans from that kind."""

    def test_c_only_dir_is_source_c(self, tmp_path):
        (tmp_path / "main.c").write_text("int main(void){return 0;}\n")
        info = detect(tmp_path)
        assert info.kind == "source-c"

    def test_cpp_only_dir_is_source_c(self, tmp_path):
        (tmp_path / "main.cpp").write_text("int main(){return 0;}\n")
        info = detect(tmp_path)
        assert info.kind == "source-c"

    def test_marker_files_still_win(self, tmp_path):
        (tmp_path / "Cargo.toml").write_text("[package]\nname='x'\n")
        (tmp_path / "main.c").write_text("int main(void){return 0;}\n")
        info = detect(tmp_path)
        assert info.kind == "rust-crate"


class TestCFamilyExtensionParity(unittest.TestCase):
    """File mode and directory mode must recognise the same C/C++
    extension set — a pure-.cxx tree detected `unknown` while a single
    .cxx file detected `source-cpp` (drifted hand-copies)."""

    def test_pure_cxx_tree_detected_as_c_family(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "lib.cxx").write_text("int f() { return 0; }\n")
            info = detect(root)
            self.assertNotEqual(info.kind, "unknown")
            self.assertTrue(info.kind.startswith("source-c"))

    def test_hh_and_hxx_trees_detected(self):
        for ext in (".hh", ".hxx"):
            with tempfile.TemporaryDirectory() as d:
                root = Path(d)
                (root / f"lib{ext}").write_text("struct S;\n")
                info = detect(root)
                self.assertNotEqual(
                    info.kind, "unknown",
                    f"{ext} tree must be detected as C/C++",
                )

    def test_modes_share_one_extension_set(self):
        """Drift oracle: both modes must consume the same frozenset."""
        from packages.fuzzing import target_detector as td

        self.assertEqual(
            td._C_FAMILY_EXTS,
            td._C_SOURCE_EXTS | td._CPP_SOURCE_EXTS,
        )


class TestTerseExecutableDetection(unittest.TestCase):
    """TE (Terse Executable) UEFI images: classify-and-decline."""

    def test_te_magic_detected_with_machine_arch(self):
        with tempfile.TemporaryDirectory() as tmp:
            # "VZ" signature + IA-32 machine + padding.
            path = _write(tmp, "driver.efi",
                          b"VZ" + (0x8664).to_bytes(2, "little")
                          + b"\x00" * 60)
            info = detect(path)
        self.assertEqual(info.kind, "te")
        self.assertEqual(info.arch, "x86_64")
        self.assertFalse(info.can_fuzz_here)
        self.assertIsNone(info.recommended_fuzzer)

    def test_te_kind_is_not_a_pe_kind(self):
        """Two downstream consumers key Windows behavior off the
        "pe-" prefix (platform labelling, driver-symbol ingress
        probing); a "pe-te" spelling would hand UEFI firmware both.
        The kind must never grow that prefix."""
        with tempfile.TemporaryDirectory() as tmp:
            info = detect(_write(tmp, "img.te", b"VZ" + b"\x00" * 62))
        self.assertEqual(info.kind, "te")
        self.assertFalse(info.kind.startswith("pe-"))

    def test_te_emits_not_analysed_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            info = detect(_write(tmp, "img.te", b"VZ" + b"\x00" * 62))
        self.assertTrue(any(b.startswith("te_not_analysed")
                            for b in info.blockers))

    def test_truncated_te_still_classifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            info = detect(_write(tmp, "stub.te", b"VZ"))
        self.assertEqual(info.kind, "te")
        self.assertEqual(info.arch, "unknown")

    def test_unknown_te_machine_falls_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            info = detect(_write(tmp, "odd.te",
                                 b"VZ\xbc\x0e" + b"\x00" * 60))
        self.assertEqual(info.kind, "te")
        self.assertEqual(info.arch, "machine_0xebc")

    def test_mz_path_undisturbed_by_te_branch(self):
        """An MZ image carrying "VZ" bytes right behind the DOS
        magic is still PE; a VZ image is never PE."""
        with tempfile.TemporaryDirectory() as tmp:
            data = bytearray(_pe_fixture(0x8664))
            data[2:4] = b"VZ"
            pe_info = detect(_write(tmp, "prog.exe", bytes(data)))
            te_info = detect(_write(tmp, "img.te",
                                    b"VZ" + b"\x00" * 62))
        self.assertEqual(pe_info.kind, "pe-exe")
        self.assertEqual(te_info.kind, "te")


class TestCargoFuzzLayout(unittest.TestCase):
    """cargo-fuzz layout detection: fuzz-dir location, target
    enumeration (charset-vetted, symlink-refusing, bounded), and the
    rust-crate hints that carry the result."""

    def _crate(self, tmp: str, targets: list[str]) -> Path:
        crate = Path(tmp) / "crate"
        (crate / "fuzz" / "fuzz_targets").mkdir(parents=True)
        (crate / "Cargo.toml").write_text("[package]\nname='c'\n")
        (crate / "fuzz" / "Cargo.toml").write_text(
            "[package]\nname='c-fuzz'\n"
            "[package.metadata]\ncargo-fuzz = true\n")
        for name in targets:
            (crate / "fuzz" / "fuzz_targets" / f"{name}.rs").write_text(
                "// ft\n")
        return crate

    def test_conventional_fuzz_child_found(self):
        from packages.fuzzing.target_detector import (
            find_cargo_fuzz_dir,
            list_cargo_fuzz_targets,
        )
        with tempfile.TemporaryDirectory() as tmp:
            crate = self._crate(tmp, ["fuzz_a", "fuzz_b"])
            fuzz_dir = find_cargo_fuzz_dir(crate)
            self.assertEqual(fuzz_dir, (crate / "fuzz").resolve())
            self.assertEqual(list_cargo_fuzz_targets(fuzz_dir),
                             ["fuzz_a", "fuzz_b"])

    def test_fuzz_workspace_itself_qualifies(self):
        # Operators can point /fuzz straight at the fuzz workspace.
        from packages.fuzzing.target_detector import find_cargo_fuzz_dir
        with tempfile.TemporaryDirectory() as tmp:
            crate = self._crate(tmp, ["fuzz_a"])
            self.assertEqual(find_cargo_fuzz_dir(crate / "fuzz"),
                             (crate / "fuzz").resolve())

    def test_symlinked_fuzz_dir_outside_the_crate_is_refused(self):
        # The fuzz workspace receives a build-phase write grant: a
        # repo-planted `fuzz` symlink pointing at a cargo-fuzz-shaped
        # tree elsewhere on the host must not steer that grant there.
        from packages.fuzzing.target_detector import find_cargo_fuzz_dir
        with tempfile.TemporaryDirectory() as tmp:
            elsewhere = self._crate(tmp, ["fuzz_a"])  # tmp/crate
            victim_fuzz = elsewhere / "fuzz"
            crate2 = Path(tmp) / "crate2"
            crate2.mkdir()
            (crate2 / "Cargo.toml").write_text("[package]\n")
            (crate2 / "fuzz").symlink_to(victim_fuzz)
            self.assertIsNone(find_cargo_fuzz_dir(crate2))

    def test_symlinked_fuzz_targets_dir_outside_the_crate_is_refused(self):
        # Symmetric containment one level down: fuzz/ itself real, but
        # fuzz_targets a symlink escaping the crate — the enumeration
        # must not follow it off the crate.
        from packages.fuzzing.target_detector import find_cargo_fuzz_dir
        with tempfile.TemporaryDirectory() as tmp:
            elsewhere = self._crate(tmp, ["fuzz_a"])   # tmp/crate
            victim_targets = elsewhere / "fuzz" / "fuzz_targets"
            crate2 = Path(tmp) / "crate2"
            (crate2 / "fuzz").mkdir(parents=True)
            (crate2 / "Cargo.toml").write_text("[package]\n")
            (crate2 / "fuzz" / "Cargo.toml").write_text("[package]\n")
            (crate2 / "fuzz" / "fuzz_targets").symlink_to(victim_targets)
            self.assertIsNone(find_cargo_fuzz_dir(crate2))

    def test_symlinked_fuzz_dir_inside_the_crate_is_allowed(self):
        # Containment is about escaping the crate, not about symlinks
        # per se: a fuzz -> ./real-fuzz indirection inside the crate
        # resolves and is granted on the REAL path.
        from packages.fuzzing.target_detector import find_cargo_fuzz_dir
        with tempfile.TemporaryDirectory() as tmp:
            crate = Path(tmp) / "crate"
            real = crate / "real-fuzz"
            (real / "fuzz_targets").mkdir(parents=True)
            (crate / "Cargo.toml").write_text("[package]\n")
            (real / "Cargo.toml").write_text("[package]\n")
            (real / "fuzz_targets" / "fuzz_a.rs").write_text("// ft\n")
            (crate / "fuzz").symlink_to(real)
            self.assertEqual(find_cargo_fuzz_dir(crate), real.resolve())

    def test_no_layout_returns_none(self):
        from packages.fuzzing.target_detector import find_cargo_fuzz_dir
        with tempfile.TemporaryDirectory() as tmp:
            crate = Path(tmp) / "crate"
            crate.mkdir()
            (crate / "Cargo.toml").write_text("[package]\n")
            self.assertIsNone(find_cargo_fuzz_dir(crate))

    def test_enumeration_vets_names_and_refuses_symlinks(self):
        # fuzz_targets/ is scanned-repo content: hostile names (shell
        # metacharacters, path separators via encoding tricks) and
        # symlinked entries never enter the target list.
        from packages.fuzzing.target_detector import (
            find_cargo_fuzz_dir,
            list_cargo_fuzz_targets,
        )
        with tempfile.TemporaryDirectory() as tmp:
            crate = self._crate(tmp, ["good_one"])
            targets_dir = crate / "fuzz" / "fuzz_targets"
            (targets_dir / "bad name$(x).rs").write_text("// ft\n")
            (targets_dir / ("x" * 80 + ".rs")).write_text("// ft\n")
            (targets_dir / "not_rust.txt").write_text("hi\n")
            (targets_dir / "linked.rs").symlink_to(
                targets_dir / "good_one.rs")
            fuzz_dir = find_cargo_fuzz_dir(crate)
            self.assertEqual(list_cargo_fuzz_targets(fuzz_dir),
                             ["good_one"])

    def test_enumeration_is_bounded(self):
        from packages.fuzzing import target_detector as td
        # Fixture scale guard: this test creates bound+5 real files, so
        # a bound raised past 1024 needs a rewritten fixture, not a
        # bigger tree.
        self.assertLessEqual(td._MAX_CARGO_FUZZ_TARGETS, 1024)
        with tempfile.TemporaryDirectory() as tmp:
            crate = self._crate(
                tmp,
                [f"t{i:04d}" for i in range(td._MAX_CARGO_FUZZ_TARGETS + 5)],
            )
            fuzz_dir = td.find_cargo_fuzz_dir(crate)
            self.assertEqual(len(td.list_cargo_fuzz_targets(fuzz_dir)),
                             td._MAX_CARGO_FUZZ_TARGETS)

    def test_rust_crate_hint_names_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            crate = self._crate(tmp, ["fuzz_a"])
            with patch("packages.fuzzing.target_detector.shutil.which",
                       return_value="/x/tool"):
                info = detect(crate)
        self.assertEqual(info.kind, "rust-crate")
        self.assertTrue(any("fuzz_a" in h for h in info.hints), info.hints)

    def test_rust_crate_hint_without_layout_names_scaffold(self):
        with tempfile.TemporaryDirectory() as tmp:
            crate = Path(tmp) / "crate"
            crate.mkdir()
            (crate / "Cargo.toml").write_text("[package]\n")
            with patch("packages.fuzzing.target_detector.shutil.which",
                       return_value="/x/tool"):
                info = detect(crate)
        self.assertTrue(
            any("cargo fuzz init" in h for h in info.hints), info.hints)


class TestJazzerLayout(unittest.TestCase):
    """Jazzer target enumeration: harness discovery across Maven /
    Gradle / bare layouts, class-name derivation (charset-vetted,
    symlink-refusing, bounded), and the java-project hints that carry
    the result."""

    _HARNESS = (
        "package com.example.fuzz;\n"
        "public class ParserFuzz {\n"
        "    public static void fuzzerTestOneInput(byte[] data) {}\n"
        "}\n"
    )

    def _project(self, tmp: str, marker: str | None = "pom.xml",
                 harness_rel: str = (
                     "src/test/java/com/example/fuzz/ParserFuzz.java"),
                 harness_text: str | None = None) -> Path:
        project = Path(tmp) / "proj"
        project.mkdir()
        if marker:
            (project / marker).write_text("<project/>\n")
        harness = project / harness_rel
        harness.parent.mkdir(parents=True, exist_ok=True)
        harness.write_text(harness_text if harness_text is not None
                           else self._HARNESS)
        return project

    def test_maven_layout_enumerates_fqcn(self):
        from packages.fuzzing.target_detector import list_jazzer_targets
        with tempfile.TemporaryDirectory() as tmp:
            project = self._project(tmp)
            targets = list_jazzer_targets(project)
        self.assertEqual([t.class_name for t in targets],
                         ["com.example.fuzz.ParserFuzz"])
        self.assertTrue(targets[0].source.name == "ParserFuzz.java")

    def test_gradle_layout_and_fuzztest_annotation(self):
        from packages.fuzzing.target_detector import list_jazzer_targets
        junit = (
            "package com.example;\n"
            "import com.code_intelligence.jazzer.junit.FuzzTest;\n"
            "class ApiFuzzTest {\n"
            "    @FuzzTest\n"
            "    void fuzz(byte[] data) {}\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            project = self._project(
                tmp, marker="build.gradle.kts",
                harness_rel="src/test/java/com/example/ApiFuzzTest.java",
                harness_text=junit)
            targets = list_jazzer_targets(project)
        self.assertEqual([t.class_name for t in targets],
                         ["com.example.ApiFuzzTest"])

    def test_bare_layout_without_package_uses_stem(self):
        from packages.fuzzing.target_detector import list_jazzer_targets
        bare = ("public class BareFuzz {\n"
                "  public static void fuzzerTestOneInput(byte[] d) {}\n"
                "}\n")
        with tempfile.TemporaryDirectory() as tmp:
            project = self._project(tmp, marker=None,
                                    harness_rel="BareFuzz.java",
                                    harness_text=bare)
            targets = list_jazzer_targets(project)
        self.assertEqual([t.class_name for t in targets], ["BareFuzz"])

    def test_kotlin_package_line_without_semicolon(self):
        from packages.fuzzing.target_detector import list_jazzer_targets
        kt = ("package com.example.kfuzz\n"
              "object KFuzz {\n"
              "    @JvmStatic fun fuzzerTestOneInput(data: ByteArray) {}\n"
              "}\n")
        with tempfile.TemporaryDirectory() as tmp:
            project = self._project(tmp,
                                    harness_rel="src/KFuzz.kt",
                                    harness_text=kt)
            targets = list_jazzer_targets(project)
        self.assertEqual([t.class_name for t in targets],
                         ["com.example.kfuzz.KFuzz"])

    def test_hostile_names_and_symlinks_never_enter_the_list(self):
        # The tree is scanned-repo content: hostile file stems (shell
        # metacharacters, spaces), hostile package lines, symlinked
        # files, and build-output copies never enter the target list.
        from packages.fuzzing.target_detector import list_jazzer_targets
        with tempfile.TemporaryDirectory() as tmp:
            project = self._project(tmp)
            src = project / "src"
            (src / "bad name$(x).java").write_text(self._HARNESS)
            (src / ("X" * 200 + ".java")).write_text(self._HARNESS)
            (src / "Linked.java").symlink_to(
                project / "src/test/java/com/example/fuzz/ParserFuzz.java")
            outside = Path(tmp) / "outside"
            outside.mkdir()
            (outside / "Victim.java").write_text(self._HARNESS)
            (src / "linkdir").symlink_to(outside)
            (project / "target" / "generated").mkdir(parents=True)
            (project / "target" / "generated" / "Copy.java").write_text(
                self._HARNESS)
            targets = list_jazzer_targets(project)
        self.assertEqual([t.class_name for t in targets],
                         ["com.example.fuzz.ParserFuzz"])

    def test_hostile_package_line_falls_back_to_vetted_stem(self):
        # A package line that fails the identifier charset is treated
        # as no package (the stem alone still names a real class in
        # the default package for a copied-in harness) — never spliced
        # into the class name.
        from packages.fuzzing.target_detector import list_jazzer_targets
        with tempfile.TemporaryDirectory() as tmp:
            project = self._project(
                tmp, harness_rel="src/StemFuzz.java",
                harness_text=("package ../../etc;\n"
                              "class StemFuzz {\n"
                              "  static void fuzzerTestOneInput() {}\n"
                              "}\n"))
            targets = list_jazzer_targets(project)
        self.assertEqual([t.class_name for t in targets], ["StemFuzz"])

    def test_enumeration_is_bounded(self):
        from packages.fuzzing import target_detector as td
        # Fixture scale guard: this test creates bound+5 real files, so
        # a bound raised past 1024 needs a rewritten fixture, not a
        # bigger tree.
        self.assertLessEqual(td._MAX_JAZZER_TARGETS, 1024)
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "proj"
            src = project / "src"
            src.mkdir(parents=True)
            (project / "pom.xml").write_text("<project/>\n")
            for i in range(td._MAX_JAZZER_TARGETS + 5):
                (src / f"F{i:04d}.java").write_text(
                    f"class F{i:04d} {{\n"
                    "  static void fuzzerTestOneInput(byte[] d) {}\n"
                    "}\n")
            targets = td.list_jazzer_targets(project)
        self.assertEqual(len(targets), td._MAX_JAZZER_TARGETS)

    def test_file_scan_is_bounded(self):
        # The walk itself is bounded: a planted tree of JVM-extension
        # files must stop the scan at the file cap, not walk millions
        # of entries. The cap is patched down so the fixture stays
        # small; the harness sorts AFTER the decoys and must never be
        # reached.
        from packages.fuzzing import target_detector as td
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "proj"
            src = project / "src"
            src.mkdir(parents=True)
            (project / "pom.xml").write_text("<project/>\n")
            for i in range(20):
                (src / f"a{i:03d}Decoy.java").write_text("class D {}\n")
            (src / "zzzFuzz.java").write_text(
                "class zzzFuzz {\n"
                "  static void fuzzerTestOneInput(byte[] d) {}\n"
                "}\n")
            with patch.object(td, "_MAX_JAZZER_SCAN_FILES", 10):
                targets = td.list_jazzer_targets(project)
        self.assertEqual(targets, [])

    def test_java_project_hint_names_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = self._project(tmp)
            with patch("packages.fuzzing.target_detector.shutil.which",
                       return_value="/x/tool"):
                info = detect(project)
        self.assertEqual(info.kind, "java-project")
        self.assertTrue(info.can_fuzz_here)
        self.assertEqual(info.recommended_fuzzer, "jazzer")
        self.assertTrue(any("com.example.fuzz.ParserFuzz" in h
                            for h in info.hints), info.hints)

    def test_java_project_without_targets_names_the_harness_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "proj"
            (project / "src").mkdir(parents=True)
            (project / "pom.xml").write_text("<project/>\n")
            (project / "src" / "Plain.java").write_text("class Plain {}\n")
            with patch("packages.fuzzing.target_detector.shutil.which",
                       return_value="/x/tool"):
                info = detect(project)
        self.assertEqual(info.kind, "java-project")
        self.assertTrue(any("fuzzerTestOneInput" in h for h in info.hints),
                        info.hints)

    def test_missing_toolchain_blocks_with_install_hints(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = self._project(tmp)
            with patch("packages.fuzzing.target_detector.shutil.which",
                       return_value=None):
                info = detect(project)
        self.assertEqual(info.kind, "java-project")
        self.assertFalse(info.can_fuzz_here)
        text = " ".join(info.blockers)
        self.assertIn("jazzer", text)
        self.assertIn("java", text)

    def test_bare_java_tree_detects_after_c_family(self):
        # Pure-Java bare tree (no build marker): java-project. A mixed
        # C+Java tree keeps its pre-existing source-c detection.
        with tempfile.TemporaryDirectory() as tmp:
            pure = self._project(tmp, marker=None)
            with patch("packages.fuzzing.target_detector.shutil.which",
                       return_value="/x/tool"):
                info = detect(pure)
            self.assertEqual(info.kind, "java-project")
            (pure / "native.c").write_text("int main(void){return 0;}\n")
            info = detect(pure)
            self.assertEqual(info.kind, "source-c")

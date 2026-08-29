"""Tests for ``core.binary.firmware_inventory`` — ELF inventory over
an extracted firmware root.

Fixtures are minimal ELF headers (magic + ident + header with
``e_shoff=0``) — enough for ``parse_elf`` to return bare metadata
with the right (family, bits). Covers:

  * ELF discovery + non-ELF exclusion
  * arch naming (family+bits → toolchain name) and majority detection
  * interest scoring and high-value-target subset
  * sort order (interest desc, then size desc)
  * symlink skip (absolute links must not pull host files in)
  * empty / no-ELF roots
"""

from __future__ import annotations

import struct
from pathlib import Path

from core.binary.firmware_inventory import (
    HIGH_VALUE_SCORE,
    _interest_score,
    inventory_firmware,
)

_EM_ARM = 0x28       # 32-bit
_EM_AARCH64 = 0xB7   # 64-bit
_EM_MIPS = 0x08      # 32-bit (big-endian fixture below)
_EM_X86_64 = 0x3E    # 64-bit


def _elf_bytes(e_machine: int, bits: int = 32, big_endian: bool = False,
               pad: int = 0) -> bytes:
    """Minimal parseable ELF: ident + header, zero section table."""
    ei_class = 2 if bits == 64 else 1
    ei_data = 2 if big_endian else 1
    ident = b"\x7fELF" + bytes([ei_class, ei_data, 1]) + b"\x00" * 9
    endian = ">" if big_endian else "<"
    fmt = endian + ("HHIQQQIHHHHHH" if bits == 64 else "HHIIIIIHHHHHH")
    header = struct.pack(fmt, 2, e_machine, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return ident + header + b"\x00" * pad


def _write(root: Path, rel: str, data: bytes) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


class TestInterestScore:
    def test_high_value_daemon_names(self):
        assert _interest_score("uhttpd") == HIGH_VALUE_SCORE
        assert _interest_score("dropbear") == HIGH_VALUE_SCORE
        assert _interest_score("BUSYBOX") == HIGH_VALUE_SCORE

    def test_cgi_extension(self):
        assert _interest_score("admin.cgi") == HIGH_VALUE_SCORE

    def test_network_adjacent(self):
        assert _interest_score("wanctl") == 5

    def test_baseline(self):
        assert _interest_score("libz.so.1") == 1


class TestInventory:
    def test_finds_elfs_and_skips_non_elf(self, tmp_path):
        _write(tmp_path, "usr/sbin/uhttpd", _elf_bytes(_EM_MIPS, big_endian=True))
        _write(tmp_path, "etc/passwd", b"root:x:0:0::/root:/bin/sh\n")
        inv = inventory_firmware(tmp_path)
        assert inv["total_elfs"] == 1
        assert inv["binaries"][0]["path"] == "usr/sbin/uhttpd"
        assert inv["binaries"][0]["arch"] == "mips"

    def test_mips_endianness_variants(self, tmp_path):
        """MIPS shares one e_machine across endiannesses; the inventory
        names the variant the way firmware toolchains do."""
        _write(tmp_path, "bin/be", _elf_bytes(_EM_MIPS, big_endian=True))
        _write(tmp_path, "bin/le", _elf_bytes(_EM_MIPS, big_endian=False))
        inv = inventory_firmware(tmp_path)
        by_path = {b["path"]: (b["arch"], b["endianness"])
                   for b in inv["binaries"]}
        assert by_path == {
            "bin/be": ("mips", "big"),
            "bin/le": ("mipsel", "little"),
        }

    def test_arm_endianness_variants(self):
        from core.binary.firmware_inventory import _arch_name
        assert _arch_name("arm", 32, "big") == "armeb"
        assert _arch_name("arm", 64, "big") == "aarch64_be"
        assert _arch_name("arm", 32, "little") == "arm"
        assert _arch_name("arm", 64, "little") == "aarch64"
        assert _arch_name("mips", 64, "little") == "mips64el"
        assert _arch_name("unknown", 32, "big") == "unknown"

    def test_arch_names_and_majority(self, tmp_path):
        _write(tmp_path, "bin/a", _elf_bytes(_EM_ARM))
        _write(tmp_path, "bin/b", _elf_bytes(_EM_ARM))
        _write(tmp_path, "bin/c", _elf_bytes(_EM_AARCH64, bits=64))
        _write(tmp_path, "bin/d", _elf_bytes(_EM_X86_64, bits=64))
        inv = inventory_firmware(tmp_path)
        by_path = {b["path"]: b["arch"] for b in inv["binaries"]}
        assert by_path == {
            "bin/a": "arm", "bin/b": "arm",
            "bin/c": "aarch64", "bin/d": "x86_64",
        }
        assert inv["detected_arch"] == "arm"

    def test_sort_order_interest_then_size(self, tmp_path):
        _write(tmp_path, "bin/zzz", _elf_bytes(_EM_ARM, pad=512))
        _write(tmp_path, "usr/sbin/httpd", _elf_bytes(_EM_ARM))
        _write(tmp_path, "www/x.cgi", _elf_bytes(_EM_ARM, pad=256))
        inv = inventory_firmware(tmp_path)
        paths = [b["path"] for b in inv["binaries"]]
        # both high-value first (bigger .cgi before smaller httpd),
        # baseline binary last despite being the largest file
        assert paths == ["www/x.cgi", "usr/sbin/httpd", "bin/zzz"]
        assert [b["path"] for b in inv["high_value_targets"]] == [
            "www/x.cgi", "usr/sbin/httpd",
        ]

    def test_symlinks_skipped(self, tmp_path):
        target = _write(tmp_path, "bin/busybox", _elf_bytes(_EM_ARM))
        (tmp_path / "bin/sh").symlink_to(target)
        # Absolute symlink escaping the root — must not be followed.
        outside = tmp_path.parent / "host-binary"
        outside.write_bytes(_elf_bytes(_EM_X86_64, bits=64))
        (tmp_path / "bin/evil").symlink_to(outside)
        inv = inventory_firmware(tmp_path)
        assert [b["path"] for b in inv["binaries"]] == ["bin/busybox"]

    def test_directory_symlinks_not_walked(self, tmp_path):
        """A symlinked DIRECTORY must not be recursed into — pathlib's
        ``**`` follows dir symlinks before Python 3.13, which would walk
        the host filesystem through a hostile ``lnk -> /`` entry."""
        root = tmp_path / "fw"
        _write(root, "bin/busybox", _elf_bytes(_EM_ARM))
        outside_dir = tmp_path / "host-dir"
        outside_dir.mkdir()
        (outside_dir / "host-elf").write_bytes(_elf_bytes(_EM_X86_64, bits=64))
        (root / "escape").symlink_to(outside_dir)
        inv = inventory_firmware(root)
        assert [b["path"] for b in inv["binaries"]] == ["bin/busybox"]

    def test_symlink_loop_terminates(self, tmp_path):
        _write(tmp_path, "bin/busybox", _elf_bytes(_EM_ARM))
        (tmp_path / "loop").symlink_to(tmp_path)
        inv = inventory_firmware(tmp_path)
        assert inv["total_elfs"] == 1

    def test_empty_root(self, tmp_path):
        inv = inventory_firmware(tmp_path)
        assert inv["total_elfs"] == 0
        assert inv["binaries"] == []
        assert inv["detected_arch"] == "unknown"
        assert inv["high_value_targets"] == []

    def test_unknown_machine_does_not_drive_detected_arch(self, tmp_path):
        _write(tmp_path, "bin/weird", _elf_bytes(0x99))
        _write(tmp_path, "bin/real", _elf_bytes(_EM_ARM))
        inv = inventory_firmware(tmp_path)
        assert inv["total_elfs"] == 2
        assert inv["detected_arch"] == "arm"

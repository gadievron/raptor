"""Tests for fat Mach-O slice selection."""

from __future__ import annotations

import pytest

from packages.binary_analysis.macho import (
    MachOSlice,
    resolve_requested_slice,
    select_slice,
)


def _slice(arch: str, cpu_type: int, bits: int) -> MachOSlice:
    return MachOSlice(
        arch=arch,
        cpu_type=cpu_type,
        cpu_subtype=0,
        offset=0,
        size=0x1000,
        bits=bits,
    )


ARM32 = _slice("arm", 12, 32)
ARM64 = _slice("arm64", 12 | 0x01000000, 64)
X86 = _slice("x86", 7, 32)
X86_64 = _slice("x86_64", 7 | 0x01000000, 64)


def test_arm_selects_32bit_arm_slice() -> None:
    # 'arm' is the canonical 32-bit slice name (cpu_type 12), not an
    # alias for arm64 — requesting it must return the 32-bit slice.
    assert select_slice([ARM32, ARM64], "arm", None) is ARM32


def test_arm64_and_aarch64_still_select_arm64() -> None:
    assert select_slice([ARM32, ARM64], "arm64", None) is ARM64
    assert select_slice([ARM32, ARM64], "aarch64", None) is ARM64


def test_armv7_alias_selects_arm() -> None:
    assert select_slice([ARM32, ARM64], "armv7", None) is ARM32


def test_x86_aliases_unchanged() -> None:
    assert select_slice([X86, X86_64], "i386", None) is X86
    assert select_slice([X86, X86_64], "amd64", None) is X86_64
    assert select_slice([X86, X86_64], "x64", None) is X86_64


def test_requested_arch_with_no_matching_slice_refuses() -> None:
    # Never fall back on an EXPLICIT request: the r2 lane forces -a/-b
    # from the requested arch, so a silent slices[0] fallback decoded
    # the fallback slice's bytes as the wrong ISA while the manifest
    # reported the fallback's arch — garbage stamped full-depth.
    with pytest.raises(ValueError, match="riscv"):
        select_slice([X86_64, ARM64], "riscv", None)


def test_resolve_requested_slice_shared_decision() -> None:
    assert resolve_requested_slice([X86_64, ARM64], "aarch64") is ARM64
    assert resolve_requested_slice([X86_64], "arm64") is None
    assert resolve_requested_slice([], "arm64") is None


def test_host_fallback_no_match_still_uses_first_slice() -> None:
    # The coarse host-arch FALLBACK (no explicit request) keeps its
    # slices[0] behaviour — there is no operator assertion to honour.
    assert select_slice([X86_64, ARM64], None, "riscv") is X86_64


def test_coarse_fallback_arch_disambiguated_by_bits() -> None:
    # Coarse analyser output reports arm64 as arch='arm', bits=64 and
    # x86_64 as arch='x86', bits=64 — the fallback (no explicit request)
    # must use bits to pick the 64-bit slice.
    assert select_slice([ARM32, ARM64], None, "arm", 64) is ARM64
    assert select_slice([X86, X86_64], None, "x86", 64) is X86_64


def test_coarse_fallback_32bit_selects_32bit_slice() -> None:
    assert select_slice([ARM32, ARM64], None, "arm", 32) is ARM32
    assert select_slice([X86, X86_64], None, "x86", 32) is X86


class TestPipelineSliceArchGate:
    """analyse_blackbox_binary refuses an explicit --slice-arch the
    binary cannot satisfy BEFORE any analysis runs."""

    def test_non_macho_binary_refuses(self, tmp_path) -> None:
        from packages.binary_analysis.pipeline import analyse_blackbox_binary

        binary = tmp_path / "plain.elf"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
        with pytest.raises(ValueError, match="slice-arch"):
            analyse_blackbox_binary(
                binary, out_dir=tmp_path / "out", quick=True,
                slice_arch="arm64")

    def test_fat_macho_without_requested_slice_refuses(
            self, tmp_path) -> None:
        import struct

        from packages.binary_analysis.pipeline import analyse_blackbox_binary

        # Fat (universal) header, big-endian, one x86_64 slice.
        header = struct.pack(">II", 0xCAFEBABE, 1)
        header += struct.pack(">IIIII", 7 | 0x01000000, 3, 48, 16, 0)
        blob = header + b"\x00" * (48 - len(header)) + b"\x90" * 16
        binary = tmp_path / "fat.bin"
        binary.write_bytes(blob)
        with pytest.raises(ValueError, match="arm64"):
            analyse_blackbox_binary(
                binary, out_dir=tmp_path / "out", quick=True,
                slice_arch="arm64")

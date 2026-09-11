"""Tests for fat Mach-O slice selection."""

from __future__ import annotations

from packages.binary_analysis.macho import MachOSlice, select_slice


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


def test_no_match_falls_back_to_first_slice() -> None:
    assert select_slice([X86_64, ARM64], "riscv", None) is X86_64


def test_coarse_fallback_arch_disambiguated_by_bits() -> None:
    # Coarse analyser output reports arm64 as arch='arm', bits=64 and
    # x86_64 as arch='x86', bits=64 — the fallback (no explicit request)
    # must use bits to pick the 64-bit slice.
    assert select_slice([ARM32, ARM64], None, "arm", 64) is ARM64
    assert select_slice([X86, X86_64], None, "x86", 64) is X86_64


def test_coarse_fallback_32bit_selects_32bit_slice() -> None:
    assert select_slice([ARM32, ARM64], None, "arm", 32) is ARM32
    assert select_slice([X86, X86_64], None, "x86", 32) is X86

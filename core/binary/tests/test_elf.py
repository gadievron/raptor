"""Tests for ``core.binary.elf`` — stdlib ELF import-table parser.

The parser is the tier-0 fast path for the capability fingerprint
primitive. Correctness target: produce the same import set
``radare2`` does, in ~1ms vs ~1s. Tests cover:

  * Header parsing (32-bit + 64-bit, both endianness modes)
  * Negative cases (non-ELF, empty, truncated, malformed)
  * Real-binary parse (gated on host availability)
  * Cross-validation against radare2 (gated on r2pipe)
  * Adversarial: oversized fields, broken section headers,
    extended-section-index (SHN_XINDEX) unsupported
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from core.binary.elf import parse_elf


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------


class TestNegativeCases:
    def test_nonexistent_path(self, tmp_path):
        assert parse_elf(tmp_path / "missing") is None

    def test_empty_file(self, tmp_path):
        p = tmp_path / "empty"
        p.write_bytes(b"")
        assert parse_elf(p) is None

    def test_text_file_not_elf(self, tmp_path):
        p = tmp_path / "notelf.txt"
        p.write_bytes(b"this is not an ELF binary, just text\n" * 50)
        assert parse_elf(p) is None

    def test_truncated_after_magic(self, tmp_path):
        """File starts with ELF magic but is too short to be a
        real header. Parser bails cleanly."""
        p = tmp_path / "truncated.bin"
        p.write_bytes(b"\x7fELF" + b"\x00" * 200)
        # Magic matches but rest is zeros — e_shnum=0, no sections.
        # Parser should return metadata-only or None; either is OK.
        out = parse_elf(p)
        # With zero section count, we return bare metadata (just
        # the metadata; no imports). e_machine=0 maps to "unknown".
        if out is not None:
            assert out.binary_format == "elf"
            assert out.imports == set()

    def test_bad_ei_class(self, tmp_path):
        """ei_class outside {1, 2} → reject."""
        p = tmp_path / "badclass.bin"
        header = bytearray(b"\x7fELF")
        header.append(99)             # ei_class — invalid
        header.extend(b"\x00" * 11)   # rest of e_ident
        header.extend(b"\x00" * 100)  # padding so we don't 0-read
        p.write_bytes(bytes(header))
        assert parse_elf(p) is None

    def test_bad_ei_data(self, tmp_path):
        """ei_data outside {1, 2} → reject."""
        p = tmp_path / "baddata.bin"
        header = bytearray(b"\x7fELF")
        header.append(2)              # ei_class = 64-bit
        header.append(99)             # ei_data — invalid
        header.extend(b"\x00" * 10)
        header.extend(b"\x00" * 100)
        p.write_bytes(bytes(header))
        assert parse_elf(p) is None

    def test_pe_binary_rejected(self, tmp_path):
        """A PE binary starts with MZ, not 7f ELF. Reject."""
        p = tmp_path / "fake.exe"
        # MZ header + DOS stub
        p.write_bytes(b"MZ\x90\x00" + b"\x00" * 200)
        assert parse_elf(p) is None


# ---------------------------------------------------------------------------
# Real-binary tests — gated on host availability
# ---------------------------------------------------------------------------


class TestRealBinaryParse:
    @pytest.fixture(autouse=True)
    def _require_elf_host(self):
        """All tests in this class need a Linux-shaped host with
        /bin/ls. macOS test runners (Mach-O coreutils) skip."""
        if not Path("/bin/ls").exists():
            pytest.skip("/bin/ls not present on host")

    def test_parse_bin_ls(self):
        """Parser doesn't crash on a real binary; the metadata
        + imports come back populated."""
        meta = parse_elf(Path("/bin/ls"))
        assert meta is not None
        assert meta.binary_format == "elf"
        assert meta.bits in (32, 64)
        assert meta.arch != ""
        # /bin/ls dynamically links libc — should have at least
        # a handful of imports
        assert len(meta.imports) > 10

    def test_parse_bin_ls_fast(self):
        """Sub-50ms — generous bound that still catches a
        regression to the slow path."""
        import time
        t0 = time.perf_counter()
        meta = parse_elf(Path("/bin/ls"))
        elapsed = time.perf_counter() - t0
        assert meta is not None
        assert elapsed < 0.05, (
            f"native ELF parser took {elapsed*1000:.1f}ms — "
            f"suggests regression to a non-stdlib path"
        )

    def test_idempotent(self):
        """Same binary parsed twice → identical metadata.
        Drift detection prerequisite."""
        a = parse_elf(Path("/bin/ls"))
        b = parse_elf(Path("/bin/ls"))
        assert a is not None and b is not None
        assert a.arch == b.arch
        assert a.bits == b.bits
        assert a.binary_format == b.binary_format
        assert a.imports == b.imports

    def test_libc_imports_present(self):
        """Coreutils binaries link against glibc — typical libc
        symbols should appear. Doesn't pin specific symbols
        (varies across distros) but checks the parser actually
        extracts something libc-shaped."""
        meta = parse_elf(Path("/bin/ls"))
        assert meta is not None
        # ANY one of these — libc symbol names vary by version
        # but at least one always appears in glibc binaries.
        libc_indicators = {
            "malloc", "free", "exit", "abort", "memcpy",
            "strlen", "strcmp", "write", "read", "open",
            "fprintf", "printf", "fopen", "fclose",
        }
        assert meta.imports & libc_indicators, (
            f"no libc-shaped imports found in /bin/ls — parser "
            f"likely missed .dynsym. Sample: "
            f"{sorted(meta.imports)[:10]}"
        )


# ---------------------------------------------------------------------------
# Cross-validation against radare2 — gated on r2pipe
# ---------------------------------------------------------------------------


class TestRadare2Parity:
    @pytest.fixture(autouse=True)
    def _require_radare2(self):
        from packages.binary_analysis.radare2_understand import (
            probe_capability,
        )
        if not probe_capability().get("available"):
            pytest.skip("radare2 stack not available")
        if not Path("/bin/ls").exists():
            pytest.skip("/bin/ls not present")

    def test_imports_match_radare2_ls(self):
        """Native ELF parser must produce the exact same import
        set as radare2's ``iij`` for /bin/ls. Any divergence is
        a parser bug (or a r2 bug; bias is our parser)."""
        from packages.binary_analysis.radare2_understand import (
            analyse_binary_context,
        )
        elf = parse_elf(Path("/bin/ls"))
        ctx = analyse_binary_context(
            Path("/bin/ls"), max_strings=0, max_decompile=0,
            quick=True,
        )
        assert elf is not None
        assert elf.imports == set(ctx.imports), (
            f"diverged from radare2:\n"
            f"  only in elf parser: "
            f"{sorted(elf.imports - set(ctx.imports))[:10]}\n"
            f"  only in radare2:    "
            f"{sorted(set(ctx.imports) - elf.imports)[:10]}"
        )

    def test_arch_matches_radare2_ls(self):
        from packages.binary_analysis.radare2_understand import (
            analyse_binary_context,
        )
        elf = parse_elf(Path("/bin/ls"))
        ctx = analyse_binary_context(
            Path("/bin/ls"), max_strings=0, max_decompile=0,
            quick=True,
        )
        assert elf is not None
        assert elf.arch == ctx.arch
        assert elf.bits == ctx.bits
        assert elf.binary_format == ctx.binary_format


# ---------------------------------------------------------------------------
# Adversarial header-level probes
# ---------------------------------------------------------------------------


class TestAdversarialHeaders:
    """Hand-crafted invalid / malicious headers — parser must
    return None or bare metadata without crashing."""

    def test_max_shnum_capped(self, tmp_path):
        """e_shnum at its uint16 max with no real section data —
        parser should return None or bare metadata rather than
        burning through 4MB of zero bytes pretending they're
        valid section headers."""
        p = tmp_path / "max_shnum.elf"
        header = bytearray()
        header.extend(b"\x7fELF\x02\x01\x01\x00")
        header.extend(b"\x00" * 8)
        header.extend(struct.pack(
            "<HHIQQQIHHHHHH",
            0x02,            # e_type
            0x3E,            # e_machine x86_64
            1, 0, 0,
            64,              # e_shoff = right after header
            0, 64, 0, 0,
            64,              # e_shentsize
            0xFFFF,          # e_shnum = uint16 max
            0xFFFE,          # e_shstrndx — definitely out of range
        ))
        p.write_bytes(bytes(header))
        out = parse_elf(p)
        # Either None or bare metadata is acceptable here; the
        # invariant is "no crash, no fake imports".
        if out is not None:
            assert out.imports == set()

    def test_shoff_zero_returns_bare_metadata(self, tmp_path):
        """e_shoff=0 → no section header table → can't enumerate
        imports but we can still surface arch / bits."""
        p = tmp_path / "no_sections.elf"
        header = bytearray()
        header.extend(b"\x7fELF\x02\x01\x01\x00")
        header.extend(b"\x00" * 8)
        header.extend(struct.pack(
            "<HHIQQQIHHHHHH",
            0x02, 0x3E, 1, 0, 0,
            0,    # e_shoff = 0
            0, 64, 0, 0, 64, 0, 0,
        ))
        p.write_bytes(bytes(header))
        out = parse_elf(p)
        assert out is not None
        assert out.binary_format == "elf"
        assert out.bits == 64
        assert out.arch == "x86"        # x86 family, bits=64 → x86_64
        assert out.imports == set()

    def test_shstrndx_out_of_bounds(self, tmp_path):
        """e_shstrndx pointing past available sections → bail
        cleanly with bare metadata (still know arch + bits)."""
        p = tmp_path / "bad_shstrndx.elf"
        header = bytearray()
        header.extend(b"\x7fELF\x02\x01\x01\x00")
        header.extend(b"\x00" * 8)
        header.extend(struct.pack(
            "<HHIQQQIHHHHHH",
            0x02, 0xB7, 1, 0, 0,       # arm64
            64, 0, 64, 0, 0, 64, 0,
            0xFFFE,                     # e_shstrndx — huge
        ))
        p.write_bytes(bytes(header))
        out = parse_elf(p)
        assert out is not None
        assert out.arch == "arm"        # arm family, bits=64 → aarch64
        assert out.bits == 64
        assert out.imports == set()


# ---------------------------------------------------------------------------
# Endianness + bit-width coverage via synthesised minimal headers
# ---------------------------------------------------------------------------


class TestHeaderShapeCoverage:
    """Confirm the parser handles all four (32/64) × (LE/BE)
    combinations of the ELF header. We craft minimal headers
    that hit the bail-out path (no section headers) so we don't
    have to build a full synthetic ELF — the point is to prove
    the header parsing branches correctly route by class+data."""

    def _build_minimal(
        self, *, bits: int, little_endian: bool,
        e_machine: int = 0x3E,
    ) -> bytes:
        ei_class = 2 if bits == 64 else 1
        ei_data = 1 if little_endian else 2
        endian = "<" if little_endian else ">"
        e_ident = bytes([
            0x7F, 0x45, 0x4C, 0x46,    # magic
            ei_class, ei_data,
            1,                          # version
            0,                          # OS ABI
        ]) + b"\x00" * 8
        if bits == 64:
            rest = struct.pack(
                endian + "HHIQQQIHHHHHH",
                0x02, e_machine, 1, 0, 0,
                0,    # e_shoff = 0 → no sections
                0, 64, 0, 0, 64, 0, 0,
            )
        else:
            rest = struct.pack(
                endian + "HHIIIIIHHHHHH",
                0x02, e_machine, 1, 0, 0,
                0,    # e_shoff = 0
                0, 52, 0, 0, 40, 0, 0,
            )
        return e_ident + rest

    def test_elf64_little_endian(self, tmp_path):
        p = tmp_path / "elf64le.elf"
        p.write_bytes(self._build_minimal(
            bits=64, little_endian=True, e_machine=0x3E,
        ))
        out = parse_elf(p)
        assert out is not None
        # ``arch`` is the family, ``bits`` disambiguates word
        # size — radare2's convention, mirrored here.
        assert out.arch == "x86"
        assert out.bits == 64

    def test_elf64_big_endian(self, tmp_path):
        p = tmp_path / "elf64be.elf"
        p.write_bytes(self._build_minimal(
            bits=64, little_endian=False, e_machine=0x15,   # ppc64
        ))
        out = parse_elf(p)
        assert out is not None
        assert out.arch == "ppc"
        assert out.bits == 64

    def test_elf32_little_endian(self, tmp_path):
        p = tmp_path / "elf32le.elf"
        p.write_bytes(self._build_minimal(
            bits=32, little_endian=True, e_machine=0x03,    # i386
        ))
        out = parse_elf(p)
        assert out is not None
        assert out.arch == "x86"
        assert out.bits == 32

    def test_elf32_big_endian(self, tmp_path):
        p = tmp_path / "elf32be.elf"
        p.write_bytes(self._build_minimal(
            bits=32, little_endian=False, e_machine=0x28,   # arm BE
        ))
        out = parse_elf(p)
        assert out is not None
        assert out.arch == "arm"
        assert out.bits == 32

    def test_unknown_machine_falls_back_to_unknown_arch(self, tmp_path):
        """e_machine not in our table → arch == 'unknown'."""
        p = tmp_path / "weird.elf"
        p.write_bytes(self._build_minimal(
            bits=64, little_endian=True, e_machine=0xDEAD,
        ))
        out = parse_elf(p)
        assert out is not None
        assert out.arch == "unknown"

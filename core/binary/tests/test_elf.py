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
        """All tests in this class need a Linux-shaped host with an
        ELF /bin/ls. macOS test runners (Mach-O coreutils) skip — the
        old guard only checked existence, so it failed to skip on a
        host where /bin/ls exists but is Mach-O."""
        p = Path("/bin/ls")
        try:
            is_elf = p.is_file() and p.read_bytes()[:4] == b"\x7fELF"
        except OSError:
            is_elf = False
        if not is_elf:
            pytest.skip("/bin/ls is not an ELF binary on this host")

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
        p = Path("/bin/ls")
        try:
            is_elf = p.is_file() and p.read_bytes()[:4] == b"\x7fELF"
        except OSError:
            is_elf = False
        if not is_elf:
            pytest.skip("/bin/ls is not an ELF binary on this host")

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


# ---------------------------------------------------------------------------
# Section-header-stripped dynamic binaries (sstrip shape)
# ---------------------------------------------------------------------------


_PT_LOAD = 1
_PT_DYNAMIC = 2


def _build_elf64_with_dynsym(
    *,
    sections: bool = True,
    p_type: int = _PT_DYNAMIC,
    e_shoff_override: int | None = None,
) -> bytes:
    """Minimal but complete little-endian ELF64: one program header,
    .dynsym with two SHN_UNDEF imports (execve, recv), .dynstr,
    .shstrtab. ``sections=False`` zeroes the section-header fields in
    the ELF header (the ``sstrip`` shape) while keeping PT_DYNAMIC."""
    phoff = 64
    dynstr_off = phoff + 56                       # 120
    dynstr = b"\x00execve\x00recv\x00"            # execve@1, recv@8
    dynsym_off = dynstr_off + len(dynstr)         # 136
    sym = struct.Struct("<IBBHQQ")
    dynsym = (
        sym.pack(0, 0, 0, 0, 0, 0)                # null entry
        + sym.pack(1, 0, 0, 0, 0, 0)              # execve, SHN_UNDEF
        + sym.pack(8, 0, 0, 0, 0, 0)              # recv, SHN_UNDEF
    )
    shstrtab_off = dynsym_off + len(dynsym)       # 208
    shstrtab = b"\x00.dynsym\x00.dynstr\x00.shstrtab\x00"
    shoff = shstrtab_off + len(shstrtab)
    shoff += (-shoff) % 8                          # 8-align the table

    sh = struct.Struct("<IIQQQQIIQQ")
    shdrs = (
        sh.pack(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)                    # null
        + sh.pack(1, 11, 0, 0, dynsym_off, len(dynsym), 2, 0, 8, 24)   # .dynsym
        + sh.pack(9, 3, 0, 0, dynstr_off, len(dynstr), 0, 0, 1, 0)     # .dynstr
        + sh.pack(17, 3, 0, 0, shstrtab_off, len(shstrtab), 0, 0, 1, 0)  # .shstrtab
    )

    e_shoff = shoff if sections else 0
    if e_shoff_override is not None:
        e_shoff = e_shoff_override
    e_shnum = 4 if sections else 0
    e_shstrndx = 3 if sections else 0
    ehdr = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + struct.pack(
        "<HHIQQQIHHHHHH",
        0x02, 0x3E, 1,           # e_type, e_machine (x86_64), e_version
        0,                        # e_entry
        phoff,                    # e_phoff
        e_shoff,                  # e_shoff
        0, 64,                    # e_flags, e_ehsize
        56, 1,                    # e_phentsize, e_phnum
        64, e_shnum, e_shstrndx,  # e_shentsize, e_shnum, e_shstrndx
    )
    phdr = struct.pack("<IIQQQQQQ", p_type, 0, 0, 0, 0, 0, 0, 0)
    body = ehdr + phdr + dynstr + dynsym + shstrtab
    body += b"\x00" * (shoff - len(body))
    return body + shdrs


class TestSectionlessDynamic:
    """A dynamic binary whose section headers were stripped
    (``sstrip``) still imports symbols via PT_DYNAMIC — the parser
    must signal "needs fallback" (None) instead of returning
    success-shaped metadata with ``imports=set()``, which would let
    the binary fingerprint as capability-free."""

    def test_full_elf_parses_imports(self, tmp_path):
        """Baseline direction: section headers intact → tier 0
        enumerates the imports itself, no fallback needed."""
        p = tmp_path / "full.elf"
        p.write_bytes(_build_elf64_with_dynsym(sections=True))
        out = parse_elf(p)
        assert out is not None
        assert out.imports == {"execve", "recv"}
        assert out.arch == "x86"
        assert out.bits == 64

    def test_sstripped_dynamic_elf_returns_none(self, tmp_path):
        """e_shoff=0 but PT_DYNAMIC present → None so the caller's
        radare2 tier engages and reads the dynamic segment."""
        p = tmp_path / "sstripped.elf"
        p.write_bytes(_build_elf64_with_dynsym(sections=False))
        assert parse_elf(p) is None

    def test_sectionless_static_elf_returns_bare_metadata(self, tmp_path):
        """No section headers AND no PT_DYNAMIC → genuinely no
        dynamic imports; header-only metadata is the truthful
        answer (no pointless fallback)."""
        p = tmp_path / "static.elf"
        p.write_bytes(_build_elf64_with_dynsym(
            sections=False, p_type=_PT_LOAD,
        ))
        out = parse_elf(p)
        assert out is not None
        assert out.imports == set()
        assert out.arch == "x86"

    def test_huge_shoff_returns_none_not_raise(self, tmp_path):
        """e_shoff past off_t range makes ``f.seek`` raise
        ValueError/OverflowError — the documented contract is
        None, never an exception out of ``parse_elf``."""
        p = tmp_path / "huge_shoff.elf"
        p.write_bytes(_build_elf64_with_dynsym(
            sections=True, e_shoff_override=2**63 + 16,
        ))
        assert parse_elf(p) is None

    def test_huge_dynsym_entsize_no_oom(self, tmp_path):
        """sh_entsize is attacker-chosen; a pathological value must
        not drive multi-GB padding reads. The parse either bails to
        the fallback signal or returns empty imports — never raises
        and never fabricates imports."""
        blob = bytearray(_build_elf64_with_dynsym(sections=True))
        # Patch .dynsym's sh_entsize (last Q of section header #1).
        shoff = len(blob) - 4 * 64
        entsize_off = shoff + 64 + 56
        blob[entsize_off:entsize_off + 8] = struct.pack("<Q", 2**40)
        p = tmp_path / "bad_entsize.elf"
        p.write_bytes(bytes(blob))
        out = parse_elf(p)
        if out is not None:
            assert out.imports == set()

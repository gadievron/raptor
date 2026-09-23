"""Hostile .dynstr bounds in core.binary.elf.parse_elf.

A crafted .dynstr with no NUL terminator must not make every .dynsym
lookup retain a distinct whole-tail suffix of the section (unbounded
memory amplification from a small file; MemoryError is deliberately
not in parse_elf's malformed-input except set, and the sca
supply-chain scan feeds every ELF in a scanned package through this
parser).
"""

from __future__ import annotations

import logging
import struct

from core.binary import elf as elf_mod
from core.binary.elf import parse_elf

from .test_elf import _build_elf64_with_dynsym


def _build_elf64_hostile_dynstr(
    *,
    entries: int,
    dynstr: bytes,
    name_offsets: list[int] | None = None,
) -> bytes:
    """Crafted little-endian ELF64 whose .dynsym entries point into an
    arbitrary caller-supplied .dynstr (e.g. one containing no NUL)."""
    ehsize, shentsize, shnum = 64, 64, 4
    shoff = ehsize
    shstrtab = b"\x00.shstrtab\x00.dynstr\x00.dynsym\x00"
    off_shstrtab = shoff + shnum * shentsize
    off_dynstr = off_shstrtab + len(shstrtab)
    sym = struct.Struct("<IBBHQQ")
    step = max(1, len(dynstr) // max(entries, 1))
    body = bytearray()
    for i in range(entries):
        if name_offsets is not None:
            st_name = name_offsets[i]
        else:
            st_name = 1 + (i * step) % max(len(dynstr) - 1, 1)
        body += sym.pack(st_name, 0, 0, 0, 0, 0)   # st_shndx=0 (UNDEF)
    off_dynsym = off_dynstr + len(dynstr)
    ehdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr += struct.pack(
        "<HHIQQQIHHHHHH", 3, 0x3E, 1, 0, 0, shoff, 0,
        ehsize, 0, 0, shentsize, shnum, 1)

    def sh(name_off: int, typ: int, off: int, size: int, link: int,
           entsize: int) -> bytes:
        return struct.pack(
            "<IIQQQQIIQQ", name_off, typ, 0, 0, off, size, link, 0, 0,
            entsize)

    shdrs = (
        sh(0, 0, 0, 0, 0, 0)
        + sh(1, 3, off_shstrtab, len(shstrtab), 0, 0)
        + sh(11, 3, off_dynstr, len(dynstr), 0, 0)
        + sh(19, 11, off_dynsym, len(body), 2, 24)
    )
    return ehdr + shdrs + shstrtab + dynstr + bytes(body)


class TestHostileDynstrBounded:

    def test_no_nul_dynstr_retains_nothing(self, tmp_path):
        entries, size = 200, 200_000
        blob = _build_elf64_hostile_dynstr(
            entries=entries, dynstr=b"A" * size)   # no NUL anywhere
        p = tmp_path / "hostile.elf"
        p.write_bytes(blob)
        out = parse_elf(p)
        assert out is not None
        retained = sum(len(s) for s in out.imports)
        # Pre-fix this retained ~entries/2 * size bytes (distinct tail
        # suffixes); post-fix every unterminated lookup is malformed.
        assert retained <= entries * elf_mod._MAX_STRTAB_NAME_BYTES
        assert out.imports == set()

    def test_name_at_cap_kept_over_cap_dropped(self, tmp_path):
        cap = elf_mod._MAX_STRTAB_NAME_BYTES
        at_cap = b"a" * cap
        over_cap = b"b" * (cap + 1)
        dynstr = b"\x00" + at_cap + b"\x00" + over_cap + b"\x00"
        blob = _build_elf64_hostile_dynstr(
            entries=2, dynstr=dynstr,
            name_offsets=[1, 1 + cap + 1])
        p = tmp_path / "cap.elf"
        p.write_bytes(blob)
        out = parse_elf(p)
        assert out is not None
        assert out.imports == {at_cap.decode()}

    def test_total_name_volume_capped_loudly(self, tmp_path, monkeypatch,
                                             caplog):
        monkeypatch.setattr(elf_mod, "_MAX_TOTAL_NAME_BYTES", 8)
        names = b"\x00alpha\x00bravo\x00charlie\x00"
        blob = _build_elf64_hostile_dynstr(
            entries=3, dynstr=names, name_offsets=[1, 7, 13])
        p = tmp_path / "volume.elf"
        p.write_bytes(blob)
        with caplog.at_level(logging.WARNING, logger="core.binary.elf"):
            out = parse_elf(p)
        assert out is not None
        assert len(out.imports) < 3
        assert any("truncated" in rec.message for rec in caplog.records)

    def test_benign_imports_unaffected(self, tmp_path):
        p = tmp_path / "full.elf"
        p.write_bytes(_build_elf64_with_dynsym(sections=True))
        out = parse_elf(p)
        assert out is not None
        assert out.imports == {"execve", "recv"}


def _build_elf64_many_named_sections(
    *, sections: int, shstrtab: bytes,
) -> bytes:
    """Crafted little-endian ELF64 with many section headers whose
    sh_name offsets all point into a caller-supplied shstrtab (e.g.
    one whose only NUL is the last byte, so every name lookup yields
    a near-cap-length valid string)."""
    ehsize, shentsize = 64, 64
    shnum = sections + 2                       # + null + shstrtab
    shoff = ehsize
    off_shstrtab = shoff + shnum * shentsize
    ehdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr += struct.pack(
        "<HHIQQQIHHHHHH", 3, 0x3E, 1, 0, 0, shoff, 0,
        ehsize, 0, 0, shentsize, shnum, 1)

    def sh(name_off: int, typ: int, off: int, size: int) -> bytes:
        return struct.pack(
            "<IIQQQQIIQQ", name_off, typ, 0, 0, off, size, 0, 0, 0, 0)

    shdrs = bytearray()
    shdrs += sh(0, 0, 0, 0)                                   # null
    shdrs += sh(0, 3, off_shstrtab, len(shstrtab))            # shstrtab
    for i in range(sections):
        # SHT_STRTAB so the name lookup cannot be type-skipped;
        # distinct-ish in-bounds offsets, never a terminator ahead.
        shdrs += sh(1 + (i % max(len(shstrtab) - 1, 1)), 3, 0, 0)
    return ehdr + bytes(shdrs) + shstrtab


class TestSectionNameWalkBounded:
    def test_many_sections_no_nul_shstrtab_stays_small(self, tmp_path):
        """The section-NAME walk must not retain a name per header: a
        crafted ELF fanning a 4 KB no-NUL shstrtab across tens of
        thousands of headers previously peaked ~150 MB of transient
        allocations (u16 e_shnum x the per-name cap) from a ~4 MB
        file."""
        import tracemalloc

        # The ONLY NUL is the final byte: every lookup yields a valid
        # near-cap-length name (an unterminated strtab would already
        # be rejected per-name).
        blob = _build_elf64_many_named_sections(
            sections=20_000, shstrtab=b"A" * 4095 + b"\x00")
        p = tmp_path / "many-sections.elf"
        p.write_bytes(blob)
        tracemalloc.start()
        try:
            parse_elf(p)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        # Pre-fix this retained one capped name per header
        # (~20k x 4 KB at this bounded scale); post-fix each lookup is
        # transient and the walk retains nothing.
        assert peak < 16 * 1024 * 1024, f"peak {peak:,} bytes"

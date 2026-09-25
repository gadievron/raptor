"""Tests for the ``core.binary.pe`` RVA → file-offset chokepoint.

Each test names the resolver invariant it pins (module docstring of
``core.binary.pe``):

  (a) memory-vs-file zero-fill — never adjacent sections' bytes
  (b) deterministic first-match in table order on overlaps + marker
  (c) header-region identity mapping bounded by SizeOfHeaders
  (d) reads bounded by min(remaining raw, caller cap); VirtualSize
      is never a read budget; reads never cross a section boundary
"""

from __future__ import annotations

import io

from core.binary.pe import PeSection, _RvaResolver, extract_pe_facts

from .test_pe_facts import PeSpec, Sec, build_pe


def _sec(name: str, va: int, vsize: int, raw_size: int,
         raw_offset: int) -> PeSection:
    return PeSection(name=name, virtual_address=va, virtual_size=vsize,
                     raw_size=raw_size, raw_offset=raw_offset,
                     characteristics=0)


def _file(total: int, chunks: dict[int, bytes]) -> io.BytesIO:
    buf = bytearray(total)
    for off, data in chunks.items():
        buf[off:off + len(data)] = data
    return io.BytesIO(bytes(buf))


class TestZeroFill:
    """Invariant (a): the VirtualSize/RawSize-skew aliasing shape."""

    def test_skew_region_is_zero_fill_never_adjacent_bytes(self):
        # .a: 0x200 raw bytes at file 0x400, but 0x2000 virtual.
        # The file bytes DIRECTLY AFTER .a's raw data are section
        # .b's — an offset-continuation bug would surface them.
        secs = [
            _sec(".a", 0x1000, 0x2000, 0x200, 0x400),
            _sec(".b", 0x3000, 0x200, 0x200, 0x600),
        ]
        f = _file(0x800, {0x400: b"A" * 0x200, 0x600: b"B" * 0x200})
        r = _RvaResolver(secs, 0x400)
        data = r.read(f, 0x1000 + 0x300, 64)
        assert data == b"\x00" * 64
        assert b"B" not in (data or b"")

    def test_read_straddling_raw_end_pads_with_zeros(self):
        secs = [
            _sec(".a", 0x1000, 0x2000, 0x200, 0x400),
            _sec(".b", 0x3000, 0x200, 0x200, 0x600),
        ]
        f = _file(0x800, {0x400: b"A" * 0x200, 0x600: b"B" * 0x200})
        r = _RvaResolver(secs, 0x400)
        data = r.read(f, 0x1000 + 0x1F8, 16)
        assert data == b"A" * 8 + b"\x00" * 8    # never "B" bytes

    def test_memory_only_rva_resolves_without_file_offset(self):
        secs = [_sec(".a", 0x1000, 0x2000, 0x200, 0x400)]
        r = _RvaResolver(secs, 0x400)
        target = r.resolve(0x1000 + 0x1000)
        assert target is not None
        assert target.file_offset is None
        assert target.raw_available == 0


class TestOverlaps:
    """Invariant (b): deterministic first-match + marker."""

    def _overlapping(self, order: str) -> list[PeSection]:
        a = _sec(".a", 0x1000, 0x1000, 0x1000, 0x400)
        b = _sec(".b", 0x1800, 0x1000, 0x1000, 0x1400)
        return [a, b] if order == "ab" else [b, a]

    def test_first_match_in_table_order(self):
        f = _file(0x2400, {0x400: b"A" * 0x1000, 0x1400: b"B" * 0x1000})
        r_ab = _RvaResolver(self._overlapping("ab"), 0x400)
        r_ba = _RvaResolver(self._overlapping("ba"), 0x400)
        # 0x1900 sits inside BOTH sections' virtual ranges.
        assert r_ab.read(f, 0x1900, 8) == b"A" * 8
        assert r_ba.read(f, 0x1900, 8) == b"B" * 8

    def test_resolution_is_repeatable(self):
        r = _RvaResolver(self._overlapping("ab"), 0x400)
        assert all(r.resolve(0x1900) == r.resolve(0x1900)
                   for _ in range(32))

    def test_overlap_marker_on_extraction(self, tmp_path):
        p = tmp_path / "overlap.exe"
        p.write_bytes(build_pe(PeSpec(secs=[
            Sec(name=b".a", va=0x1000, data=b"A" * 0x1000),
            Sec(name=b".b", va=0x1800, data=b"B" * 0x1000),
        ])))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert "overlapping_sections" in facts.caps_hit

    def test_no_marker_without_overlap(self, tmp_path):
        p = tmp_path / "clean.exe"
        p.write_bytes(build_pe(PeSpec(secs=[
            Sec(name=b".a", va=0x1000, data=b"A" * 0x200),
            Sec(name=b".b", va=0x2000, data=b"B" * 0x200),
        ])))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert "overlapping_sections" not in facts.caps_hit


class TestHeaderRegion:
    """Invariant (c): identity map bounded by SizeOfHeaders."""

    def test_header_rva_identity_maps(self):
        f = _file(0x400, {0x40: b"HDRBYTES"})
        r = _RvaResolver([_sec(".a", 0x1000, 0x100, 0x100, 0x200)],
                         0x400)
        assert r.read(f, 0x40, 8) == b"HDRBYTES"

    def test_bounded_by_size_of_headers(self):
        f = _file(0x1000, {0x3FC: b"XXXXYYYY"})
        r = _RvaResolver([_sec(".a", 0x1000, 0x100, 0x100, 0x400)],
                         0x400)
        # 4 bytes remain inside the header region; the read stops
        # there — it must NOT continue into post-header file bytes.
        assert r.read(f, 0x3FC, 100) == b"XXXX"
        assert r.resolve(0x400) is None          # at the bound
        assert r.resolve(0x999) is None          # past it, unmapped

    def test_section_claim_beats_header_region(self):
        # A section mapping an RVA below SizeOfHeaders wins over the
        # identity map — first-match determinism includes (c).
        f = _file(0x1000, {0x800: b"S" * 0x100})
        r = _RvaResolver([_sec(".a", 0x100, 0x100, 0x100, 0x800)],
                         0x400)
        assert r.read(f, 0x100, 4) == b"SSSS"


class TestReadBounds:
    """Invariant (d): min(remaining raw, caller cap); VirtualSize
    is never a read budget; no cross-section reads."""

    def test_virtual_size_never_a_read_budget(self):
        # VirtualSize claims 256 MB; raw is 16 bytes. The read must
        # touch at most 16 file bytes — the sentinel AFTER the raw
        # extent must never appear.
        secs = [_sec(".a", 0x1000, 0x10000000, 0x10, 0x400)]
        f = _file(0x500, {0x400: b"R" * 0x10 + b"SENTINEL"})
        r = _RvaResolver(secs, 0x400)
        data = r.read(f, 0x1000, 64)
        assert data is not None
        assert data[:0x10] == b"R" * 0x10
        assert data[0x10:] == b"\x00" * (64 - 0x10)
        assert b"SENT" not in data

    def test_caller_cap_bounds_the_read(self):
        secs = [_sec(".a", 0x1000, 0x200, 0x200, 0x400)]
        f = _file(0x600, {0x400: b"R" * 0x200})
        r = _RvaResolver(secs, 0x400)
        assert r.read(f, 0x1000, 8) == b"R" * 8

    def test_read_never_crosses_section_boundary(self):
        # Virtually contiguous sections: a read that would continue
        # into the next section stops at the boundary instead.
        secs = [
            _sec(".a", 0x1000, 0x100, 0x100, 0x400),
            _sec(".b", 0x1100, 0x100, 0x100, 0x500),
        ]
        f = _file(0x600, {0x400: b"A" * 0x100, 0x500: b"B" * 0x100})
        r = _RvaResolver(secs, 0x400)
        data = r.read(f, 0x10F8, 64)
        assert data == b"A" * 8                  # short, no "B" bytes

    def test_raw_claim_past_eof_is_a_gap_not_zeros(self):
        # The header claims raw bytes the file does not have —
        # fabricating zeros would launder truncation into
        # "measured zero bytes".
        secs = [_sec(".a", 0x1000, 0x200, 0x200, 0x400)]
        f = _file(0x420, {0x400: b"A" * 0x20})
        r = _RvaResolver(secs, 0x400)
        assert r.read(f, 0x1000, 0x100) is None

    def test_unmapped_rva_is_none(self):
        r = _RvaResolver([_sec(".a", 0x1000, 0x100, 0x100, 0x400)],
                         0x400)
        assert r.resolve(0x100000) is None
        assert r.read(io.BytesIO(b"\x00" * 0x600), 0x100000, 4) is None

    def test_negative_rva_and_zero_length(self):
        f = io.BytesIO(b"\x00" * 0x600)
        r = _RvaResolver([_sec(".a", 0x1000, 0x100, 0x100, 0x400)],
                         0x400)
        assert r.resolve(-1) is None
        assert r.read(f, 0x1000, 0) == b""
        assert r.read(f, 0x1000, -4) == b""

    def test_zero_virtual_size_uses_raw_extent(self):
        # VirtualSize 0 with raw bytes: the raw size is the honest
        # extent (object-style / doctored headers).
        secs = [_sec(".a", 0x1000, 0, 0x40, 0x400)]
        f = _file(0x440, {0x400: b"Z" * 0x40})
        r = _RvaResolver(secs, 0x400)
        assert r.read(f, 0x1000, 8) == b"Z" * 8
        assert r.resolve(0x1040) is None

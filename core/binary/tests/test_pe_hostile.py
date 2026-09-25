"""Adversarial battery for ``core.binary.pe``.

Empirical attacks on the parser itself, complementing the per-fact
suites:

  * seeded random byte-mutation fuzz over a rich crafted image
    (header-biased), asserting the never-raises contract and a
    per-parse wall-clock bound
  * a full truncation sweep — every prefix boundary of the crafted
    image parses to ``None`` or a marked record, never an exception
  * the section-table flood at the REAL cap boundary (cap and
    cap + 1, both directions pinned)
  * the RVA-resolver differential: every RVA in the crafted range
    resolved twice with identical results
  * a wall-clock bound on the largest crafted input this module
    will ever be handed shape-wise
  * hostile pdb-basename / section-name text through the repo's
    render chokepoint (``core.security.log_sanitisation``)
"""

from __future__ import annotations

import random
import struct
import time

from core.binary import pe as pe_mod
from core.binary.pe import PeFacts, _RvaResolver, extract_pe_facts
from core.security.log_sanitisation import (
    escape_nonprintable,
    has_nonprintable,
)

from .test_pe_facts import PeSpec, Sec, build_pe
from .test_pe_identity import _image_with_debug, _rsds_blob

_VEC_GUID_RAW = bytes.fromhex("d4c3b2a1f6e5180790abcdef01234567")


def _rich_image() -> bytes:
    """One image exercising every parse path: debug directory with
    an RSDS blob, presence directories, skewed sections, overlay."""
    blob = _rsds_blob(_VEC_GUID_RAW, 42, b"c:\\build\\rich.pdb")
    section = bytearray(0x400)
    section[0x40:0x40 + len(blob)] = blob
    entry = struct.pack("<IIHHIIII", 0, 0, 0, 0, 2, len(blob),
                        0x4000 + 0x40, 0x800 + 0x40)
    section[0:28] = entry
    return build_pe(PeSpec(
        dll_characteristics=0x4160,
        secs=[
            Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x200,
                vsize=0x2000),                      # raw/virtual skew
            Sec(name=b".rdata", va=0x3000, data=bytes(range(256))),
            Sec(name=b".dbg", va=0x4000, data=bytes(section),
                raw_ptr=0x800),
        ],
        data_dirs={4: (0xC00, 0x80), 6: (0x4000, 28),
                   14: (0x3000, 72)},
        overlay=b"OVERLAY-BYTES" * 8,
    ))


class TestMutationFuzz:
    def test_ten_thousand_seeded_mutations_never_raise(self, tmp_path):
        """The never-raises contract under random damage. Seeded —
        every run replays the identical corpus. Mutations are
        header-biased (the first 0x400 bytes hold every structure
        this parser walks) and mixed with truncations. The parse is
        also individually time-bounded: no mutation may buy a
        pathological walk."""
        base = _rich_image()
        rng = random.Random(0x9E_FAC75)
        p = tmp_path / "mut.exe"
        worst = 0.0
        for i in range(10_000):
            blob = bytearray(base)
            if i % 10 == 9:
                blob = blob[:rng.randrange(1, len(blob))]
            n_flips = rng.randint(1, 8)
            for _ in range(n_flips):
                if rng.random() < 0.5:
                    pos = rng.randrange(min(0x400, len(blob)))
                else:
                    pos = rng.randrange(len(blob))
                blob[pos] = rng.randrange(256)
            p.write_bytes(bytes(blob))
            start = time.perf_counter()
            facts = extract_pe_facts(p)     # must never raise
            elapsed = time.perf_counter() - start
            worst = max(worst, elapsed)
            assert elapsed < 1.0, (
                f"mutation {i} took {elapsed:.3f}s — pathological walk")
            assert facts is None or isinstance(facts, PeFacts)
        # Belt-and-braces visibility: the whole corpus stayed fast.
        assert worst < 1.0


class TestTruncationSweep:
    def test_every_prefix_boundary(self, tmp_path):
        """Every prefix of the crafted image — one file per length
        through the section table and stride-sampled beyond — is
        either not-a-PE (None) or a degraded record. Never an
        exception, and a record's caps_hit must say SOMETHING when
        the image lost structure before the section data."""
        base = _rich_image()
        table_end = 0x80 + 4 + 20 + (112 + 16 * 8) + 3 * 40
        lengths = list(range(table_end + 1)) + \
            list(range(table_end + 1, len(base), 64))
        p = tmp_path / "trunc.exe"
        for n in lengths:
            p.write_bytes(base[:n])
            facts = extract_pe_facts(p)
            if facts is None:
                continue
            if n < table_end:
                assert facts.caps_hit, (
                    f"prefix {n} lost header structure silently")


class TestSectionFloodBoundary:
    def _flood(self, count: int) -> bytes:
        secs = [
            Sec(name=b".s", va=0x1000 * (i + 1), data=b"",
                raw_size=0, raw_ptr=0)
            for i in range(count)
        ]
        return build_pe(PeSpec(secs=secs, size_of_headers=0x200))

    def test_at_the_real_cap(self, tmp_path):
        p = tmp_path / "atcap.exe"
        p.write_bytes(self._flood(pe_mod._MAX_SECTIONS))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert len(facts.sections) == pe_mod._MAX_SECTIONS
        assert "section_table_capped" not in facts.caps_hit

    def test_one_past_the_real_cap(self, tmp_path):
        p = tmp_path / "pastcap.exe"
        p.write_bytes(self._flood(pe_mod._MAX_SECTIONS + 1))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert len(facts.sections) == pe_mod._MAX_SECTIONS
        assert facts.declared_section_count == pe_mod._MAX_SECTIONS + 1
        assert "section_table_capped" in facts.caps_hit

    def test_u16_max_claim_with_tiny_file(self, tmp_path):
        blob = bytearray(build_pe(PeSpec(
            secs=[Sec(name=b".t", va=0x1000, data=b"x" * 16)])))
        struct.pack_into("<H", blob, 0x80 + 4 + 2, 0xFFFF)
        p = tmp_path / "claim64k.exe"
        p.write_bytes(bytes(blob))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.declared_section_count == 0xFFFF
        assert "section_table_capped" in facts.caps_hit
        assert "section_table_truncated" in facts.caps_hit


class TestResolverDifferential:
    def test_every_rva_resolves_identically_twice(self):
        """Determinism over the whole crafted address range,
        including overlapping and skewed sections and the header
        region — resolution must be a pure function of the table."""
        secs = [
            pe_mod.PeSection(name=".a", virtual_address=0x1000,
                             virtual_size=0x2000, raw_size=0x200,
                             raw_offset=0x400, characteristics=0),
            pe_mod.PeSection(name=".b", virtual_address=0x1800,
                             virtual_size=0x1000, raw_size=0x1000,
                             raw_offset=0x600, characteristics=0),
            pe_mod.PeSection(name=".c", virtual_address=0x4000,
                             virtual_size=0, raw_size=0x100,
                             raw_offset=0x1600, characteristics=0),
        ]
        r = _RvaResolver(secs, 0x400)
        for rva in range(0, 0x5000):
            assert r.resolve(rva) == r.resolve(rva), hex(rva)

    def test_whole_extraction_is_deterministic(self, tmp_path):
        p = tmp_path / "det.exe"
        p.write_bytes(_rich_image())
        a = extract_pe_facts(p)
        b = extract_pe_facts(p)
        assert a is not None and b is not None
        assert a == b


class TestWallClock:
    def test_largest_crafted_shape_parses_fast(self, tmp_path):
        """The worst shape this parser can be handed structurally:
        the section table at the cap, every count field at claim
        maximum, an entropy-eligible payload per section. The parse
        must stay interactive-fast — this is the two-direction
        regression bound for anyone raising the caps."""
        secs = [
            Sec(name=b".s", va=0x1000 * (i + 1), data=b"e" * 64)
            for i in range(512)
        ]
        # size_of_headers pushed past the 512-entry table so the
        # auto-placed section data cannot overlap it.
        blob = bytearray(build_pe(PeSpec(
            secs=secs, n_dirs_claimed=2**31 - 1,
            size_of_headers=0x6000)))
        struct.pack_into("<H", blob, 0x80 + 4 + 2, 0xFFFF)
        p = tmp_path / "big.exe"
        p.write_bytes(bytes(blob))
        start = time.perf_counter()
        facts = extract_pe_facts(p)
        elapsed = time.perf_counter() - start
        assert facts is not None
        # The u16-max claim walks past the 512 real entries into
        # section data reinterpreted as headers, up to the cap —
        # bounded and marked, with the real prefix intact.
        assert len(facts.sections) == pe_mod._MAX_SECTIONS
        assert "section_table_capped" in facts.caps_hit
        assert all(s.name == ".s" for s in facts.sections[:512])
        assert elapsed < 2.0


class TestHostileTextRenderContract:
    def test_pdb_basename_with_controls_and_rtl(self, tmp_path):
        """Control bytes and a bidi override in the pdb basename:
        stored capped-at-capture as DATA, and the repo's render
        chokepoint (core.security.log_sanitisation) turns every
        non-printable into an inert escape before any terminal /
        report / prompt use."""
        hostile = "evil\x1b[2Jfake-\u202egdp.cod".encode()
        blob = _rsds_blob(_VEC_GUID_RAW, 7, b"c:\\x\\" + hostile)
        p = tmp_path / "hostilename.exe"
        p.write_bytes(_image_with_debug([(0x40, blob)]))
        facts = extract_pe_facts(p)
        assert facts is not None
        name = facts.pdb_basename
        assert name is not None
        # Stored raw (capped): the control bytes are still data.
        assert "\x1b" in name and "\u202e" in name
        assert len(name.encode("utf-8")) <= pe_mod._MAX_PDB_BASENAME_BYTES
        # Render chokepoint: inert, reviewable text.
        rendered = escape_nonprintable(name)
        assert not has_nonprintable(rendered)
        assert "\\x1b" in rendered
        assert "\\u202e" in rendered

    def test_section_name_render_contract(self, tmp_path):
        p = tmp_path / "escsec.exe"
        p.write_bytes(build_pe(PeSpec(
            secs=[Sec(name=b"\x1b]0;xX", va=0x1000,
                      data=b"x" * 16)])))
        facts = extract_pe_facts(p)
        assert facts is not None
        rendered = escape_nonprintable(facts.sections[0].name)
        assert not has_nonprintable(rendered)
        assert "\\x1b" in rendered


class TestSelfReferentialHeaders:
    def test_e_lfanew_zero_aliases_the_dos_header(self, tmp_path):
        """e_lfanew = 0 makes the PE signature read hit 'MZ...' —
        cleanly not a PE, never a crash."""
        blob = bytearray(build_pe(PeSpec(
            secs=[Sec(name=b".t", va=0x1000, data=b"x" * 16)])))
        struct.pack_into("<I", blob, 0x3C, 0)
        p = tmp_path / "selfref.exe"
        p.write_bytes(bytes(blob))
        assert extract_pe_facts(p) is None

    def test_e_lfanew_pointing_into_section_data(self, tmp_path):
        """A PE signature planted inside section data: the parse
        follows it (that IS the header by format rules) and still
        holds the never-raises contract."""
        planted = b"PE\x00\x00" + struct.pack(
            "<HHIIIHH", 0x8664, 1, 0, 0, 0, 0, 0x0002)
        blob = bytearray(build_pe(PeSpec(
            secs=[Sec(name=b".t", va=0x1000,
                      data=planted + b"\x00" * 64)])))
        struct.pack_into("<I", blob, 0x3C, 0x400)   # first raw byte
        p = tmp_path / "planted.exe"
        p.write_bytes(bytes(blob))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert "optional_header_missing" in facts.caps_hit

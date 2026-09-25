"""Adversarial battery for the Mach-O load-command walk.

Empirical attacks on the parser itself, complementing the per-fact
suites in ``test_macho_facts.py``:

  * seeded random byte-mutation fuzz over rich thin AND fat crafted
    images (three seeds, header-biased flips mixed with truncations),
    asserting the never-raises contract and a per-parse wall-clock
    bound
  * a full truncation sweep — every prefix boundary of both crafted
    images parses to ``None`` or a marked record, never an exception
  * OP-COUNT inertness pins: hostile count/size claims must not buy
    reads, not merely stay fast — a counting file object proves the
    caps make the surplus work NOT HAPPEN
  * an empirical bound pin: no read ever touches bytes past the slice
    being walked (invariant c, measured, not argued)
  * a no-fabrication differential: every extracted name is a byte
    substring of the input file; the UUID's bytes exist in the input
  * hostile dylib/rpath/section text through the repo's render
    chokepoint (``core.security.log_sanitisation``)
  * the worst crafted shape at the REAL caps — 64 fat entries
    aliasing one slice at the load-command cap with name-heavy
    commands and budget-exhausting sections — wall-clock and op-count
    bounded (the two-direction regression bound for anyone raising
    the caps)
"""

from __future__ import annotations

import io
import random
import time

import pytest

from core.security.log_sanitisation import (
    escape_nonprintable,
    has_nonprintable,
)
from packages.binary_analysis import macho as macho_mod
from packages.binary_analysis.macho import (
    MachOFacts,
    extract_macho_facts,
)

from .test_macho_facts import (
    LC_LOAD_DYLIB,
    LC_LOAD_WEAK_DYLIB,
    LC_REEXPORT_DYLIB,
    LC_UNIXTHREAD,
    LC_VERSION_MIN_MACOSX,
    build_fat,
    build_thin,
    build_version_cmd,
    codesig_cmd,
    dylib_cmd,
    dysymtab_cmd,
    fat_table,
    lc,
    main_cmd,
    rpath_cmd,
    section_entry,
    segment_cmd,
    thin_with_sections,
    uuid_cmd,
    version_min_cmd,
)


def _rich_thin(*, bits: int = 64, endian: str = "<") -> bytes:
    """One thin image exercising every parse path."""
    header_size = 32 if bits == 64 else 28
    fixed = 72 if bits == 64 else 56
    entry = 80 if bits == 64 else 68
    data = bytes(range(256)) + b"\x00" * 64
    cmds = [
        uuid_cmd(bytes(range(16)), endian=endian),
        dylib_cmd(b"/usr/lib/libSystem.B.dylib", endian=endian),
        dylib_cmd(b"/usr/lib/libweak.dylib", cmd=LC_LOAD_WEAK_DYLIB,
                  endian=endian),
        dylib_cmd(b"@rpath/libre.dylib", cmd=LC_REEXPORT_DYLIB,
                  endian=endian),
        rpath_cmd(b"@loader_path/../Frameworks", endian=endian),
        dysymtab_cmd((0, 4, 4, 9, 13, 3), endian=endian),
        build_version_cmd(1, 0x000D0100, 0x000E0000, endian=endian),
        version_min_cmd(LC_VERSION_MIN_MACOSX, 0x000A0F00,
                        endian=endian),
        main_cmd(0x4F00, endian=endian),
        lc(LC_UNIXTHREAD, b"\x00" * 16, endian=endian),
        codesig_cmd(0x8000, 0x400, endian=endian),
    ]
    seg_cmdsize = fixed + 2 * entry
    body_before = sum(len(c) for c in cmds)
    data_off = header_size + body_before + seg_cmdsize
    cmds.append(segment_cmd(b"__RICH", [
        section_entry(b"__text", b"__RICH", size=256, offset=data_off,
                      bits=bits, endian=endian),
        section_entry(b"__bss", b"__RICH", size=0x1000, offset=0,
                      flags=0x1, bits=bits, endian=endian),
    ], bits=bits, endian=endian))
    return build_thin(cmds, bits=bits, endian=endian, tail=data)


def _rich_fat() -> bytes:
    return build_fat([_rich_thin(), _rich_thin(bits=32, endian=">")])


class TestMutationFuzz:
    def test_seeded_mutations_never_raise(self, tmp_path):
        """The never-raises contract under random damage, three
        seeds, thin and fat bases. Seeded — every run replays the
        identical corpus. Mutations are header-biased (the leading
        bytes hold the fat table, mach header, and every command this
        parser walks) and mixed with truncations. Each parse is also
        individually time-bounded: no mutation may buy a pathological
        walk."""
        bases = [_rich_thin(), _rich_fat()]
        p = tmp_path / "mut.bin"
        worst = 0.0
        total = 0
        for seed in (0xA11CE, 0xB0B, 0xC0FFEE):
            rng = random.Random(seed)
            for i in range(1700):
                base = bases[i % 2]
                blob = bytearray(base)
                if i % 10 == 9:
                    blob = blob[:rng.randrange(1, len(blob))]
                for _ in range(rng.randint(1, 8)):
                    if rng.random() < 0.6:
                        pos = rng.randrange(min(0x200, len(blob)))
                    else:
                        pos = rng.randrange(len(blob))
                    blob[pos] = rng.randrange(256)
                p.write_bytes(bytes(blob))
                start = time.perf_counter()
                facts = extract_macho_facts(p)   # must never raise
                elapsed = time.perf_counter() - start
                worst = max(worst, elapsed)
                assert elapsed < 1.0, (
                    f"seed {seed:#x} mutation {i} took {elapsed:.3f}s"
                    " — pathological walk")
                assert facts is None or isinstance(facts, MachOFacts)
                total += 1
        assert total == 5100
        assert worst < 1.0


class TestTruncationSweep:
    def _sweep(self, tmp_path, base: bytes) -> None:
        p = tmp_path / "trunc.bin"
        for n in list(range(min(len(base), 0x240))) + \
                list(range(0x240, len(base), 32)):
            p.write_bytes(base[:n])
            facts = extract_macho_facts(p)    # must never raise
            if facts is None:
                continue
            assert isinstance(facts, MachOFacts)

    def test_thin_every_prefix(self, tmp_path):
        base = _rich_thin()
        self._sweep(tmp_path, base)
        # A record produced from a header-complete but command-cut
        # prefix must say SOMETHING (never a silently-complete look).
        p = tmp_path / "cut.bin"
        # Stop before the section-data tail: a prefix that only cuts
        # the tail truthfully degrades a MEASUREMENT (sampled < size),
        # which is record-visible without a marker.
        for n in range(4, len(base) - 340, 17):
            p.write_bytes(base[:n])
            facts = extract_macho_facts(p)
            if facts is None or not facts.slices:
                continue
            assert facts.slices[0].caps_hit, (
                f"prefix {n} lost command structure silently")

    def test_fat_every_prefix(self, tmp_path):
        self._sweep(tmp_path, _rich_fat())


class CountingFile:
    """A file object counting read/seek calls and the furthest byte
    position any read returned — the empirical substrate for the
    inertness and bounds pins."""

    def __init__(self, blob: bytes) -> None:
        self._io = io.BytesIO(blob)
        self.reads = 0
        self.seeks = 0
        self.max_end = 0

    def read(self, count: int = -1) -> bytes:
        position = self._io.tell()
        data = self._io.read(count)
        self.reads += 1
        self.max_end = max(self.max_end, position + len(data))
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        self.seeks += 1
        return self._io.seek(offset, whence)

    def tell(self) -> int:
        return self._io.tell()


def _count(blob: bytes) -> tuple[MachOFacts | None, CountingFile]:
    handle = CountingFile(blob)
    facts = macho_mod._extract_facts_stream(handle)
    return facts, handle


class TestOpCountInertness:
    """A cap that only made hostile work FAST would still be selling
    CPU; these pins prove the capped work does not happen at all —
    operations counted, not timed."""

    def test_u32_max_ncmds_claim_buys_zero_reads(self):
        cap = macho_mod._MAX_LOAD_COMMANDS
        honest = build_thin([lc(0x3F3F)] * cap)
        _, honest_counts = _count(honest)
        hostile = bytearray(honest)
        # ncmds field lives at offset 16 in the 64-bit header.
        hostile[16:20] = b"\xff\xff\xff\xff"
        facts, hostile_counts = _count(bytes(hostile))
        assert facts is not None
        assert facts.slices[0].ncmds_walked == cap
        assert "lc_ncmds_capped" in facts.slices[0].caps_hit
        # The four-billion claim bought not one extra read or seek.
        assert hostile_counts.reads == honest_counts.reads
        assert hostile_counts.seeks == honest_counts.seeks

    def test_surplus_dylibs_past_list_cap_cost_one_read_each(self):
        cap = macho_mod._MAX_DYLIB_NAMES
        surplus = 40
        at_cap = build_thin(
            [dylib_cmd(b"lib%04d.dylib" % i) for i in range(cap)])
        past = build_thin(
            [dylib_cmd(b"lib%04d.dylib" % i)
             for i in range(cap + surplus)])
        facts_a, counts_a = _count(at_cap)
        facts_b, counts_b = _count(past)
        assert facts_a is not None and facts_b is not None
        assert facts_b.slices[0].dylib_counts["load"] == cap + surplus
        # Each surplus command costs exactly ONE read (its 8-byte
        # header) — the name-offset and name-window reads are not
        # merely cheap, they are absent.
        assert counts_b.reads - counts_a.reads == surplus

    def test_exhausted_entropy_budget_stops_section_reads(
            self, monkeypatch):
        blob = thin_with_sections([
            (b"__one", b"x" * 64, 0),
            (b"__two", b"y" * 64, 0),
            (b"__three", b"z" * 64, 0),
        ])
        _, normal = _count(blob)
        monkeypatch.setattr(macho_mod, "_MAX_ENTROPY_TOTAL_BYTES", 0)
        facts, starved = _count(blob)
        assert facts is not None
        assert ("entropy_budget_exhausted"
                in facts.slices[0].caps_hit)
        # Exactly the three section-data reads disappeared.
        assert normal.reads - starved.reads == 3

    def test_no_read_ever_leaves_the_slice(self):
        """Invariant (c), measured: a slice stuffed with overreaching
        claims (sizeofcmds huge, ncmds huge, sections claiming
        gigabytes from offset 0) sits BEFORE trailing garbage — no
        read may return bytes from past the slice's declared end."""
        inner_cmds = [
            uuid_cmd(),
            dylib_cmd(b"/usr/lib/libSystem.B.dylib"),
            segment_cmd(b"__GREEDY", [section_entry(
                b"__huge", b"__GREEDY", size=2**31, offset=0)]),
        ]
        inner = build_thin(inner_cmds, ncmds=0xFFFF,
                           sizeofcmds=0x7FFFFFFF)
        table = fat_table([(0x01000007, 0, 28, len(inner))])
        blob = table + inner + b"G" * 8192       # trailing garbage
        slice_end = len(table) + len(inner)
        facts, counts = _count(blob)
        assert facts is not None
        item = facts.slices[0]
        assert "lc_sizeofcmds_clamped" in item.caps_hit
        assert counts.max_end <= slice_end


class TestNoFabrication:
    def test_extracted_names_are_byte_substrings_of_input(
            self, tmp_path):
        """200 seeded random well-formed images: every extracted
        dylib/rpath/segment/section name and the UUID must exist as
        bytes in the input — the extractor reports, never invents."""
        rng = random.Random(0x5EED)
        alphabet = ("abcdefghijklmnopqrstuvwxyz"
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-@")
        p = tmp_path / "gen.bin"

        def _name(lo: int = 3, hi: int = 30) -> bytes:
            return "".join(rng.choice(alphabet) for _ in
                           range(rng.randint(lo, hi))).encode()

        for _ in range(200):
            uuid_raw = rng.randbytes(16)
            cmds = [uuid_cmd(uuid_raw)]
            for _ in range(rng.randint(1, 10)):
                kind = rng.choice([LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB,
                                   LC_REEXPORT_DYLIB])
                cmds.append(dylib_cmd(_name(), cmd=kind))
            for _ in range(rng.randint(0, 3)):
                cmds.append(rpath_cmd(_name()))
            cmds.append(segment_cmd(_name(3, 15)[:16], [
                section_entry(_name(3, 15)[:16], b"__SEG")
                for _ in range(rng.randint(0, 4))]))
            blob = build_thin(cmds)
            p.write_bytes(blob)
            facts = extract_macho_facts(p)
            assert facts is not None
            item = facts.slices[0]
            assert item.uuid is not None
            assert bytes.fromhex(item.uuid) in blob
            names = (item.load_dylibs + item.weak_dylibs
                     + item.reexport_dylibs + item.rpaths)
            for segment in item.segments:
                names.append(segment.name)
                names.extend(s.name for s in segment.sections)
            for name in names:
                assert name.encode("utf-8") in blob, name


class TestHostileTextRenderContract:
    def test_dylib_name_with_controls_and_bidi(self, tmp_path):
        """Control bytes and a bidi override in a dylib name: stored
        capped-at-capture as DATA, and the repo's render chokepoint
        (core.security.log_sanitisation) turns every non-printable
        into an inert escape before any terminal / report / prompt
        use."""
        hostile = "lib\x1b[2Jevil-\u202egnp.bil".encode()
        p = tmp_path / "hostile.bin"
        p.write_bytes(build_thin([
            dylib_cmd(hostile),
            rpath_cmd(b"@rpath/\x07bell\x9b[31m"),
        ]))
        facts = extract_macho_facts(p)
        assert facts is not None
        item = facts.slices[0]
        name = item.load_dylibs[0]
        # Stored raw (capped): the control bytes are still data.
        assert "\x1b" in name and "\u202e" in name
        assert (len(name.encode("utf-8"))
                <= macho_mod._MAX_LC_NAME_BYTES)
        rendered = escape_nonprintable(name)
        assert not has_nonprintable(rendered)
        assert "\\x1b" in rendered
        assert "\\u202e" in rendered
        rpath_rendered = escape_nonprintable(item.rpaths[0])
        assert not has_nonprintable(rpath_rendered)

    def test_section_name_render_contract(self, tmp_path):
        p = tmp_path / "escsec.bin"
        p.write_bytes(build_thin([segment_cmd(b"__D", [
            section_entry(b"\x1b]0;xX", b"__D")])]))
        facts = extract_macho_facts(p)
        assert facts is not None
        rendered = escape_nonprintable(
            facts.slices[0].segments[0].sections[0].name)
        assert not has_nonprintable(rendered)
        assert "\\x1b" in rendered


class TestGrowthRatio:
    """CI-speed-robust complexity pin. A wall-clock bound with
    slow-CI headroom cannot catch superlinear per-command work (a
    restored quadratic re-sum parses the committed worst shape well
    under the 30s bound), so this pin compares the SAME shape at two
    command counts and asserts the growth is near-linear — a ratio
    is host-speed-invariant and reds on ANY superlinear
    per-command cost."""

    @staticmethod
    def _segment_flood(count: int) -> bytes:
        # Minimal 72-byte segment commands, zero sections: pure
        # per-command bookkeeping, no name or entropy reads.
        return build_thin([segment_cmd(b"__G", [])] * count)

    @staticmethod
    def _best_parse_time(blob: bytes, repeats: int = 5) -> float:
        best = float("inf")
        for _ in range(repeats):
            handle = io.BytesIO(blob)
            start = time.perf_counter()
            facts = macho_mod._extract_facts_stream(handle)
            best = min(best, time.perf_counter() - start)
            assert facts is not None
            assert facts.slices[0].ncmds_walked == len(
                facts.slices[0].segments)
        return best

    def test_segment_walk_scales_linearly(self):
        small_n, large_n = 1024, 4096
        small = self._segment_flood(small_n)
        large = self._segment_flood(large_n)
        self._best_parse_time(small, repeats=1)      # warm-up
        t_small = self._best_parse_time(small)
        t_large = self._best_parse_time(large)
        ratio = t_large / t_small
        # Linear per-command work predicts ratio ~4 (the count
        # quadrupled); quadratic bookkeeping (per-command re-sum
        # over prior segments) predicts ~16. 8.0 leaves generous
        # slack for timer noise while cleanly separating the two.
        assert ratio < 8.0, (
            f"superlinear growth: {small_n} cmds {t_small:.4f}s vs "
            f"{large_n} cmds {t_large:.4f}s (ratio {ratio:.1f}, "
            f"linear predicts ~4)")


class TestDeterminism:
    def test_whole_extraction_is_deterministic(self, tmp_path):
        p = tmp_path / "det.bin"
        p.write_bytes(_rich_fat())
        first = extract_macho_facts(p)
        second = extract_macho_facts(p)
        assert first is not None and second is not None
        assert first == second


def _worst_shape() -> bytes:
    """The adversarial product at the REAL caps: one crafted slice at
    the 4096-command cap (name-heavy linkage commands up to every
    list cap; one segment whose sections claim gigabytes from
    offset 0; then MINIMAL segment commands, one section each, to the
    command cap), aliased by 64 fat entries — attacker ncmds x
    per-command work x slice count. The segment-heavy fill is
    deliberate: per-command section-record bookkeeping across
    thousands of segments is its own cost axis (a dylib-only fill
    left it unpriced), and it must stay O(1) per command."""
    name = b"/w" + b"a" * 998                      # 1000-byte names
    cmds: list[bytes] = []
    for kind in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB,
                 LC_REEXPORT_DYLIB):
        cmds.extend(dylib_cmd(name, cmd=kind) for _ in
                    range(macho_mod._MAX_DYLIB_NAMES))
    cmds.extend(rpath_cmd(name) for _ in range(macho_mod._MAX_RPATHS))
    cmds.append(segment_cmd(b"__WORST", [
        section_entry(b"__s%03d" % i, b"__WORST", size=2**31,
                      offset=0)
        for i in range(255)]))
    filler_segment = segment_cmd(
        b"__F", [section_entry(b"__z", b"__F")])
    cmds.extend(filler_segment for _ in
                range(macho_mod._MAX_LOAD_COMMANDS - len(cmds)))
    assert len(cmds) == macho_mod._MAX_LOAD_COMMANDS
    inner = build_thin(cmds)
    entries = [(0x01000007, 0, 8 + 64 * 20, len(inner))] * 64
    return fat_table(entries) + inner


class TestWorstCraftedShape:
    @pytest.mark.slow
    def test_wall_clock_and_op_count_at_the_real_caps(self, tmp_path):
        """Nightly tier: parsing the worst shape at the REAL caps
        twice is genuine multi-second CPU that breaches the
        default-tier budget under loaded-runner variance (its own
        wall bound below is 30s); the default tier keeps the seeded
        mutation fuzz and the per-cap suites for per-PR coverage.

        The worst shape this parser can be handed structurally,
        measured — this is the two-direction regression bound for
        anyone raising the caps (raise a cap, re-measure, re-pin).
        Wall clock alone is not the pin: the op count asserts the
        budget-driven inertness (64 aliasing slices CANNOT each pay
        the full name walk or the full entropy walk)."""
        blob = _worst_shape()
        facts, counts = _count(blob)
        assert facts is not None
        assert len(facts.slices) == 64
        assert "fat_slices_overlap" in facts.caps_hit
        for item in facts.slices:
            assert item.ncmds_walked == macho_mod._MAX_LOAD_COMMANDS
        # File-level budgets held across the aliasing slices:
        retained = sum(
            len(n.encode()) for s in facts.slices
            for n in (s.load_dylibs + s.weak_dylibs
                      + s.reexport_dylibs + s.rpaths))
        assert retained <= macho_mod._MAX_TOTAL_NAME_BYTES + \
            macho_mod._MAX_LC_NAME_BYTES        # soft-budget overdraw
        assert any("lc_name_budget_exhausted" in s.caps_hit
                   for s in facts.slices)
        assert any("entropy_budget_exhausted" in s.caps_hit
                   for s in facts.slices)
        # The segment-heavy fill: every slice hits the per-slice
        # section-record cap and retains exactly the cap, no more.
        for item in facts.slices:
            assert "section_records_capped" in item.caps_hit
            assert (sum(len(seg.sections) for seg in item.segments)
                    == macho_mod._MAX_SECTION_RECORDS)
        # Op-count bound: <= 2 reads for magic/count + table, and per
        # slice <= 2 header reads + 3 reads per command + segment
        # rows + entropy reads. The dominant term is the header walk;
        # everything else is budget-capped.
        per_slice_ceiling = 2 + 3 * macho_mod._MAX_LOAD_COMMANDS + 32
        assert counts.reads <= 2 + 64 * per_slice_ceiling
        # Wall clock on the file-backed public path.
        p = tmp_path / "worst.bin"
        p.write_bytes(blob)
        start = time.perf_counter()
        result = extract_macho_facts(p)
        elapsed = time.perf_counter() - start
        assert result is not None
        assert elapsed < 30.0

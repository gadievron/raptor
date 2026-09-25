"""Tests for the Mach-O load-command facts walk: crafted thin/fat
builders, the header facts, and the four named walk invariants —

  (a) monotonic advance (cmdsize >= 8, cursor strictly increasing;
      zero / short / fixed-header-truncated cmdsize aborts),
  (b) the ncmds cap and the sizeofcmds clamp,
  (c) the walk bounds ITSELF to the slice extent and file EOF and
      screens every fat-header value before trusting it,
  (d) lc_str offsets bounded within their own command's cmdsize
      (exercised in the per-fact suites that extract names).

The builders here are the shared crafting substrate for every Mach-O
facts suite (the battery imports them).
"""

from __future__ import annotations

import struct

from packages.binary_analysis import macho as macho_mod
from packages.binary_analysis.macho import (
    MachOFacts,
    extract_macho_facts,
    extract_macho_slice_facts,
)

CPU_X86_64 = 7 | 0x01000000
CPU_ARM64 = 12 | 0x01000000
CPU_PPC = 18

# A load-command value the walk does not parse (no LC with this value
# exists in <mach-o/loader.h>); used for filler commands.
LC_FILLER = 0x3F3F

_THIN_MAGIC = {
    ("<", 32): b"\xce\xfa\xed\xfe",
    ("<", 64): b"\xcf\xfa\xed\xfe",
    (">", 32): b"\xfe\xed\xfa\xce",
    (">", 64): b"\xfe\xed\xfa\xcf",
}


def lc(cmd: int, payload: bytes = b"", *, endian: str = "<",
       cmdsize: int | None = None) -> bytes:
    """One raw load command; ``cmdsize`` overrides for hostile shapes
    (the emitted bytes still carry the full payload)."""
    size = cmdsize if cmdsize is not None else 8 + len(payload)
    return struct.pack(f"{endian}II", cmd, size) + payload


def uuid_cmd(raw: bytes = bytes(range(16)), *, endian: str = "<",
             cmdsize: int | None = None) -> bytes:
    return lc(0x1B, raw, endian=endian, cmdsize=cmdsize)


def build_thin(cmds: list[bytes], *, bits: int = 64, endian: str = "<",
               cputype: int = CPU_X86_64, cpusubtype: int = 0,
               filetype: int = 2, flags: int = 0,
               ncmds: int | None = None, sizeofcmds: int | None = None,
               tail: bytes = b"") -> bytes:
    """A crafted thin Mach-O: header + concatenated load commands.
    ``ncmds`` / ``sizeofcmds`` override the truthful values for lying
    headers; ``tail`` appends bytes after the command region."""
    body = b"".join(cmds)
    n = ncmds if ncmds is not None else len(cmds)
    size = sizeofcmds if sizeofcmds is not None else len(body)
    header = _THIN_MAGIC[(endian, bits)] + struct.pack(
        f"{endian}IIIIII", cputype, cpusubtype, filetype, n, size,
        flags)
    if bits == 64:
        header += struct.pack(f"{endian}I", 0)     # reserved
    return header + body + tail


def build_fat(slices: list[bytes], *, fat64: bool = False,
              cputypes: list[int] | None = None) -> bytes:
    """An honest fat container: table + slices at 8-aligned offsets."""
    entry_size = 32 if fat64 else 20
    cursor = 8 + entry_size * len(slices)
    placed: list[tuple[int, bytes]] = []
    entries: list[tuple[int, int, int, int]] = []
    for index, blob in enumerate(slices):
        offset = (cursor + 7) & ~7
        placed.append((offset, blob))
        cpu = (cputypes[index] if cputypes is not None else CPU_X86_64)
        entries.append((cpu, 0, offset, len(blob)))
        cursor = offset + len(blob)
    out = bytearray(fat_table(entries, fat64=fat64))
    for offset, blob in placed:
        if len(out) < offset:
            out += b"\x00" * (offset - len(out))
        out[offset:offset + len(blob)] = blob
    return bytes(out)


def fat_table(entries: list[tuple[int, int, int, int]], *,
              fat64: bool = False, nfat: int | None = None) -> bytes:
    """A raw fat header + entry table (big-endian, as real fat headers
    are) — entries are (cputype, cpusubtype, offset, size) and may
    point anywhere: the hostile-shape substrate."""
    magic = b"\xca\xfe\xba\xbf" if fat64 else b"\xca\xfe\xba\xbe"
    out = magic + struct.pack(
        ">I", nfat if nfat is not None else len(entries))
    for cpu, sub, offset, size in entries:
        if fat64:
            out += struct.pack(">IIQQII", cpu, sub, offset, size, 0, 0)
        else:
            out += struct.pack(">IIIII", cpu, sub, offset, size, 0)
    return out


def extract(tmp_path, blob: bytes) -> MachOFacts | None:
    p = tmp_path / "sample.bin"
    p.write_bytes(blob)
    return extract_macho_facts(p)


# ---------------------------------------------------------------------------
# Header facts
# ---------------------------------------------------------------------------


class TestHeaderFacts:
    def test_thin_little_64(self, tmp_path):
        facts = extract(tmp_path, build_thin(
            [uuid_cmd()], filetype=2, flags=0x00200085))
        assert facts is not None
        assert facts.is_fat is False
        assert facts.declared_slices == 1
        assert len(facts.slices) == 1
        item = facts.slices[0]
        assert item.arch == "x86_64"
        assert item.bits == 64
        assert item.endianness == "little"
        assert item.filetype == 2
        assert item.flags == 0x00200085
        assert item.ncmds_declared == 1
        assert item.ncmds_walked == 1
        assert item.sizeofcmds_declared == 24
        assert item.caps_hit == []

    def test_thin_big_32(self, tmp_path):
        facts = extract(tmp_path, build_thin(
            [uuid_cmd(endian=">")], bits=32, endian=">",
            cputype=CPU_PPC))
        assert facts is not None
        item = facts.slices[0]
        assert item.arch == "ppc"
        assert item.bits == 32
        assert item.endianness == "big"
        assert item.ncmds_walked == 1

    def test_byte_swapped_slices_agree(self, tmp_path):
        """Ground truth for the MH_CIGAM variants: the same logical
        content built little- and big-endian yields identical facts
        apart from the endianness field itself."""
        payload = bytes(range(16))
        for bits in (32, 64):
            le = extract(tmp_path, build_thin(
                [uuid_cmd(payload)], bits=bits, endian="<"))
            be = extract(tmp_path, build_thin(
                [uuid_cmd(payload, endian=">")], bits=bits, endian=">"))
            assert le is not None and be is not None
            a, b = le.slices[0], be.slices[0]
            assert (a.endianness, b.endianness) == ("little", "big")
            for field_name in ("arch", "bits", "filetype", "uuid",
                               "ncmds_declared", "ncmds_walked",
                               "sizeofcmds_declared", "caps_hit"):
                assert getattr(a, field_name) == getattr(b, field_name)

    def test_unknown_cputype_and_filetype_fail_open(self, tmp_path):
        facts = extract(tmp_path, build_thin(
            [uuid_cmd()], cputype=0x7777, filetype=0x99))
        assert facts is not None
        item = facts.slices[0]
        assert item.arch == "cpu_0x7777"
        assert item.filetype == 0x99      # raw value recorded

    def test_not_macho_is_none(self, tmp_path):
        assert extract(tmp_path, b"\x7fELF" + b"\x00" * 60) is None
        assert extract(tmp_path, b"") is None
        assert extract(tmp_path, b"\xcf\xfa") is None

    def test_header_truncated_is_marked(self, tmp_path):
        blob = build_thin([uuid_cmd()])[:20]     # magic ok, header cut
        facts = extract(tmp_path, blob)
        assert facts is not None
        assert facts.slices[0].caps_hit == ["slice_header_truncated"]


# ---------------------------------------------------------------------------
# LC_UUID
# ---------------------------------------------------------------------------


class TestUuid:
    def test_uuid_lowercase_hex(self, tmp_path):
        raw = bytes.fromhex("D4C3B2A1F6E5180790ABCDEF01234567")
        facts = extract(tmp_path, build_thin([uuid_cmd(raw)]))
        assert facts is not None
        assert facts.slices[0].uuid == \
            "d4c3b2a1f6e5180790abcdef01234567"

    def test_all_zero_uuid_recorded_verbatim(self, tmp_path):
        """The degenerate screen is a later phase's policy — this
        layer records what the file says."""
        facts = extract(tmp_path, build_thin([uuid_cmd(bytes(16))]))
        assert facts is not None
        assert facts.slices[0].uuid == "00" * 16
        assert facts.slices[0].caps_hit == []

    def test_duplicate_identical_uuid_is_silent(self, tmp_path):
        facts = extract(tmp_path, build_thin(
            [uuid_cmd(), uuid_cmd()]))
        assert facts is not None
        assert facts.slices[0].caps_hit == []

    def test_conflicting_uuid_first_wins_and_marked(self, tmp_path):
        first = bytes(range(16))
        second = bytes(range(16, 32))
        facts = extract(tmp_path, build_thin(
            [uuid_cmd(first), uuid_cmd(second)]))
        assert facts is not None
        item = facts.slices[0]
        assert item.uuid == first.hex()
        assert "conflicting_lc_uuid" in item.caps_hit

    def test_truncated_uuid_command_aborts_walk(self, tmp_path):
        """Invariant (a): cmdsize below LC_UUID's fixed 24 bytes —
        decoding would overlap the next command. Walk abort, facts so
        far kept."""
        facts = extract(tmp_path, build_thin(
            [uuid_cmd(cmdsize=20), uuid_cmd(bytes(range(16, 32)))]))
        assert facts is not None
        item = facts.slices[0]
        assert item.uuid is None
        assert item.ncmds_walked == 0
        assert "lc_walk_abort_fixed_header_truncated" in item.caps_hit


# ---------------------------------------------------------------------------
# Invariant (a): monotonic advance
# ---------------------------------------------------------------------------


class TestMonotonicAdvance:
    def test_cmdsize_zero_aborts(self, tmp_path):
        facts = extract(tmp_path, build_thin(
            [lc(LC_FILLER, b"\x00" * 8, cmdsize=0), uuid_cmd()]))
        assert facts is not None
        item = facts.slices[0]
        assert item.ncmds_walked == 0
        assert item.uuid is None
        assert "lc_walk_abort_cmdsize_underflow" in item.caps_hit

    def test_cmdsize_seven_aborts(self, tmp_path):
        facts = extract(tmp_path, build_thin(
            [lc(LC_FILLER, b"\x00" * 8, cmdsize=7), uuid_cmd()]))
        assert facts is not None
        assert ("lc_walk_abort_cmdsize_underflow"
                in facts.slices[0].caps_hit)

    def test_command_overrunning_region_aborts(self, tmp_path):
        """A cmdsize past the region end would read outside the
        bounded extent — abort, prior facts kept."""
        facts = extract(tmp_path, build_thin(
            [uuid_cmd(), lc(LC_FILLER, b"\x00" * 8, cmdsize=0x1000)]))
        assert facts is not None
        item = facts.slices[0]
        assert item.uuid is not None       # first command's fact kept
        assert item.ncmds_walked == 1
        assert "lc_walk_abort_bounds" in item.caps_hit

    def test_cursor_never_stalls_on_minimal_commands(self, tmp_path):
        """8-byte commands are the smallest legal step: the walk must
        consume each exactly once (walked == declared, no markers)."""
        facts = extract(tmp_path, build_thin([lc(LC_FILLER)] * 32))
        assert facts is not None
        item = facts.slices[0]
        assert item.ncmds_walked == 32
        assert item.caps_hit == []


class TestCmdsizeAlignment:
    """The module's one documented tolerance: an unaligned cmdsize
    (spec: multiple of 4 on 32-bit, 8 on 64-bit; dyld refuses
    violations) is consumed — a facts reader is not a loader — but
    marked, never silent."""

    def test_unaligned_cmdsize_in_64_bit_marked_not_fatal(
            self, tmp_path):
        # 12 % 8 != 0 in a 64-bit slice: marked, walk continues.
        facts = extract(tmp_path, build_thin(
            [lc(LC_FILLER, b"\x00" * 4), uuid_cmd()]))
        assert facts is not None
        item = facts.slices[0]
        assert item.ncmds_walked == 2
        assert item.uuid is not None
        assert "lc_cmdsize_unaligned" in item.caps_hit

    def test_multiple_of_four_is_clean_in_32_bit(self, tmp_path):
        # The same 12-byte command IS aligned for a 32-bit slice.
        facts = extract(tmp_path, build_thin(
            [lc(LC_FILLER, b"\x00" * 4, endian=">"),
             uuid_cmd(endian=">")],
            bits=32, endian=">", cputype=CPU_PPC))
        assert facts is not None
        assert ("lc_cmdsize_unaligned"
                not in facts.slices[0].caps_hit)

    def test_odd_cmdsize_in_32_bit_marked(self, tmp_path):
        facts = extract(tmp_path, build_thin(
            [lc(LC_FILLER, b"\x00" * 5, endian=">"),
             uuid_cmd(endian=">")],
            bits=32, endian=">", cputype=CPU_PPC))
        assert facts is not None
        item = facts.slices[0]
        assert item.ncmds_walked == 2
        assert "lc_cmdsize_unaligned" in item.caps_hit


# ---------------------------------------------------------------------------
# Invariant (b): ncmds cap + sizeofcmds clamp
# ---------------------------------------------------------------------------


class TestNcmdsAndSizeofcmds:
    def test_ncmds_at_the_real_cap_is_clean(self, tmp_path):
        cap = macho_mod._MAX_LOAD_COMMANDS
        facts = extract(tmp_path, build_thin([lc(LC_FILLER)] * cap))
        assert facts is not None
        item = facts.slices[0]
        assert item.ncmds_walked == cap
        assert "lc_ncmds_capped" not in item.caps_hit

    def test_ncmds_one_past_the_real_cap(self, tmp_path):
        cap = macho_mod._MAX_LOAD_COMMANDS
        facts = extract(tmp_path,
                        build_thin([lc(LC_FILLER)] * (cap + 1)))
        assert facts is not None
        item = facts.slices[0]
        assert item.ncmds_declared == cap + 1
        assert item.ncmds_walked == cap
        assert "lc_ncmds_capped" in item.caps_hit

    def test_ncmds_u32_max_claim(self, tmp_path):
        facts = extract(tmp_path, build_thin(
            [uuid_cmd(), lc(LC_FILLER)], ncmds=0xFFFFFFFF))
        assert facts is not None
        item = facts.slices[0]
        assert item.ncmds_declared == 0xFFFFFFFF
        assert item.ncmds_walked == 2
        assert item.uuid is not None
        assert "lc_ncmds_capped" in item.caps_hit
        assert "lc_walk_abort_region_end" in item.caps_hit

    def test_sizeofcmds_lying_small_stops_the_walk(self, tmp_path):
        """Two 24-byte commands but sizeofcmds admits only 30 bytes:
        the second command's header no longer fits the region."""
        facts = extract(tmp_path, build_thin(
            [uuid_cmd(), uuid_cmd(bytes(range(16, 32)))],
            sizeofcmds=30))
        assert facts is not None
        item = facts.slices[0]
        assert item.ncmds_walked == 1
        assert item.uuid == bytes(range(16)).hex()
        assert "lc_walk_abort_region_end" in item.caps_hit

    def test_sizeofcmds_lying_large_is_clamped(self, tmp_path):
        facts = extract(tmp_path, build_thin(
            [uuid_cmd(), lc(LC_FILLER)], sizeofcmds=0x40000000))
        assert facts is not None
        item = facts.slices[0]
        assert item.sizeofcmds_declared == 0x40000000
        assert "lc_sizeofcmds_clamped" in item.caps_hit
        # Both real commands still parse inside the clamped region.
        assert item.ncmds_walked == 2
        assert item.uuid is not None


# ---------------------------------------------------------------------------
# Invariant (c): own bounds — fat entries screened, slices clamped
# ---------------------------------------------------------------------------


class TestOwnBounds:
    def test_honest_fat_parses_all_slices(self, tmp_path):
        a = build_thin([uuid_cmd()])
        b = build_thin([uuid_cmd(bytes(range(16, 32)))],
                       cputype=CPU_ARM64)
        facts = extract(tmp_path, build_fat(
            [a, b], cputypes=[CPU_X86_64, CPU_ARM64]))
        assert facts is not None
        assert facts.is_fat is True
        assert facts.declared_slices == 2
        assert [s.arch for s in facts.slices] == ["x86_64", "arm64"]
        assert facts.caps_hit == []

    def test_fat64_container_parses(self, tmp_path):
        facts = extract(tmp_path, build_fat(
            [build_thin([uuid_cmd()])], fat64=True))
        assert facts is not None
        assert len(facts.slices) == 1
        assert facts.slices[0].uuid is not None

    def test_fat_entry_past_eof_rejected(self, tmp_path):
        blob = fat_table([(CPU_X86_64, 0, 0x100000, 64)])
        facts = extract(tmp_path, blob)
        assert facts is not None
        assert facts.slices == []
        assert "fat_entry_past_eof" in facts.caps_hit

    def test_fat_entry_size_overrunning_eof_rejected(self, tmp_path):
        inner = build_thin([uuid_cmd()])
        blob = fat_table([(CPU_X86_64, 0, 28, len(inner) + 4096)])
        blob += inner
        facts = extract(tmp_path, blob)
        assert facts is not None
        assert facts.slices == []
        assert "fat_entry_past_eof" in facts.caps_hit

    def test_fat_entry_offset_screened(self, tmp_path):
        blob = fat_table([(CPU_X86_64, 0, 2**62 + 8, 64)], fat64=True)
        facts = extract(tmp_path, blob)
        assert facts is not None
        assert facts.slices == []
        assert "fat_entry_offset_screened" in facts.caps_hit

    def test_fat_entry_offset_plus_size_overflow(self, tmp_path):
        """Both terms pass the individual screen; the explicit sum
        check must still reject the pair (no wraparound exists in
        Python — the sum check IS the overflow check)."""
        blob = fat_table(
            [(CPU_X86_64, 0, 2**61, 2**61 + 2**20)], fat64=True)
        facts = extract(tmp_path, blob)
        assert facts is not None
        assert facts.slices == []
        assert "fat_entry_past_eof" in facts.caps_hit

    def test_fat_entry_not_macho_marked(self, tmp_path):
        blob = fat_table([(CPU_X86_64, 0, 28, 64)])
        blob += b"\x7fELF" + b"\x00" * 60
        facts = extract(tmp_path, blob)
        assert facts is not None
        assert facts.slices == []
        assert "fat_entry_not_macho" in facts.caps_hit

    def test_fat_entry_smaller_than_a_magic_rejected(self, tmp_path):
        """An entry too small to hold a magic is rejected BEFORE the
        slice walk's first read — otherwise the 4-byte magic read
        would take bytes from beyond the declared extent
        (invariant c)."""
        inner = build_thin([uuid_cmd()])
        blob = fat_table([(CPU_X86_64, 0, 28, 2)]) + inner
        facts = extract(tmp_path, blob)
        assert facts is not None
        assert facts.slices == []
        assert "fat_entry_not_macho" in facts.caps_hit
        p = _write(tmp_path, blob)
        assert extract_macho_slice_facts(p, offset=28, size=2) is None

    def test_overlapping_fat_slices_marked_and_parsed(self, tmp_path):
        inner = build_thin([uuid_cmd()])
        entry_area = 8 + 2 * 20
        blob = fat_table([
            (CPU_X86_64, 0, entry_area, len(inner)),
            (CPU_ARM64, 0, entry_area + 8, len(inner) - 8),
        ])
        blob += inner
        facts = extract(tmp_path, blob)
        assert facts is not None
        assert "fat_slices_overlap" in facts.caps_hit
        # Each walk is independently bounded — the aliasing entry
        # yields no crash; the first slice still parses fully.
        assert any(s.uuid is not None for s in facts.slices)

    def test_fat_slice_count_capped(self, tmp_path):
        inner = build_thin([uuid_cmd()])
        blob = fat_table([(CPU_X86_64, 0, 28, len(inner))], nfat=5000)
        blob += inner
        facts = extract(tmp_path, blob)
        assert facts is not None
        assert facts.declared_slices == 5000
        assert "fat_slices_capped" in facts.caps_hit
        assert "fat_table_truncated" in facts.caps_hit

    def test_slice_clamps_its_own_region_inside_fat(self, tmp_path):
        """A slice whose sizeofcmds AND ncmds claim past its OWN
        fat-declared extent is clamped at the slice end, not the file
        end — bytes of the next slice are never walked as this
        slice's commands."""
        inner = build_thin([uuid_cmd()], ncmds=4, sizeofcmds=0x10000)
        second = build_thin([uuid_cmd(bytes(range(16, 32)))])
        blob = bytearray(build_fat([inner, second]))
        facts = extract_macho_facts(_write(tmp_path, bytes(blob)))
        assert facts is not None
        first = facts.slices[0]
        assert "lc_sizeofcmds_clamped" in first.caps_hit
        # The first slice's walk saw only its own single command and
        # stopped AT THE SLICE END — never inside the next slice.
        assert first.ncmds_walked == 1
        assert first.uuid == bytes(range(16)).hex()
        assert "lc_walk_abort_region_end" in first.caps_hit
        assert "conflicting_lc_uuid" not in first.caps_hit


def _write(tmp_path, blob: bytes):
    p = tmp_path / "sample.bin"
    p.write_bytes(blob)
    return p


# ---------------------------------------------------------------------------
# Explicit slice selection (public per-slice entry point)
# ---------------------------------------------------------------------------


class TestExplicitSliceSelection:
    def test_selected_slice_extracts(self, tmp_path):
        inner = build_thin([uuid_cmd()])
        blob = build_fat([inner])
        p = _write(tmp_path, blob)
        offset = blob.index(_THIN_MAGIC[("<", 64)])
        item = extract_macho_slice_facts(
            p, offset=offset, size=len(inner))
        assert item is not None
        assert item.uuid == bytes(range(16)).hex()

    def test_stale_selection_past_eof_refused(self, tmp_path):
        p = _write(tmp_path, build_thin([uuid_cmd()]))
        assert extract_macho_slice_facts(
            p, offset=64, size=10**9) is None

    def test_screened_offset_refused(self, tmp_path):
        p = _write(tmp_path, build_thin([uuid_cmd()]))
        assert extract_macho_slice_facts(
            p, offset=2**62 + 1, size=8) is None
        assert extract_macho_slice_facts(
            p, offset=-1, size=8) is None

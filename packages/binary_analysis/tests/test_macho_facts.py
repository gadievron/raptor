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


# ---------------------------------------------------------------------------
# Builders for the fact-carrying commands
# ---------------------------------------------------------------------------

LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_RPATH = 0x8000001C
LC_DYSYMTAB = 0xB
LC_SYMTAB = 0x2
LC_BUILD_VERSION = 0x32
LC_VERSION_MIN_MACOSX = 0x24
LC_VERSION_MIN_IPHONEOS = 0x25
LC_MAIN = 0x80000028
LC_UNIXTHREAD = 0x5
LC_CODE_SIGNATURE = 0x1D
LC_SEGMENT = 0x1
LC_SEGMENT_64 = 0x19


def _lc_str_pad(blob: bytes) -> bytes:
    """Real linkers NUL-pad lc_str commands to 8-byte alignment
    (dyld refuses unaligned cmdsize); the builders emit realistic
    aligned commands so alignment tolerance stays a deliberate,
    separately-tested shape."""
    return blob + b"\x00" * ((-(8 + len(blob))) % 8)


def dylib_cmd(name: bytes, cmd: int = LC_LOAD_DYLIB, *,
              endian: str = "<", name_off: int = 24,
              cmdsize: int | None = None,
              terminate: bool = True) -> bytes:
    payload = struct.pack(f"{endian}IIII", name_off, 0, 0x10000,
                          0x10000)
    blob = payload + name
    if terminate:
        blob = _lc_str_pad(blob + b"\x00")
    return lc(cmd, blob, endian=endian, cmdsize=cmdsize)


def rpath_cmd(path: bytes, *, endian: str = "<",
              name_off: int = 12) -> bytes:
    blob = _lc_str_pad(struct.pack(f"{endian}I", name_off)
                       + path + b"\x00")
    return lc(LC_RPATH, blob, endian=endian)


def dysymtab_cmd(counts: tuple[int, int, int, int, int, int], *,
                 endian: str = "<") -> bytes:
    payload = struct.pack(f"{endian}6I", *counts)
    payload += struct.pack(f"{endian}12I", *([0] * 12))
    return lc(LC_DYSYMTAB, payload, endian=endian)


def build_version_cmd(platform: int, minos: int, sdk: int = 0, *,
                      endian: str = "<") -> bytes:
    return lc(LC_BUILD_VERSION,
              struct.pack(f"{endian}IIII", platform, minos, sdk, 0),
              endian=endian)


def version_min_cmd(cmd: int, version: int, sdk: int = 0, *,
                    endian: str = "<") -> bytes:
    return lc(cmd, struct.pack(f"{endian}II", version, sdk),
              endian=endian)


def main_cmd(entryoff: int, *, endian: str = "<") -> bytes:
    return lc(LC_MAIN, struct.pack(f"{endian}QQ", entryoff, 0),
              endian=endian)


def codesig_cmd(dataoff: int, datasize: int, *,
                endian: str = "<") -> bytes:
    return lc(LC_CODE_SIGNATURE,
              struct.pack(f"{endian}II", dataoff, datasize),
              endian=endian)


def section_entry(sectname: bytes, segname: bytes, *, addr: int = 0,
                  size: int = 0, offset: int = 0, flags: int = 0,
                  bits: int = 64, endian: str = "<") -> bytes:
    if bits == 64:
        return struct.pack(
            f"{endian}16s16sQQIIIIIIII", sectname, segname, addr,
            size, offset, 0, 0, 0, flags, 0, 0, 0)
    return struct.pack(
        f"{endian}16s16sIIIIIIIII", sectname, segname, addr, size,
        offset, 0, 0, 0, flags, 0, 0)


def segment_cmd(segname: bytes, sections: list[bytes] = (), *,  # type: ignore[assignment]
                bits: int = 64, endian: str = "<", vmaddr: int = 0,
                vmsize: int = 0, fileoff: int = 0, filesize: int = 0,
                maxprot: int = 7, initprot: int = 5,
                nsects: int | None = None,
                cmdsize: int | None = None) -> bytes:
    cmd = LC_SEGMENT_64 if bits == 64 else LC_SEGMENT
    count = nsects if nsects is not None else len(sections)
    if bits == 64:
        fixed = struct.pack(f"{endian}16sQQQQiiII", segname, vmaddr,
                            vmsize, fileoff, filesize, maxprot,
                            initprot, count, 0)
    else:
        fixed = struct.pack(f"{endian}16sIIIIiiII", segname, vmaddr,
                            vmsize, fileoff, filesize, maxprot,
                            initprot, count, 0)
    return lc(cmd, fixed + b"".join(sections), endian=endian,
              cmdsize=cmdsize)


def thin_with_sections(specs: list[tuple[bytes, bytes, int]], *,
                       bits: int = 64, endian: str = "<") -> bytes:
    """A thin Mach-O carrying ONE segment whose sections' data is
    placed after the load commands, with truthful offsets (relative
    to the slice start, as the format defines them)."""
    header_size = 32 if bits == 64 else 28
    fixed = 72 if bits == 64 else 56
    entry = 80 if bits == 64 else 68
    cmdsize = fixed + entry * len(specs)
    cursor = header_size + cmdsize
    entries: list[bytes] = []
    tail = b""
    for name, data, flags in specs:
        entries.append(section_entry(
            name, b"__CRAFT", size=len(data), offset=cursor,
            flags=flags, bits=bits, endian=endian))
        tail += data
        cursor += len(data)
    seg = segment_cmd(b"__CRAFT", entries, bits=bits, endian=endian)
    return build_thin([seg], bits=bits, endian=endian, tail=tail)


# ---------------------------------------------------------------------------
# Dylib linkage + rpaths (invariant d: lc_str bounded by cmdsize)
# ---------------------------------------------------------------------------


class TestDylibLinkage:
    def test_three_kinds_split_and_counted(self, tmp_path):
        facts = extract(tmp_path, build_thin([
            dylib_cmd(b"/usr/lib/libSystem.B.dylib"),
            dylib_cmd(b"/usr/lib/libweak.dylib",
                      cmd=LC_LOAD_WEAK_DYLIB),
            dylib_cmd(b"/usr/lib/libre.dylib", cmd=LC_REEXPORT_DYLIB),
            dylib_cmd(b"@rpath/libplugin.dylib"),
        ]))
        assert facts is not None
        item = facts.slices[0]
        assert item.load_dylibs == ["/usr/lib/libSystem.B.dylib",
                                    "@rpath/libplugin.dylib"]
        assert item.weak_dylibs == ["/usr/lib/libweak.dylib"]
        assert item.reexport_dylibs == ["/usr/lib/libre.dylib"]
        assert item.dylib_counts == {"load": 2, "weak": 1,
                                     "reexport": 1}
        assert item.caps_hit == []

    def test_lc_str_offset_past_cmdsize_dropped(self, tmp_path):
        facts = extract(tmp_path, build_thin([
            dylib_cmd(b"libx.dylib", name_off=0x4000),
        ]))
        assert facts is not None
        item = facts.slices[0]
        assert item.load_dylibs == []
        assert item.dylib_counts["load"] == 1     # counted regardless
        assert "lc_str_out_of_bounds" in item.caps_hit

    def test_lc_str_negative_ish_offset_dropped(self, tmp_path):
        facts = extract(tmp_path, build_thin([
            dylib_cmd(b"libx.dylib", name_off=0xFFFFFFF0),
        ]))
        assert facts is not None
        assert "lc_str_out_of_bounds" in facts.slices[0].caps_hit

    def test_lc_str_offset_into_fixed_header_dropped(self, tmp_path):
        # Pointing back into the cmd/cmdsize/timestamp fields is
        # in-command but semantically bogus — refused, marked.
        facts = extract(tmp_path, build_thin([
            dylib_cmd(b"libx.dylib", name_off=4),
        ]))
        assert facts is not None
        assert facts.slices[0].load_dylibs == []
        assert "lc_str_out_of_bounds" in facts.slices[0].caps_hit

    def test_unterminated_name_never_crosses_into_next_command(
            self, tmp_path):
        """No NUL inside the command: the name is exactly the bytes
        to cmdsize (legal lc_str), and the NEXT command's bytes never
        leak into it. (16-byte name keeps the unterminated command
        aligned without padding.)"""
        facts = extract(tmp_path, build_thin([
            dylib_cmd(b"libnoterm.16byte", terminate=False),
            uuid_cmd(b"\x41" * 16),
        ]))
        assert facts is not None
        item = facts.slices[0]
        assert item.load_dylibs == ["libnoterm.16byte"]
        assert item.uuid == "41" * 16     # next command still parsed
        assert item.caps_hit == []

    def test_name_over_the_byte_cap_truncated(self, tmp_path):
        long_name = b"/opt/" + b"a" * (macho_mod._MAX_LC_NAME_BYTES + 50)
        facts = extract(tmp_path, build_thin([dylib_cmd(long_name)]))
        assert facts is not None
        item = facts.slices[0]
        assert len(item.load_dylibs) == 1
        assert (len(item.load_dylibs[0].encode("utf-8"))
                == macho_mod._MAX_LC_NAME_BYTES)
        assert "lc_name_truncated" in item.caps_hit

    def test_list_capped_at_real_cap_counts_stay_exact(self, tmp_path):
        cap = macho_mod._MAX_DYLIB_NAMES
        cmds = [dylib_cmd(b"lib%d.dylib" % i) for i in range(cap + 5)]
        facts = extract(tmp_path, build_thin(cmds))
        assert facts is not None
        item = facts.slices[0]
        assert len(item.load_dylibs) == cap
        assert item.dylib_counts["load"] == cap + 5
        assert "dylib_names_capped" in item.caps_hit

    def test_at_the_real_cap_is_clean(self, tmp_path):
        cap = macho_mod._MAX_DYLIB_NAMES
        cmds = [dylib_cmd(b"lib%d.dylib" % i) for i in range(cap)]
        facts = extract(tmp_path, build_thin(cmds))
        assert facts is not None
        item = facts.slices[0]
        assert len(item.load_dylibs) == cap
        assert "dylib_names_capped" not in item.caps_hit

    def test_file_level_name_budget_shared_across_slices(
            self, tmp_path, monkeypatch):
        """The retained-name budget is FILE-level: fat entries
        aliasing one name-heavy slice cannot multiply the retained
        text (the slices x names product stays bounded)."""
        monkeypatch.setattr(macho_mod, "_MAX_TOTAL_NAME_BYTES", 10)
        # 13 retained bytes overdraw the 10-byte budget (soft budget,
        # like the entropy one): the SECOND slice's walk sees it
        # exhausted.
        inner = build_thin([dylib_cmd(b"/twelve.chars")])
        facts = extract(tmp_path, build_fat([inner, inner]))
        assert facts is not None
        first, second = facts.slices
        assert first.load_dylibs == ["/twelve.chars"]
        assert second.load_dylibs == []
        assert second.dylib_counts["load"] == 1    # still counted
        assert "lc_name_budget_exhausted" in second.caps_hit


class TestRpaths:
    def test_rpaths_extracted_in_order(self, tmp_path):
        facts = extract(tmp_path, build_thin([
            rpath_cmd(b"@loader_path/../Frameworks"),
            rpath_cmd(b"/usr/local/lib"),
        ]))
        assert facts is not None
        assert facts.slices[0].rpaths == [
            "@loader_path/../Frameworks", "/usr/local/lib"]

    def test_rpath_cap_both_directions(self, tmp_path):
        cap = macho_mod._MAX_RPATHS
        at_cap = extract(tmp_path, build_thin(
            [rpath_cmd(b"/r%d" % i) for i in range(cap)]))
        assert at_cap is not None
        assert len(at_cap.slices[0].rpaths) == cap
        assert "rpaths_capped" not in at_cap.slices[0].caps_hit
        past = extract(tmp_path, build_thin(
            [rpath_cmd(b"/r%d" % i) for i in range(cap + 1)]))
        assert past is not None
        assert len(past.slices[0].rpaths) == cap
        assert "rpaths_capped" in past.slices[0].caps_hit

    def test_rpath_lc_str_bounded(self, tmp_path):
        facts = extract(tmp_path, build_thin(
            [rpath_cmd(b"/real", name_off=0x2000)]))
        assert facts is not None
        assert facts.slices[0].rpaths == []
        assert "lc_str_out_of_bounds" in facts.slices[0].caps_hit


# ---------------------------------------------------------------------------
# Dysymtab counts, versions, entry point, code signature
# ---------------------------------------------------------------------------


class TestDysymtab:
    def test_counts_recorded(self, tmp_path):
        facts = extract(tmp_path, build_thin([
            dysymtab_cmd((0, 10, 10, 42, 52, 7))]))
        assert facts is not None
        assert facts.slices[0].dysymtab == {
            "ilocalsym": 0, "nlocalsym": 10,
            "iextdefsym": 10, "nextdefsym": 42,
            "iundefsym": 52, "nundefsym": 7,
        }

    def test_absent_is_empty(self, tmp_path):
        facts = extract(tmp_path, build_thin([uuid_cmd()]))
        assert facts is not None
        assert facts.slices[0].dysymtab == {}

    def test_first_wins_on_duplicate(self, tmp_path):
        facts = extract(tmp_path, build_thin([
            dysymtab_cmd((0, 1, 1, 2, 3, 4)),
            dysymtab_cmd((9, 9, 9, 9, 9, 9))]))
        assert facts is not None
        assert facts.slices[0].dysymtab["nextdefsym"] == 2


class TestVersions:
    def test_build_version_macos(self, tmp_path):
        facts = extract(tmp_path, build_thin([
            build_version_cmd(1, 0x000D0100, 0x000E0000)]))
        assert facts is not None
        item = facts.slices[0]
        assert item.platform == "macos"
        assert item.min_os == "13.1.0"
        assert item.sdk == "14.0.0"
        assert item.min_os_source == "build_version"

    def test_unknown_platform_fails_open(self, tmp_path):
        facts = extract(tmp_path, build_thin([
            build_version_cmd(77, 0x00010000)]))
        assert facts is not None
        assert facts.slices[0].platform == "platform_77"

    def test_sdk_zero_is_absent(self, tmp_path):
        facts = extract(tmp_path, build_thin([
            build_version_cmd(1, 0x000C0000, 0)]))
        assert facts is not None
        assert facts.slices[0].sdk is None

    def test_legacy_version_min(self, tmp_path):
        facts = extract(tmp_path, build_thin([
            version_min_cmd(LC_VERSION_MIN_MACOSX, 0x000A0F06,
                            0x000B0000)]))
        assert facts is not None
        item = facts.slices[0]
        assert item.platform == "macos"
        assert item.min_os == "10.15.6"
        assert item.sdk == "11.0.0"
        assert item.min_os_source == "version_min"

    def test_legacy_ios_platform_implied_by_command(self, tmp_path):
        facts = extract(tmp_path, build_thin([
            version_min_cmd(LC_VERSION_MIN_IPHONEOS, 0x000E0000)]))
        assert facts is not None
        assert facts.slices[0].platform == "ios"

    def test_build_version_preferred_regardless_of_order(
            self, tmp_path):
        for cmds in (
            [version_min_cmd(LC_VERSION_MIN_MACOSX, 0x000A0000),
             build_version_cmd(1, 0x000D0000)],
            [build_version_cmd(1, 0x000D0000),
             version_min_cmd(LC_VERSION_MIN_MACOSX, 0x000A0000)],
        ):
            facts = extract(tmp_path, build_thin(cmds))
            assert facts is not None
            item = facts.slices[0]
            assert item.min_os == "13.0.0"
            assert item.min_os_source == "build_version"

    def test_second_differing_build_version_marked(self, tmp_path):
        facts = extract(tmp_path, build_thin([
            build_version_cmd(1, 0x000D0000),
            build_version_cmd(6, 0x000D0000)]))
        assert facts is not None
        item = facts.slices[0]
        assert item.platform == "macos"       # first wins
        assert "multiple_build_versions" in item.caps_hit

    def test_second_identical_build_version_silent(self, tmp_path):
        facts = extract(tmp_path, build_thin([
            build_version_cmd(1, 0x000D0000),
            build_version_cmd(1, 0x000D0000)]))
        assert facts is not None
        assert "multiple_build_versions" not in facts.slices[0].caps_hit

    def test_second_differing_version_min_marked(self, tmp_path):
        facts = extract(tmp_path, build_thin([
            version_min_cmd(LC_VERSION_MIN_MACOSX, 0x000A0000),
            version_min_cmd(LC_VERSION_MIN_IPHONEOS, 0x000E0000)]))
        assert facts is not None
        item = facts.slices[0]
        assert item.platform == "macos"        # first wins
        assert item.min_os == "10.0.0"
        assert "multiple_version_min" in item.caps_hit

    def test_second_identical_version_min_silent(self, tmp_path):
        facts = extract(tmp_path, build_thin([
            version_min_cmd(LC_VERSION_MIN_MACOSX, 0x000A0000),
            version_min_cmd(LC_VERSION_MIN_MACOSX, 0x000A0000)]))
        assert facts is not None
        assert ("multiple_version_min"
                not in facts.slices[0].caps_hit)

    def test_version_min_after_build_version_is_silent(self, tmp_path):
        # build_version is the preferred source (documented); a
        # legacy command after it steers nothing and is not a
        # conflict among equals.
        facts = extract(tmp_path, build_thin([
            build_version_cmd(1, 0x000D0000),
            version_min_cmd(LC_VERSION_MIN_MACOSX, 0x000A0000)]))
        assert facts is not None
        item = facts.slices[0]
        assert item.min_os == "13.0.0"
        assert "multiple_version_min" not in item.caps_hit


class TestEntryAndSignature:
    def test_lc_main_entry_offset(self, tmp_path):
        facts = extract(tmp_path, build_thin([main_cmd(0x4F00)]))
        assert facts is not None
        item = facts.slices[0]
        assert item.entry_offset == 0x4F00
        assert item.has_unixthread is False

    def test_unixthread_presence_only(self, tmp_path):
        facts = extract(tmp_path, build_thin([
            lc(LC_UNIXTHREAD, b"\x00" * 24)]))
        assert facts is not None
        item = facts.slices[0]
        assert item.has_unixthread is True
        assert item.entry_offset is None

    def test_code_signature_presence_and_declared_size(self, tmp_path):
        facts = extract(tmp_path, build_thin([
            codesig_cmd(0x9000, 0x1234)]))
        assert facts is not None
        item = facts.slices[0]
        assert item.code_signature_present is True
        assert item.code_signature_size == 0x1234

    def test_code_signature_never_read(self, tmp_path):
        """A declared blob far past EOF: the size is recorded as the
        file's CLAIM, no read happens, no marker fires — the blob is
        out of scope by design."""
        facts = extract(tmp_path, build_thin([
            codesig_cmd(0x40000000, 0x7FFFFFFF)]))
        assert facts is not None
        item = facts.slices[0]
        assert item.code_signature_size == 0x7FFFFFFF
        assert item.caps_hit == []


# ---------------------------------------------------------------------------
# Segments, sections, entropy
# ---------------------------------------------------------------------------


class TestSegmentsAndEntropy:
    def test_sections_with_known_entropy(self, tmp_path):
        facts = extract(tmp_path, thin_with_sections([
            (b"__zeros", b"\x00" * 1024, 0),
            (b"__cycle", bytes(range(256)) * 4, 0),
        ]))
        assert facts is not None
        seg = facts.slices[0].segments[0]
        assert seg.name == "__CRAFT"
        assert seg.nsects_declared == 2
        by_name = {s.name: s for s in seg.sections}
        assert by_name["__zeros"].entropy == 0.0
        assert by_name["__zeros"].sampled == 1024
        assert by_name["__cycle"].entropy == 8.0
        assert facts.slices[0].caps_hit == []

    def test_32_bit_segment_parses(self, tmp_path):
        facts = extract(tmp_path, thin_with_sections(
            [(b"__text", b"\xccPAYLOAD" * 4, 0)], bits=32))
        assert facts is not None
        seg = facts.slices[0].segments[0]
        assert seg.sections[0].name == "__text"
        assert seg.sections[0].entropy is not None

    def test_zerofill_section_is_truthful_absence(self, tmp_path):
        facts = extract(tmp_path, build_thin([
            segment_cmd(b"__DATA", [section_entry(
                b"__bss", b"__DATA", size=0x4000, offset=0,
                flags=0x1)]),
        ]))
        assert facts is not None
        item = facts.slices[0]
        sec = item.segments[0].sections[0]
        assert sec.entropy is None and sec.sampled == 0
        assert "section_data_unreadable" not in item.caps_hit

    def test_section_offset_past_slice_end_marked(self, tmp_path):
        facts = extract(tmp_path, build_thin([
            segment_cmd(b"__DATA", [section_entry(
                b"__ghost", b"__DATA", size=64, offset=0x100000)]),
        ]))
        assert facts is not None
        item = facts.slices[0]
        assert item.segments[0].sections[0].entropy is None
        assert "section_data_unreadable" in item.caps_hit

    def test_entropy_read_stops_at_slice_boundary(self, tmp_path):
        """A section claiming bytes past its slice's fat extent is
        clipped AT THE SLICE END — the next slice's bytes are never
        measured into this slice's record (invariant c)."""
        header_size = 32
        cmdsize = 72 + 80
        data = b"\xAA" * 16
        seg = segment_cmd(b"__CRAFT", [section_entry(
            b"__greedy", b"__CRAFT", size=0x10000,
            offset=header_size + cmdsize)])
        first = build_thin([seg], tail=data)
        second = build_thin([uuid_cmd()])
        facts = extract(tmp_path, build_fat([first, second]))
        assert facts is not None
        sec = facts.slices[0].segments[0].sections[0]
        assert sec.sampled == len(data)     # clipped at the slice end
        assert sec.entropy == 0.0           # one distinct byte value

    def test_nsects_lying_past_cmdsize_clamped(self, tmp_path):
        """Invariant (d) on the section array: rows live inside the
        command's own bytes — a huge nsects claim reads only what
        cmdsize holds."""
        facts = extract(tmp_path, build_thin([
            segment_cmd(b"__DATA", [section_entry(
                b"__one", b"__DATA")], nsects=0xFFFF)]))
        assert facts is not None
        item = facts.slices[0]
        seg = item.segments[0]
        assert seg.nsects_declared == 0xFFFF
        assert len(seg.sections) == 1
        assert "segment_sections_clamped" in item.caps_hit

    def test_section_record_cap(self, tmp_path, monkeypatch):
        monkeypatch.setattr(macho_mod, "_MAX_SECTION_RECORDS", 3)
        entries = [section_entry(b"__s%d" % i, b"__DATA")
                   for i in range(5)]
        facts = extract(tmp_path, build_thin([
            segment_cmd(b"__DATA", entries)]))
        assert facts is not None
        item = facts.slices[0]
        assert len(item.segments[0].sections) == 3
        assert "section_records_capped" in item.caps_hit

    def test_section_record_cap_at_the_real_value(self, tmp_path):
        """Both directions at the REAL cap (lifting the constant must
        redden this): a slice holding exactly the cap is clean; one
        more row across a second segment is capped + marked, and the
        total retained across segments never exceeds the cap."""
        cap = macho_mod._MAX_SECTION_RECORDS
        at_cap = extract(tmp_path, build_thin([segment_cmd(
            b"__BIG", [section_entry(b"__s", b"__BIG")] * cap)]))
        assert at_cap is not None
        item = at_cap.slices[0]
        assert len(item.segments[0].sections) == cap
        assert "section_records_capped" not in item.caps_hit
        past = extract(tmp_path, build_thin([
            segment_cmd(b"__BIG",
                        [section_entry(b"__s", b"__BIG")] * cap),
            segment_cmd(b"__ONE",
                        [section_entry(b"__t", b"__ONE")])]))
        assert past is not None
        item = past.slices[0]
        assert sum(len(seg.sections) for seg in item.segments) == cap
        assert item.segments[1].sections == []
        assert "section_records_capped" in item.caps_hit

    def test_sample_window_recorded(self, tmp_path, monkeypatch):
        monkeypatch.setattr(macho_mod,
                            "_MAX_ENTROPY_SECTION_BYTES", 16)
        facts = extract(tmp_path, thin_with_sections(
            [(b"__big", bytes(range(256)), 0)]))
        assert facts is not None
        sec = facts.slices[0].segments[0].sections[0]
        assert sec.size == 256 and sec.sampled == 16
        assert sec.entropy == 4.0            # 16 distinct byte values

    def test_total_budget_shared_across_fat_slices(self, tmp_path,
                                                   monkeypatch):
        """The IO budget is FILE-level: a fat container must not
        multiply the bound per slice."""
        monkeypatch.setattr(macho_mod, "_MAX_ENTROPY_TOTAL_BYTES", 8)
        one = thin_with_sections([(b"__one", b"x" * 64, 0)])
        two = thin_with_sections([(b"__two", b"y" * 64, 0)])
        facts = extract(tmp_path, build_fat([one, two]))
        assert facts is not None
        first = facts.slices[0].segments[0].sections[0]
        second = facts.slices[1].segments[0].sections[0]
        assert first.sampled == 8           # clipped by the budget
        assert second.entropy is None and second.sampled == 0
        assert ("entropy_budget_exhausted"
                in facts.slices[1].caps_hit)

    def test_measured_count_capped(self, tmp_path, monkeypatch):
        monkeypatch.setattr(macho_mod, "_MAX_ENTROPY_SECTIONS", 1)
        facts = extract(tmp_path, thin_with_sections([
            (b"__one", b"x" * 8, 0), (b"__two", b"y" * 8, 0)]))
        assert facts is not None
        secs = facts.slices[0].segments[0].sections
        assert secs[0].entropy is not None
        assert secs[1].entropy is None       # row survives, unmeasured
        assert ("entropy_sections_capped"
                in facts.slices[0].caps_hit)

    def test_truncated_segment_fixed_header_aborts(self, tmp_path):
        """Invariant (a): a segment command shorter than its own
        fixed header aborts the walk."""
        facts = extract(tmp_path, build_thin([
            segment_cmd(b"__DATA", [], cmdsize=40), uuid_cmd()]))
        assert facts is not None
        item = facts.slices[0]
        assert item.segments == []
        assert item.uuid is None
        assert ("lc_walk_abort_fixed_header_truncated"
                in item.caps_hit)


# ---------------------------------------------------------------------------
# Cap parity with the ELF tier
# ---------------------------------------------------------------------------


class TestCapParityWithElf:
    def test_shared_bounds_match_the_elf_tier(self):
        """The entropy caps and the seek screen are VALUE-COUPLED to
        the ELF facts extractor: a consumer comparing elf/pe/macho
        records must never read a cap difference as a content
        difference. Change both modules together, or split them here
        deliberately with a recorded reason."""
        from core.binary import elf as elf_mod
        assert (macho_mod._MAX_ENTROPY_SECTION_BYTES
                == elf_mod._MAX_ENTROPY_SECTION_BYTES)
        assert (macho_mod._MAX_ENTROPY_TOTAL_BYTES
                == elf_mod._MAX_ENTROPY_TOTAL_BYTES)
        assert (macho_mod._MAX_ENTROPY_SECTIONS
                == elf_mod._MAX_ENTROPY_SECTIONS)
        assert macho_mod._MAX_SEEK_OFFSET == elf_mod._MAX_SEEK_OFFSET
        assert (macho_mod._MAX_TOTAL_NAME_BYTES
                == elf_mod._MAX_TOTAL_NAME_BYTES)

    def test_entropy_primitive_is_the_elf_tiers(self):
        from core.binary import elf as elf_mod
        assert macho_mod._shannon_entropy is elf_mod._shannon_entropy


# ---------------------------------------------------------------------------
# Evidence record + serialization
# ---------------------------------------------------------------------------


class TestEvidence:
    def test_header_backed_record(self, tmp_path):
        import json

        from core.evidence import EvidenceTier
        from packages.binary_analysis.macho import macho_facts_evidence

        p = _write(tmp_path, build_thin([
            uuid_cmd(), dylib_cmd(b"/usr/lib/libSystem.B.dylib")]))
        facts = extract_macho_facts(p)
        assert facts is not None
        record = macho_facts_evidence("ab" * 32, p, facts)
        assert record.kind == "macho_facts"
        assert record.tier == EvidenceTier.HEADER_BACKED
        payload = record.data["facts"]
        assert payload["slices"][0]["uuid"] == bytes(range(16)).hex()
        json.dumps(payload)                  # JSON-serializable

"""Native PE parser — tier 0 of the binary substrate.

Stdlib-only (``struct``) shallow-facts parser for Windows PE images
(PE32 and PE32+). Companion to :mod:`core.binary.elf`, mirroring its
conventions: named caps with both-direction rationale, per-field
``caps_hit`` markers, offset screens + OSError nets, fail-open on
unknown enum values (the raw value is recorded, never raised on).

One entry point:

- :func:`extract_pe_facts` — the shallow-FACTS parse for
  inventory / triage consumers: DOS/COFF/optional headers,
  machine / arch / bits, subsystem, characteristics and
  DLL-characteristics mitigation bits as named booleans, the
  section table, ``SizeOfHeaders``, and the entrypoint RVA.

Scope
- PE32 + PE32+ images (little-endian by format definition)
- ``bits`` comes from the OPTIONAL-HEADER MAGIC, never from the
  COFF machine field: the machine value is a family label and a
  crafted header can disagree with the actual image layout — the
  magic is what selects the layout actually parsed.

Out of scope
- Import / delay-import / export tables (a follow-up extension of
  this module; nothing here walks a thunk array or name table)
- The resource tree INCLUDING version-info (canonical PE
  hostile-recursion surface — deliberately not parsed)
- TE (Terse Executable) images — no DOS/COFF header, different
  format; callers classify separately
- Authenticode certificate parsing (presence only, in this module)
- .NET metadata beyond the CLR-directory presence bit

Error handling
Every whole-parse failure returns ``None`` (unreadable file, no MZ,
``e_lfanew`` out of range, no PE signature, truncated COFF header).
Past the COFF header the extractor degrades PER FIELD: a malformed
SUB-structure empties only the affected field and records a marker
in ``PeFacts.caps_hit`` — truncation is record-visible, never
silent.

The RVA → file-offset resolver (:class:`_RvaResolver`) is the ONE
chokepoint every RVA-addressed read in this module goes through.
Its named invariants:

  (a) memory-vs-file rule: an RVA inside ``VirtualSize`` but past
      ``SizeOfRawData`` resolves to ZERO-FILL — never adjacent
      sections' file bytes (the VirtualSize/RawSize-skew aliasing
      shape);
  (b) overlapping sections resolve deterministically to the FIRST
      match in section-table order, and the overlap is surfaced as
      an ``overlapping_sections`` marker;
  (c) header-region RVAs claimed by no section identity-map to file
      offsets, bounded by ``SizeOfHeaders``;
  (d) every resolved read is bounded by ``min(remaining raw bytes,
      the caller's named cap)`` — ``VirtualSize`` is never a read
      budget, and a read never crosses a section boundary.
"""

from __future__ import annotations

import logging
import os
import struct
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

logger = logging.getLogger(__name__)


# DOS / PE signatures
_MZ_MAGIC = b"MZ"
_PE_SIGNATURE = b"PE\x00\x00"
# File offset of e_lfanew (u32) in the DOS header
_E_LFANEW_OFFSET = 0x3C

# Optional-header magic values — the AUTHORITATIVE 32/64 selector
# (layout discriminator); the COFF machine field is a family label
# only. IMAGE_ROM_OPTIONAL_HDR_MAGIC (0x107) and anything else fall
# through as unknown: raw value recorded, optional fields skipped.
_PE32_MAGIC = 0x10B
_PE32PLUS_MAGIC = 0x20B

# COFF header directly after the PE signature: Machine(H)
# NumberOfSections(H) TimeDateStamp(I) PointerToSymbolTable(I)
# NumberOfSymbols(I) SizeOfOptionalHeader(H) Characteristics(H)
_COFF_HEADER = struct.Struct("<HHIIIHH")

# One section-table entry: Name(8s) VirtualSize(I) VirtualAddress(I)
# SizeOfRawData(I) PointerToRawData(I) PointerToRelocations(I)
# PointerToLinenumbers(I) NumberOfRelocations(H)
# NumberOfLinenumbers(H) Characteristics(I)
_SECTION_HEADER = struct.Struct("<8sIIIIIIHHI")

# COFF machine → arch FAMILY string. Same convention as the ELF
# tier's e_machine map (family label; ``bits`` is a separate field
# from the optional-header magic), so facts records from both tiers
# join without translation. Unknown machine values fall through to
# "unknown" — the raw value stays on the record.
_MACHINE_ARCH = {
    0x014C: "x86",       # IMAGE_FILE_MACHINE_I386
    0x8664: "x86",       # IMAGE_FILE_MACHINE_AMD64
    0x01C0: "arm",       # IMAGE_FILE_MACHINE_ARM
    0x01C4: "arm",       # IMAGE_FILE_MACHINE_ARMNT (Thumb-2)
    0xAA64: "arm",       # IMAGE_FILE_MACHINE_ARM64
    0x5032: "riscv",     # IMAGE_FILE_MACHINE_RISCV32
    0x5064: "riscv",     # IMAGE_FILE_MACHINE_RISCV64
    0x0166: "mips",      # IMAGE_FILE_MACHINE_R4000
    0x0200: "ia64",      # IMAGE_FILE_MACHINE_IA64
    0x6232: "loongarch",  # IMAGE_FILE_MACHINE_LOONGARCH32
    0x6264: "loongarch",  # IMAGE_FILE_MACHINE_LOONGARCH64
    0x0EBC: "ebc",       # EFI Byte Code
}

# Subsystem → name. Unknown values are ABSENT from the map —
# ``subsystem_name`` stays None and the raw value is on the record
# (fail open: an unmappable subsystem must never fail the parse).
_SUBSYSTEM_NAME = {
    1: "native",
    2: "windows_gui",
    3: "windows_cui",
    5: "os2_cui",
    7: "posix_cui",
    8: "native_windows",
    9: "windows_ce_gui",
    10: "efi_application",
    11: "efi_boot_service_driver",
    12: "efi_runtime_driver",
    13: "efi_rom",
    14: "xbox",
    16: "windows_boot_application",
}

# COFF Characteristics bits surfaced as named booleans
_IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
_IMAGE_FILE_DLL = 0x2000

# DllCharacteristics mitigation bits surfaced as named booleans.
# The raw u16 stays on the record so unmapped bits are never lost.
_DLLCHAR_HIGH_ENTROPY_VA = 0x0020
_DLLCHAR_DYNAMIC_BASE = 0x0040       # ASLR
_DLLCHAR_NX_COMPAT = 0x0100          # DEP
_DLLCHAR_GUARD_CF = 0x4000           # Control Flow Guard

# ---- Sanity caps. Every breach is surfaced in ``PeFacts.caps_hit``
# — bounded AND honest, never silently partial.
#
# Section-table walk bound. NumberOfSections is an attacker-chosen
# u16 (up to 65535); the Windows loader itself refuses images with
# more than 96 sections, so nothing real is ever truncated at 4096,
# while an uncapped walk would hand a crafted count a 65535-entry
# read loop and a ~65k-row record. Lower buys nothing (real images
# stay two orders below); higher just sells CPU and record size to
# hostile files.
_MAX_SECTIONS = 4_096
# Section names in a PE IMAGE are a fixed 8-byte header field
# (NUL-padded; a full 8-byte name simply has no terminator), so name
# capture is format-bounded at 8 bytes by construction — the capture
# itself is the cap. Names are hostile text either way; consumers
# escape at render. ("/NNN" COFF string-table references are kept
# as their literal 8-byte text: MSVC-linked images never carry
# them, but GCC/MinGW-linked images can ship long section names
# into the final image, so the literal "/NNN" IS what such an
# image says in its header field. Chasing the string table is
# refused because it would add a whole new attacker-priced walk —
# u32 offset plus terminator scan over an unbounded table — to buy
# only a prettier name.)
_SECTION_NAME_BYTES = 8
# f.seek() rejects offsets past off_t range, and reads near the
# 2**63 boundary can raise OSError after a successful seek — same
# screen + belt-and-braces net as the ELF facts extractor (see
# core.binary.elf._MAX_SEEK_OFFSET for the full kernel-behavior
# rationale). PE file offsets are u32 so a genuine PE can never
# trip this; the screen guards derived arithmetic and keeps the
# per-field degradation contract airtight.
_MAX_SEEK_OFFSET = 2**62
# Data-directory entries parsed. The spec defines exactly 16;
# NumberOfRvaAndSizes is an attacker u32, and honoring a larger
# claim would walk header bytes past the defined table (or off the
# buffer). Parsing fewer than the claim on a REAL image cannot drop
# facts — everything this module consumes sits at index 14 or
# below.
_MAX_DATA_DIRS = 16


@dataclass(frozen=True)
class PeSection:
    """One section-table row — raw header facts.

    ``name`` originates in the hostile file (8-byte field, captured
    verbatim up to the field width) — escape at render.
    ``characteristics`` is the raw u32; consumers mask what they
    need (fail open on unknown bits).
    """

    name: str
    virtual_address: int      # RVA
    virtual_size: int         # VirtualSize as claimed
    raw_size: int             # SizeOfRawData as claimed
    raw_offset: int           # PointerToRawData as claimed
    characteristics: int


@dataclass
class PeFacts:
    """Shallow header / layout facts for one PE image.

    Mirrors :class:`core.binary.elf.ElfFacts` conventions: every
    string field is attacker-controlled text — length-capped at
    capture, NOT escaped here; consumers escape at render before
    any terminal / report / prompt use. ``caps_hit`` is a sorted
    list of machine-readable markers naming every cap or parse gap
    that fired (empty = complete extraction).

    ``bits`` / ``pe_format`` derive from the optional-header magic
    (the layout actually parsed); ``machine`` / ``arch`` from the
    COFF machine field (a family label). A crafted image can make
    them disagree — both are recorded, neither is "corrected".
    """

    machine: int = 0                      # raw COFF machine value
    arch: str = "unknown"                 # family (fail-open)
    bits: int = 0                         # 32 | 64 | 0 when unknown
    binary_format: str = "pe"
    pe_format: str | None = None          # "pe32" | "pe32+"
    optional_magic: int = 0               # raw optional-header magic
    timestamp: int = 0                    # COFF TimeDateStamp
    characteristics: int = 0              # raw COFF characteristics
    is_dll: bool = False
    is_executable_image: bool = False
    subsystem: int = 0                    # raw value
    subsystem_name: str | None = None     # mapped; None when unknown
    dll_characteristics: int = 0          # raw u16
    aslr: bool = False                    # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    high_entropy_va: bool = False         # ..._HIGH_ENTROPY_VA
    dep: bool = False                     # ..._NX_COMPAT
    cfg: bool = False                     # ..._GUARD_CF
    entrypoint: int = 0                   # AddressOfEntryPoint RVA
    image_base: int = 0
    size_of_image: int = 0
    size_of_headers: int = 0
    declared_section_count: int = 0       # NumberOfSections as claimed
    sections: list[PeSection] = field(default_factory=list)
    caps_hit: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready dict (nested dataclasses included)."""
        return asdict(self)


def is_pe(path: Path | str) -> bool:
    """Cheap MZ + PE-signature check — no full parse.

    Bounded the same way the extractor's own header read is: the
    signature AND the COFF header must fit inside the file, so a
    file truncated right at the signature is not "a PE" here while
    :func:`extract_pe_facts` returns ``None`` — probe and extractor
    never disagree. ``False`` on any read error: an unreadable file
    is not a usable PE candidate for any caller, so refusal and
    absence collapse to the same answer (same contract as
    :func:`core.binary.elf.is_elf`).
    """
    try:
        with open(path, "rb") as f:
            if f.read(2) != _MZ_MAGIC:
                return False
            file_size = os.fstat(f.fileno()).st_size
            f.seek(_E_LFANEW_OFFSET)
            raw = f.read(4)
            if len(raw) < 4:
                return False
            (e_lfanew,) = struct.unpack("<I", raw)
            if (e_lfanew + len(_PE_SIGNATURE)
                    + _COFF_HEADER.size > file_size):
                return False
            f.seek(e_lfanew)
            return f.read(4) == _PE_SIGNATURE
    except (OSError, ValueError, OverflowError):
        return False


def extract_pe_facts(path: Path) -> PeFacts | None:
    """Extract shallow facts from ``path``, or ``None`` when the
    file is not PE / unreadable — never raises past this function
    (same malformed-input contract as
    :func:`core.binary.elf.extract_elf_facts`). Malformed
    SUB-structures past the COFF header degrade per field with a
    ``caps_hit`` marker.
    """
    try:
        with Path(path).open("rb") as f:
            file_size = os.fstat(f.fileno()).st_size
            return _extract_facts_stream(f, file_size)
    except OSError as e:
        logger.debug("core.binary.pe: read failed for %s: %s", path, e)
        return None
    except struct.error as e:
        logger.debug("core.binary.pe: truncated / malformed %s: %s",
                     path, e)
        return None
    except (ValueError, OverflowError) as e:
        # f.seek() rejects offsets that don't fit a C off_t with
        # ValueError or OverflowError depending on the io layer —
        # same "malformed input" contract as struct.error.
        logger.debug("core.binary.pe: pathological offsets in %s: %s",
                     path, e)
        return None


# ---------------------------------------------------------------------------
# RVA → file-offset resolution (the ONE chokepoint)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _RvaTarget:
    """Where one RVA lands.

    ``file_offset`` is ``None`` when the RVA is memory-only (inside
    ``VirtualSize`` but past ``SizeOfRawData`` — zero-filled at
    load time). ``raw_available`` counts file bytes readable from
    ``file_offset`` before the section's raw data ends;
    ``virtual_available`` counts bytes to the end of the section's
    virtual extent. Both are read bounds, never budgets to trust.
    """

    file_offset: int | None
    raw_available: int
    virtual_available: int


class _RvaResolver:
    """RVA → file-offset chokepoint. See the module docstring for
    the named invariants (a)-(d); every RVA-addressed read in this
    module goes through :meth:`read`."""

    def __init__(self, sections: list[PeSection],
                 size_of_headers: int) -> None:
        self._sections = sections
        self._size_of_headers = max(0, size_of_headers)

    @staticmethod
    def _virtual_extent(sec: PeSection) -> int:
        # VirtualSize 0 with a nonzero raw size occurs in
        # object-style / doctored headers; the loader maps the raw
        # bytes, so the raw size is the honest extent then.
        return sec.virtual_size if sec.virtual_size else sec.raw_size

    def has_overlaps(self) -> bool:
        """True when any two sections' virtual ranges intersect —
        the ``overlapping_sections`` marker's evidence (invariant
        b: resolution stays deterministic regardless, first match
        in table order wins)."""
        spans = sorted(
            (s.virtual_address,
             s.virtual_address + self._virtual_extent(s))
            for s in self._sections if self._virtual_extent(s) > 0
        )
        return any(
            spans[i][1] > spans[i + 1][0]
            for i in range(len(spans) - 1)
        )

    def resolve(self, rva: int) -> _RvaTarget | None:
        """Resolve one RVA. ``None`` = unmapped (no section claims
        it and it is outside the header region)."""
        if rva < 0:
            return None
        for sec in self._sections:            # table order — (b)
            extent = self._virtual_extent(sec)
            if extent <= 0:
                continue
            if sec.virtual_address <= rva < sec.virtual_address + extent:
                delta = rva - sec.virtual_address
                raw_avail = sec.raw_size - delta if delta < sec.raw_size else 0
                return _RvaTarget(
                    file_offset=(sec.raw_offset + delta)
                    if raw_avail > 0 else None,
                    raw_available=raw_avail,
                    virtual_available=extent - delta,
                )
        if rva < self._size_of_headers:       # header region — (c)
            remaining = self._size_of_headers - rva
            return _RvaTarget(
                file_offset=rva,
                raw_available=remaining,
                virtual_available=remaining,
            )
        return None

    def read(self, f: BinaryIO, rva: int, length: int) -> bytes | None:
        """Read up to ``length`` bytes at ``rva``.

        ``length`` MUST be a named cap chosen by the caller — this
        method enforces the section bounds (invariant d), the
        caller enforces the field-size cap. Returns:

        - the bytes (file bytes up to the section's raw extent,
          then zero-fill up to its virtual extent — invariant a;
          possibly SHORTER than ``length`` when the virtual extent
          ends first: reads never cross a section boundary),
        - ``b""`` for a non-positive length,
        - ``None`` when the RVA is unmapped, the file is shorter
          than the raw bytes the header claims (truncated /
          doctored image), or the read is refused by the kernel.
        """
        if length <= 0:
            return b""
        target = self.resolve(rva)
        if target is None:
            return None
        want = min(length, target.virtual_available)
        n_raw = min(want, target.raw_available)
        data = b""
        if n_raw > 0:
            if (target.file_offset is None
                    or target.file_offset > _MAX_SEEK_OFFSET):
                return None
            try:
                f.seek(target.file_offset)
                data = f.read(n_raw)
            except OSError:
                # Belt-and-braces behind the offset screen: a kernel
                # read refusal costs this field, never the record.
                return None
            if len(data) < n_raw:
                # The header claims raw bytes the file does not have
                # — fabricating zeros here would launder truncation
                # into "measured zero bytes".
                return None
        # Invariant (a): the memory-only tail is ZERO-FILL, never
        # adjacent sections' file bytes.
        return data + b"\x00" * (want - len(data))


# ---------------------------------------------------------------------------
# Stream parsing
# ---------------------------------------------------------------------------


def _read_e_lfanew(f: BinaryIO, file_size: int) -> int | None:
    """MZ check + e_lfanew read. ``None`` = not a usable PE."""
    if f.read(2) != _MZ_MAGIC:
        return None
    f.seek(_E_LFANEW_OFFSET)
    raw = f.read(4)
    if len(raw) < 4:
        return None
    (e_lfanew,) = struct.unpack("<I", raw)
    # Out-of-range e_lfanew: the signature + COFF header must fit
    # inside the file. u32 keeps this far below _MAX_SEEK_OFFSET,
    # but the file-size bound is the honest "is there a PE header
    # here at all" screen.
    if e_lfanew + len(_PE_SIGNATURE) + _COFF_HEADER.size > file_size:
        return None
    return e_lfanew


def _extract_facts_stream(f: BinaryIO, file_size: int) -> PeFacts | None:
    e_lfanew = _read_e_lfanew(f, file_size)
    if e_lfanew is None:
        return None
    f.seek(e_lfanew)
    if f.read(4) != _PE_SIGNATURE:
        return None
    coff_raw = f.read(_COFF_HEADER.size)
    if len(coff_raw) < _COFF_HEADER.size:
        return None
    (machine, n_sections, timestamp, _sym_ptr, _sym_count,
     size_of_optional, characteristics) = _COFF_HEADER.unpack(coff_raw)

    facts = PeFacts(
        machine=machine,
        arch=_MACHINE_ARCH.get(machine, "unknown"),
        timestamp=timestamp,
        characteristics=characteristics,
        is_dll=bool(characteristics & _IMAGE_FILE_DLL),
        is_executable_image=bool(
            characteristics & _IMAGE_FILE_EXECUTABLE_IMAGE),
        declared_section_count=n_sections,
    )
    caps: set[str] = set()

    # --- Optional header ----------------------------------------
    if size_of_optional == 0:
        # A COFF object shape, not an image — header facts survive,
        # everything optional-derived is a recorded gap.
        caps.add("optional_header_missing")
    else:
        opt = f.read(size_of_optional)
        if len(opt) < size_of_optional:
            caps.add("optional_header_truncated")
        _parse_optional_header(opt, facts, caps)

    # --- Section table ------------------------------------------
    # Located directly after the optional header — at the DECLARED
    # SizeOfOptionalHeader distance, even when the read above came
    # up short (the table position is defined by the header field,
    # not by what we managed to read).
    section_table_off = (
        e_lfanew + len(_PE_SIGNATURE) + _COFF_HEADER.size
        + size_of_optional
    )
    facts.sections = _read_section_table(
        f, section_table_off, n_sections, caps,
    )

    resolver = _RvaResolver(facts.sections, facts.size_of_headers)
    if resolver.has_overlaps():
        caps.add("overlapping_sections")

    facts.caps_hit = sorted(caps)
    return facts


def _parse_optional_header(opt: bytes, facts: PeFacts,
                           caps: set[str]) -> None:
    """Decode the optional header into ``facts`` — per-field
    degradation: a short buffer marks ``optional_header_truncated``
    once and leaves the unreachable fields at their defaults."""
    if len(opt) < 2:
        caps.add("optional_header_truncated")
        return
    (magic,) = struct.unpack_from("<H", opt, 0)
    facts.optional_magic = magic
    if magic == _PE32_MAGIC:
        facts.bits, facts.pe_format = 32, "pe32"
        image_base_fmt, image_base_off = "<I", 28
    elif magic == _PE32PLUS_MAGIC:
        facts.bits, facts.pe_format = 64, "pe32+"
        image_base_fmt, image_base_off = "<Q", 24
    else:
        # Fail open on unknown magic (ROM images, hostile values):
        # the raw value is recorded above; the layout is unknown so
        # no optional field beyond it can be trusted to decode.
        caps.add("optional_magic_unknown")
        return

    def _u32(offset: int) -> int | None:
        if offset + 4 > len(opt):
            caps.add("optional_header_truncated")
            return None
        return struct.unpack_from("<I", opt, offset)[0]

    def _u16(offset: int) -> int | None:
        if offset + 2 > len(opt):
            caps.add("optional_header_truncated")
            return None
        return struct.unpack_from("<H", opt, offset)[0]

    facts.entrypoint = _u32(16) or 0
    if image_base_off + struct.calcsize(image_base_fmt) <= len(opt):
        facts.image_base = struct.unpack_from(
            image_base_fmt, opt, image_base_off)[0]
    else:
        caps.add("optional_header_truncated")
    facts.size_of_image = _u32(56) or 0
    facts.size_of_headers = _u32(60) or 0
    subsystem = _u16(68)
    if subsystem is not None:
        facts.subsystem = subsystem
        facts.subsystem_name = _SUBSYSTEM_NAME.get(subsystem)
    dll_chars = _u16(70)
    if dll_chars is not None:
        facts.dll_characteristics = dll_chars
        facts.aslr = bool(dll_chars & _DLLCHAR_DYNAMIC_BASE)
        facts.high_entropy_va = bool(
            dll_chars & _DLLCHAR_HIGH_ENTROPY_VA)
        facts.dep = bool(dll_chars & _DLLCHAR_NX_COMPAT)
        facts.cfg = bool(dll_chars & _DLLCHAR_GUARD_CF)


def _read_section_table(
    f: BinaryIO, table_offset: int, n_declared: int, caps: set[str],
) -> list[PeSection]:
    """Read up to ``_MAX_SECTIONS`` section headers at
    ``table_offset``. A short read keeps the parsed prefix and
    marks the truncation."""
    if n_declared <= 0:
        return []
    count = n_declared
    if count > _MAX_SECTIONS:
        count = _MAX_SECTIONS
        caps.add("section_table_capped")
    if table_offset > _MAX_SEEK_OFFSET:
        caps.add("section_table_truncated")
        return []
    sections: list[PeSection] = []
    try:
        f.seek(table_offset)
        for _ in range(count):
            raw = f.read(_SECTION_HEADER.size)
            if len(raw) < _SECTION_HEADER.size:
                caps.add("section_table_truncated")
                break
            (name_raw, virtual_size, virtual_address, raw_size,
             raw_offset, _reloc_ptr, _line_ptr, _n_reloc, _n_line,
             sec_characteristics) = _SECTION_HEADER.unpack(raw)
            # Name capture is format-bounded: the 8-byte field IS
            # the cap (a full 8-byte name has no NUL terminator —
            # that is well-formed, not hostile).
            name = name_raw[:_SECTION_NAME_BYTES].split(
                b"\x00", 1)[0].decode("utf-8", errors="replace")
            sections.append(PeSection(
                name=name,
                virtual_address=virtual_address,
                virtual_size=virtual_size,
                raw_size=raw_size,
                raw_offset=raw_offset,
                characteristics=sec_characteristics,
            ))
    except OSError:
        # Screened-read net: keep the walked prefix, record the gap.
        caps.add("section_table_truncated")
    return sections


__all__ = [
    "PeFacts",
    "PeSection",
    "extract_pe_facts",
    "is_pe",
]

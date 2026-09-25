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
from typing import TYPE_CHECKING, Any, BinaryIO

if TYPE_CHECKING:
    from core.evidence import BinaryEvidenceRecord

# ONE entropy primitive repo-wide — deliberately shared with the ELF
# tier so the number means the same thing on every facts record. Its
# packedness-refusal rationale (entropy is a measurement, never a
# packed/encrypted verdict) travels with it; any change to that
# posture is amended THERE, beside is_packed.
from core.binary.elf import _shannon_entropy

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
# ---- Entropy caps: same values and both-direction rationale as the
# ELF facts extractor (core.binary.elf) — the two tiers measure the
# same fact and must degrade identically, so a consumer comparing
# elf/pe records never reads a cap difference as a content
# difference.
#
# Per-section sample window: leading bytes are representative for the
# compressed/encrypted/code question; larger re-opens IO
# amplification from one attacker-padded section, smaller invites a
# low-entropy decoy prefix (which at 4 MiB costs the attacker real
# file size). ``sampled`` on the record says exactly what was
# measured.
_MAX_ENTROPY_SECTION_BYTES = 4 * 1024 * 1024
# Whole-walk IO budget across MANY large sections; lower loses
# tail-section facts on legitimately huge binaries, higher re-opens
# the aggregate amplification the per-section window closed.
_MAX_ENTROPY_TOTAL_BYTES = 64 * 1024 * 1024
# Sections measured. Real images stay two orders below; a crafted
# table at the _MAX_SECTIONS cap would otherwise buy 4096 bounded
# reads. The section ROW is still recorded past this — only the
# measurement is skipped, with a marker.
_MAX_ENTROPY_SECTIONS = 2_048
# Data-directory entries parsed. The spec defines exactly 16;
# NumberOfRvaAndSizes is an attacker u32, and honoring a larger
# claim would walk header bytes past the defined table (or off the
# buffer). Parsing fewer than the claim on a REAL image cannot drop
# facts — everything this module consumes sits at index 14 or
# below.
_MAX_DATA_DIRS = 16
# Debug-directory entries walked. The directory Size is an attacker
# u32 driving a size/28 walk; real images carry under ~10 entries
# (CodeView, POGO, VC feature, repro, extended-dllcharacteristics).
# 64 truncates nothing real; higher only sells iterations and
# resolver reads to a crafted directory.
_MAX_DEBUG_DIR_ENTRIES = 64
# CodeView blob read bound: 24 fixed bytes (magic + GUID + age) plus
# the NUL-terminated pdb path. SizeOfData is an attacker u32 that
# would otherwise price the read; real pdb paths are a few hundred
# bytes, so 4 KB truncates nothing real while an unterminated path
# inside the window is malformed, marker-visibly.
_MAX_PDB_PATH_BYTES = 4_096
# pdb BASENAME bytes retained on the record (counted on the raw
# bytes — what is actually retained). Real basenames are tens of
# bytes; the record must not become the amplifier for a crafted
# 4 KB path whose last component is the whole path. Hostile text
# either way — consumers escape at render.
_MAX_PDB_BASENAME_BYTES = 256

# Data-directory indices consumed (spec order). The security entry
# holds a FILE OFFSET (not an RVA) to the certificate table; only
# its PRESENCE is read here — certificate parsing is a separate,
# deliberately-unimplemented surface.
_DIR_SECURITY = 4
_DIR_DEBUG = 6
_DIR_CLR = 14

# One debug-directory entry: Characteristics(I) TimeDateStamp(I)
# MajorVersion(H) MinorVersion(H) Type(I) SizeOfData(I)
# AddressOfRawData(I) PointerToRawData(I)
_DEBUG_DIR_ENTRY = struct.Struct("<IIHHIIII")
_IMAGE_DEBUG_TYPE_CODEVIEW = 2
_RSDS_MAGIC = b"RSDS"


@dataclass(frozen=True)
class PeSection:
    """One section-table row — raw header facts.

    ``name`` originates in the hostile file (8-byte field, captured
    verbatim up to the field width) — escape at render.
    ``characteristics`` is the raw u32; consumers mask what they
    need (fail open on unknown bits).

    ``entropy`` is the Shannon entropy of the section's leading RAW
    file bytes (bits per byte) — a deterministic measurement, never
    a packedness verdict (see :func:`core.binary.elf.is_packed`'s
    recorded refusal). ``None`` when nothing was measured (no raw
    bytes, unreadable data, or a cap fired — the ``caps_hit``
    markers say which). ``sampled < raw_size`` means the bounded
    leading window was measured, not the whole section.
    """

    name: str
    virtual_address: int      # RVA
    virtual_size: int         # VirtualSize as claimed
    raw_size: int             # SizeOfRawData as claimed
    raw_offset: int           # PointerToRawData as claimed
    characteristics: int
    entropy: float | None = None
    sampled: int = 0


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
    # Overlay = file bytes past the headers AND past every section's
    # raw data, clamped to the actual file size. A claim STARTING
    # past EOF establishes no extent; an in-file claim over-running
    # EOF clamps to the file end — which extends the mapped region
    # there, so a trailing overlay behind such an over-claim is
    # masked (the claim owns those bytes as far as this fact can
    # tell). Authenticode certificates conventionally live here.
    overlay_present: bool = False
    overlay_offset: int | None = None
    overlay_size: int = 0
    # Security (certificate table) directory PRESENCE only — a
    # nonzero entry means the image CLAIMS an Authenticode blob.
    # Nothing here verifies, parses, or trusts it.
    authenticode_present: bool = False
    # CLR runtime header directory presence — the .NET bit.
    dotnet_present: bool = False
    # Signing-facts slot, pre-declared so the record schema stays
    # stable across phases: populated by the signing-facts
    # extraction when it lands; empty string means UNEXAMINED.
    # ``authenticode_present`` above is the only signing fact this
    # extractor asserts.
    claimed_signer: str = ""
    # Debug-directory RSDS (CodeView) identity: the raw 16 GUID
    # bytes in file order as lowercase hex, the age, the pdb path's
    # last component (hostile text — capped at capture, escape at
    # render), and the canonical symbol-server serialization from
    # :func:`canonical_pe_identity`. An all-zero GUID is recorded
    # verbatim — degenerate-identity screening is a CONSUMER
    # policy, not an extraction fact.
    debug_guid: str | None = None
    debug_age: int | None = None
    pdb_basename: str | None = None
    debug_identity: str | None = None
    caps_hit: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready dict (nested dataclasses included)."""
        return asdict(self)


def canonical_pe_identity(guid: bytes, age: int) -> str:
    """Canonical PE debug-identity serialization — the Microsoft
    symbol-server text convention, lowercased.

    The GUID renders as ``%08x%04x%04x`` from the little-endian
    Data1/Data2/Data3 fields of the raw 16 RSDS bytes, then the 8
    Data4 bytes as raw hex, then the age in UNPADDED lowercase hex
    (symsrv keys never zero-pad the age). Lowercase throughout so
    one identity has exactly one spelling.

    Helper contract (unlike the extractor): ``guid`` must be the 16
    raw bytes as stored in the RSDS record and ``age`` a
    non-negative integer — anything else raises ``ValueError``
    (programming error, not hostile input; the extractor always
    passes a fixed-width slice and an unpacked u32).
    """
    if len(guid) != 16:
        msg = f"RSDS GUID must be 16 raw bytes, got {len(guid)}"
        raise ValueError(msg)
    if age < 0:
        msg = f"RSDS age must be non-negative, got {age}"
        raise ValueError(msg)
    data1, data2, data3 = struct.unpack_from("<IHH", guid)
    return (f"{data1:08x}{data2:04x}{data3:04x}"
            f"{guid[8:].hex()}{age:x}")


def canonical_pe_identity_from_guid_string(guid: str, age: int) -> str:
    """Dashed / braced / uppercase GUID TEXT → the same canonical
    hex as :func:`canonical_pe_identity`.

    The dashed rendering is already field-order
    (``Data1-Data2-Data3-Data4[0:2]-Data4[2:8]``), so stripping
    separators and lowercasing yields the ``%08x%04x%04x`` + Data4
    form directly — no byte swapping (that only applies to the RAW
    little-endian bytes the other helper takes). Raises
    ``ValueError`` on non-GUID text or a negative age.
    """
    cleaned = guid.strip()
    if cleaned.startswith("{") and cleaned.endswith("}"):
        cleaned = cleaned[1:-1]
    cleaned = cleaned.replace("-", "")
    if len(cleaned) != 32:
        msg = f"GUID text must carry 32 hex digits, got {len(cleaned)}"
        raise ValueError(msg)
    int(cleaned, 16)          # ValueError on non-hex text
    if age < 0:
        msg = f"RSDS age must be non-negative, got {age}"
        raise ValueError(msg)
    return cleaned.lower() + f"{age:x}"


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
    data_dirs: dict[int, tuple[int, int]] = {}
    if size_of_optional == 0:
        # A COFF object shape, not an image — header facts survive,
        # everything optional-derived is a recorded gap.
        caps.add("optional_header_missing")
    else:
        opt = f.read(size_of_optional)
        if len(opt) < size_of_optional:
            caps.add("optional_header_truncated")
        data_dirs = _parse_optional_header(opt, facts, caps)

    # Directory PRESENCE bits: a nonzero (address, size) pair is the
    # claim. The security entry is never dereferenced here at all;
    # the CLR entry only as a bit.
    sec_dir = data_dirs.get(_DIR_SECURITY, (0, 0))
    facts.authenticode_present = sec_dir[0] != 0 and sec_dir[1] != 0
    clr_dir = data_dirs.get(_DIR_CLR, (0, 0))
    facts.dotnet_present = clr_dir[0] != 0 and clr_dir[1] != 0

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

    debug_va, debug_size = data_dirs.get(_DIR_DEBUG, (0, 0))
    _read_debug_identity(f, resolver, debug_va, debug_size,
                         facts, caps)

    _compute_overlay(facts, file_size)

    facts.caps_hit = sorted(caps)
    return facts


def _read_debug_identity(
    f: BinaryIO, resolver: _RvaResolver, debug_va: int,
    debug_size: int, facts: PeFacts, caps: set[str],
) -> None:
    """Walk the debug directory for the RSDS (CodeView) identity.

    Named rules: the FIRST RSDS entry in directory order wins;
    later RSDS entries that parse to a DIFFERENT identity are a
    ``conflicting_debug_entries`` marker (a doctored second entry
    must not silently steer the identity, and its existence must
    not be silent either). Within one entry, ``PointerToRawData``
    (a file offset) is preferred over ``AddressOfRawData`` (an RVA)
    whenever it is present — the two can be made to disagree and
    the file offset is what a symbol-server consumer reads.
    Non-CodeView entry types are skipped without markers: POGO /
    repro / VC-feature entries are normal, not gaps.
    """
    if debug_va == 0 or debug_size == 0:
        return
    count = debug_size // _DEBUG_DIR_ENTRY.size
    if count > _MAX_DEBUG_DIR_ENTRIES:
        count = _MAX_DEBUG_DIR_ENTRIES
        caps.add("debug_entries_capped")
    first: tuple[bytes, int, str | None] | None = None
    for i in range(count):
        raw = resolver.read(f, debug_va + i * _DEBUG_DIR_ENTRY.size,
                            _DEBUG_DIR_ENTRY.size)
        if raw is None or len(raw) < _DEBUG_DIR_ENTRY.size:
            caps.add("debug_directory_unreadable")
            break
        (_chars, _ts, _major, _minor, dtype, size_of_data,
         addr_of_raw, ptr_to_raw) = _DEBUG_DIR_ENTRY.unpack(raw)
        if dtype != _IMAGE_DEBUG_TYPE_CODEVIEW:
            continue
        blob = _read_codeview_blob(f, resolver, size_of_data,
                                   addr_of_raw, ptr_to_raw)
        if blob is None or len(blob) < 24 or blob[:4] != _RSDS_MAGIC:
            # A CodeView entry that yields no identity — unreadable
            # data, both pointers zero, a blob shorter than
            # magic + GUID + age, or a non-RSDS CodeView format
            # (NB10). No identity claim to record or conflict with,
            # but marked: "no identity + this marker" must stay
            # distinguishable from "no CodeView entry at all".
            caps.add("debug_codeview_unparsed")
            continue
        guid = blob[4:20]
        (age,) = struct.unpack_from("<I", blob, 20)
        basename, name_caps = _pdb_basename(blob[24:])
        if first is None:
            first = (guid, age, basename)
            facts.debug_guid = guid.hex()
            facts.debug_age = age
            facts.pdb_basename = basename
            facts.debug_identity = canonical_pe_identity(guid, age)
            # Name-shape markers describe only the RECORDED identity.
            caps |= name_caps
        elif (guid, age, basename) != first:
            caps.add("conflicting_debug_entries")


def _read_codeview_blob(
    f: BinaryIO, resolver: _RvaResolver, size_of_data: int,
    addr_of_raw: int, ptr_to_raw: int,
) -> bytes | None:
    """Fetch one CodeView entry's data, bounded by
    ``min(SizeOfData, the RSDS fixed part + the pdb-path cap)`` —
    SizeOfData is attacker-priced and never a read budget on its
    own. ``PointerToRawData`` preferred; ``AddressOfRawData``
    resolves through the chokepoint."""
    length = min(size_of_data, 24 + _MAX_PDB_PATH_BYTES)
    if length <= 0:
        return None
    if ptr_to_raw:
        if ptr_to_raw > _MAX_SEEK_OFFSET:
            return None
        try:
            f.seek(ptr_to_raw)
            return f.read(length)
        except OSError:
            return None
    if addr_of_raw:
        return resolver.read(f, addr_of_raw, length)
    return None


def _pdb_basename(payload: bytes) -> tuple[str | None, set[str]]:
    """Last path component of the NUL-terminated pdb path.

    ``None`` + marker when no terminator exists inside the capped
    window (the path is hostile text; an unterminated one must not
    materialise the tail of the read). The basename itself is
    byte-capped at retention — still hostile text, escape at
    render."""
    nul = payload.find(b"\x00")
    if nul < 0:
        return None, {"pdb_name_malformed"}
    raw = payload[:nul]
    # Both separators: pdb paths are conventionally Windows-style
    # but a crafted path can mix.
    for sep in (b"\\", b"/"):
        raw = raw.rsplit(sep, 1)[-1]
    caps: set[str] = set()
    if len(raw) > _MAX_PDB_BASENAME_BYTES:
        raw = raw[:_MAX_PDB_BASENAME_BYTES]
        caps.add("pdb_name_truncated")
    return raw.decode("utf-8", errors="replace"), caps


def pe_facts_evidence(
    binary_sha256: str, path: Path, facts: PeFacts,
) -> BinaryEvidenceRecord:
    """Wrap one facts record as HEADER_BACKED evidence (the
    ``make_evidence`` shape the Mach-O intake uses). Imported
    lazily so this module's import surface stays light for hot
    consumers that only ever parse."""
    from core.evidence import EvidenceTier, make_evidence
    return make_evidence(
        binary_sha256,
        kind="pe_facts",
        source="pe_header",
        summary=(f"PE header facts: {facts.pe_format or 'pe'}, "
                 f"{len(facts.sections)} section(s)"),
        tier=EvidenceTier.HEADER_BACKED,
        confidence="confirmed",
        reproducible=True,
        tool="binary-intake",
        location=str(path),
        data={"facts": facts.to_dict()},
    )


def _compute_overlay(facts: PeFacts, file_size: int) -> None:
    """Overlay presence/size: file bytes past every mapped extent.

    Every contribution is clamped to ``file_size``. Precisely: a
    raw claim STARTING past EOF (truncated / doctored image)
    establishes no extent at all; a claim starting in-file but
    over-running EOF clamps to the file end — which extends the
    mapped region there, so a trailing overlay sitting behind such
    an over-claim is masked by it (the claim owns those bytes as
    far as this fact can tell). When NO extent is establishable at
    all (no usable SizeOfHeaders and no in-file section data), the
    overlay stays absent rather than declaring the whole file an
    overlay; the optional-header / section markers already record
    why.
    """
    end = 0
    if facts.size_of_headers:
        end = min(facts.size_of_headers, file_size)
    for sec in facts.sections:
        if sec.raw_size and sec.raw_offset < file_size:
            end = max(end, min(sec.raw_offset + sec.raw_size,
                               file_size))
    if end and file_size > end:
        facts.overlay_present = True
        facts.overlay_offset = end
        facts.overlay_size = file_size - end


def _parse_optional_header(
    opt: bytes, facts: PeFacts, caps: set[str],
) -> dict[int, tuple[int, int]]:
    """Decode the optional header into ``facts`` — per-field
    degradation: a short buffer marks ``optional_header_truncated``
    once and leaves the unreachable fields at their defaults.
    Returns the data-directory table as ``{index: (address,
    size)}`` (empty when the layout is unknown or the table is out
    of reach)."""
    if len(opt) < 2:
        caps.add("optional_header_truncated")
        return {}
    (magic,) = struct.unpack_from("<H", opt, 0)
    facts.optional_magic = magic
    if magic == _PE32_MAGIC:
        facts.bits, facts.pe_format = 32, "pe32"
        image_base_fmt, image_base_off = "<I", 28
        dirs_count_off, dirs_off = 92, 96
    elif magic == _PE32PLUS_MAGIC:
        facts.bits, facts.pe_format = 64, "pe32+"
        image_base_fmt, image_base_off = "<Q", 24
        dirs_count_off, dirs_off = 108, 112
    else:
        # Fail open on unknown magic (ROM images, hostile values):
        # the raw value is recorded above; the layout is unknown so
        # no optional field beyond it can be trusted to decode.
        caps.add("optional_magic_unknown")
        return {}

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

    # --- Data directories ---------------------------------------
    claimed = _u32(dirs_count_off)
    if claimed is None:
        return {}
    n_dirs = claimed
    if n_dirs > _MAX_DATA_DIRS:
        n_dirs = _MAX_DATA_DIRS
        caps.add("data_directories_capped")
    dirs: dict[int, tuple[int, int]] = {}
    for idx in range(n_dirs):
        entry_off = dirs_off + 8 * idx
        if entry_off + 8 > len(opt):
            caps.add("optional_header_truncated")
            break
        address, size = struct.unpack_from("<II", opt, entry_off)
        dirs[idx] = (address, size)
    return dirs


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
    headers: list[tuple[str, int, int, int, int, int]] = []
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
            headers.append((name, virtual_address, virtual_size,
                            raw_size, raw_offset, sec_characteristics))
    except OSError:
        # Screened-read net: keep the walked prefix, record the gap.
        caps.add("section_table_truncated")

    # Second pass: measure entropy over each section's leading raw
    # bytes, bounded by the per-section window and the whole-walk
    # budget. The row is recorded either way — only the measurement
    # degrades, marker-visibly.
    sections: list[PeSection] = []
    entropy_budget = _MAX_ENTROPY_TOTAL_BYTES
    measured = 0
    for (name, virtual_address, virtual_size, raw_size, raw_offset,
         sec_characteristics) in headers:
        entropy: float | None = None
        sampled = 0
        if raw_size == 0:
            pass                    # no file bytes — nothing to measure
        elif measured >= _MAX_ENTROPY_SECTIONS:
            caps.add("entropy_sections_capped")
        elif entropy_budget <= 0:
            caps.add("entropy_budget_exhausted")
        elif raw_offset > _MAX_SEEK_OFFSET:
            caps.add("section_data_unreadable")
        else:
            data = b""
            try:
                f.seek(raw_offset)
                data = f.read(min(raw_size, _MAX_ENTROPY_SECTION_BYTES,
                                  entropy_budget))
            except OSError:
                # Belt-and-braces behind the offset screen: a kernel
                # refusal costs this measurement, not the walk.
                pass
            if not data:
                caps.add("section_data_unreadable")   # offset past EOF
            else:
                entropy_budget -= len(data)
                entropy = _shannon_entropy(data)
                sampled = len(data)
                measured += 1
        sections.append(PeSection(
            name=name,
            virtual_address=virtual_address,
            virtual_size=virtual_size,
            raw_size=raw_size,
            raw_offset=raw_offset,
            characteristics=sec_characteristics,
            entropy=entropy,
            sampled=sampled,
        ))
    return sections


__all__ = [
    "PeFacts",
    "PeSection",
    "canonical_pe_identity",
    "canonical_pe_identity_from_guid_string",
    "extract_pe_facts",
    "is_pe",
    "pe_facts_evidence",
]

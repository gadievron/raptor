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
  section table, ``SizeOfHeaders``, the entrypoint RVA, and the
  import / delay-import / export tables.

Scope
- PE32 + PE32+ images (little-endian by format definition)
- ``bits`` comes from the OPTIONAL-HEADER MAGIC, never from the
  COFF machine field: the machine value is a family label and a
  crafted header can disagree with the actual image layout — the
  magic is what selects the layout actually parsed.
- Import + delay-import tables: per-DLL name and function list
  (hint/name or ordinal), thunk width and ordinal-flag bit
  selected PER FORMAT from the optional-header magic.
- Export table: declared name, ordinal base, declared-vs-walked
  counts, named + ordinal-only entries, forwarders as capped
  literal strings (never resolved — invariant g below).
- Signing facts: the security-directory presence bit plus a
  bounded DER skim of the first PKCS#7 certificate entry for the
  claimed signer's CN (``claimed_signer`` — a recorded CLAIM,
  never a verification; see the field docs and the skim's own
  doctrine at :class:`_DerSkim`).

Out of scope
- The bound-import table (a pre-Vista binding optimisation; its
  facts duplicate the import table's DLL list)
- The resource tree INCLUDING version-info (canonical PE
  hostile-recursion surface — deliberately not parsed)
- TE (Terse Executable) images — no DOS/COFF header, different
  format; callers classify separately
- Authenticode VERIFICATION in any form: no signature or digest
  check, no chain building, no timestamp/counter-signature
  parsing, no trust or validity decision — the skim copies one
  capped name string out of an attacker-authored structure and
  stops
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
      budget, and a read never crosses a section boundary;
  (e) every count- or terminator-driven walk (import descriptors,
      thunk arrays, export slots, name strings) runs under a NAMED
      cap with a ``caps_hit`` marker on breach — declared counts
      are attacker u32s and terminators are attacker-optional, so
      no walk trusts either for its budget;
  (g) forwarded exports are retained as capped LITERAL STRINGS,
      never resolved or chased — a forwarder is text data, so no
      forwarder cycle can exist by construction.
"""

from __future__ import annotations

import bisect
import heapq
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
# ---- Import / delay-import walk caps (invariant e).
#
# Import descriptors walked (one per DLL). The descriptor array is
# null-descriptor terminated — its length is attacker-shaped, not
# declared — and each descriptor prices a 20-byte resolver read
# plus a name read and a thunk walk. Real images link tens of
# DLLs; plugin-heavy monsters reach the low hundreds. 1024
# truncates nothing real; higher only sells resolver reads to a
# crafted array whose terminator never comes (the walk would
# otherwise run to the section's virtual end).
_MAX_IMPORT_DESCRIPTORS = 1_024
# Delay-load descriptors walked. The linker emits one ImgDelayDescr
# per /delayload'd DLL — real images carry a handful, heavyweight
# suites tens. 256 is an order above anything real; the cost model
# per entry is the regular-import one (32-byte descriptor + name +
# thunk walk), so a higher cap only resells the same hostile walk.
_MAX_DELAY_DESCRIPTORS = 256
# Thunks walked per DLL. A thunk array is null-terminated (length
# attacker-shaped again); the largest real per-DLL import lists
# (statically-imported CRT, mega-DLLs) stay under ~2k entries.
# 4096 truncates nothing real; an uncapped walk would hand an
# unterminated array a read loop across its whole section extent.
_MAX_IMPORT_THUNKS_PER_DLL = 4_096
# Whole-walk thunk budget across every import AND delay-import
# DLL. Bounds the aggregate when a crafted directory maxes
# descriptors x per-DLL thunks (1024 x 4096 would otherwise price
# ~4M resolver reads plus a name read each). Real images total a
# few thousand imports across all DLLs; lower would truncate
# extreme-but-real aggregates, higher just sells CPU.
_MAX_IMPORT_THUNKS_TOTAL = 16_384
# Longest name string a table lookup will materialise — same value
# and rationale as the ELF tier's strtab lookup
# (core.binary.elf._MAX_STRTAB_NAME_BYTES): deeply nested C++
# manglings genuinely reach a few KB, so lower drops real import /
# export names. A string unterminated inside the window (past the
# cap OR running into the section's virtual end) is retained as a
# CAPPED PREFIX with a marker — capture is capped, never a section
# dump. Hostile text either way — consumers escape at render.
_MAX_TABLE_NAME_BYTES = 4_096
# Total name bytes the whole tables walk (imports + delay-imports
# + exports) may retain — the record-size backstop, same value and
# rationale as the ELF import walk's _MAX_TOTAL_NAME_BYTES: real
# name volumes stay under a few hundred KB, and the worst crafted
# case (every entry at the per-name cap) must not turn the facts
# record itself into the amplifier. On breach, names degrade to
# None with a marker AND further name/forwarder READS stop — a
# spent budget must not keep selling chokepoint reads (tens of
# thousands across a max-shape table) for text that can no longer
# be retained; counts stay honest, the walk itself continues.
# The budget prices the RAW bytes retained; the record stores
# DECODED text, and errors="replace" expands an invalid byte to
# one U+FFFD (3 UTF-8 bytes) — a bounded x3 constant factor on
# top of the budget, not a bypass.
_MAX_TABLE_NAME_TOTAL_BYTES = 8 * 1024 * 1024
# ---- Export walk caps (invariant e).
#
# Export function slots / name entries walked. NumberOfFunctions
# and NumberOfNames are attacker u32s driving bulk array reads,
# per-name string reads, and record rows; the largest real export
# tables (mega C++ / system DLLs) stay around ~20k entries. 32768
# truncates nothing real; higher re-opens the read-and-record
# amplification the caps close (each name entry prices a
# name-window read, each function slot a record row).
_MAX_EXPORT_FUNCTIONS = 32_768
_MAX_EXPORT_NAMES = 32_768
# ---- Signing-facts skim caps (invariant e applies here too: every
# walk runs under a named cap with a marker on breach).
#
# WIN_CERTIFICATE entries walked in the certificate table. Real
# tables carry 1-3 entries (the primary signature, occasionally a
# second-algorithm one); dwLength is an attacker u32 pricing the
# stride, so an uncapped walk would sell one seek+read per crafted
# entry across the whole declared table. 16 truncates nothing real;
# higher only resells the same hostile walk.
_MAX_CERT_TABLE_ENTRIES = 16
# Bytes of the ONE skimmed PKCS#7 blob materialised in memory.
# dwLength is an attacker u32 and never a read budget on its own;
# real Authenticode blobs (chain + countersignatures + page-hash
# attributes) stay under a few hundred KB, so 1 MiB truncates
# nothing real, while higher re-opens allocation amplification from
# a single crafted directory entry. A capped blob degrades
# marker-visibly (``authenticode_blob_capped``).
_MAX_CERT_BLOB_BYTES = 1024 * 1024
# Nested-TLV depth ceiling for the DER walk. The skim's deepest
# fixed path (ContentInfo → content → SignedData → certificates →
# Certificate → tbsCertificate → subject → RDN → attribute → value)
# sits at depth 9 BY CONSTRUCTION — the walk is targeted, never
# recursive-on-input — so the cap is belt-and-braces: it exists so
# a future edit that introduces input-driven descent cannot
# silently unbound it. 32 is three real paths deep (nothing real
# breaches); lower would leave no headroom for legitimate structure
# growth, higher only weakens the tripwire.
_MAX_DER_DEPTH = 32
# TLV headers parsed per skim — the op-count budget, and the term
# that bounds the whole walk's work: worst case is
# _MAX_DER_NODES x (one O(1) header parse + at most one capped
# content copy at the few capture points), over an in-memory blob
# already bounded by _MAX_CERT_BLOB_BYTES — no per-node file IO
# exists. A real blob's targeted walk touches well under a few
# hundred nodes (skipped siblings cost one header each); a crafted
# flood of 2-byte TLVs prices one header parse per 2 input bytes,
# so without this budget the work would scale with blob size. 4096
# is an order above real; higher only sells CPU to a TLV flood.
_MAX_DER_NODES = 4_096
# Signer-CN bytes retained (raw DER content, counted before
# decode). X.520 bounds real common names at 64 characters; 256
# truncates nothing real while the record never becomes the
# amplifier for a crafted megabyte string value. Hostile text
# either way — escape at render.
_MAX_SIGNER_NAME_BYTES = 256

# WIN_CERTIFICATE header: dwLength(I) wRevision(H)
# wCertificateType(H), then bCertificate. Entries are 8-byte
# aligned within the table.
_WIN_CERT_HEADER = struct.Struct("<IHH")
_WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002

# OIDs compared as RAW DER content bytes — never arc-decoded: an
# arc decoder is a second numeric parser with its own overflow
# surface, and byte equality answers the only question the skim
# asks. Bounded by construction: comparison against a fixed-width
# constant reads at most that many bytes.
_OID_PKCS7_SIGNED_DATA = bytes.fromhex("2a864886f70d010702")  # 1.2.840.113549.1.7.2
_OID_COMMON_NAME = bytes.fromhex("550403")                    # 2.5.4.3

# DER tags the skim recognises. The context-specific constructed
# tags appear both as the EXPLICIT content wrapper ([0] in
# ContentInfo) and as the IMPLICIT certificates field of SignedData.
_DER_INTEGER = 0x02
_DER_OID = 0x06
_DER_UTF8_STRING = 0x0C
_DER_PRINTABLE_STRING = 0x13
_DER_TELETEX_STRING = 0x14
_DER_IA5_STRING = 0x16
_DER_BMP_STRING = 0x1E
_DER_SEQUENCE = 0x30
_DER_SET = 0x31
_DER_CONTEXT_0 = 0xA0

# Data-directory indices consumed (spec order). The security entry
# holds a FILE OFFSET (not an RVA) to the certificate table — the
# one directory that must NOT resolve through the RVA chokepoint
# (the table is never mapped); its presence bit and the bounded
# claimed-signer skim are the only things read from it.
_DIR_EXPORT = 0
_DIR_IMPORT = 1
_DIR_SECURITY = 4
_DIR_DEBUG = 6
_DIR_DELAY_IMPORT = 13
_DIR_CLR = 14

# The export directory: Characteristics(I) TimeDateStamp(I)
# MajorVersion(H) MinorVersion(H) Name(I) Base(I)
# NumberOfFunctions(I) NumberOfNames(I) AddressOfFunctions(I)
# AddressOfNames(I) AddressOfNameOrdinals(I)
_EXPORT_DIRECTORY = struct.Struct("<IIHHIIIIIII")

# One import descriptor: OriginalFirstThunk(I) TimeDateStamp(I)
# ForwarderChain(I) Name(I) FirstThunk(I)
_IMPORT_DESCRIPTOR = struct.Struct("<IIIII")
# One delay-load descriptor (ImgDelayDescr): Attributes(I)
# DllNameRVA(I) ModuleHandleRVA(I) IATRVA(I) ImportNameTableRVA(I)
# BoundIATRVA(I) UnloadIATRVA(I) TimeStamp(I)
_DELAY_DESCRIPTOR = struct.Struct("<IIIIIIII")
# ImgDelayDescr.grAttrs bit 0: SET = the descriptor's address
# fields are RVAs (the form every post-VC6 linker emits); CLEAR =
# the legacy form whose fields are absolute virtual addresses.
_DELAY_ATTR_RVA = 0x1
# Thunk width and ordinal-flag bit are selected PER FORMAT from the
# optional-header magic — the classic import-walk bug is applying
# the 32-bit flag to 64-bit thunks (or vice versa): 0x80000000 in
# a PE32+ thunk is NOT an ordinal import, it is a value inside the
# hint/name RVA field's u64 slot.
_THUNK_STRUCTS = {32: struct.Struct("<I"), 64: struct.Struct("<Q")}
_ORDINAL_FLAGS = {32: 0x8000_0000, 64: 0x8000_0000_0000_0000}
# Bits 30:0 of a non-ordinal thunk hold the hint/name RVA; the
# non-flag bits above them must be zero per spec and are ignored
# by masking (fail open — a doctored high bit must not invent a
# giant RVA and must not flip the import's shape).
_THUNK_RVA_MASK = 0x7FFF_FFFF

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


@dataclass(frozen=True)
class PeImportedFunction:
    """One import thunk, in its ground-truth shape: a hint/name
    import carries ``name`` (hostile text — capped at capture,
    escape at render) plus the loader ``hint``; an ordinal import
    carries ``ordinal`` only. A thunk whose hint/name data was
    unreadable, unterminated, or dropped by the name budget keeps
    whatever was recovered (possibly ``hint`` alone, possibly
    nothing) — the owning DLL's ``caps_hit`` says why."""

    name: str | None = None
    hint: int | None = None
    ordinal: int | None = None


@dataclass
class PeImportedDll:
    """One import-directory descriptor's facts.

    ``name`` is the DLL-name string from the hostile file — capped
    at capture, stored as data, escape at render. ``thunk_count``
    counts thunks WALKED (== ``len(functions)``; entries are
    recorded even when their names degrade), split by shape into
    ``named_count`` / ``ordinal_count``. ``used_first_thunk``
    records the OriginalFirstThunk = 0 fallback (see the walk).
    ``caps_hit`` carries this DLL's own walk markers; every marker
    is mirrored into ``PeFacts.caps_hit`` so record-level "empty =
    complete" stays true.
    """

    name: str | None = None
    functions: list[PeImportedFunction] = field(default_factory=list)
    thunk_count: int = 0
    named_count: int = 0
    ordinal_count: int = 0
    used_first_thunk: bool = False
    caps_hit: list[str] = field(default_factory=list)


@dataclass
class PeDelayImportedDll:
    """One delay-load descriptor's facts (ImgDelayDescr).

    ``rva_addressed`` mirrors attribute bit 0 (``_DELAY_ATTR_RVA``).
    When False — the legacy pre-VC7 form — every address field
    including the DLL name is an absolute virtual address, which
    this extractor deliberately does NOT chase: rebasing VAs
    through ImageBase would be a second resolution path beside the
    RVA chokepoint. The descriptor is recorded with its raw
    ``attributes`` and a ``delay_import_va_form`` marker instead.
    All other fields follow :class:`PeImportedDll`.
    """

    name: str | None = None
    attributes: int = 0
    rva_addressed: bool = True
    functions: list[PeImportedFunction] = field(default_factory=list)
    thunk_count: int = 0
    named_count: int = 0
    ordinal_count: int = 0
    caps_hit: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class PeExportedSymbol:
    """One export-table entry.

    ``ordinal`` is biased (``ordinal_base + function index``);
    ``name`` is present for named exports (hostile text — capped
    at capture, escape at render) and ``None`` for ordinal-only
    entries. ``rva`` is the raw AddressOfFunctions slot value;
    ``None`` only when the name's ordinal points outside the
    walked function array (table marker says so).

    ``forwarder`` holds the forwarder string as a CAPPED LITERAL
    (invariant g): a function slot whose value lands inside the
    export directory's extent is, by format definition, an RVA of
    "DLL.Symbol" text — that text is captured as data and NEVER
    resolved or chased, so no forwarder cycle can exist by
    construction. It is attacker-authored steering text like every
    other name here — escape at render.
    """

    ordinal: int
    rva: int | None
    name: str | None = None
    forwarder: str | None = None


@dataclass
class PeExports:
    """Export-table facts.

    ``declared_*`` counts are the directory's raw u32 claims
    (attacker-priced — recorded, never trusted); ``walked_*`` are
    what the capped walk actually recorded (invariant e), so a
    consumer always sees claim and truth side by side. ``named``
    and ``ordinal_only`` partition the walked entries; unused
    (zero) function slots are absent by design — real tables carry
    ordinal gaps and a zero slot exports nothing. ``caps_hit``
    carries the table's walk markers, mirrored into
    ``PeFacts.caps_hit``.
    """

    dll_name: str | None = None
    ordinal_base: int = 0
    declared_function_count: int = 0
    declared_name_count: int = 0
    walked_function_count: int = 0
    walked_name_count: int = 0
    forwarder_count: int = 0
    named: list[PeExportedSymbol] = field(default_factory=list)
    ordinal_only: list[PeExportedSymbol] = field(
        default_factory=list)
    caps_hit: list[str] = field(default_factory=list)


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
    # Security (certificate table) directory presence — a nonzero
    # entry means the image CLAIMS an Authenticode blob. Nothing
    # here verifies or trusts it.
    authenticode_present: bool = False
    # CLR runtime header directory presence — the .NET bit.
    dotnet_present: bool = False
    # ``claimed_signer`` is the subject CN of the certificate the
    # blob's first SignerInfo names — recovered by a bounded DER
    # SKIM (:func:`_skim_claimed_signer`), never a verification:
    # no signature, digest, chain, validity or trust decision
    # exists in this module. The name carries the epistemic status:
    # this is attacker-authored STEERING TEXT by design — capped at
    # capture, stored as data, escape at render. "" = no claim
    # extracted (no signature, a non-PKCS#7 entry, or a skim
    # degrade — the markers say which).
    # FENCE: no mechanical consumer may gate, suppress, or trust
    # on ``authenticode_present`` / ``claimed_signer`` — they are
    # display/correlation facts only. The consumer census pinning
    # this fence lives in core/binary/tests/test_pe_signing.py
    # (the signing-facts fence test); amend BOTH places together
    # if a consumer is ever added deliberately.
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
    # Import / delay-import / export table facts. Empty lists (or
    # ``exports is None``) mean the corresponding directory is
    # absent or empty; an unreadable directory leaves a marker, so
    # absence and degradation stay distinguishable.
    imports: list[PeImportedDll] = field(default_factory=list)
    delay_imports: list[PeDelayImportedDll] = field(
        default_factory=list)
    exports: PeExports | None = None
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
    module goes through :meth:`read`.

    Resolution is served from a segment index built ONCE at
    construction: the section table is swept into disjoint sorted
    ``(start, end, section)`` segments whose owner is the FIRST
    section in table order covering them — invariant (b),
    precomputed. The pricing rationale: the table walks issue tens
    of thousands of chokepoint reads per image and
    ``NumberOfSections`` is attacker-chosen up to
    ``_MAX_SECTIONS``, so a per-READ linear scan hands a crafted
    image a sections x reads product (measured in the tens of
    seconds from a sub-MB file). Bisect over the index makes every
    read O(log n) while resolution stays a pure function of the
    table.
    """

    def __init__(self, sections: list[PeSection],
                 size_of_headers: int) -> None:
        self._sections = sections
        self._size_of_headers = max(0, size_of_headers)
        self._seg_starts: list[int] = []
        self._seg_ends: list[int] = []
        self._seg_secs: list[PeSection] = []
        self._build_index()

    def _build_index(self) -> None:
        """Sweep the (possibly overlapping) section spans into the
        disjoint segment index. A lazy-deletion heap keyed on table
        index makes the winner at every elementary interval the
        live section with the LOWEST table index — exactly the
        first-match rule the per-RVA scan implemented, paid once
        instead of per read."""
        spans = [
            (sec.virtual_address,
             sec.virtual_address + self._virtual_extent(sec),
             idx, sec)
            for idx, sec in enumerate(self._sections)
            if self._virtual_extent(sec) > 0
        ]
        if not spans:
            return
        points = sorted({p for start, end, _idx, _sec in spans
                         for p in (start, end)})
        by_start = sorted(spans, key=lambda s: s[0])
        # Heap entries: (table_index, end, section) — table_index
        # is unique, so the section never participates in ordering.
        heap: list[tuple[int, int, PeSection]] = []
        si = 0
        for k in range(len(points) - 1):
            p = points[k]
            while si < len(by_start) and by_start[si][0] == p:
                _start, end, idx, sec = by_start[si]
                heapq.heappush(heap, (idx, end, sec))
                si += 1
            while heap and heap[0][1] <= p:      # lazy deletion
                heapq.heappop(heap)
            if not heap:
                continue                         # gap between spans
            sec = heap[0][2]
            if (self._seg_secs and self._seg_secs[-1] is sec
                    and self._seg_ends[-1] == p):
                self._seg_ends[-1] = points[k + 1]
            else:
                self._seg_starts.append(p)
                self._seg_ends.append(points[k + 1])
                self._seg_secs.append(sec)

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
        i = bisect.bisect_right(self._seg_starts, rva) - 1
        if i >= 0 and rva < self._seg_ends[i]:
            sec = self._seg_secs[i]           # table-order winner — (b)
            extent = self._virtual_extent(sec)
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

    # Claimed-signer skim. The security entry is FILE-OFFSET
    # addressed by format definition, so it never touches the RVA
    # resolver — the walk applies the seek screen + OSError net
    # directly.
    if facts.authenticode_present:
        _read_signing_facts(f, file_size, sec_dir[0], sec_dir[1],
                            facts, caps)

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

    # Table walks share ONE name-retention budget (and the import
    # walks one thunk budget): the caps bound the whole record, not
    # one directory at a time. A populated directory table implies
    # a decoded optional-header layout, so ``facts.bits`` is 32/64
    # here whenever a walk runs — the membership check is
    # belt-and-braces against future layout additions, not a
    # reachable branch today.
    name_budget = _Budget(_MAX_TABLE_NAME_TOTAL_BYTES)
    thunk_budget = _Budget(_MAX_IMPORT_THUNKS_TOTAL)
    if facts.bits in _THUNK_STRUCTS:
        import_va, import_size = data_dirs.get(_DIR_IMPORT, (0, 0))
        if import_va and import_size:
            _read_imports(f, resolver, import_va, facts, caps,
                          name_budget, thunk_budget)
        delay_va, delay_size = data_dirs.get(_DIR_DELAY_IMPORT,
                                             (0, 0))
        if delay_va and delay_size:
            _read_delay_imports(f, resolver, delay_va, facts, caps,
                                name_budget, thunk_budget)
    export_va, export_size = data_dirs.get(_DIR_EXPORT, (0, 0))
    if export_va and export_size:
        _read_exports(f, resolver, export_va, export_size, facts,
                      caps, name_budget)

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


# ---------------------------------------------------------------------------
# Signing facts — the claimed-signer skim (NEVER verification)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _DerNode:
    """One parsed TLV: identifier offset plus content extent.
    ``start`` keeps the identifier octet's offset so a caller can
    take the FULL element bytes (``blob[start:content_end]``) for
    verbatim DER comparison."""

    tag: int
    start: int
    content_start: int
    content_end: int


class _DerSkim:
    """Bounded, targeted DER walk over ONE in-memory PKCS#7 blob —
    its own hostile parser with its own doctrine, mirroring the
    module's invariants:

      * every length is an attacker-chosen claim, screened against
        the enclosing extent BEFORE use — a length lying past its
        enclosure is refused (marker), never clamped-and-continued,
        so no node can read its parent's siblings as content;
      * indefinite lengths (BER-only, forbidden by DER) are refused
        with a marker — a terminator-driven scan is exactly the
        attacker-priced walk this parser does not run;
      * the walk spends a named NODE budget (the op-count bound —
        see ``_MAX_DER_NODES`` for the worst-case cost product) and
        a named DEPTH budget (belt-and-braces: the targeted walk's
        deepest path is fixed at 9 by construction);
      * every refusal lands a ``caps_hit`` marker, never an
        exception past the module contract.

    No signature, digest, chain, validity, or trust decision exists
    anywhere here — the skim copies ONE capped name string out of
    an attacker-authored structure and stops.
    """

    def __init__(self, blob: bytes, caps: set[str]) -> None:
        self._blob = blob
        self._caps = caps
        self._nodes_left = _MAX_DER_NODES

    def top(self) -> _DerNode | None:
        """The blob's outermost TLV (``None`` + marker when even
        that does not parse — the empty blob included)."""
        return self._header(0, len(self._blob))

    def content(self, node: _DerNode) -> bytes:
        return self._blob[node.content_start:node.content_end]

    def element(self, node: _DerNode) -> bytes:
        """Full encoded element (identifier + length + content) —
        for verbatim DER comparison (DER is canonical by
        definition, so byte equality IS name equality; anything
        that would only match after re-encoding is malformed input
        and degrades)."""
        return self._blob[node.start:node.content_end]

    def children(self, node: _DerNode, depth: int) -> list[_DerNode]:
        """The child TLVs of one constructed node. On a malformed
        child, the parsed PREFIX is returned and the marker set by
        the header parse records the gap (per-field degradation —
        a malformation can only ever DROP later siblings, never
        skip past one, so first-wins selections stay steer-proof);
        a spent depth budget returns nothing, marker-visibly."""
        if depth >= _MAX_DER_DEPTH:
            self._caps.add("signer_skim_depth_capped")
            return []
        out: list[_DerNode] = []
        off = node.content_start
        while off < node.content_end:
            child = self._header(off, node.content_end)
            if child is None:
                break                    # marker already recorded
            out.append(child)
            off = child.content_end
        return out

    def children_strict(self, node: _DerNode,
                        depth: int) -> list[_DerNode] | None:
        """:meth:`children` with a TERMINAL malformation contract:
        a child that fails to parse (or a spent depth budget)
        refuses the WHOLE enclosure — ``None``, marker already
        recorded — instead of returning the walked prefix.

        For walks that SELECT among siblings by content (the
        claimed-signer CN walk): prefix-degrade there would make a
        structurally-poisoned first candidate silently skippable,
        handing a hostile subject the choice of which sibling gets
        recorded — exactly the steering the first-wins rules deny.
        Refusal-with-no-claim is the same no-fallback posture the
        certificate-table walk applies to a doctored first entry.
        """
        if depth >= _MAX_DER_DEPTH:
            self._caps.add("signer_skim_depth_capped")
            return None
        out: list[_DerNode] = []
        off = node.content_start
        while off < node.content_end:
            child = self._header(off, node.content_end)
            if child is None:
                return None              # marker already recorded
            out.append(child)
            off = child.content_end
        return out

    def _header(self, off: int, end: int) -> _DerNode | None:
        """Parse one TLV header inside ``[off, end)``. ``None`` +
        marker on any malformation or a spent node budget."""
        blob = self._blob
        if off >= end:
            self._caps.add("signer_skim_malformed")
            return None
        if self._nodes_left <= 0:
            self._caps.add("signer_skim_nodes_capped")
            return None
        self._nodes_left -= 1
        tag = blob[off]
        cur = off + 1
        if tag & 0x1F == 0x1F:
            # High-tag-number form: nothing the skim LOOKS FOR uses
            # it, but a skipped sibling may — the header must still
            # parse so its length can be honoured. Continuation
            # bytes are capped at 4 (a longer run claims a tag
            # number past 2**28, which nothing real encodes).
            for _ in range(4):
                if cur >= end:
                    self._caps.add("signer_skim_malformed")
                    return None
                cont = blob[cur]
                cur += 1
                if not cont & 0x80:
                    break
            else:
                self._caps.add("signer_skim_malformed")
                return None
        if cur >= end:
            self._caps.add("signer_skim_malformed")
            return None
        first = blob[cur]
        cur += 1
        if first == 0x80:
            self._caps.add("signer_skim_indefinite_length")
            return None
        if first < 0x80:
            length = first
        else:
            n_len = first & 0x7F
            if n_len > 4 or cur + n_len > end:
                # A length-of-length past 4 claims content past
                # 4 GiB — no honest blob under the read cap can.
                self._caps.add("signer_skim_malformed")
                return None
            length = int.from_bytes(blob[cur:cur + n_len], "big")
            cur += n_len
        if length > end - cur:
            self._caps.add("signer_skim_malformed")
            return None
        return _DerNode(tag=tag, start=off, content_start=cur,
                        content_end=cur + length)


def _skim_claimed_signer(blob: bytes, caps: set[str]) -> str | None:
    """Subject CN of the certificate the blob's first SignerInfo
    names — the claimed signer, exactly the way the format
    identifies it (issuer + serial), with named rules:

      * the FIRST SignerInfo in encoding order is the recorded
        claim; further SignerInfos are surfaced as
        ``signer_multiple_signers`` (first-wins, mirroring the
        debug-directory rule);
      * only the v1 ``issuerAndSerialNumber`` signer-identifier
        form is skimmed (the only form Authenticode emits); any
        other shape degrades with ``signer_skim_malformed``;
      * issuer and serial are matched against each certificate's
        tbsCertificate by VERBATIM DER bytes — no name
        canonicalisation, no chain walk; no match (including an
        absent certificates field) is ``signer_cert_unmatched``;
      * the FIRST CN attribute in the subject's encoding order is
        the claim; an undecodable value type degrades
        (``signer_cn_unrecognised_type``) rather than falling
        through to a later CN — a hostile subject must not choose
        which CN is recorded by poisoning the first.
    """
    skim = _DerSkim(blob, caps)
    root = skim.top()
    if root is None or root.tag != _DER_SEQUENCE:
        caps.add("signer_skim_malformed")
        return None
    info = skim.children(root, 1)
    if (len(info) < 2 or info[0].tag != _DER_OID
            or skim.content(info[0]) != _OID_PKCS7_SIGNED_DATA
            or info[1].tag != _DER_CONTEXT_0):
        caps.add("signer_skim_malformed")
        return None
    wrap = skim.children(info[1], 2)
    if not wrap or wrap[0].tag != _DER_SEQUENCE:
        caps.add("signer_skim_malformed")
        return None
    # SignedData fields in order: version, digestAlgorithms,
    # contentInfo, [0]certificates?, [1]crls?, signerInfos (last).
    fields = skim.children(wrap[0], 3)
    if len(fields) < 4 or fields[-1].tag != _DER_SET:
        caps.add("signer_skim_malformed")
        return None
    certs_node = next(
        (n for n in fields[3:-1] if n.tag == _DER_CONTEXT_0), None)
    signer_seqs = [n for n in skim.children(fields[-1], 4)
                   if n.tag == _DER_SEQUENCE]
    if not signer_seqs:
        caps.add("signer_skim_malformed")
        return None
    if len(signer_seqs) > 1:
        caps.add("signer_multiple_signers")
    si_fields = skim.children(signer_seqs[0], 5)
    if (len(si_fields) < 2 or si_fields[0].tag != _DER_INTEGER
            or si_fields[1].tag != _DER_SEQUENCE):
        caps.add("signer_skim_malformed")
        return None
    isn = skim.children(si_fields[1], 6)
    if (len(isn) != 2 or isn[0].tag != _DER_SEQUENCE
            or isn[1].tag != _DER_INTEGER):
        caps.add("signer_skim_malformed")
        return None
    want_issuer = skim.element(isn[0])
    want_serial = skim.content(isn[1])

    subject: _DerNode | None = None
    for cert in skim.children(certs_node, 4) if certs_node else []:
        if cert.tag != _DER_SEQUENCE:
            continue     # extendedCertificate / attr-cert choices — skipped
        cert_fields = skim.children(cert, 5)
        if not cert_fields or cert_fields[0].tag != _DER_SEQUENCE:
            continue
        tbs = skim.children(cert_fields[0], 6)
        # tbsCertificate: [0]version?, serialNumber, signature,
        # issuer, validity, subject, ...
        idx = 1 if tbs and tbs[0].tag == _DER_CONTEXT_0 else 0
        if (len(tbs) < idx + 5
                or tbs[idx].tag != _DER_INTEGER
                or tbs[idx + 2].tag != _DER_SEQUENCE
                or tbs[idx + 4].tag != _DER_SEQUENCE):
            continue
        if (skim.content(tbs[idx]) == want_serial
                and skim.element(tbs[idx + 2]) == want_issuer):
            subject = tbs[idx + 4]
            break
    if subject is None:
        caps.add("signer_cert_unmatched")
        return None

    # The CN walk SELECTS among siblings, so malformation here is
    # TERMINAL (children_strict): a structurally-poisoned first
    # candidate must refuse the claim, never fall through to a
    # later, attacker-chosen CN — the same denial the type-poison
    # lane below already applies. Well-formed non-CN siblings
    # (other attribute types, wrong tags) are skipped as normal
    # subject structure.
    rdns = skim.children_strict(subject, 7)
    if rdns is None:
        return None
    for rdn in rdns:
        if rdn.tag != _DER_SET:
            continue
        atvs = skim.children_strict(rdn, 8)
        if atvs is None:
            return None
        for atv in atvs:
            if atv.tag != _DER_SEQUENCE:
                continue
            parts = skim.children_strict(atv, 9)
            if parts is None:
                return None
            if (len(parts) < 2 or parts[0].tag != _DER_OID
                    or skim.content(parts[0]) != _OID_COMMON_NAME):
                continue
            return _decode_signer_cn(skim.content(parts[1]),
                                     parts[1].tag, caps)
    caps.add("signer_cn_absent")
    return None


def _decode_signer_cn(raw: bytes, tag: int,
                      caps: set[str]) -> str | None:
    """Decode one CN value by its string type, capped at retention.
    Hostile bytes survive AS DATA (``errors="replace"`` marks lossy
    decodes; control bytes and bidi overrides pass through) —
    consumers escape at render, same contract as every other name
    field here."""
    if len(raw) > _MAX_SIGNER_NAME_BYTES:
        raw = raw[:_MAX_SIGNER_NAME_BYTES]
        caps.add("signer_name_truncated")
    if tag == _DER_BMP_STRING:
        return raw.decode("utf-16-be", errors="replace")
    if tag in (_DER_UTF8_STRING, _DER_PRINTABLE_STRING,
               _DER_TELETEX_STRING, _DER_IA5_STRING):
        # PrintableString / IA5 / Teletex are ASCII-ish subsets a
        # UTF-8 decode reads verbatim; a hostile value violating
        # its declared universe degrades per byte to U+FFFD, never
        # raises.
        return raw.decode("utf-8", errors="replace")
    caps.add("signer_cn_unrecognised_type")
    return None


def _read_at(f: BinaryIO, offset: int, length: int) -> bytes | None:
    """Screened + netted direct file read (the certificate table is
    file-offset addressed — the one lane that bypasses the RVA
    chokepoint by format definition). Possibly-short bytes; ``None``
    on a refused seek/read."""
    if offset > _MAX_SEEK_OFFSET:
        return None
    if length <= 0:
        # A zero-length claim reads nothing — the caller's parse of
        # the empty bytes records the honest degradation.
        return b""
    try:
        f.seek(offset)
        return f.read(length)
    except OSError:
        return None


def _read_signing_facts(
    f: BinaryIO, file_size: int, table_offset: int, table_size: int,
    facts: PeFacts, caps: set[str],
) -> None:
    """Walk the WIN_CERTIFICATE table for the claimed-signer skim.

    Named rules, mirroring the debug-directory walk:

      * the FIRST entry of type WIN_CERT_TYPE_PKCS_SIGNED_DATA in
        table order is the recorded claim; every entry after it
        (any type) is only counted, as
        ``authenticode_extra_certificates`` — a second signature
        must not silently steer the record;
      * a non-PKCS#7 entry BEFORE the claim is skipped with
        ``authenticode_non_pkcs_entry`` and the walk continues;
      * a first PKCS#7 entry whose skim fails leaves the field
        empty with its skim markers — later entries are never
        consulted as a fallback (a doctored first entry fails SAFE
        to "no claim", it cannot redirect the record to entry two);
      * ``dwLength`` is an attacker u32 pricing both the stride and
        the blob read — the entry count, the blob size, and the
        table extent (clamped to EOF) are all named caps.
    """
    end = table_offset + table_size
    if (table_offset <= 0 or table_offset > _MAX_SEEK_OFFSET
            or table_offset >= file_size):
        caps.add("authenticode_unreadable")
        return
    if end > file_size:
        # The directory claims bytes past EOF: the walk degrades to
        # what the file really has (short entries mark themselves).
        end = file_size
    off = table_offset
    skimmed = False
    for i in range(_MAX_CERT_TABLE_ENTRIES + 1):
        if off >= end:
            break
        if i == _MAX_CERT_TABLE_ENTRIES:
            caps.add("authenticode_entries_capped")
            break
        header = _read_at(f, off, _WIN_CERT_HEADER.size)
        if header is None or len(header) < _WIN_CERT_HEADER.size:
            caps.add("authenticode_malformed")
            break
        dw_length, _revision, cert_type = _WIN_CERT_HEADER.unpack(
            header)
        if dw_length < _WIN_CERT_HEADER.size:
            # Cannot even cover its own header — and a stride this
            # small would re-read the same bytes forever.
            caps.add("authenticode_malformed")
            break
        entry_end = off + dw_length
        if entry_end > end:
            caps.add("authenticode_malformed")
            entry_end = end
        if skimmed:
            caps.add("authenticode_extra_certificates")
        elif cert_type != _WIN_CERT_TYPE_PKCS_SIGNED_DATA:
            caps.add("authenticode_non_pkcs_entry")
        else:
            skimmed = True
            blob_len = entry_end - off - _WIN_CERT_HEADER.size
            if blob_len > _MAX_CERT_BLOB_BYTES:
                blob_len = _MAX_CERT_BLOB_BYTES
                caps.add("authenticode_blob_capped")
            blob = _read_at(f, off + _WIN_CERT_HEADER.size, blob_len)
            if blob is None:
                caps.add("authenticode_unreadable")
            else:
                name = _skim_claimed_signer(blob, caps)
                if name is not None:
                    facts.claimed_signer = name
        # Entries are 8-byte aligned; the aligned stride past a
        # clamped entry_end lands at/after ``end`` and exits.
        off = entry_end + (-entry_end % 8)


# ---------------------------------------------------------------------------
# Import / delay-import tables
# ---------------------------------------------------------------------------


@dataclass
class _Budget:
    """One mutable walk budget (name bytes retained / thunks
    walked), shared across every table walk of one extraction so
    the caps bound the RECORD, not one directory at a time."""

    remaining: int


def _take_cstring(window: bytes, budget: _Budget, caps: set[str],
                  marker_prefix: str) -> str | None:
    """Capped NUL-terminated capture from an already-read window
    (the window itself is one chokepoint read of the name cap + 1,
    possibly shorter where the section's virtual extent ends).

    No terminator inside the window — the string overruns the cap
    or its section — keeps the CAPPED PREFIX with a
    ``<prefix>_truncated`` marker: capture is capped, never a
    section dump, and the retained text is still honest file data.
    Retention is priced against the whole-walk name budget on the
    RAW bytes (what is actually kept); a name that would overdraw
    it degrades to ``None`` + ``<prefix>_budget_exhausted`` —
    whole-or-absent, never a silently partial name — and the
    overdraw SPENDS the remaining budget (ordered-fill), arming
    the spent-budget read-stop."""
    nul = window.find(b"\x00")
    if nul < 0:
        raw = window[:_MAX_TABLE_NAME_BYTES]
        caps.add(marker_prefix + "_truncated")
    else:
        raw = window[:nul]
    if len(raw) > budget.remaining:
        caps.add(marker_prefix + "_budget_exhausted")
        # Ordered-fill: the FIRST overdraw spends the whole
        # budget. Leaving the remainder unspent would park it just
        # under one name stride, and the spent-budget read-stop
        # (which fires only at remaining <= 0) could then never
        # engage except on an exact drain — inert exactly on the
        # max-shape tables it exists for. Real images never come
        # near the budget, and a hostile image controls its own
        # name order, so which names survive an overdraw was
        # attacker-chosen either way — zeroing arms the read-stop
        # without changing any honest outcome.
        budget.remaining = 0
        return None
    budget.remaining -= len(raw)
    return raw.decode("utf-8", errors="replace")


def _read_table_string(
    f: BinaryIO, resolver: _RvaResolver, rva: int, budget: _Budget,
    caps: set[str], marker_prefix: str,
) -> str | None:
    """One NUL-terminated string at ``rva`` through the chokepoint
    — ``None`` + ``<prefix>_unreadable`` when the RVA is unmapped
    or its raw bytes are truncated; otherwise the
    :func:`_take_cstring` contract."""
    if budget.remaining <= 0:
        # A spent retention budget stops the READ, not just the
        # retention: with the record full, issuing more window
        # reads only sells chokepoint work to a max-shape table.
        caps.add(marker_prefix + "_budget_exhausted")
        return None
    window = resolver.read(f, rva, _MAX_TABLE_NAME_BYTES + 1)
    if not window:
        caps.add(marker_prefix + "_unreadable")
        return None
    return _take_cstring(window, budget, caps, marker_prefix)


def _walk_thunk_array(
    f: BinaryIO, resolver: _RvaResolver, thunk_va: int, bits: int,
    dll_caps: set[str], name_budget: _Budget, thunk_budget: _Budget,
    marker_prefix: str,
) -> tuple[list[PeImportedFunction], int, int]:
    """Walk one null-terminated thunk array (an import name table).

    Thunk width and ordinal-flag bit come from ``bits`` — i.e.
    from the optional-header magic, per format (see
    ``_THUNK_STRUCTS`` / ``_ORDINAL_FLAGS``). The walk ends at the
    first zero thunk; note the zero-fill rule (resolver invariant
    a) hands an array whose raw bytes end before its terminator a
    zero terminator for free — exactly what the loader maps — so
    ``<prefix>_thunks_unterminated`` fires only when the array
    runs out its section's VIRTUAL extent (or was unmapped),
    which no loadable image does. The slot AT the per-DLL cap may
    only hold the terminator: a full-cap array with its
    terminator right behind is complete, one more real thunk is a
    ``<prefix>_thunks_capped`` breach.

    Returns ``(functions, named_count, ordinal_count)``.
    """
    functions: list[PeImportedFunction] = []
    named = 0
    ordinals = 0
    thunk_struct = _THUNK_STRUCTS[bits]
    flag = _ORDINAL_FLAGS[bits]
    width = thunk_struct.size
    for i in range(_MAX_IMPORT_THUNKS_PER_DLL + 1):
        raw = resolver.read(f, thunk_va + i * width, width)
        if raw is None or len(raw) < width:
            dll_caps.add(marker_prefix + "_thunks_unterminated")
            break
        (value,) = thunk_struct.unpack(raw)
        if value == 0:
            break                    # null terminator — clean end
        if i == _MAX_IMPORT_THUNKS_PER_DLL:
            dll_caps.add(marker_prefix + "_thunks_capped")
            break
        if thunk_budget.remaining <= 0:
            dll_caps.add(marker_prefix + "_thunk_budget_exhausted")
            break
        thunk_budget.remaining -= 1
        if value & flag:
            # Ordinal import: bits 15:0 are the ordinal by spec;
            # the bits between them and the flag are ignored by
            # masking (fail open, same posture as the RVA mask).
            functions.append(
                PeImportedFunction(ordinal=value & 0xFFFF))
            ordinals += 1
            continue
        hint: int | None = None
        name: str | None = None
        if name_budget.remaining <= 0:
            # Spent retention budget: the hint/name entry read is
            # skipped entirely (same posture as
            # _read_table_string) — the thunk is recorded
            # shape-degraded and the counts stay honest.
            dll_caps.add(marker_prefix + "_name_budget_exhausted")
        else:
            entry = resolver.read(f, value & _THUNK_RVA_MASK,
                                  2 + _MAX_TABLE_NAME_BYTES + 1)
            if entry is None or len(entry) < 2:
                dll_caps.add(marker_prefix + "_name_unreadable")
            else:
                (hint,) = struct.unpack_from("<H", entry)
                name = _take_cstring(entry[2:], name_budget,
                                     dll_caps,
                                     marker_prefix + "_name")
        functions.append(PeImportedFunction(name=name, hint=hint))
        if name is not None:
            named += 1
    return functions, named, ordinals


def _read_imports(
    f: BinaryIO, resolver: _RvaResolver, import_va: int,
    facts: PeFacts, caps: set[str], name_budget: _Budget,
    thunk_budget: _Budget,
) -> None:
    """Walk the import-descriptor array.

    The directory SIZE is deliberately not a walk budget — it is
    an attacker u32 that real linkers already disagree about, so
    the walk is bounded by the array's own terminator plus the
    named caps, and an under- or over-claimed size steers nothing.
    Termination mirrors the Windows loader: a descriptor with
    ``Name == 0`` or ``FirstThunk == 0`` ends the walk (the loader
    stops there too, so descriptors behind such an entry never
    load); a terminating descriptor whose other fields are nonzero
    is surfaced as ``import_terminator_nonzero`` — doctored dead
    claims end the walk, but never silently. The slot AT the
    descriptor cap may only hold the terminator (cap descriptors
    + terminator = complete; one more is a breach).

    ``OriginalFirstThunk`` is the import name table; some linkers
    (old Borland, hand-crafted stubs) emit ``OFT == 0``, in which
    case the loader — and therefore this walk — reads the
    hint/name RVAs from ``FirstThunk``, which holds the same
    values on disk and is only overwritten with resolved addresses
    at load time. ``used_first_thunk`` records that fallback.
    """
    for i in range(_MAX_IMPORT_DESCRIPTORS + 1):
        raw = resolver.read(f, import_va + i * _IMPORT_DESCRIPTOR.size,
                            _IMPORT_DESCRIPTOR.size)
        if raw is None or len(raw) < _IMPORT_DESCRIPTOR.size:
            caps.add("import_directory_unreadable")
            break
        (oft, _ts, _fwd_chain, name_rva,
         ft) = _IMPORT_DESCRIPTOR.unpack(raw)
        if name_rva == 0 or ft == 0:
            if raw != b"\x00" * _IMPORT_DESCRIPTOR.size:
                caps.add("import_terminator_nonzero")
            break
        if i == _MAX_IMPORT_DESCRIPTORS:
            caps.add("import_descriptors_capped")
            break
        dll_caps: set[str] = set()
        name = _read_table_string(f, resolver, name_rva, name_budget,
                                  dll_caps, "import_dll_name")
        functions, named, ordinals = _walk_thunk_array(
            f, resolver, oft if oft else ft, facts.bits, dll_caps,
            name_budget, thunk_budget, "import")
        facts.imports.append(PeImportedDll(
            name=name,
            functions=functions,
            thunk_count=len(functions),
            named_count=named,
            ordinal_count=ordinals,
            used_first_thunk=(oft == 0),
            caps_hit=sorted(dll_caps),
        ))
        caps |= dll_caps


def _read_delay_imports(
    f: BinaryIO, resolver: _RvaResolver, delay_va: int,
    facts: PeFacts, caps: set[str], name_budget: _Budget,
    thunk_budget: _Budget,
) -> None:
    """Walk the delay-load descriptor array (ImgDelayDescr).

    Same walk doctrine as :func:`_read_imports` (size never a
    budget; zero-DllName terminates, nonzero remainder marked;
    the slot at the cap may only terminate). Only the all-RVA
    form (attribute bit 0 set) is walked; the legacy all-VA form
    is recorded + marked, never chased (see
    :class:`PeDelayImportedDll`). The function walk reads the
    import NAME table (``ImportNameTableRVA``) — the delay IAT
    holds loader-stub addresses, not names, even on disk.
    """
    for i in range(_MAX_DELAY_DESCRIPTORS + 1):
        raw = resolver.read(f, delay_va + i * _DELAY_DESCRIPTOR.size,
                            _DELAY_DESCRIPTOR.size)
        if raw is None or len(raw) < _DELAY_DESCRIPTOR.size:
            caps.add("delay_import_directory_unreadable")
            break
        (attributes, name_rva, _hmod, _iat, int_rva, _bound,
         _unload, _ts) = _DELAY_DESCRIPTOR.unpack(raw)
        if name_rva == 0:
            if raw != b"\x00" * _DELAY_DESCRIPTOR.size:
                caps.add("delay_import_terminator_nonzero")
            break
        if i == _MAX_DELAY_DESCRIPTORS:
            caps.add("delay_import_descriptors_capped")
            break
        dll_caps: set[str] = set()
        if not attributes & _DELAY_ATTR_RVA:
            dll_caps.add("delay_import_va_form")
            facts.delay_imports.append(PeDelayImportedDll(
                name=None,
                attributes=attributes,
                rva_addressed=False,
                caps_hit=sorted(dll_caps),
            ))
            caps |= dll_caps
            continue
        name = _read_table_string(f, resolver, name_rva, name_budget,
                                  dll_caps, "delay_import_dll_name")
        functions: list[PeImportedFunction] = []
        named = 0
        ordinals = 0
        if int_rva:
            functions, named, ordinals = _walk_thunk_array(
                f, resolver, int_rva, facts.bits, dll_caps,
                name_budget, thunk_budget, "delay_import")
        facts.delay_imports.append(PeDelayImportedDll(
            name=name,
            attributes=attributes,
            rva_addressed=True,
            functions=functions,
            thunk_count=len(functions),
            named_count=named,
            ordinal_count=ordinals,
            caps_hit=sorted(dll_caps),
        ))
        caps |= dll_caps


# ---------------------------------------------------------------------------
# Export table
# ---------------------------------------------------------------------------


def _read_slot_array(
    f: BinaryIO, resolver: _RvaResolver, rva: int, count: int,
    width: int, caps: set[str], marker: str,
) -> list[int]:
    """Bulk-read ``count`` little-endian slots of ``width`` bytes
    through the chokepoint — ONE bounded read (``count`` is already
    capped by the caller, invariant e). A short or refused read
    keeps the parsed PREFIX and marks ``<marker>_unreadable``: the
    walk degrades to what the section really holds, never invents
    slots."""
    if count <= 0:
        return []
    raw = resolver.read(f, rva, count * width)
    if raw is None:
        caps.add(marker + "_unreadable")
        return []
    n = len(raw) // width
    if n < count:
        caps.add(marker + "_unreadable")
    fmt = "<%d%s" % (n, "I" if width == 4 else "H")
    return list(struct.unpack(fmt, raw[:n * width]))


def _read_exports(
    f: BinaryIO, resolver: _RvaResolver, export_va: int,
    export_size: int, facts: PeFacts, caps: set[str],
    name_budget: _Budget,
) -> None:
    """Walk the export directory into a :class:`PeExports` record.

    Declared counts are recorded verbatim and walked only up to
    the named caps (invariant e). A function slot whose value
    lands inside the export directory's claimed extent
    ``[export_va, export_va + export_size)`` is a FORWARDER by
    format definition — captured as a capped literal string,
    never resolved (invariant g); the extent test uses the
    directory's own claimed size because that is exactly the rule
    the loader applies, and both operands are recorded facts.

    Table oddities stay record-visible, never fatal:
    ``export_names_exceed_functions`` (NumberOfNames > Number-
    OfFunctions — an OBSERVATION, not a proven malformation: name
    aliasing onto shared ordinals keeps such a table loadable, but
    no standard linker emits the shape), ``export_ordinal_out_of_
    range`` (an ordinal-table index past the walked function array
    — the name is recorded address-less), ``export_name_rva_zero``
    (a zero AddressOfNames slot names nothing; reading RVA 0
    through the header-region rule would fabricate DOS-stub text
    as a "name"), ``export_ordinal_overflow`` (``ordinal_base +
    index`` past the u32 range consumers may assume — masked into
    range, marker keeps it honest), and per-array ``*_unreadable``
    markers. Zero function slots are unused ordinals (real tables
    carry gaps) — skipped as absence, not marked.
    """
    raw = resolver.read(f, export_va, _EXPORT_DIRECTORY.size)
    if raw is None or len(raw) < _EXPORT_DIRECTORY.size:
        caps.add("export_directory_unreadable")
        return
    (_chars, _ts, _major, _minor, name_rva, base, n_funcs,
     n_names, funcs_rva, names_rva,
     ords_rva) = _EXPORT_DIRECTORY.unpack(raw)
    ecaps: set[str] = set()
    exp = PeExports(
        ordinal_base=base,
        declared_function_count=n_funcs,
        declared_name_count=n_names,
    )
    if name_rva:
        exp.dll_name = _read_table_string(
            f, resolver, name_rva, name_budget, ecaps,
            "export_dll_name")
    if n_names > n_funcs:
        ecaps.add("export_names_exceed_functions")
    walk_funcs = n_funcs
    if walk_funcs > _MAX_EXPORT_FUNCTIONS:
        walk_funcs = _MAX_EXPORT_FUNCTIONS
        ecaps.add("export_functions_capped")
    walk_names = n_names
    if walk_names > _MAX_EXPORT_NAMES:
        walk_names = _MAX_EXPORT_NAMES
        ecaps.add("export_names_capped")

    funcs = _read_slot_array(f, resolver, funcs_rva, walk_funcs, 4,
                             ecaps, "export_functions")
    names = _read_slot_array(f, resolver, names_rva, walk_names, 4,
                             ecaps, "export_names_table")
    ords = _read_slot_array(f, resolver, ords_rva, walk_names, 2,
                            ecaps, "export_ordinals")

    def _forwarder_text(rva: int) -> str | None:
        if not export_va <= rva < export_va + export_size:
            return None
        text = _read_table_string(f, resolver, rva, name_budget,
                                  ecaps, "export_forwarder")
        if text is not None:
            # forwarder_count counts CAPTURED forwarder literals —
            # strings actually on the record — so the count can
            # never disagree with the record's contents. A
            # forwarder-SHAPED slot whose string was unreadable or
            # budget-dropped leaves its marker instead (and its
            # directory-extent classification stays recomputable
            # from the recorded rva + the directory facts).
            exp.forwarder_count += 1
        return text

    def _biased_ordinal(idx: int) -> int:
        # ordinal_base is an attacker u32; base + index can leave
        # the u32 range consumers may assume for an export
        # ordinal. Masked into range + marked — in-range field,
        # honest record.
        value = base + idx
        if value > 0xFFFF_FFFF:
            ecaps.add("export_ordinal_overflow")
            value &= 0xFFFF_FFFF
        return value

    consumed: set[int] = set()
    for i in range(min(len(names), len(ords))):
        if names[i] == 0:
            # A zero AddressOfNames slot names nothing; resolving
            # RVA 0 through the header-region rule would fabricate
            # DOS-stub bytes as a "name" — marked absence instead.
            ecaps.add("export_name_rva_zero")
            sym_name = None
        else:
            sym_name = _read_table_string(f, resolver, names[i],
                                          name_budget, ecaps,
                                          "export_name")
        idx = ords[i]
        if idx >= len(funcs):
            ecaps.add("export_ordinal_out_of_range")
            exp.named.append(PeExportedSymbol(
                ordinal=_biased_ordinal(idx), rva=None,
                name=sym_name))
            continue
        consumed.add(idx)
        exp.named.append(PeExportedSymbol(
            ordinal=_biased_ordinal(idx), rva=funcs[idx],
            name=sym_name, forwarder=_forwarder_text(funcs[idx])))
    for idx, slot in enumerate(funcs):
        if idx in consumed or slot == 0:
            continue
        exp.ordinal_only.append(PeExportedSymbol(
            ordinal=_biased_ordinal(idx), rva=slot,
            forwarder=_forwarder_text(slot)))
    exp.walked_function_count = len(funcs)
    exp.walked_name_count = min(len(names), len(ords))
    exp.caps_hit = sorted(ecaps)
    caps |= ecaps
    facts.exports = exp


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
    "PeDelayImportedDll",
    "PeExportedSymbol",
    "PeExports",
    "PeFacts",
    "PeImportedDll",
    "PeImportedFunction",
    "PeSection",
    "canonical_pe_identity",
    "canonical_pe_identity_from_guid_string",
    "extract_pe_facts",
    "is_pe",
    "pe_facts_evidence",
]

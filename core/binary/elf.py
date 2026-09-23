"""Native ELF parser — tier 0 of the binary substrate.

Stdlib-only (``struct``) parser of the ELF dynamic-import table.
Sub-millisecond on typical binaries; no radare2 / r2pipe / lief
dependency. Used by :mod:`core.binary.fingerprint` as the
preferred path for Linux ELF binaries; falls back to the tier-1
radare2 path for PE / Mach-O / cross-reference analysis.

Two entry points share the parsing substrate:

- :func:`parse_elf` — the CAPABILITY parse: minimal metadata plus the
  dynamic-import set that feeds :mod:`core.binary.fingerprint`.
- :func:`extract_elf_facts` — the shallow-FACTS parse for
  inventory / triage consumers: linkage (``DT_NEEDED`` /
  ``DT_SONAME``), identity (build-id, ``.gnu_debuglink``),
  dynamic-symbol exports, per-section entropy numbers, and
  ``PT_INTERP`` presence.

Scope (parse_elf)
- ELF32 + ELF64
- Little- and big-endian
- Linux + BSD + bare-metal ABIs (we don't filter by OSABI)
- Imports = entries in ``.dynsym`` whose section index is
  ``SHN_UNDEF`` (i.e. unresolved at link time, satisfied by the
  dynamic linker — exactly what ``radare2 iij`` calls "imports")

Out of scope
- ``.symtab`` static symbols (not relevant for capability surface)
- ``DT_NEEDED`` library names for the CAPABILITY parse: linkage names
  answer "what does this link against", not "what symbols can it
  call" — folding them into :class:`ElfMetadata` would churn
  capability fingerprints on library renames that change no symbol.
  The linkage question is answered by the separate
  :func:`extract_elf_facts` record instead, so each consumer pays
  only for the parse it needs.
- Cross-references / call graph (radare2's territory)
- Mach-O / PE (different format; fall back to radare2)

Error handling
Every parse failure returns ``None``. The parser is intentionally
defensive — corrupt / truncated / non-ELF inputs return cleanly
because we run against operator-supplied bytes which may come
from misconfigured registries, mislabelled files, etc.
:func:`extract_elf_facts` shares that outer contract and adds
per-field degradation: a malformed SUB-structure empties only the
affected field and records a marker in ``ElfFacts.caps_hit``.
"""

from __future__ import annotations

import logging
import math
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


# ELF magic — first 4 bytes of any valid ELF file
_ELF_MAGIC = b"\x7fELF"

# EI_CLASS values
_ELFCLASS32 = 1
_ELFCLASS64 = 2

# EI_DATA values
_ELFDATA2LSB = 1
_ELFDATA2MSB = 2

# Section types
_SHT_PROGBITS = 1
_SHT_SYMTAB = 2
_SHT_STRTAB = 3
_SHT_DYNAMIC = 6
_SHT_NOBITS = 8
_SHT_DYNSYM = 11

# Program header types
_PT_DYNAMIC = 2
_PT_INTERP = 3

# Dynamic-section entry tags (facts extractor)
_DT_NULL = 0
_DT_NEEDED = 1
_DT_SONAME = 14

# Symbol bindings (st_info >> 4). STB_GNU_UNIQUE is the GNU
# vague-linkage binding every g++-built library uses for inline-static
# and template-static definitions (nm's ``u`` set) — real, externally
# visible exports that a GLOBAL/WEAK-only filter silently drops.
_STB_GLOBAL = 1
_STB_WEAK = 2
_STB_GNU_UNIQUE = 10
_EXPORT_BINDINGS = (_STB_GLOBAL, _STB_WEAK, _STB_GNU_UNIQUE)

# Symbol type (st_info & 0xF) → ``export_types`` value. Upper-cased
# short names match the radare2 ``iEj`` vocabulary the manifest layer
# already carries (``export_types`` on the binary manifest / context
# map in ``packages.binary_analysis``), so facts records join without
# translation. Values outside the map are ABSENT from the dict —
# consumers fail open (unknown = callable), mirroring the ingress
# demotion policy: the type byte is attacker-controlled, so an
# unmappable type must never hide an export.
_STT_EXPORT_TYPE = {
    0: "NOTYPE",
    1: "OBJ",
    2: "FUNC",
    3: "SECTION",
    4: "FILE",
    5: "COMMON",
    6: "TLS",
    10: "IFUNC",   # STT_GNU_IFUNC — callable through its resolver
}

# Symbol section index — SHN_UNDEF means "imported"
_SHN_UNDEF = 0
_SHN_LORESERVE = 0xFF00

# e_machine → arch FAMILY string. Convention matches radare2
# (``r2 ij`` reports bin.arch as the family with bits as a
# separate field), so fingerprints produced by the native ELF
# tier and by the radare2 tier are bit-compatible:
#   * EM_386 → arch="x86" bits=32  (i386)
#   * EM_X86_64 → arch="x86" bits=64  (x86_64)
#   * EM_ARM → arch="arm" bits=32
#   * EM_AARCH64 → arch="arm" bits=64
# Combined ``(arch, bits)`` tuple uniquely identifies the
# instruction set. Unknown e_machine values fall through to
# ``"unknown"``.
_MACHINE_ARCH = {
    0x03: "x86",      # EM_386
    0x28: "arm",      # EM_ARM
    0x3E: "x86",      # EM_X86_64
    0xB7: "arm",      # EM_AARCH64
    0xF3: "riscv",
    0x14: "ppc",
    0x15: "ppc",      # EM_PPC64 — same family, bits=64 disambiguates
    0x16: "s390",
    0x08: "mips",
    0x0A: "mips",     # EM_MIPS_RS3_LE — same family, endian differs
}

# Sanity caps on field values. ELF spec doesn't bound these but
# real-world binaries stay well under; treating anything outside
# as malformed defends against pathological / hostile inputs.
_MAX_SHNUM = 100_000
_MAX_DYNSYM_ENTRIES = 1_000_000
_MAX_SHSTRNDX_BOUND = 100_000
# Real .dynsym entries are 24 (ELF64) / 16 (ELF32) bytes. sh_entsize
# is a 64-bit field in ELF64, so a hostile value would otherwise
# drive a per-entry padding read of up to ~2**64 bytes (MemoryError).
_MAX_SYM_ENTSIZE = 4096
# Longest string a strtab lookup will materialise. Real symbol names
# top out around a few KB (deeply nested C++ template manglings);
# anything longer — or a name with NO NUL terminator inside the
# window — is malformed. Without this bound a crafted .dynstr
# containing no NUL byte makes every st_name lookup retain a whole
# distinct tail-suffix of the section (~O(entries x section_size)
# total: unbounded memory amplification from a small file, and
# MemoryError is deliberately NOT in parse_elf's malformed-input
# except set).
_MAX_STRTAB_NAME_BYTES = 4096
# Total name bytes one binary's import walk may retain. Generous —
# real binaries stay under a few hundred KB of import names — while
# keeping the worst crafted case (every entry at the per-name cap)
# bounded. On breach the walk stops LOUDLY: the capability
# fingerprint for such a binary would be junk either way, so the
# analysis gap is surfaced, never silent.
_MAX_TOTAL_NAME_BYTES = 8 * 1024 * 1024
# ---- Facts-extractor caps. Every breach is surfaced in
# ``ElfFacts.caps_hit`` — bounded AND honest, never silently partial.
#
# Dynamic-section walk bound. Real ``.dynamic`` tables hold tens of
# entries, but sh_size is attacker-chosen: without a bound a crafted
# header buys a ~sh_size/entsize entry walk. Lower would truncate no
# real binary yet leaves headroom pointless; higher just sells CPU to
# hostile files — 100k is ~3 orders above anything real while keeping
# the worst walk sub-second.
_MAX_DYN_ENTRIES = 100_000
# Retained DT_NEEDED names. Plugin-heavy real binaries reach ~100+
# NEEDED entries, so a low cap would drop genuine linkage facts; a
# high cap lets a crafted table fan the record (4096 names x the 4 KB
# per-name cap already bounds worst-case retention at ~16 MB).
_MAX_NEEDED_ENTRIES = 4_096
# Per-section entropy sample window. Entropy is measured over the
# section's LEADING bytes: representative for the compressed /
# encrypted / code question consumers ask, while an attacker padding
# one section to gigabytes cannot turn a shallow facts pass into a
# whole-file read. Larger sharpens the figure on huge sections but
# re-opens the IO amplification; smaller invites a crafted
# low-entropy prefix masking a high-entropy body — at 4 MiB that
# decoy prefix costs the attacker real file size, and ``sampled`` on
# the record tells the consumer exactly what was measured.
_MAX_ENTROPY_SECTION_BYTES = 4 * 1024 * 1024
# Whole-walk entropy IO budget. Bounds total read volume when a
# hostile file carries MANY large sections (each individually under
# the window above). Lower loses tail-section facts on legitimately
# huge binaries; higher re-opens the aggregate-IO amplification the
# per-section window closed.
_MAX_ENTROPY_TOTAL_BYTES = 64 * 1024 * 1024
# Per-section entropy records retained. Real binaries have <40
# sections; e_shnum is attacker-chosen up to _MAX_SHNUM, and a record
# per header would hand a crafted file a 100k-row artifact. Low
# enough to bound the record, high enough that no real binary is
# ever truncated.
_MAX_ENTROPY_SECTIONS = 2_048
# Section-name BYTES retained per entropy record (counted on the
# UTF-8 encoding — what is actually retained — so a multibyte name
# can't dodge the bound). Real names are <32 bytes; the general
# strtab lookup tolerates up to 4 KB (needed for C++ mangled
# SYMBOLS), and letting each of the 2048 records retain 4 KB of
# attacker text would make the record itself the amplifier. Names
# are hostile text either way — consumers escape at render.
_MAX_SECTION_RECORD_NAME = 256
# ``.gnu_debuglink`` payload read bound (NUL-terminated filename +
# alignment padding + CRC32 — real payloads are tens of bytes;
# anything past this is malformed).
_MAX_DEBUGLINK_BYTES = 4_096
# f.seek() rejects offsets past off_t range with ValueError /
# OverflowError, and Linux read() at offsets in roughly the last page
# BELOW 2**63 fails with OSError EINVAL even though the seek itself
# succeeded — so a screen at exactly the off_t ceiling still lets a
# crafted sh_offset (e.g. 2**63 - 1) raise out of a screened read.
# parse_elf treats all of that as whole-parse malformation; the facts
# extractor degrades PER FIELD, so hostile offsets are screened
# before any seek at a bound safely distant from BOTH the off_t
# ceiling and any real file size (2**62 = 4 EiB; largest real
# filesystems top out well under it), and the screened reads are
# additionally OSError-wrapped as belt-and-braces — a surviving
# kernel refusal degrades that one field, never the whole record.
_MAX_SEEK_OFFSET = 2**62


@dataclass
class ElfMetadata:
    """Minimal ELF metadata + import-symbol list.

    ``imports`` is the set of names from ``.dynsym`` whose
    ``st_shndx == SHN_UNDEF`` — the dynamic-linker-satisfied
    symbols. Order is not preserved (set semantics; consumers
    sort if rendering).

    ``arch`` / ``bits`` / ``binary_format`` mirror the radare2-
    populated fields on :class:`packages.binary_analysis.
    radare2_understand.BinaryContextMap`, so fingerprints
    produced by the ELF tier and by the radare2 tier are
    comparable. ``endianness`` comes from ``EI_DATA`` — it
    distinguishes e.g. mipsel from mips firmware, which share an
    e_machine value.
    """

    arch: str
    bits: int
    binary_format: str = "elf"
    endianness: str = "little"   # "little" | "big" (from EI_DATA)
    imports: set[str] = field(default_factory=set)


def is_elf(path: "Path | str") -> bool:
    """Cheap 4-byte ELF magic check — no subprocess, no full parse.

    ``False`` on any read error: an unreadable file is not a usable
    ELF candidate for any caller (provenance probing, binary-oracle
    auto-detect), so refusal and absence collapse to the same answer.
    """
    try:
        with open(path, "rb") as f:
            return f.read(4) == _ELF_MAGIC
    except OSError:
        return False


def parse_elf(path: Path) -> ElfMetadata | None:
    """Parse ``path`` as ELF and return its capability-relevant
    metadata, or ``None`` on any read / parse failure.

    Reads only the bytes it needs (header + section headers +
    .dynsym + .dynstr); does not load the whole binary into
    memory.
    """
    try:
        with Path(path).open("rb") as f:
            return _parse_elf_stream(f)
    except OSError as e:
        logger.debug("core.binary.elf: read failed for %s: %s", path, e)
        return None
    except struct.error as e:
        logger.debug("core.binary.elf: truncated / malformed %s: %s",
                     path, e)
        return None
    except (ValueError, OverflowError) as e:
        # f.seek() rejects offsets that don't fit a C off_t
        # (e_shoff / sh_offset >= 2**63 in a crafted header) with
        # ValueError or OverflowError depending on the io layer —
        # same "malformed input" contract as struct.error.
        logger.debug("core.binary.elf: pathological offsets in %s: %s",
                     path, e)
        return None


@dataclass(frozen=True)
class _ElfHeader:
    """Decoded fixed ELF header fields — one header decoder shared by
    the capability parse and the facts extractor."""

    bits: int
    endian: str        # struct byte-order prefix: "<" | ">"
    endianness: str    # "little" | "big"
    e_machine: int
    e_phoff: int
    e_phentsize: int
    e_phnum: int
    e_shoff: int
    e_shentsize: int
    e_shnum: int
    e_shstrndx: int


def _read_elf_header(f) -> _ElfHeader | None:
    # --- e_ident (first 16 bytes) -----------------------------
    e_ident = f.read(16)
    if len(e_ident) < 16 or e_ident[:4] != _ELF_MAGIC:
        return None
    ei_class = e_ident[4]
    ei_data = e_ident[5]
    if ei_class not in (_ELFCLASS32, _ELFCLASS64):
        return None
    if ei_data not in (_ELFDATA2LSB, _ELFDATA2MSB):
        return None
    bits = 64 if ei_class == _ELFCLASS64 else 32
    endian = "<" if ei_data == _ELFDATA2LSB else ">"
    endianness = "little" if ei_data == _ELFDATA2LSB else "big"

    # --- ELF header (continues after e_ident) -----------------
    # ELF64: HHIQQQIHHHHHH (12-byte preamble + Q for entry/phoff/shoff)
    # ELF32: HHIIIIIHHHHHH
    if bits == 64:
        # e_type(H) e_machine(H) e_version(I) e_entry(Q) e_phoff(Q)
        # e_shoff(Q) e_flags(I) e_ehsize(H) e_phentsize(H) e_phnum(H)
        # e_shentsize(H) e_shnum(H) e_shstrndx(H)
        rest_fmt = endian + "HHIQQQIHHHHHH"
    else:
        rest_fmt = endian + "HHIIIIIHHHHHH"
    rest_size = struct.calcsize(rest_fmt)
    rest = f.read(rest_size)
    if len(rest) < rest_size:
        return None
    (_e_type, e_machine, _e_version, _e_entry, e_phoff,
     e_shoff, _e_flags, _e_ehsize, e_phentsize, e_phnum,
     e_shentsize, e_shnum, e_shstrndx) = struct.unpack(
        rest_fmt, rest,
    )
    return _ElfHeader(
        bits=bits, endian=endian, endianness=endianness,
        e_machine=e_machine, e_phoff=e_phoff,
        e_phentsize=e_phentsize, e_phnum=e_phnum,
        e_shoff=e_shoff, e_shentsize=e_shentsize,
        e_shnum=e_shnum, e_shstrndx=e_shstrndx,
    )


def _parse_elf_stream(f) -> ElfMetadata | None:
    hdr = _read_elf_header(f)
    if hdr is None:
        return None
    bits, endian, endianness = hdr.bits, hdr.endian, hdr.endianness
    e_machine, e_phoff = hdr.e_machine, hdr.e_phoff
    e_phentsize, e_phnum = hdr.e_phentsize, hdr.e_phnum
    e_shoff, e_shentsize = hdr.e_shoff, hdr.e_shentsize
    e_shnum, e_shstrndx = hdr.e_shnum, hdr.e_shstrndx

    def _bail() -> ElfMetadata | None:
        """We can't enumerate imports from the section headers.

        When the binary has a PT_DYNAMIC segment it DOES import
        symbols via the dynamic linker — returning header-only
        metadata here would look like a successful parse with
        ``imports=set()``, and the caller's radare2 fallback
        (which reads the dynamic segment without section headers)
        would never engage. A section-header-stripped (sstrip'd)
        binary would then fingerprint as capability-free. Signal
        "needs fallback" with ``None`` instead. Binaries without
        PT_DYNAMIC (static / bare-metal) genuinely have no dynamic
        imports, so header-only metadata is the truthful answer.
        """
        if _has_pt_dynamic(f, e_phoff, e_phentsize, e_phnum,
                           bits=bits, endian=endian):
            return None
        return _bare_metadata(e_machine, bits, endianness)

    if e_shoff == 0 or e_shnum == 0 or e_shnum > _MAX_SHNUM:
        # No section headers — possible (PIE stripped binary)
        # but we can't enumerate imports without them. Bail.
        return _bail()
    if e_shstrndx >= _MAX_SHSTRNDX_BOUND:
        # SHN_XINDEX or similar — would require reading
        # section 0 for the extended index. Not handling.
        return _bail()

    # --- Section header table ----------------------------------
    sections = _read_section_headers(
        f, e_shoff, e_shentsize, e_shnum, bits=bits, endian=endian,
    )
    if sections is None or e_shstrndx >= len(sections):
        return _bail()

    # --- Section-name string table -----------------------------
    shstrtab_section = sections[e_shstrndx]
    shstrtab = _read_section_bytes(f, shstrtab_section)
    if shstrtab is None:
        return _bail()

    # --- Find .dynsym and .dynstr ------------------------------
    # Resolve names inline and retain NOTHING: only .dynsym/.dynstr
    # matter, and keeping a (per-name-capped) string per header let a
    # crafted many-section ELF with a no-NUL shstrtab fan a few KB
    # into ~150 MB of transient allocations (u16 e_shnum x the 4 KB
    # per-name cap). The type filter also skips the lookup entirely
    # for headers that could never match.
    dynsym = None
    dynstr = None
    for sh in sections:
        if (dynsym is None and sh.sh_type == _SHT_DYNSYM
                and _read_strtab_string(shstrtab, sh.sh_name) == ".dynsym"):
            dynsym = sh
        elif (dynstr is None and sh.sh_type == _SHT_STRTAB
                and _read_strtab_string(shstrtab, sh.sh_name) == ".dynstr"):
            dynstr = sh
        if dynsym is not None and dynstr is not None:
            break

    if dynsym is None or dynstr is None:
        # No .dynsym/.dynstr sections. Truly static binaries have
        # no PT_DYNAMIC either → header-only metadata is accurate.
        # A dynamic binary whose sections were doctored away needs
        # the fallback tier (see _bail).
        return _bail()

    # --- Read .dynstr (the symbol-name string table) -----------
    dynstr_bytes = _read_section_bytes(f, dynstr)
    if dynstr_bytes is None:
        return _bail()

    # --- Walk .dynsym entries, collect imports -----------------
    imports = _read_dynsym_imports(
        f, dynsym, dynstr_bytes, bits=bits, endian=endian,
    )

    return ElfMetadata(
        arch=_MACHINE_ARCH.get(e_machine, "unknown"),
        bits=bits,
        binary_format="elf",
        endianness=endianness,
        imports=imports,
    )


# ---------------------------------------------------------------------------
# Section header parsing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _SectionHeader:
    """Fields we care about from an ELF section header. The
    full struct has more (sh_flags, sh_addr, sh_addralign, etc.)
    but they're not relevant for the import-table extraction."""

    sh_name: int          # offset into shstrtab
    sh_type: int
    sh_offset: int
    sh_size: int
    sh_link: int
    sh_entsize: int


def _read_section_headers(
    f, e_shoff: int, e_shentsize: int, e_shnum: int,
    *, bits: int, endian: str,
) -> list[_SectionHeader] | None:
    f.seek(e_shoff)
    out: list[_SectionHeader] = []
    # ELF64 section header: 64 bytes
    # ELF32 section header: 40 bytes
    if bits == 64:
        # sh_name(I) sh_type(I) sh_flags(Q) sh_addr(Q) sh_offset(Q)
        # sh_size(Q) sh_link(I) sh_info(I) sh_addralign(Q) sh_entsize(Q)
        fmt = endian + "IIQQQQIIQQ"
    else:
        fmt = endian + "IIIIIIIIII"
    record_size = struct.calcsize(fmt)
    if e_shentsize < record_size:
        return None
    for _ in range(e_shnum):
        buf = f.read(record_size)
        if len(buf) < record_size:
            return None
        # Field ORDER is identical for ELF32/ELF64 section headers;
        # only the fmt widths (chosen above) differ — one unpack
        # serves both.
        (sh_name, sh_type, _sh_flags, _sh_addr, sh_offset,
         sh_size, sh_link, _sh_info, _sh_align,
         sh_entsize) = struct.unpack(fmt, buf)
        out.append(_SectionHeader(
            sh_name=sh_name, sh_type=sh_type,
            sh_offset=sh_offset, sh_size=sh_size,
            sh_link=sh_link, sh_entsize=sh_entsize,
        ))
        # Skip extra bytes if e_shentsize > record_size (rare;
        # spec allows but no real ELF does this).
        if e_shentsize > record_size:
            f.read(e_shentsize - record_size)
    return out


def _read_section_bytes(f, sh: _SectionHeader) -> bytes | None:
    if sh.sh_size == 0:
        return b""
    # Sanity cap — 256 MB is way larger than any realistic
    # section we'd want to read; bigger usually means malformed.
    if sh.sh_size > 256 * 1024 * 1024:
        return None
    f.seek(sh.sh_offset)
    data = f.read(sh.sh_size)
    if len(data) < sh.sh_size:
        return None
    return data


def _read_strtab_string(strtab: bytes, offset: int) -> str:
    """Read a NUL-terminated string at ``offset`` in ``strtab``.
    Returns ``""`` for any out-of-bounds / malformed input —
    including a string longer than ``_MAX_STRTAB_NAME_BYTES`` or one
    whose NUL terminator is missing (a crafted no-NUL strtab must not
    materialise a whole section tail per lookup)."""
    if offset < 0 or offset >= len(strtab):
        return ""
    end = strtab.find(b"\x00", offset,
                      offset + _MAX_STRTAB_NAME_BYTES + 1)
    if end < 0:
        return ""
    raw = strtab[offset:end]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        # Tolerate non-UTF-8 symbol names — they exist in some
        # binaries built with exotic toolchains. Replace
        # un-decodable bytes; the symbol still matches the
        # taxonomy buckets if it has any printable ASCII core.
        return raw.decode("utf-8", errors="replace")


def _read_dynsym_imports(
    f, dynsym: _SectionHeader, dynstr_bytes: bytes,
    *, bits: int, endian: str,
) -> set[str]:
    """Walk ``.dynsym`` and collect undefined-section symbol
    names (the imports)."""
    if dynsym.sh_entsize == 0 or dynsym.sh_size == 0:
        return set()
    if dynsym.sh_entsize > _MAX_SYM_ENTSIZE:
        # Bounds the per-entry padding read below — sh_entsize is
        # attacker-chosen in a crafted binary.
        return set()
    entries = dynsym.sh_size // dynsym.sh_entsize
    if entries > _MAX_DYNSYM_ENTRIES:
        return set()

    # ELF64 sym: st_name(I) st_info(B) st_other(B) st_shndx(H)
    #           st_value(Q) st_size(Q)  → 24 bytes
    # ELF32 sym: st_name(I) st_value(I) st_size(I) st_info(B)
    #           st_other(B) st_shndx(H) → 16 bytes
    sym_fmt = endian + "IBBHQQ" if bits == 64 else endian + "IIIBBH"
    record_size = struct.calcsize(sym_fmt)
    if dynsym.sh_entsize < record_size:
        return set()

    imports: set[str] = set()
    total_name_bytes = 0
    dropped_malformed = 0
    f.seek(dynsym.sh_offset)
    for _ in range(entries):
        buf = f.read(record_size)
        if len(buf) < record_size:
            break
        if bits == 64:
            (st_name, _st_info, _st_other, st_shndx,
             _st_value, _st_size) = struct.unpack(sym_fmt, buf)
        else:
            (st_name, _st_value, _st_size, _st_info, _st_other,
             st_shndx) = struct.unpack(sym_fmt, buf)
        # Skip padding if entsize > record_size (rare)
        if dynsym.sh_entsize > record_size:
            f.read(dynsym.sh_entsize - record_size)
        # SHN_UNDEF (0) = imported (satisfied by dynamic linker).
        # Everything else is defined in some section of this
        # binary — exported or local.
        if st_shndx != _SHN_UNDEF:
            continue
        if st_name == 0:
            continue
        name = _read_strtab_string(dynstr_bytes, st_name)
        if not name:
            # In-bounds st_name that still produced nothing means the
            # strtab entry was malformed (over-cap / unterminated) —
            # count it so the gap is surfaced once, not per entry.
            if 0 < st_name < len(dynstr_bytes):
                dropped_malformed += 1
            continue
        if name not in imports:
            total_name_bytes += len(name)
            if total_name_bytes > _MAX_TOTAL_NAME_BYTES:
                logger.warning(
                    "core.binary.elf: import-name volume exceeded %d "
                    "bytes — malformed/hostile .dynstr; import list "
                    "truncated at %d names (capability fingerprint "
                    "for this binary is incomplete)",
                    _MAX_TOTAL_NAME_BYTES, len(imports))
                break
            imports.add(name)
    if dropped_malformed:
        logger.warning(
            "core.binary.elf: dropped %d malformed .dynsym name(s) "
            "(unterminated or over %d bytes) — capability fingerprint "
            "for this binary may be incomplete",
            dropped_malformed, _MAX_STRTAB_NAME_BYTES)
    return imports


def _has_pt_dynamic(
    f, e_phoff: int, e_phentsize: int, e_phnum: int,
    *, bits: int, endian: str,
) -> bool:
    """True when the program header table contains a PT_DYNAMIC
    segment — i.e. the binary imports symbols at load time even
    if its section headers are absent or unusable. Malformed tables
    collapse to False here (parse_elf's pre-existing behavior: no
    evidence of PT_DYNAMIC → header-only metadata); the facts
    extractor consumes the tri-state scanner directly so a malformed
    table is a recorded gap instead."""
    return _scan_phdr_for_type(
        f, e_phoff, e_phentsize, e_phnum,
        bits=bits, endian=endian, wanted=_PT_DYNAMIC,
    ) is True


def _scan_phdr_for_type(
    f, e_phoff: int, e_phentsize: int, e_phnum: int,
    *, bits: int, endian: str, wanted: int,
) -> bool | None:
    """Tri-state program-header scan for a segment of type ``wanted``
    (e.g. PT_DYNAMIC for the fallback signal, PT_INTERP for the
    exec-vs-library fact). True/False are EVIDENCE-backed presence /
    absence; ``None`` means the table exists but is malformed or
    truncated — no absence claim is possible, and callers that report
    facts must record the gap rather than read None as "absent".
    A pathological ``e_phoff`` still raises through ``f.seek`` here:
    parse_elf's contract maps that to a whole-parse ``None`` (facts
    callers screen offsets before calling)."""
    if e_phoff == 0 or e_phnum == 0:
        return False              # genuinely no table → no segment
    # ELF64 phdr: p_type(I) p_flags(I) then six Qs → 56 bytes.
    # ELF32 phdr: p_type(I) then seven Is → 32 bytes.
    # Only p_type is needed; it is the first field in both layouts.
    record_size = 56 if bits == 64 else 32
    if e_phentsize < record_size:
        return None
    type_fmt = endian + "I"
    f.seek(e_phoff)
    for _ in range(e_phnum):
        buf = f.read(e_phentsize)
        if len(buf) < record_size:
            return None
        (p_type,) = struct.unpack_from(type_fmt, buf)
        if p_type == wanted:
            return True
    return False


def _bare_metadata(e_machine: int, bits: int, endianness: str) -> ElfMetadata:
    """Return metadata-only result (no imports). Used when the
    section headers are malformed or absent — we can still
    surface arch / bits / endianness / format from the ELF header
    alone."""
    return ElfMetadata(
        arch=_MACHINE_ARCH.get(e_machine, "unknown"),
        bits=bits,
        binary_format="elf",
        endianness=endianness,
        imports=set(),
    )


# ---------------------------------------------------------------------------
# Packer detection (Phase 8 — binary forensic surface)
# ---------------------------------------------------------------------------

# Magic strings each packer drops into the packed binary's header
# region.  ``UPX`` writes its name at file offsets 0x10 / 0x88 in
# the packed-ELF preamble; UPX-NRV (the legacy variant) prepends
# ``$Info: This file is packed with the UPX executable packer``.
# Other packers documented below produce similarly unique strings.
#
# Detection is FIRST-BYTES-ONLY (one read of the leading 4 KB) so
# the check is sub-millisecond and can run on every binary the
# Phase 3 ``binary_in_package`` detector hits.
_PACKER_SIGNATURES: tuple[tuple[str, bytes], ...] = (
    ("upx",        b"UPX!"),
    ("upx",        b"$Info: This file is packed with the UPX"),
    ("aspack",     b"aPLib"),
    ("petite",     b"petite"),
    ("themida",    b"Themida"),
    ("vmprotect",  b"VMProtect"),
    ("mpress",     b"MPRESS"),
    # Generic obfuscator marker.  Multiple commercial-grade
    # protectors drop this string.
    ("enigma",     b"Enigma Protector"),
)


def is_packed(path: Path) -> str | None:
    """Return the detected packer name when ``path``'s leading
    bytes match a known packer signature, otherwise None.

    Reads up to 4 KB from the file.  Errors return None silently —
    a missing / unreadable file is "not packed" for this layer's
    purposes; the caller can do its own existence check if it
    cares.

    Adversarial: a custom packer or unknown variant slips past;
    documented as a limitation.  The signature list grows as new
    packers surface in real packages.  Not in scope: detecting
    arbitrary high-entropy sections (high FP, not deterministic).
    The per-section entropy NUMBERS on :class:`ElfFacts` are raw
    inventory facts for downstream consumers to interpret — they
    deliberately do NOT feed this verdict: wiring them in would
    reinstate the refused heuristic one hop later.  Any future change
    that wants entropy as a packedness signal must amend this
    rationale in both directions, here and at
    :func:`_shannon_entropy`.
    """
    try:
        with Path(path).open("rb") as f:
            head = f.read(4096)
    except OSError:
        return None
    for name, sig in _PACKER_SIGNATURES:
        if sig in head:
            return name
    return None


# ---------------------------------------------------------------------------
# Shallow facts extraction (linkage / identity / layout)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SectionEntropy:
    """Shannon entropy of one section's leading bytes — a raw,
    deterministic FACT (bits per byte, rounded to 4 decimals).

    Interpretation belongs to the consumer; in particular this number
    never feeds :func:`is_packed` (see the recorded refusal of
    entropy-based packedness detection in its docstring).
    ``sampled < size`` means the figure covers the bounded leading
    window only, not the whole section.  ``name`` originates in the
    hostile file — length-capped at capture, escape at render.
    """

    name: str
    size: int      # sh_size as claimed by the section header
    sampled: int   # bytes actually read and measured
    entropy: float


@dataclass
class ElfFacts:
    """Shallow linkage / identity / layout facts for one ELF.

    Complements :class:`ElfMetadata` (the capability parse) without
    changing it — inventory / triage consumers read this record while
    the fingerprint path keeps paying only for the import walk.

    Hostile-input contract: every string field (``needed``,
    ``soname``, ``debuglink``, export names, section names) is
    attacker-controlled text from the parsed file — length-capped at
    capture, NOT escaped here (matching how ``ElfMetadata.imports``
    ships raw decoded names); consumers escape at render before any
    terminal / report / prompt use.  ``caps_hit`` is a sorted list of
    machine-readable markers naming every cap or parse gap that fired
    (empty = complete extraction): truncation is record-visible,
    never silent.
    """

    needed: list[str] = field(default_factory=list)   # DT_NEEDED, link order
    soname: str | None = None                          # DT_SONAME
    build_id: str | None = None                        # lower-case hex
    debuglink: str | None = None                       # .gnu_debuglink name
    exports: list[str] = field(default_factory=list)   # sorted
    # Symbol type per export name (FUNC, OBJ, ...) — same shape and
    # vocabulary as the manifest layer's ``export_types``; names whose
    # st_info type has no mapping are absent (consumers fail open).
    export_types: dict[str, str] = field(default_factory=dict)
    section_entropy: list[SectionEntropy] = field(default_factory=list)
    has_interpreter: bool = False    # PT_INTERP present (exec-vs-lib)
    caps_hit: list[str] = field(default_factory=list)


def extract_elf_facts(path: Path) -> ElfFacts | None:
    """Extract shallow facts from ``path``, or ``None`` when the file
    is not ELF / unreadable — the same malformed-input contract as
    :func:`parse_elf` (never raises past it).  Malformed
    SUB-structures degrade per field: the affected field stays empty
    and a marker lands in ``caps_hit``.

    Reads only the bytes it needs; per-section entropy reads are
    sample-window- and total-budget-bounded.  The build-id comes from
    the shared sandboxed helper (see :func:`_read_build_id`), not a
    second notes parser — ``None`` when that toolchain is
    unavailable.
    """
    try:
        with Path(path).open("rb") as f:
            facts = _extract_facts_stream(f)
    except OSError as e:
        logger.debug("core.binary.elf: facts read failed for %s: %s",
                     path, e)
        return None
    except struct.error as e:
        logger.debug("core.binary.elf: truncated / malformed %s: %s",
                     path, e)
        return None
    except (ValueError, OverflowError) as e:
        logger.debug("core.binary.elf: pathological offsets in %s: %s",
                     path, e)
        return None
    if facts is None:
        return None
    facts.build_id, build_id_gap = _read_build_id(path)
    if build_id_gap is not None:
        facts.caps_hit = sorted({*facts.caps_hit, build_id_gap})
    return facts


def _read_build_id(path: Path) -> tuple[str | None, str | None]:
    """Build-id via ``core.analysis.binary_oracle.read_build_id`` —
    the sandboxed ``readelf -n`` helper the reachability oracle
    already relies on.  One notes parser repo-wide: re-implementing
    ``.note.gnu.build-id`` extraction here would be a second copy of
    an existing judgment.  The import is lazy so this module's import
    surface stays stdlib-only for hot consumers (the sca supply-chain
    scan feeds every ELF in a scanned package through
    :func:`parse_elf` and must never pay for the oracle stack).

    Returns ``(build_id, caps_hit_marker)``.  The value is ``None``
    when the helper or its toolchain is unavailable — the helper
    itself degrades to ``None`` on tool failure or timeout.  On a
    sandbox-refusing host the helper raises ``SandboxSetupError``
    (``BaseException`` by design, catchable only by name): the
    refusal means readelf NEVER EXECUTED over the hostile bytes, so
    degrading to no-build-id here weakens no containment — but the
    gap is a recorded marker, never a silent ``None``.
    """
    try:
        from core.analysis.binary_oracle import read_build_id
        from core.sandbox import SandboxSetupError
    except ImportError:
        return None, None
    try:
        return read_build_id(Path(path)), None
    except SandboxSetupError:
        return None, "build_id_sandbox_refused"


def _read_section_bytes_screened(f, sh: _SectionHeader) -> bytes | None:
    """:func:`_read_section_bytes` behind an offset screen plus an
    OSError net. The unscreened reader lets a pathological
    ``sh_offset`` raise through ``f.seek``/``f.read`` — correct for
    parse_elf (whole-parse ``None``), wrong for the facts extractor,
    whose contract degrades PER FIELD. The except clause is
    belt-and-braces behind the screen: kernels refuse reads at
    offsets the seek accepted (EINVAL near the off_t ceiling), and
    that refusal must cost one field, not the record."""
    if sh.sh_offset > _MAX_SEEK_OFFSET:
        return None
    try:
        return _read_section_bytes(f, sh)
    except OSError:
        return None


def _shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0–8.0), rounded to 4
    decimals.  Pure byte-histogram arithmetic — deterministic for a
    given byte sequence.  This is a measurement primitive only: it
    renders no packed / encrypted verdict, and must not grow one (the
    packedness question is :func:`is_packed`'s, which records a
    deliberate refusal of entropy heuristics — amend both rationales
    together or not at all)."""
    n = len(data)
    if n == 0:
        return 0.0
    entropy = 0.0
    for count in Counter(data).values():
        p = count / n
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def _extract_facts_stream(f) -> ElfFacts | None:
    hdr = _read_elf_header(f)
    if hdr is None:
        return None
    facts = ElfFacts()
    caps: set[str] = set()

    def _finish() -> ElfFacts:
        facts.caps_hit = sorted(caps)
        return facts

    interp_scan: bool | None
    dyn_scan: bool | None
    if hdr.e_phoff > _MAX_SEEK_OFFSET:
        interp_scan = dyn_scan = None
    else:
        try:
            interp_scan = _scan_phdr_for_type(
                f, hdr.e_phoff, hdr.e_phentsize, hdr.e_phnum,
                bits=hdr.bits, endian=hdr.endian, wanted=_PT_INTERP,
            )
            dyn_scan = _scan_phdr_for_type(
                f, hdr.e_phoff, hdr.e_phentsize, hdr.e_phnum,
                bits=hdr.bits, endian=hdr.endian, wanted=_PT_DYNAMIC,
            )
        except OSError:
            interp_scan = dyn_scan = None
    if interp_scan is None or dyn_scan is None:
        # An existing-but-malformed table yields NO absence evidence:
        # both flags stay conservatively False, and the gap is
        # recorded — silently-False flags would also suppress the
        # stripped-dynamic-sections witness below.
        caps.add("phdr_table_unreadable")
    facts.has_interpreter = interp_scan is True
    has_pt_dynamic = dyn_scan is True

    # --- Section header table + name table ---------------------
    sections = None
    if (hdr.e_shoff != 0 and 0 < hdr.e_shnum <= _MAX_SHNUM
            and hdr.e_shstrndx < _MAX_SHSTRNDX_BOUND
            and hdr.e_shoff <= _MAX_SEEK_OFFSET):
        sections = _read_section_headers(
            f, hdr.e_shoff, hdr.e_shentsize, hdr.e_shnum,
            bits=hdr.bits, endian=hdr.endian,
        )
    if sections is None or hdr.e_shstrndx >= len(sections):
        # Header-only facts (interpreter bit) are still truthful;
        # everything section-derived is a recorded gap.
        caps.add("section_headers_unusable")
        return _finish()
    shstrtab = _read_section_bytes_screened(f, sections[hdr.e_shstrndx])
    if shstrtab is None:
        caps.add("shstrtab_unreadable")
        return _finish()

    # --- One section walk: locate + measure --------------------
    # Names resolve inline and are retained only inside bounded
    # records — the many-section no-NUL-shstrtab amplification
    # defense from the import path applies here too.
    dynamic = dynsym = dynstr = debuglink_sh = None
    entropy_records: list[SectionEntropy] = []
    entropy_budget = _MAX_ENTROPY_TOTAL_BYTES
    for sh in sections:
        name = _read_strtab_string(shstrtab, sh.sh_name)
        if dynamic is None and sh.sh_type == _SHT_DYNAMIC:
            # By spec at most one .dynamic per object; matched by
            # type so a doctored name can't hide the linkage facts.
            dynamic = sh
        elif (dynsym is None and sh.sh_type == _SHT_DYNSYM
                and name == ".dynsym"):
            dynsym = sh
        elif (dynstr is None and sh.sh_type == _SHT_STRTAB
                and name == ".dynstr"):
            dynstr = sh
        elif (debuglink_sh is None and sh.sh_type == _SHT_PROGBITS
                and name == ".gnu_debuglink"):
            # Type-filtered on top of the name: a NOBITS decoy named
            # .gnu_debuglink would otherwise get arbitrary aliased
            # file bytes read back as the debug-file name.
            debuglink_sh = sh

        # Entropy fact — every byte-carrying section, bounded.
        if sh.sh_type == _SHT_NOBITS or sh.sh_size == 0:
            continue          # occupies no file bytes
        if len(entropy_records) >= _MAX_ENTROPY_SECTIONS:
            caps.add("entropy_sections_capped")
            continue
        if entropy_budget <= 0:
            caps.add("entropy_budget_exhausted")
            continue
        if sh.sh_offset > _MAX_SEEK_OFFSET:
            caps.add("section_data_unreadable")
            continue
        try:
            f.seek(sh.sh_offset)
            data = f.read(min(sh.sh_size, _MAX_ENTROPY_SECTION_BYTES,
                              entropy_budget))
        except OSError:
            # Belt-and-braces behind the offset screen (see
            # _MAX_SEEK_OFFSET): a kernel read refusal costs this
            # section's record, not the walk.
            caps.add("section_data_unreadable")
            continue
        if not data:
            caps.add("section_data_unreadable")   # offset past EOF
            continue
        entropy_budget -= len(data)
        if not name and 0 < sh.sh_name < len(shstrtab):
            # In-bounds sh_name that resolved to nothing: the name
            # was unterminated or over-cap — the record keeps the
            # empty string but the gap is marked, not silent.
            caps.add("section_name_malformed")
        # The cap counts BYTES (matching what it bounds — retained
        # attacker text), so a multibyte name can't dodge it.
        name_bytes = name.encode("utf-8")
        if len(name_bytes) > _MAX_SECTION_RECORD_NAME:
            name = name_bytes[:_MAX_SECTION_RECORD_NAME].decode(
                "utf-8", errors="replace")
            caps.add("section_name_truncated")
        entropy_records.append(SectionEntropy(
            name=name, size=sh.sh_size, sampled=len(data),
            entropy=_shannon_entropy(data),
        ))
    facts.section_entropy = entropy_records

    # --- Linkage: DT_NEEDED / DT_SONAME ------------------------
    if dynamic is not None:
        # The dynamic table's string table is named by sh_link (the
        # authoritative join); fall back to the .dynstr found by name
        # when sh_link is malformed.
        dyn_strtab_sh = None
        if (0 < dynamic.sh_link < len(sections)
                and sections[dynamic.sh_link].sh_type == _SHT_STRTAB):
            dyn_strtab_sh = sections[dynamic.sh_link]
        elif dynstr is not None:
            dyn_strtab_sh = dynstr
        dyn_strtab = (_read_section_bytes_screened(f, dyn_strtab_sh)
                      if dyn_strtab_sh is not None else None)
        if dyn_strtab is None:
            caps.add("dynamic_strtab_missing")
        else:
            _read_dynamic_linkage(
                f, dynamic, dyn_strtab, facts, caps,
                bits=hdr.bits, endian=hdr.endian,
            )
    elif has_pt_dynamic:
        # PT_DYNAMIC proves this binary links dynamically, yet no
        # .dynamic SECTION header survived — empty needed/soname
        # would otherwise read as a truthful "links nothing". Same
        # witness as the exports branch below.
        caps.add("dynamic_sections_stripped")

    # --- Exports ------------------------------------------------
    if dynsym is not None:
        dynstr_bytes = (_read_section_bytes_screened(f, dynstr)
                        if dynstr is not None else None)
        if dynstr_bytes is None:
            # .dynsym is itself evidence of dynamic linkage: names
            # unrecoverable (absent OR unreadable .dynstr) is a gap
            # whether or not the program headers survived.
            caps.add("dynstr_unreadable")
        else:
            names, types = _read_dynsym_exports(
                f, dynsym, dynstr_bytes, caps,
                bits=hdr.bits, endian=hdr.endian,
            )
            facts.exports = sorted(names)
            facts.export_types = types
    elif has_pt_dynamic:
        # A dynamic binary whose .dynsym/.dynstr sections were
        # doctored away (sstrip shape) DOES export/link — absent
        # sections are a gap here, not a truthful "no dynamic facts"
        # (which is what a static binary's absence means).
        caps.add("dynamic_sections_stripped")

    # --- .gnu_debuglink -----------------------------------------
    if debuglink_sh is not None:
        data = b""
        if (debuglink_sh.sh_size
                and debuglink_sh.sh_offset <= _MAX_SEEK_OFFSET):
            try:
                f.seek(debuglink_sh.sh_offset)
                data = f.read(min(debuglink_sh.sh_size,
                                  _MAX_DEBUGLINK_BYTES))
            except OSError:
                data = b""    # screened-read net: field-local gap
        # Payload: NUL-terminated filename + padding + CRC32. The
        # bounded strtab lookup gives the NUL-scan + name cap for
        # free (empty on unterminated / over-cap payloads).
        name = _read_strtab_string(data, 0)
        if name:
            facts.debuglink = name
        else:
            caps.add("debuglink_malformed")

    return _finish()


def _read_dynamic_linkage(
    f, dynamic: _SectionHeader, strtab: bytes,
    facts: ElfFacts, caps: set[str],
    *, bits: int, endian: str,
) -> None:
    """Walk the ``.dynamic`` entry table into ``facts.needed`` /
    ``facts.soname``.  DT_NEEDED order is preserved (link order is
    itself a fact); duplicate names are kept as the file states them.
    """
    if dynamic.sh_offset > _MAX_SEEK_OFFSET:
        caps.add("dynamic_unreadable")
        return
    # d_tag is signed (Sxword/Sword), d_un unsigned — per spec.
    fmt = endian + ("qQ" if bits == 64 else "iI")
    record_size = struct.calcsize(fmt)
    total = dynamic.sh_size // record_size
    if total > _MAX_DYN_ENTRIES:
        total = _MAX_DYN_ENTRIES
        caps.add("dynamic_entries_capped")
    needed: list[str] = []
    try:
        f.seek(dynamic.sh_offset)
        for _ in range(total):
            buf = f.read(record_size)
            if len(buf) < record_size:
                break
            d_tag, d_val = struct.unpack(fmt, buf)
            if d_tag == _DT_NULL:
                break
            if d_tag == _DT_NEEDED:
                if len(needed) >= _MAX_NEEDED_ENTRIES:
                    caps.add("needed_truncated")
                    continue
                name = _read_strtab_string(strtab, d_val)
                if name:
                    needed.append(name)
                else:
                    caps.add("needed_name_malformed")
            elif d_tag == _DT_SONAME and facts.soname is None:
                # At most one by spec; first wins on a crafted repeat.
                soname = _read_strtab_string(strtab, d_val)
                if soname:
                    facts.soname = soname
                else:
                    caps.add("soname_malformed")
    except OSError:
        # Screened-read net (see _MAX_SEEK_OFFSET): a kernel refusal
        # keeps whatever was walked and records the gap.
        caps.add("dynamic_unreadable")
    facts.needed = needed


def _read_dynsym_exports(
    f, dynsym: _SectionHeader, dynstr_bytes: bytes, caps: set[str],
    *, bits: int, endian: str,
) -> tuple[set[str], dict[str, str]]:
    """Walk ``.dynsym`` and collect DEFINED global/weak symbol names
    (the exports) plus their symbol type.  Deliberate mirror of
    :func:`_read_dynsym_imports` with the section-index filter
    inverted — same entry bounds, same per-name and total-volume
    caps, because it walks the identical hostile table; breaches land
    in ``caps`` instead of only the log."""
    exports: set[str] = set()
    export_types: dict[str, str] = {}
    if dynsym.sh_entsize == 0 or dynsym.sh_size == 0:
        return exports, export_types
    if (dynsym.sh_entsize > _MAX_SYM_ENTSIZE
            or dynsym.sh_offset > _MAX_SEEK_OFFSET):
        caps.add("dynsym_malformed")
        return exports, export_types
    entries = dynsym.sh_size // dynsym.sh_entsize
    if entries > _MAX_DYNSYM_ENTRIES:
        caps.add("dynsym_malformed")
        return exports, export_types

    sym_fmt = endian + "IBBHQQ" if bits == 64 else endian + "IIIBBH"
    record_size = struct.calcsize(sym_fmt)
    if dynsym.sh_entsize < record_size:
        caps.add("dynsym_malformed")
        return exports, export_types

    total_name_bytes = 0
    try:
        f.seek(dynsym.sh_offset)
        for _ in range(entries):
            buf = f.read(record_size)
            if len(buf) < record_size:
                break
            if bits == 64:
                (st_name, st_info, _st_other, st_shndx,
                 _st_value, _st_size) = struct.unpack(sym_fmt, buf)
            else:
                (st_name, _st_value, _st_size, st_info, _st_other,
                 st_shndx) = struct.unpack(sym_fmt, buf)
            if dynsym.sh_entsize > record_size:
                f.read(dynsym.sh_entsize - record_size)
            # Export = defined somewhere in THIS binary (not
            # SHN_UNDEF) with external linkage — GLOBAL, WEAK, or
            # STB_GNU_UNIQUE (g++ vague linkage; dropping it loses
            # real exports on every C++ library). Local symbols are
            # not callable from outside; undefined ones are the
            # import walk's business.
            if st_shndx == _SHN_UNDEF or st_name == 0:
                continue
            if (st_info >> 4) not in _EXPORT_BINDINGS:
                continue
            name = _read_strtab_string(dynstr_bytes, st_name)
            if not name:
                if 0 < st_name < len(dynstr_bytes):
                    caps.add("export_name_malformed")
                continue
            if name not in exports:
                total_name_bytes += len(name)
                if total_name_bytes > _MAX_TOTAL_NAME_BYTES:
                    caps.add("export_names_truncated")
                    logger.warning(
                        "core.binary.elf: export-name volume exceeded "
                        "%d bytes — malformed/hostile .dynstr; export "
                        "list truncated at %d names (facts record for "
                        "this binary is incomplete)",
                        _MAX_TOTAL_NAME_BYTES, len(exports))
                    break
                exports.add(name)
            stt = _STT_EXPORT_TYPE.get(st_info & 0xF)
            if stt is not None:
                # Versioned symbols repeat a name; the first MAPPED
                # type wins (deterministic: .dynsym file order; an
                # earlier unmapped type claims nothing).
                export_types.setdefault(name, stt)
    except OSError:
        # Screened-read net (see _MAX_SEEK_OFFSET): keep the walked
        # prefix, record the gap.
        caps.add("dynsym_malformed")
    return exports, export_types


__all__ = [
    "ElfFacts",
    "ElfMetadata",
    "SectionEntropy",
    "extract_elf_facts",
    "is_packed",
    "parse_elf",
]

"""Native ELF parser — tier 0 of the binary substrate.

Stdlib-only (``struct``) parser of the ELF dynamic-import table.
Sub-millisecond on typical binaries; no radare2 / r2pipe / lief
dependency. Used by :mod:`core.binary.fingerprint` as the
preferred path for Linux ELF binaries; falls back to the tier-1
radare2 path for PE / Mach-O / cross-reference analysis.

Scope
- ELF32 + ELF64
- Little- and big-endian
- Linux + BSD + bare-metal ABIs (we don't filter by OSABI)
- Imports = entries in ``.dynsym`` whose section index is
  ``SHN_UNDEF`` (i.e. unresolved at link time, satisfied by the
  dynamic linker — exactly what ``radare2 iij`` calls "imports")

Out of scope
- ``.symtab`` static symbols (not relevant for capability surface)
- ``DT_NEEDED`` library names (separate question — what does this
  link against, not what symbols does it call)
- Cross-references / call graph (radare2's territory)
- Mach-O / PE (different format; fall back to radare2)

Error handling
Every parse failure returns ``None``. The parser is intentionally
defensive — corrupt / truncated / non-ELF inputs return cleanly
because we run against operator-supplied bytes which may come
from misconfigured registries, mislabelled files, etc.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set, Tuple

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
_SHT_SYMTAB = 2
_SHT_STRTAB = 3
_SHT_DYNSYM = 11

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
    comparable.
    """

    arch: str
    bits: int
    binary_format: str = "elf"
    imports: Set[str] = field(default_factory=set)


def parse_elf(path: Path) -> Optional[ElfMetadata]:
    """Parse ``path`` as ELF and return its capability-relevant
    metadata, or ``None`` on any read / parse failure.

    Reads only the bytes it needs (header + section headers +
    .dynsym + .dynstr); does not load the whole binary into
    memory.
    """
    try:
        with open(path, "rb") as f:
            return _parse_elf_stream(f)
    except OSError as e:
        logger.debug("core.binary.elf: read failed for %s: %s", path, e)
        return None
    except struct.error as e:
        logger.debug("core.binary.elf: truncated / malformed %s: %s",
                     path, e)
        return None


def _parse_elf_stream(f) -> Optional[ElfMetadata]:
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
    (e_type, e_machine, _e_version, _e_entry, _e_phoff,
     e_shoff, _e_flags, _e_ehsize, _e_phentsize, _e_phnum,
     e_shentsize, e_shnum, e_shstrndx) = struct.unpack(
        rest_fmt, rest,
    )

    if e_shoff == 0 or e_shnum == 0 or e_shnum > _MAX_SHNUM:
        # No section headers — possible (PIE stripped binary)
        # but we can't enumerate imports without them. Bail.
        return _bare_metadata(e_machine, bits)
    if e_shstrndx >= _MAX_SHSTRNDX_BOUND:
        # SHN_XINDEX or similar — would require reading
        # section 0 for the extended index. Not handling.
        return _bare_metadata(e_machine, bits)

    # --- Section header table ----------------------------------
    sections = _read_section_headers(
        f, e_shoff, e_shentsize, e_shnum, bits=bits, endian=endian,
    )
    if sections is None or e_shstrndx >= len(sections):
        return _bare_metadata(e_machine, bits)

    # --- Section-name string table -----------------------------
    shstrtab_section = sections[e_shstrndx]
    shstrtab = _read_section_bytes(f, shstrtab_section)
    if shstrtab is None:
        return _bare_metadata(e_machine, bits)

    # Resolve section names so we can find .dynsym + .dynstr
    named_sections: List[Tuple[str, "_SectionHeader"]] = []
    for sh in sections:
        name = _read_strtab_string(shstrtab, sh.sh_name)
        named_sections.append((name, sh))

    # --- Find .dynsym and .dynstr ------------------------------
    dynsym = None
    dynstr = None
    for name, sh in named_sections:
        if name == ".dynsym" and sh.sh_type == _SHT_DYNSYM:
            dynsym = sh
        elif name == ".dynstr" and sh.sh_type == _SHT_STRTAB:
            dynstr = sh

    if dynsym is None or dynstr is None:
        # Static binary or stripped — no dynamic imports.
        # Return metadata without imports.
        return _bare_metadata(e_machine, bits)

    # --- Read .dynstr (the symbol-name string table) -----------
    dynstr_bytes = _read_section_bytes(f, dynstr)
    if dynstr_bytes is None:
        return _bare_metadata(e_machine, bits)

    # --- Walk .dynsym entries, collect imports -----------------
    imports = _read_dynsym_imports(
        f, dynsym, dynstr_bytes, bits=bits, endian=endian,
    )

    return ElfMetadata(
        arch=_MACHINE_ARCH.get(e_machine, "unknown"),
        bits=bits,
        binary_format="elf",
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
) -> Optional[List[_SectionHeader]]:
    f.seek(e_shoff)
    out: List[_SectionHeader] = []
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
        if bits == 64:
            (sh_name, sh_type, _sh_flags, _sh_addr, sh_offset,
             sh_size, sh_link, _sh_info, _sh_align,
             sh_entsize) = struct.unpack(fmt, buf)
        else:
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


def _read_section_bytes(f, sh: _SectionHeader) -> Optional[bytes]:
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
    Returns ``""`` for any out-of-bounds / malformed input."""
    if offset < 0 or offset >= len(strtab):
        return ""
    end = strtab.find(b"\x00", offset)
    if end < 0:
        end = len(strtab)
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
) -> Set[str]:
    """Walk ``.dynsym`` and collect undefined-section symbol
    names (the imports)."""
    if dynsym.sh_entsize == 0 or dynsym.sh_size == 0:
        return set()
    entries = dynsym.sh_size // dynsym.sh_entsize
    if entries > _MAX_DYNSYM_ENTRIES:
        return set()

    # ELF64 sym: st_name(I) st_info(B) st_other(B) st_shndx(H)
    #           st_value(Q) st_size(Q)  → 24 bytes
    # ELF32 sym: st_name(I) st_value(I) st_size(I) st_info(B)
    #           st_other(B) st_shndx(H) → 16 bytes
    if bits == 64:
        sym_fmt = endian + "IBBHQQ"
    else:
        sym_fmt = endian + "IIIBBH"
    record_size = struct.calcsize(sym_fmt)
    if dynsym.sh_entsize < record_size:
        return set()

    imports: Set[str] = set()
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
        if name:
            imports.add(name)
    return imports


def _bare_metadata(e_machine: int, bits: int) -> ElfMetadata:
    """Return metadata-only result (no imports). Used when the
    section headers are malformed or absent — we can still
    surface arch / bits / format from the ELF header alone."""
    return ElfMetadata(
        arch=_MACHINE_ARCH.get(e_machine, "unknown"),
        bits=bits,
        binary_format="elf",
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
_PACKER_SIGNATURES: Tuple[Tuple[str, bytes], ...] = (
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


def is_packed(path: Path) -> Optional[str]:
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
    """
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
    except OSError:
        return None
    for name, sig in _PACKER_SIGNATURES:
        if sig in head:
            return name
    return None


__all__ = [
    "ElfMetadata",
    "is_packed",
    "parse_elf",
]

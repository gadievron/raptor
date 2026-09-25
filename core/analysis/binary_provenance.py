"""Binary fact-provenance probes.

Answers, for one ELF, the questions every name-provenance consumer
needs before trusting a binary-derived fact: does the file carry
debug info, a static symbol table, a dynamic symbol table; what is
its build-id; were the libc string/memory calls compiler-fortified
(``__*_chk`` imports have genuinely different semantics from the
author-level call they replaced)?

Everything here is best-effort and degrades honestly: a missing
``readelf``, a non-ELF path, or a parse failure produce a block whose
``probe`` field says so and whose boolean fields stay ``None`` —
consumers must treat an unprobed binary as unknown, never as any
particular class.

The section probe runs under the full sandbox (same rationale as the
binary-oracle's binutils invocations: BFD parses attacker bytes).
"""

from __future__ import annotations

import logging
import re
import shutil
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from core.binary.elf import is_elf

logger = logging.getLogger(__name__)

# Compiler-fortified libc entry points (``strcpy`` → ``__strcpy_chk``).
_FORTIFIED_IMPORT_RE = re.compile(r"^__\w+_chk(?:@.*)?$")

# ``readelf -S --wide`` section row:  [Nr] Name Type Addr Off Size ...
_SECTION_ROW_RE = re.compile(
    r"^\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+[0-9a-fA-F]+\s+"
    r"([0-9a-fA-F]+)\s+([0-9a-fA-F]+)"
)

# SHF_COMPRESSED section header ch_type values (Elf_Chdr).
_ELFCOMPRESS_TYPES = frozenset({1, 2})  # ZLIB, ZSTD

# DWARF versions with the classic CU header layout this check knows.
_DWARF_VERSIONS = frozenset({2, 3, 4, 5})


def _debug_info_header_sane(
    binary_path: Path,
    offset: int,
    size: int,
    little_endian: bool,
) -> bool:
    """Does ``.debug_info`` START like DWARF (or a compressed section)?

    Section PRESENCE is a single objcopy away — garbage bytes glued
    into both ``.debug_info`` and ``.debug_abbrev`` must not read as
    debug info. Check the leading compilation-unit header: a sane
    DWARF32/64 unit length bounded by the section size and a known
    DWARF version (2–5). ``SHF_COMPRESSED`` sections (``-gz`` builds)
    are accepted on their ``Elf_Chdr`` type tag alone — the payload
    would need decompression to validate, which is the full parser's
    job, and real toolchains emit exactly ZLIB/ZSTD there.

    Deliberately a bar-raiser, not a proof: well-formed forged DWARF
    passes (and must — the tag records what the file claims). Any
    read/parse failure returns False: fail toward NOT-dwarf, the
    direction that can only under-claim.
    """
    if size < 8:
        return False
    try:
        with open(binary_path, "rb") as f:
            f.seek(offset)
            head = f.read(24)
    except OSError:
        return False
    if len(head) < 8:
        return False
    endian = "little" if little_endian else "big"

    # Compressed section: Elf_Chdr.ch_type (always 4 bytes first).
    if int.from_bytes(head[0:4], endian) in _ELFCOMPRESS_TYPES:
        return True

    unit_length = int.from_bytes(head[0:4], endian)
    if unit_length == 0xFFFFFFFF:
        # DWARF64: 12-byte initial length, then version.
        if len(head) < 14:
            return False
        unit_length64 = int.from_bytes(head[4:12], endian)
        if not 0 < unit_length64 <= size - 12:
            return False
        version = int.from_bytes(head[12:14], endian)
    else:
        if not 0 < unit_length <= size - 4:
            return False
        version = int.from_bytes(head[4:6], endian)
    return version in _DWARF_VERSIONS

# Probe results keyed by (resolved path, size, mtime_ns): the checklist
# builder and the audit prep both ask about the same binary.
_probe_cache: Dict[tuple, Dict[str, Any]] = {}
_PROBE_CACHE_MAX = 32


def _is_elf(binary_path: Path) -> bool:
    """Shared magic check — core.binary.elf.is_elf (kept as the
    module-local name callers and patches use)."""
    return is_elf(binary_path)


def probe_binary(binary_path: "Path | str") -> Dict[str, Any]:
    """Probe one ELF for symbol/debug-section presence and build-id.

    Returns::

        {
          "probe": "readelf" | "unavailable" | "not_elf" | "error",
          "build_id": str | None,       # .note.gnu.build-id hex
          "identity_kind": str | None,  # front-door identity kind
                                        # (elf_build_id | macho_uuid |
                                        # pe_guid_age | sha256)
          "identity_value": str | None, # front-door identity value
          "has_dwarf": bool | None,     # non-empty .debug_info AND
                                        # .debug_abbrev, with a sane
                                        # leading CU header
          "has_symtab": bool | None,    # non-empty .symtab
          "has_dynsym": bool | None,    # non-empty .dynsym
          "stripped": bool | None,      # no .symtab
        }

    ``None`` means the probe could not tell — callers must not treat
    an unprobed binary as any particular provenance class.
    ``build_id`` stays the ELF GNU build-id only (the DWARF/symbol
    verdict lane is ELF by design); the ``identity_*`` pair is the
    kind-aware module identity every format gets
    (:func:`core.binary.identity.content_identity`).
    """
    unknown: Dict[str, Any] = {
        "probe": "unavailable",
        "build_id": None,
        "identity_kind": None,
        "identity_value": None,
        "has_dwarf": None,
        "has_symtab": None,
        "has_dynsym": None,
        "stripped": None,
    }

    path = Path(binary_path)
    try:
        st = path.stat()
    except OSError:
        return unknown

    key = (str(path.resolve()), st.st_size, st.st_mtime_ns)
    cached = _probe_cache.get(key)
    if cached is not None:
        return dict(cached)

    if not _is_elf(path):
        # Non-ELF targets still get a kind-aware module identity
        # (PE GUID+age, Mach-O LC_UUID, else the content hash) —
        # cached like the readelf block: the identity probe may hash
        # the whole file.
        block = {**unknown, "probe": "not_elf", **_identity_values(path)}
        _cache_probe(key, block)
        return dict(block)
    if shutil.which("readelf") is None:
        return unknown

    from core.analysis.binary_oracle import _run_status, read_build_id

    out, ok = _run_status(
        ["readelf", "-S", "--wide", str(path)], binary=path,
    )
    if not ok:
        return {**unknown, "probe": "error"}

    # Section presence requires a NON-EMPTY section: a planted
    # zero-size .debug_info must not upgrade symbol names to dwarf.
    sizes: Dict[str, int] = {}
    offsets: Dict[str, int] = {}
    for line in out.splitlines():
        m = _SECTION_ROW_RE.match(line)
        if m:
            try:
                offsets[m.group(1)] = int(m.group(3), 16)
                sizes[m.group(1)] = int(m.group(4), 16)
            except ValueError:
                continue

    # ELF ident byte 5 (EI_DATA): 2 = big-endian, else assume little.
    # A wrong guess can only make the header check FAIL → not-dwarf.
    little_endian = True
    try:
        with open(path, "rb") as f:
            ident = f.read(6)
        if len(ident) == 6 and ident[5] == 2:
            little_endian = False
    except OSError:
        pass

    # Real DWARF ships .debug_abbrev next to .debug_info AND starts
    # with a sane compilation-unit header — presence alone is a
    # single objcopy away for a forger. A file that carries
    # WELL-FORMED forged DWARF still probes true: the tag records
    # what the file claims, never more.
    has_dwarf = (
        sizes.get(".debug_info", 0) > 0
        and sizes.get(".debug_abbrev", 0) > 0
        and _debug_info_header_sane(
            path,
            offsets.get(".debug_info", 0),
            sizes.get(".debug_info", 0),
            little_endian,
        )
    )

    build_id = read_build_id(path)
    result: Dict[str, Any] = {
        "probe": "readelf",
        "build_id": build_id,
        # Front-door-equivalent identity without a second sandboxed
        # readelf spawn: a plausible build-id IS the elf_build_id
        # identity; an ELF without one identifies by content hash.
        **_elf_identity_values(path, build_id),
        "has_dwarf": has_dwarf,
        "has_symtab": sizes.get(".symtab", 0) > 0,
        "has_dynsym": sizes.get(".dynsym", 0) > 0,
        "stripped": sizes.get(".symtab", 0) == 0,
    }

    _cache_probe(key, result)
    return result


def _cache_probe(key: tuple, block: Dict[str, Any]) -> None:
    _probe_cache[key] = dict(block)
    if len(_probe_cache) > _PROBE_CACHE_MAX:
        _probe_cache.pop(next(iter(_probe_cache)))


def _identity_values(path: Path) -> Dict[str, Any]:
    """``identity_kind`` / ``identity_value`` via the front door;
    ``None``s when the file cannot be identified at all."""
    try:
        from core.binary.identity import content_identity
        ident = content_identity(path)
    except Exception:  # noqa: BLE001 — identity is enrichment; the probe block stays honest with Nones
        logger.debug("identity probe failed for %s", path, exc_info=True)
        ident = None
    if ident is None:
        return {"identity_kind": None, "identity_value": None}
    return {"identity_kind": ident.kind, "identity_value": ident.value}


def _elf_identity_values(
    path: Path, build_id: "str | None",
) -> Dict[str, Any]:
    from core.binary.identity import (
        KIND_ELF_BUILD_ID,
        KIND_SHA256,
        identity_anchor,
    )
    if build_id and identity_anchor(KIND_ELF_BUILD_ID, build_id):
        return {
            "identity_kind": KIND_ELF_BUILD_ID,
            "identity_value": build_id.strip().lower(),
        }
    try:
        from core.hash import sha256_file
        value = sha256_file(path)
    except OSError:
        return {"identity_kind": None, "identity_value": None}
    return {"identity_kind": KIND_SHA256, "identity_value": value}


_FORTIFIED_LIST_CAP = 32


def fortified_import_names(import_names: Iterable[str]) -> list:
    """The ``__*_chk`` fortified entry points among *import_names*.

    Bounded: the import table is attacker-authored bytes and this
    list rides into journal records and the build-id cache — a forged
    table with thousands of ``__*_chk`` entries must not bloat them.
    """
    hits = set()
    for name in import_names:
        base = (name or "").split("@")[0]
        if _FORTIFIED_IMPORT_RE.match(base):
            hits.add(base)
    return sorted(hits)[:_FORTIFIED_LIST_CAP]


def binary_provenance_block(
    binary_path: "Path | str | None",
    import_names: Iterable[str] = (),
) -> Dict[str, Any]:
    """Assemble the per-binary provenance block for checklist/journal.

    ``fortified`` comes from the already-imported symbol list (no
    extra tool run); the section facts come from :func:`probe_binary`.
    """
    fortified = fortified_import_names(import_names)
    if binary_path is None:
        block: Dict[str, Any] = {
            "probe": "unavailable",
            "build_id": None,
            "identity_kind": None,
            "identity_value": None,
            "has_dwarf": None,
            "has_symtab": None,
            "has_dynsym": None,
            "stripped": None,
        }
    else:
        block = probe_binary(binary_path)
    block["fortified"] = bool(fortified)
    block["fortified_imports"] = fortified
    return block


def refine_import_provenance(db, binary_path: "Path | str | None" = None) -> int:
    """Split Ghidra's conflated IMPORTED name tag using a section probe.

    The Ghidra export cannot tell debug-info names from symbol-table
    names — the parser provisionally tags IMPORTED as ``symtab``.
    When the analysed binary is reachable, re-tag per the file's
    actual symbol sources:

    - non-empty ``.debug_info`` → ``dwarf`` (per-binary split; on a
      file carrying BOTH debug info and a symbol table the individual
      name's origin is not recoverable from the export — both classes
      grade identically for name-join purposes and the block records
      ``has_symtab`` so a stricter consumer can refuse)
    - else non-empty ``.symtab`` → keep ``symtab``
    - else non-empty ``.dynsym`` → ``dynsym_plt``

    Only functions the Ghidra parser tagged provisionally
    (``source_tool == "ghidra"`` and ``name_provenance == "symtab"``)
    are touched; r2/nm tags are per-name facts and never rewritten.
    Returns the number of functions re-tagged.
    """
    from packages.ghidra.model import (
        NAME_PROVENANCE_DWARF,
        NAME_PROVENANCE_DYNSYM_PLT,
        NAME_PROVENANCE_SYMTAB,
    )

    path: Optional[Path] = None
    for candidate in (binary_path, getattr(db, "binary_path", None)):
        if candidate:
            p = Path(candidate)
            if p.is_file():
                path = p
                break
    if path is None:
        return 0

    probe = probe_binary(path)
    if probe.get("probe") != "readelf":
        return 0

    if probe.get("has_dwarf"):
        new_tag = NAME_PROVENANCE_DWARF
    elif probe.get("has_symtab"):
        new_tag = NAME_PROVENANCE_SYMTAB
    elif probe.get("has_dynsym"):
        new_tag = NAME_PROVENANCE_DYNSYM_PLT
    else:
        # No symbol source at all — the IMPORTED names came from
        # somewhere the probe cannot see (or a hostile mismatch);
        # leave the conservative tag rather than guess upward.
        return 0

    retagged = 0
    for func in getattr(db, "functions", []):
        if (
            func.source_tool == "ghidra"
            and func.name_provenance == NAME_PROVENANCE_SYMTAB
            and new_tag != NAME_PROVENANCE_SYMTAB
        ):
            func.name_provenance = new_tag
            retagged += 1

    if retagged:
        meta = getattr(db, "metadata", None)
        if isinstance(meta, dict):
            meta["name_provenance_probe"] = {
                "probe_path": str(path),
                **{k: probe.get(k) for k in (
                    "build_id", "has_dwarf", "has_symtab", "has_dynsym",
                )},
            }
    return retagged

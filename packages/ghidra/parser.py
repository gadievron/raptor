"""Parse Ghidra export JSON into an REDatabase."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict

from .model import (
    NAME_PROVENANCE_DEMANGLED,
    NAME_PROVENANCE_PATTERN_RECOVERED,
    NAME_PROVENANCE_SYMTAB,
    NAME_PROVENANCE_TOOL_SYNTHETIC,
    REComment,
    REDatabase,
    REFunction,
    RESegment,
    REType,
    REXref,
    looks_tool_synthetic,
    normalise_name_provenance,
)

logger = logging.getLogger(__name__)


def parse_export(path: Path) -> REDatabase:
    """Parse a Ghidra export JSON file into an REDatabase.

    Args:
        path: Path to the JSON file produced by the export script (ExportRaptor.java).

    Returns:
        An REDatabase populated with the Ghidra project data.

    Raises:
        ValueError: If the JSON is malformed or missing required fields.
    """
    # Bounded read at the shared RE-database ceiling: the export is
    # produced by the sandboxed JVM while parsing a HOSTILE binary,
    # which controls the document's size — an unbounded whole-document
    # json.load in the trusted parent is a memory-exhaustion
    # primitive (same artifact family, and same effective budget, as
    # the re-database.json this export becomes).
    from core.json.bounded import load_json_bounded
    from core.json.utils import RE_DATABASE_MAX_BYTES
    try:
        data = load_json_bounded(path, max_bytes=RE_DATABASE_MAX_BYTES)
    except (json.JSONDecodeError, OSError, ValueError) as e:
        raise ValueError(f"failed to read Ghidra export: {e}") from e

    if not isinstance(data, dict):
        raise ValueError("Ghidra export must be a JSON object")

    db = parse_dict(data)

    # Ghidra's IMPORTED source type conflates debug-info and symbol
    # table names; when the original binary is reachable, split the
    # provisional tag with a section probe (best-effort — an absent
    # or non-ELF binary leaves the conservative symtab tag).
    try:
        from core.analysis.binary_provenance import refine_import_provenance
        refine_import_provenance(db)
    except Exception:
        logger.debug("import-provenance refinement failed", exc_info=True)

    return db


def parse_dict(data: Dict[str, Any]) -> REDatabase:
    """Parse a Ghidra export dict into an REDatabase.

    Separated from :func:`parse_export` so tests can pass dicts
    directly without writing JSON files.
    """
    functions = [
        _parse_function(f) for f in data.get("functions", [])
    ]

    xrefs = [
        REXref.from_dict(x) for x in data.get("xrefs", [])
    ]

    types = [
        REType.from_dict(t) for t in data.get("types", [])
    ]

    comments = [
        REComment.from_dict(c) for c in data.get("comments", [])
    ]

    segments = [
        RESegment.from_dict(s) for s in data.get("segments", [])
    ]

    return REDatabase(
        source_tool=str(data.get("source_tool", "ghidra")),
        binary_path=data.get("binary_path"),
        architecture=str(data.get("architecture", "")),
        functions=functions,
        xrefs=xrefs,
        types=types,
        comments=comments,
        segments=segments,
        imports=data.get("imports", []),
        exports=data.get("exports", []),
        strings=data.get("strings", []),
        bookmarks=data.get("bookmarks", []),
        metadata=data.get("metadata", {}),
    )


def _parse_function(d: Dict[str, Any]) -> REFunction:
    """Parse a function dict with Ghidra-specific auto-name detection."""
    name = str(d.get("name", ""))
    is_auto = bool(d.get("is_auto_named", False))

    # Belt-and-braces: detect auto-naming patterns the export script
    # might not have flagged (e.g. older Ghidra versions).
    if not is_auto and _looks_auto_named(name):
        is_auto = True

    return REFunction(
        name=name,
        address=int(d.get("address", 0)),
        size=int(d.get("size", 0)),
        signature=d.get("signature"),
        calling_convention=d.get("calling_convention"),
        is_auto_named=is_auto,
        is_thunk=bool(d.get("is_thunk", False)),
        is_external=bool(d.get("is_external", False)),
        decompilation=d.get("decompilation"),
        source_tool=str(d.get("source_tool", "ghidra")),
        name_provenance=_function_name_provenance(d, name, is_auto),
    )


# Demangled C++/Rust names carry decoration a FunctionID pattern name
# never has. Heuristic split of Ghidra's ANALYSIS source type between
# the demangler and FID — both are tool-recovered (same trust band),
# so a miss here cannot upgrade a name's authority.
_DEMANGLED_DECORATION = ("::", "(", "<", "~")


def _function_name_provenance(
    d: Dict[str, Any],
    name: str,
    is_auto: bool,
) -> str:
    """Map a Ghidra export function record to a name-provenance tag.

    Precedence:

    1. A placeholder-looking name is ``tool_synthetic`` no matter what
       the record claims — a forged better tag on a ``FUN_*``/``fcn.*``
       name is the dangerous direction.
    2. An explicit ``name_provenance`` (round-tripped databases) wins.
    3. Ghidra's ``symbol_source`` maps: DEFAULT → tool_synthetic,
       ANALYSIS → demangled/pattern_recovered, IMPORTED → symtab
       (provisionally — the export cannot tell debug-info names from
       symbol-table names; ``refine_import_provenance`` splits when
       the binary is available). USER_DEFINED and unknown values map
       to "" (unknown).
    4. No symbol_source (older export scripts): auto-named functions
       tag tool_synthetic, everything else stays unknown.
    """
    if looks_tool_synthetic(name):
        return NAME_PROVENANCE_TOOL_SYNTHETIC

    explicit = normalise_name_provenance(d.get("name_provenance", ""))
    if explicit:
        return explicit

    source = str(d.get("symbol_source", "") or "").strip().lower()
    if source == "default":
        return NAME_PROVENANCE_TOOL_SYNTHETIC
    if source == "analysis":
        if any(t in name for t in _DEMANGLED_DECORATION):
            return NAME_PROVENANCE_DEMANGLED
        return NAME_PROVENANCE_PATTERN_RECOVERED
    if source == "imported":
        return NAME_PROVENANCE_SYMTAB

    if is_auto:
        return NAME_PROVENANCE_TOOL_SYNTHETIC
    return ""


def _looks_auto_named(name: str) -> bool:
    """Heuristic: does this function name look auto-generated?

    Ghidra uses ``FUN_XXXXXXXX`` for auto-analysed functions.
    r2 uses ``fcn.XXXXXXXX``.  IDA uses ``sub_XXXXXXXX``.
    Single definition in :func:`packages.ghidra.model.looks_tool_synthetic`.
    """
    return looks_tool_synthetic(name)

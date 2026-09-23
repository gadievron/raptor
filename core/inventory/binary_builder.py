"""Binary checklist builder — REDatabase to checklist.json.

Parallel to :func:`build_inventory` for source targets. Takes an
:class:`~packages.ghidra.model.REDatabase` (from Ghidra, r2, or
objdump) and produces a checklist dict in the same schema shape that
:mod:`core/audit` and :mod:`core/orchestration/understand_bridge`
consume.

Items use ``address`` + ``size`` instead of ``line_start`` / ``line_end``.
File paths use a ``binary:<stem>`` prefix so downstream consumers know
this is not a source file.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

#: Sentinel prefix marking a checklist/journal ``file`` value as a
#: binary program rather than a source path. Emitters go through
#: :func:`binary_path_key` — never hand-roll the string, so the
#: discriminator has exactly one definition.
BINARY_PATH_PREFIX = "binary:"

_CTRL_CHARS = re.compile(
    r"[\x00-\x08\x0b-\x1f\x7f\x9b\u202a-\u202e\u2066-\u2069]"
)


def binary_path_key(binary_path: "Path | str") -> str:
    """Canonical ``file`` value for a binary program's checklist items."""
    return BINARY_PATH_PREFIX + Path(binary_path).stem


def is_binary_item(item: Dict[str, Any]) -> bool:
    """True when a checklist/journal/gap item refers to a binary function.

    Routing predicate for consumers (audit context assembly, sweep
    substitution, coverage grouping): binary items carry the
    ``binary:`` file sentinel or an ``address`` instead of line
    numbers.
    """
    file_val = item.get("file") or ""
    return (
        file_val.startswith(BINARY_PATH_PREFIX)
        or item.get("address") is not None
    )


_DANGEROUS_SINKS: Optional[frozenset] = None


def _get_dangerous_sinks() -> frozenset:
    """Lazy-load the dangerous-sink set from the function taxonomy."""
    global _DANGEROUS_SINKS  # noqa: PLW0603
    if _DANGEROUS_SINKS is not None:
        return _DANGEROUS_SINKS
    try:
        from core.function_taxonomy import (
            EXEC_FUNCS,
            FORMAT_STRING_FUNCS,
            MEMORY_COPY_FUNCS,
            NETWORK_INGEST_FUNCS,
            SCAN_FAMILY_FUNCS,
            STRING_OVERFLOW_FUNCS,
        )
        _DANGEROUS_SINKS = frozenset(
            STRING_OVERFLOW_FUNCS | SCAN_FAMILY_FUNCS | MEMORY_COPY_FUNCS
            | FORMAT_STRING_FUNCS | EXEC_FUNCS | NETWORK_INGEST_FUNCS
        )
    except ImportError:
        _DANGEROUS_SINKS = frozenset()
    return _DANGEROUS_SINKS


def build_binary_checklist(
    db,
    *,
    binary_path: Optional[Path] = None,
    include_auto_named: bool = False,
    min_size: int = 16,
    context_map: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a checklist from an REDatabase.

    Parameters
    ----------
    db:
        An :class:`~packages.ghidra.model.REDatabase` instance.
    binary_path:
        Override path for the ``binary:`` prefix. Defaults to
        ``db.binary_path``.
    include_auto_named:
        If True, include auto-named functions (FUN_XXXXX). Default False.
    min_size:
        Skip functions smaller than this (thunks, stubs). Default 16 bytes.
    context_map:
        Optional BinaryContextMap dict (from r2 or ``/understand``). Used
        to enrich priority scoring with entry-point and sink data.

    Returns
    -------
    dict
        Checklist in the same schema as :func:`core.inventory.build_inventory`.
    """
    bp = binary_path or Path(db.binary_path or "unknown")
    path_key = binary_path_key(bp)

    binary_sha = ""
    try:
        if Path(bp).is_file():
            from core.hash import sha256_file
            binary_sha = sha256_file(Path(bp))
    except OSError:
        logger.debug("could not hash %s", bp, exc_info=True)

    dangerous = _get_dangerous_sinks()
    import_names = {
        (imp.get("name") or "").split("@")[0]
        for imp in (db.imports or [])
    }
    export_names = {
        (exp.get("name") or "")
        for exp in (db.exports or [])
    }

    callee_index = _build_callee_index(db)

    # Clamp sizes against the next function's start: on symbol-table
    # fallbacks the size is raw st_size from the (attacker-controlled)
    # binary, and an inflated span would over-mark address-space
    # coverage — one reviewed decoy could blanket every other
    # function's range and hide real gaps.
    starts = sorted(f.address for f in db.functions if f.address >= 0)
    import bisect
    # Hard ceiling regardless of neighbours: the last symbol has no
    # next start to clamp against, and widely spaced symbols evade
    # the gap clamp — an attacker-forged multi-GiB st_size would
    # otherwise ride into every address-range consumer (coverage
    # spans, trace-vote intervals). No real function needs more.
    _MAX_FUNCTION_SPAN = 0x100000

    def _clamped_size(func) -> int:
        size = min(max(func.size or 0, 0), _MAX_FUNCTION_SPAN)
        i = bisect.bisect_right(starts, func.address)
        if i < len(starts):
            gap = starts[i] - func.address
            if 0 < gap < size:
                return gap
        return size

    entry_addrs: Set[int] = set()
    sink_addrs: Set[int] = set()
    if context_map:
        for ep in context_map.get("entry_points", []):
            addr = ep.get("address")
            if addr is not None:
                entry_addrs.add(_parse_addr(addr))
        for sk in context_map.get("dangerous_sinks", context_map.get("sinks", [])):
            addr = sk.get("address")
            if addr is not None:
                sink_addrs.add(_parse_addr(addr))

    items: List[Dict[str, Any]] = []
    seen_names: Dict[str, int] = {}
    for func in db.functions:
        if func.is_thunk or func.is_external:
            continue
        if not include_auto_named and func.is_auto_named:
            continue
        if func.size < min_size:
            continue

        priority, reasons = _score_function(
            func, dangerous, import_names, export_names,
            callee_index, entry_addrs, sink_addrs,
        )

        metadata = _build_metadata(func, export_names)
        # The gap loop copies only known keys off checklist items —
        # address/size must ride inside metadata to survive into
        # context assembly and the journal.
        metadata["address"] = func.address
        metadata["size"] = _clamped_size(func)
        # Name provenance rides in metadata for the same reason: a
        # downstream consumer joining on this NAME must be able to
        # see whether the import seam minted it from debug info, a
        # symbol table, or thin air. Auto-named functions without a
        # tag are tool placeholders by construction; "" = unknown.
        metadata["name_provenance"] = _item_name_provenance(func)

        # Duplicate symbol names (cross-TU statics, or a forged
        # symtab aliasing a hot name) would collapse journal/coverage
        # keys — every instance after the first gets an address
        # suffix so each function keys uniquely. The minted spelling
        # itself is forgeable (a symtab entry literally named
        # "foo@0x.." collides with the disambiguation of a duplicate
        # foo at that address), so minted names join the seen set and
        # re-disambiguate until unique.
        item_name = func.name
        if item_name in seen_names:
            item_name = f"{func.name}@{func.address:#x}"
            while item_name in seen_names:
                item_name += "+"
        seen_names[func.name] = seen_names.get(func.name, 0) + 1
        if item_name != func.name:
            seen_names[item_name] = seen_names.get(item_name, 0) + 1

        item: Dict[str, Any] = {
            "name": item_name,
            "kind": "function",
            "address": func.address,
            "size": _clamped_size(func),
            "source_tool": func.source_tool,
            "name_provenance": metadata["name_provenance"],
            "metadata": metadata,
        }
        if func.signature:
            item["signature"] = func.signature
        if func.decompilation:
            item["has_decompilation"] = True
        if priority == "high":
            item["priority"] = "high"
            item["priority_reason"] = "; ".join(reasons)

        items.append(item)

    items.sort(key=_sort_key)

    total_funcs = len(db.functions)
    named = sum(1 for f in db.functions if not f.is_auto_named)

    provenance_counts: Dict[str, int] = {}
    for f in db.functions:
        tag = _item_name_provenance(f) or "unknown"
        provenance_counts[tag] = provenance_counts.get(tag, 0) + 1

    binary_provenance = _binary_provenance_block(bp, db)

    return {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "target_path": str(bp),
        "total_files": 1,
        "total_items": len(items),
        "total_functions": len(items),
        "total_sloc": 0,
        "skipped_files": 0,
        "excluded_patterns": [],
        "excluded_files": [],
        "files": [
            {
                "path": path_key,
                "language": "binary",
                "lines": 0,
                "sloc": 0,
                "sha256": binary_sha,
                "items": items,
            },
        ],
        "target_kind": "binary",
        "target_kind_reason": "binary target (REDatabase)",
        "target_kind_source": db.source_tool,
        "binary_stats": {
            "total_functions": total_funcs,
            "named_functions": named,
            "auto_named": total_funcs - named,
            "auto_named_ratio": (
                round((total_funcs - named) / total_funcs, 4)
                if total_funcs else 0.0
            ),
            "name_provenance_counts": provenance_counts,
            "architecture": db.architecture,
            "source_tool": db.source_tool,
            "provenance": binary_provenance,
        },
    }


def _item_name_provenance(func) -> str:
    """Resolve one function's name-provenance tag for checklist use.

    An auto-named function without an explicit tag is a tool
    placeholder by construction (legacy databases predating the
    provenance field); everything else passes through, "" = unknown.
    """
    tag = getattr(func, "name_provenance", "") or ""
    if not tag and getattr(func, "is_auto_named", False):
        return "tool_synthetic"
    return tag


def _binary_provenance_block(bp, db) -> Dict[str, Any]:
    """Per-binary provenance facts (build-id, stripped-ness, DWARF,
    fortification) for ``binary_stats`` — best-effort, honest about
    what could not be probed."""
    import_names = [
        (imp.get("name") or "") for imp in (db.imports or [])
    ]
    try:
        from core.analysis.binary_provenance import binary_provenance_block
        path = Path(bp)
        return binary_provenance_block(
            path if path.is_file() else None, import_names,
        )
    except Exception:
        logger.debug("binary provenance probe failed", exc_info=True)
        return {"probe": "error"}


def _build_callee_index(db) -> Dict[int, List[str]]:
    """Map function entry address → names of functions it calls."""
    addr_to_name: Dict[int, str] = {}
    for f in db.functions:
        addr_to_name[f.address] = f.name

    index: Dict[int, List[str]] = {}
    for xref in db.xrefs:
        if xref.kind != "call":
            continue
        caller = db.function_containing_address(xref.from_addr)
        if caller is None:
            continue
        callee_name = addr_to_name.get(xref.to_addr, "")
        if callee_name:
            index.setdefault(caller.address, []).append(callee_name)

    return index


def _score_function(
    func, dangerous, import_names, export_names,
    callee_index, entry_addrs, sink_addrs,
):
    """Score a function for priority. Returns (priority, reasons)."""
    reasons = []

    if func.address in entry_addrs:
        reasons.append("entry point")
    if func.name in export_names:
        reasons.append("exported symbol")
    if func.address in sink_addrs:
        reasons.append("dangerous sink")

    callees = callee_index.get(func.address, [])
    dangerous_calls = [c for c in callees if c in dangerous]
    if dangerous_calls:
        # Callee names come from the binary; strip control characters
        # before they reach prompts/terminals via priority_reason.
        cleaned = [
            _CTRL_CHARS.sub("", c)[:80] for c in dangerous_calls[:3]
        ]
        reasons.append("calls %s" % ", ".join(cleaned))

    if reasons:
        return "high", reasons
    return "normal", []


def _sort_key(item: Dict[str, Any]):
    """Sort: high-priority first, then by size (largest first)."""
    priority_order = 0 if item.get("priority") == "high" else 1
    return (priority_order, -(item.get("size", 0)))


def _build_metadata(func, export_names: Set[str]) -> Dict[str, Any]:
    """Build a metadata dict from a binary function for strategy selection."""
    meta: Dict[str, Any] = {}

    if func.signature:
        meta["signature"] = func.signature
        ret, params = _parse_c_signature(func.signature)
        if ret:
            meta["return_type"] = ret
        if params:
            meta["parameters"] = [
                {"name": p[0], "type": p[1]} for p in params
            ]

    if func.name in export_names:
        meta["visibility"] = "exported"

    return meta


def _parse_c_signature(sig: str):
    """Parse a C-style signature into (return_type, [(name, type), ...]).

    Handles common Ghidra/r2 output like:
        "int main(int argc, char **argv)"
        "void *malloc(size_t size)"
        "undefined processPacket(byte *param_1, int param_2)"
    """
    sig = sig.strip().rstrip(";")
    paren_open = sig.find("(")
    if paren_open < 0:
        return None, []

    prefix = sig[:paren_open].strip()
    parts = prefix.rsplit(None, 1)
    if len(parts) == 2:
        return_type = parts[0]
        stars = ""
        if parts[1].startswith("*"):
            stars = "*" * parts[1].count("*")
        if stars:
            return_type = return_type + " " + stars
    elif len(parts) == 1:
        return_type = "void"
    else:
        return_type = None

    params_str = sig[paren_open + 1:].rstrip(")")
    if not params_str.strip() or params_str.strip() == "void":
        return return_type, []

    params = []
    for p in params_str.split(","):
        p = p.strip()
        if not p:
            continue
        last_space = p.rfind(" ")
        last_star = p.rfind("*")
        split_at = max(last_space, last_star)
        if split_at > 0:
            ptype = p[:split_at + 1].strip()
            pname = p[split_at + 1:].strip() or "?"
        else:
            ptype = p
            pname = "?"
        params.append((pname, ptype))

    return return_type, params


def _parse_addr(value) -> int:
    """Parse an address that may be hex string or int."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16) if value.startswith("0x") else int(value)
        except (ValueError, TypeError):
            return -1
    return -1

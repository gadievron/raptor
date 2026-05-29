"""Tolerant validation/normalisation for a loaded coverage store payload.

Phase 4 feeds the store from externally-produced coverage (gcov / lcov /
coverage.py) and the store round-trips through ``coverage.json`` across runs.
A single malformed entry — a truncated interval, a string where an int is
expected, a hand-edited file — must not crash every coverage query. This
module normalises a loaded payload into a well-formed shape, dropping the
pieces it can't repair and logging what it dropped, so a damaged store
degrades to partial coverage rather than an exception.

Validation is intentionally tolerant, not strict: it never raises on bad
data (only the store's own queries decide meaning) and returns the largest
well-formed subset it can. The normalised shape is exactly the five keys the
store's :meth:`CoverageStore._entry` defaults to — unknown keys are dropped,
which (with the schema-version warning) is the read-side of forward-compat.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.logging import get_logger

logger = get_logger(__name__)


def _is_int(x: Any) -> bool:
    # bool is an int subclass; a boolean interval bound / line number is
    # malformed, so reject it explicitly.
    return isinstance(x, int) and not isinstance(x, bool)


def _opt_int(x: Any) -> Optional[int]:
    return x if _is_int(x) else None


def _valid_interval(iv: Any) -> Optional[List[int]]:
    """An inclusive ``[lo, hi]`` of two ints, or ``None`` if malformed."""
    if (isinstance(iv, (list, tuple)) and len(iv) == 2
            and _is_int(iv[0]) and _is_int(iv[1])):
        return [int(iv[0]), int(iv[1])]
    return None


def _normalise_tools(tools: Any, path: str, source: str) -> Dict[str, List[List[int]]]:
    if not isinstance(tools, dict):
        logger.warning(
            "coverage store %s: file %r has non-dict 'tools'; dropping", source, path)
        return {}
    out: Dict[str, List[List[int]]] = {}
    for tool, ivs in tools.items():
        if not isinstance(tool, str) or not isinstance(ivs, list):
            logger.warning(
                "coverage store %s: file %r tool %r has malformed intervals; "
                "dropping", source, path, tool)
            continue
        good: List[List[int]] = []
        for iv in ivs:
            v = _valid_interval(iv)
            if v is None:
                logger.warning(
                    "coverage store %s: file %r tool %r dropping malformed "
                    "interval %r", source, path, tool, iv)
                continue
            good.append(v)
        if good:
            out[tool] = good
    return out


def _normalise_findings(findings: Any, path: str, source: str) -> List[Dict[str, Any]]:
    if not isinstance(findings, list):
        return []
    out: List[Dict[str, Any]] = []
    for f in findings:
        if not isinstance(f, dict) or "id" not in f:
            logger.warning(
                "coverage store %s: file %r dropping finding without id: %r",
                source, path, f)
            continue
        out.append({
            "id": str(f["id"]),
            "line": _opt_int(f.get("line")),
            "retained": bool(f.get("retained", True)),
        })
    return out


def _normalise_entry(path: str, entry: Any, source: str) -> Optional[Dict[str, Any]]:
    if not isinstance(entry, dict):
        logger.warning(
            "coverage store %s: file %r entry is not an object; dropping",
            source, path)
        return None
    prov = entry.get("provenance")
    return {
        "total_lines": _opt_int(entry.get("total_lines")),
        "sloc": _opt_int(entry.get("sloc")),
        "tools": _normalise_tools(entry.get("tools", {}), path, source),
        "findings": _normalise_findings(entry.get("findings", []), path, source),
        "provenance": prov if isinstance(prov, dict) else {},
    }


def normalise_loaded_files(
    files: Any, source: str = "<coverage store>",
) -> Dict[str, Dict[str, Any]]:
    """Return the largest well-formed ``{path: entry}`` subset of ``files``.

    Non-dict input, non-string paths, and non-object entries are dropped with
    a warning; each surviving entry is coerced to the store's canonical shape.
    """
    if not isinstance(files, dict):
        logger.warning(
            "coverage store %s: 'files' is not an object; ignoring persisted "
            "coverage", source)
        return {}
    out: Dict[str, Dict[str, Any]] = {}
    for path, entry in files.items():
        if not isinstance(path, str):
            logger.warning(
                "coverage store %s: dropping non-string file key %r", source, path)
            continue
        norm = _normalise_entry(path, entry, source)
        if norm is not None:
            out[path] = norm
    return out


def check_version(version: Any, current: int, source: str = "<coverage store>") -> None:
    """Warn (do not raise) when the persisted schema version is newer than the
    code supports — the store is read best-effort and newer fields are dropped
    by :func:`normalise_loaded_files`."""
    if _is_int(version) and version > current:
        logger.warning(
            "coverage store %s: schema version %d is newer than supported %d; "
            "reading best-effort (newer fields ignored)", source, version, current)

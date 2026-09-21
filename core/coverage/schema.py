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

from typing import Any, TYPE_CHECKING

from core.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import Iterator

logger = get_logger(__name__)


def _is_int(x: Any) -> bool:
    # bool is an int subclass; a boolean interval bound / line number is
    # malformed, so reject it explicitly.
    return isinstance(x, int) and not isinstance(x, bool)


def _opt_int(x: Any) -> int | None:
    return x if _is_int(x) else None


def iter_file_entries(checklist: Any) -> Iterator[dict[str, Any]]:
    """Yield the dict rows of ``checklist["files"]``, tolerating any
    hostile container shape.

    The checklist is a run-dir JSON artifact (re-importable, inside
    the sandbox write grant), so its container shapes are as
    attacker-writable as its values: a non-list ``files`` or a
    non-dict row crashed every walk that assumed the produced shape.
    One tolerant walk for every consumer — non-conforming rows are
    skipped with a warning, conforming rows still flow.
    """
    if not isinstance(checklist, dict):
        return
    files = checklist.get("files")
    if files is None:
        return
    if not isinstance(files, list):
        logger.warning(
            "checklist: 'files' is %s, not a list; ignoring",
            type(files).__name__)
        return
    for fe in files:
        if isinstance(fe, dict):
            yield fe
        else:
            logger.warning(
                "checklist: skipping non-object file entry (%s)",
                type(fe).__name__)


def iter_item_entries(fe: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield the dict item rows of one file entry (``items`` with the
    legacy ``functions`` fallback), tolerating hostile shapes — the
    per-item companion of :func:`iter_file_entries`."""
    items = fe.get("items", fe.get("functions"))
    if items is None or not isinstance(items, list):
        return
    for it in items:
        if isinstance(it, dict):
            yield it


def _valid_interval(iv: Any) -> list[int] | None:
    """An inclusive ``[lo, hi]`` of two ints, or ``None`` if malformed."""
    if (isinstance(iv, (list, tuple)) and len(iv) == 2
            and _is_int(iv[0]) and _is_int(iv[1])):
        return [int(iv[0]), int(iv[1])]
    return None


def _normalise_tools(tools: Any, path: str, source: str) -> dict[str, list[list[int]]]:
    if not isinstance(tools, dict):
        logger.warning(
            "coverage store %s: file %r has non-dict 'tools'; dropping", source, path)
        return {}
    out: dict[str, list[list[int]]] = {}
    for tool, ivs in tools.items():
        if not isinstance(tool, str) or not isinstance(ivs, list):
            logger.warning(
                "coverage store %s: file %r tool %r has malformed intervals; "
                "dropping", source, path, tool)
            continue
        good: list[list[int]] = []
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


def _normalise_findings(findings: Any, path: str, source: str) -> list[dict[str, Any]]:
    if not isinstance(findings, list):
        return []
    out: list[dict[str, Any]] = []
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


def _normalise_provenance(
    prov: Any, path: str, source: str,
) -> dict[str, dict[str, Any]]:
    """Per-tool provenance slots, one level down.

    The top-level dict check alone left the SLOTS unvalidated — a
    planted ``coverage.json`` with ``{"provenance": {"semgrep": 5}}``
    crashed ``provenance_summary`` (reached on every rendered
    summary) and ``tool_provenance``, and unhashable ``version`` /
    ``models`` members or a non-string ``timestamp`` crashed the
    aggregate's set-adds and newest-compare. Slots must be dicts;
    the three aggregated fields are type-gated (str version/timestamp,
    str-list models); other stamp fields pass through untouched
    (consumers only dict-copy them)."""
    if not isinstance(prov, dict):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for tool, slot in prov.items():
        if not isinstance(tool, str) or not isinstance(slot, dict):
            logger.warning(
                "coverage store %s: file %r has malformed provenance "
                "slot %r; dropping", source, path, tool)
            continue
        clean = dict(slot)
        for key in ("version", "timestamp"):
            if key in clean and not isinstance(clean[key], str):
                logger.warning(
                    "coverage store %s: file %r tool %r dropping "
                    "non-string provenance %s", source, path, tool, key)
                del clean[key]
        if "models" in clean:
            models = clean["models"]
            clean["models"] = (
                [m for m in models if isinstance(m, str)]
                if isinstance(models, list) else []
            )
        out[tool] = clean
    return out


def _normalise_entry(path: str, entry: Any, source: str) -> dict[str, Any] | None:
    if not isinstance(entry, dict):
        logger.warning(
            "coverage store %s: file %r entry is not an object; dropping",
            source, path)
        return None
    return {
        "total_lines": _opt_int(entry.get("total_lines")),
        "sloc": _opt_int(entry.get("sloc")),
        "tools": _normalise_tools(entry.get("tools", {}), path, source),
        "findings": _normalise_findings(entry.get("findings", []), path, source),
        "provenance": _normalise_provenance(
            entry.get("provenance"), path, source),
    }


def normalise_loaded_files(
    files: Any, source: str = "<coverage store>",
) -> dict[str, dict[str, Any]]:
    """Return the largest well-formed ``{path: entry}`` subset of ``files``.

    Non-dict input, non-string paths, and non-object entries are dropped with
    a warning; each surviving entry is coerced to the store's canonical shape.
    """
    if not isinstance(files, dict):
        logger.warning(
            "coverage store %s: 'files' is not an object; ignoring persisted "
            "coverage", source)
        return {}
    out: dict[str, dict[str, Any]] = {}
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

"""Shared helpers for the per-ecosystem reachability tiers.

Small, pure functions that recur byte-for-byte across the
per-ecosystem modules (``cargo_function_level``,
``rubygems_function_level``, ``python.py``, ``nuget.py``, ...).
Consolidated here so the copies can't drift.

Deliberately NOT here: the per-ecosystem variants that look similar
but differ behaviourally — e.g. ``go_function_level`` /
``java_function_level`` / ``nuget_function_level`` each carry their
own qualified-symbol extraction with ecosystem-specific separator
and fallback rules. Those stay local until someone does the semantic
unification.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def extract_qualified_symbols(advisory: Any, dep_name: str) -> list[str]:
    """Pull qualified affected-symbol names out of an OSV advisory.

    Handles the two shapes seen in real OSV records:

      * ``imports[].symbols`` (mirrors the Go convention) — each
        symbol is qualified with the import's ``path``, falling back
        to ``dep_name`` when the record omits it.
      * Flat ``affected_symbols`` / ``affected_functions`` lists —
        qualified with ``dep_name``.

    Both ``ecosystem_specific`` and ``database_specific`` are
    consulted. Non-dict sources and non-string symbols are skipped.
    """
    out: list[str] = []
    es = getattr(advisory, "ecosystem_specific", None) or {}
    ds = getattr(advisory, "database_specific", None) or {}
    for source in (es, ds):
        if not isinstance(source, dict):
            continue
        for imp in source.get("imports") or []:
            if not isinstance(imp, dict):
                continue
            path = imp.get("path") or dep_name
            symbols = imp.get("symbols") or []
            out.extend(f"{path}.{s}" for s in symbols if isinstance(s, str) and s and isinstance(path, str))
        for key in ("affected_symbols", "affected_functions"):
            v = source.get(key)
            if isinstance(v, list) and dep_name:
                out.extend(f"{dep_name}.{s}" for s in v if isinstance(s, str))
    return out


def extract_function_names(advisory: Any) -> list[str]:
    """Pull bare (unqualified) function names out of an OSV advisory.

    Tries every shape seen in real OSV PyPI / npm records — schema
    variation is high: some GHSAs use
    ``database_specific.affected_functions``, others
    ``ecosystem_specific.imports[].symbols`` mirroring Go's
    convention, others inline structured data. Both
    ``ecosystem_specific`` and ``database_specific`` are consulted;
    callers dedupe.
    """
    out: list[str] = []
    es = getattr(advisory, "ecosystem_specific", None) or {}
    ds = getattr(advisory, "database_specific", None) or {}
    # ``imports[].symbols`` shape (mirrors Go convention).
    for source in (es, ds):
        if not isinstance(source, dict):
            continue
        for imp in source.get("imports") or []:
            if not isinstance(imp, dict):
                continue
            syms = imp.get("symbols") or []
            out.extend(s for s in syms if isinstance(s, str))
    # Flat-list variants.
    for key in ("affected_symbols", "affected_functions"):
        for source in (es, ds):
            if not isinstance(source, dict):
                continue
            v = source.get(key)
            if isinstance(v, list):
                out.extend(s for s in v if isinstance(s, str))
    return out


def format_evidence(
    hits: list[tuple[Path, int, bool]],
    *,
    target: Path | None,
    cap: int = 5,
) -> list[str]:
    """Format scan hits as compact ``file:line`` evidence strings.

    Paths under ``target`` are shown relative to it; the list is
    capped at ``cap`` entries with a ``... (+N more)`` marker when
    hits overflow.
    """
    out: list[str] = []
    for f, line, _ in hits[:cap]:
        rel = (f.relative_to(target) if target and target in f.parents
                else f)
        out.append(f"{rel}:{line}")
    if len(hits) > cap:
        out.append(f"... (+{len(hits) - cap} more)")
    return out

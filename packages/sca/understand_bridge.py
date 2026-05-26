"""``raptor-sca`` ↔ ``/understand`` integration — read the ``context-map.json``
written by an earlier ``/understand --map`` run and use it to enrich
reachability evidence.

Lookup order (first hit wins):

  1. Co-located: ``<run_dir>/context-map.json`` (when /agentic ran both
     stages into the same output dir).
  2. Project-sibling: any ``out/understand_*`` dir under the same
     project root, picked newest-first.
  3. Absent: silently fall back to bare module-level reachability.

Match semantics: a Reachability evidence entry that points at a file
which appears in the context-map's ``entry_points`` / ``sink_details``
/ ``boundary_details`` is annotated with the matching context — "this
dep imports a file that's an entry point", "this dep imports a file
with a tainted-data sink", etc. Operators see this in the report
alongside the bare import line.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

from .models import Confidence, Reachability

logger = logging.getLogger(__name__)


@dataclass
class ContextMap:
    """Normalised view of ``context-map.json`` keyed for fast lookup."""

    entry_point_files: Set[str]      # file paths
    sink_files: Set[str]
    boundary_files: Set[str]
    raw: dict                         # original JSON for ad-hoc inspection


def load_context_map(
    target: Path, *, run_dir: Optional[Path] = None,
) -> Optional[ContextMap]:
    """Try to load a context-map for the project; return ``None`` on miss."""
    candidates: List[Path] = []
    if run_dir is not None:
        candidates.append(run_dir / "context-map.json")
    # Search ``<target>/out/understand_*`` newest-first.
    out_dir = target / "out"
    if out_dir.is_dir():
        understand_runs = sorted(
            (p for p in out_dir.iterdir()
              if p.is_dir() and p.name.startswith("understand_")),
            reverse=True,
        )
        for ur in understand_runs:
            candidates.append(ur / "context-map.json")
    for c in candidates:
        if c.is_file():
            try:
                return _parse(c)
            except (OSError, json.JSONDecodeError) as e:
                logger.warning("sca.understand_bridge: cannot read %s: %s",
                                c, e)
                continue
    return None


def annotate(
    reach: Reachability, ctx: ContextMap,
) -> Reachability:
    """Augment a Reachability with context-map context.

    Returns a NEW Reachability — the input is not mutated. When evidence
    files match an entry-point / sink / boundary, the verdict is
    promoted (``imported`` → ``likely_called`` when the file is a
    sink; ``called_in_dead_code`` → ``likely_called`` when the file
    is an entry point or sink — operator's /understand pass has
    direct evidence the host is reachable, overriding our static
    "no callers" claim). ``not_reachable`` / ``not_evaluated`` /
    ``not_function_reachable`` verdicts are returned unchanged.
    """
    if reach.verdict not in (
        "imported", "likely_called", "called_in_dead_code",
    ):
        return reach
    matched_kinds: List[str] = []
    matched_paths: List[str] = []
    for ev in reach.evidence:
        # Evidence shape: ``"path/to/file.py:42"`` (file:line). Strip
        # the line number for the match.
        path = ev.split(":", 1)[0]
        if path in ctx.sink_files:
            matched_kinds.append("sink")
            matched_paths.append(ev)
        if path in ctx.entry_point_files:
            matched_kinds.append("entry_point")
            matched_paths.append(ev)
        if path in ctx.boundary_files:
            matched_kinds.append("trust_boundary")
            matched_paths.append(ev)
    if not matched_kinds:
        return reach

    # Promote to ``likely_called`` when:
    #   * the file is a sink (vulnerable code path is in scope), OR
    #   * the file is an entry point and we'd previously classified
    #     the call as ``called_in_dead_code`` — operator's
    #     /understand pass identified the host as a real entry,
    #     so the static "no callers" claim was wrong.
    if "sink" in matched_kinds:
        new_verdict = "likely_called"
    elif (reach.verdict == "called_in_dead_code"
            and "entry_point" in matched_kinds):
        new_verdict = "likely_called"
    else:
        new_verdict = reach.verdict
    kinds_uniq = sorted(set(matched_kinds))
    reason = (
        f"{reach.confidence.reason}; context-map: dep "
        f"imported in {', '.join(kinds_uniq)} site(s)"
    )
    new_confidence = Confidence(
        level="high",
        reason=reason,
    )
    return Reachability(
        verdict=new_verdict,                    # type: ignore[arg-type]
        confidence=new_confidence,
        evidence=list(reach.evidence) + [
            f"# context-map: {kinds_uniq}",
        ],
    )


def annotate_all(
    reachability: Dict[str, Reachability], ctx: ContextMap,
) -> Dict[str, Reachability]:
    """Apply ``annotate`` to every entry in a reachability map."""
    return {k: annotate(v, ctx) for k, v in reachability.items()}


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _parse(path: Path) -> ContextMap:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise json.JSONDecodeError("expected dict at top level", "", 0)
    entry_point_files = _extract_files(raw.get("entry_points", []))
    sink_files = _extract_files(raw.get("sink_details", []))
    boundary_files = _extract_files(raw.get("boundary_details", []))
    # Some context-maps put files under "sinks" with a different shape;
    # try both.
    sink_files |= _extract_files(raw.get("sinks", []))
    return ContextMap(
        entry_point_files=entry_point_files,
        sink_files=sink_files,
        boundary_files=boundary_files,
        raw=raw,
    )


def _extract_files(items: Iterable) -> Set[str]:
    out: Set[str] = set()
    for item in items or []:
        if isinstance(item, dict):
            f = item.get("file") or item.get("path")
            if isinstance(f, str):
                out.add(f)
            # Some shapes use ``"location": "path:line"``.
            loc = item.get("location")
            if isinstance(loc, str):
                out.add(loc.split(":", 1)[0])
        elif isinstance(item, str):
            out.add(item.split(":", 1)[0])
    return out


__all__ = ["ContextMap", "annotate", "annotate_all", "load_context_map"]

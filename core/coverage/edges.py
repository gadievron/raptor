"""Touched-edge capture from /understand outputs.

A flow-trace ``call``/``sink`` step is a caller→callee edge
observation (``call_site`` is a ``file:line`` in the caller,
``definition`` the ``file:line`` of the callee), and the AST-view
enricher adds body-level ``ast_view.calls_made`` evidence per stepped-
into function. ``import_understand`` historically flattened both to
per-line coverage marks and discarded the edge structure; this module
records it.

Touched is the ``scanned`` tier for edges: a trace crossing A→B chased
one tainted variable across the edge — it did NOT review the A→B trust
contract. Touched edges therefore never satisfy an edge obligation
(``core.audit.edge_obligations``); they only record extent, the same
read-vs-reviewed discipline functions follow.

On-disk contract — ``edges-touched.json`` in the run directory, a
derived artifact (rebuildable from the run's flow-traces at any time):

    {"schema_version": 1,
     "edges": [{"caller_file", "caller", "callee_file", "callee",
                "call_line", "source"}]}

Edge identity for dedup is ``(caller_file, caller, callee_file,
callee, call_line)`` — the call line keeps same-named sites distinct.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from core.json import load_json, save_json

logger = logging.getLogger(__name__)

EDGES_TOUCHED_FILENAME = "edges-touched.json"

# ``file:line`` — anchored, same discipline as the AST-view enricher's
# definition parser (malformed strings fail whole, not partially).
_LOC_RE = re.compile(r"^(.+):(\d+)$")


def parse_loc(value: Any) -> tuple[str, int] | None:
    if not isinstance(value, str):
        return None
    m = _LOC_RE.match(value)
    if not m:
        return None
    return m.group(1), int(m.group(2))


def item_spans(checklist: dict[str, Any]) -> dict[str, list[tuple]]:
    """``{path: [(lo, hi, name)]}`` for every named, ranged inventory
    item — the containing-function lookup for a ``file:line``."""
    out: dict[str, list[tuple]] = {}
    for fe in checklist.get("files", []) or []:
        path = fe.get("path")
        if not path:
            continue
        spans = []
        for it in fe.get("items", fe.get("functions", [])) or []:
            name = it.get("name")
            lo = it.get("line_start")
            if not name or not isinstance(lo, int):
                continue
            hi = it.get("line_end")
            if not isinstance(hi, int):
                hi = lo
            spans.append((lo, hi, name))
        if spans:
            out[path] = sorted(spans)
    return out


def containing_item(
    spans: dict[str, list[tuple]], path: str, line: int,
) -> str | None:
    """Name of the innermost inventory item containing ``path:line``."""
    best: tuple | None = None
    for lo, hi, name in spans.get(path, []):
        if lo <= line <= hi and (best is None or lo >= best[0]):
            best = (lo, hi, name)
    return best[2] if best else None


def normalise_trace_path(raw: str, inv_paths: set[str]) -> str | None:
    """Map a trace path (possibly absolute / ``./``-prefixed) onto its
    inventory key. Exact match first; else a unique suffix match."""
    if raw in inv_paths:
        return raw
    cleaned = raw.lstrip("./")
    if cleaned in inv_paths:
        return cleaned
    hits = [p for p in inv_paths if raw.endswith("/" + p)]
    if len(hits) == 1:
        return hits[0]
    return None


def _name_definitions(checklist: dict[str, Any]) -> dict[str, list[str]]:
    """``{item_name: [paths defining it]}`` for callee-name resolution."""
    out: dict[str, list[str]] = {}
    for fe in checklist.get("files", []) or []:
        path = fe.get("path")
        if not path:
            continue
        for it in fe.get("items", fe.get("functions", [])) or []:
            name = it.get("name")
            if name:
                paths = out.setdefault(name, [])
                if path not in paths:
                    paths.append(path)
    return out


def collect_touched_edges(
    run_dir: Path, checklist: dict[str, Any],
) -> list[dict[str, Any]]:
    """Extract deduplicated touched edges from a run's flow-traces.

    Two evidence sources per ``call``/``sink`` step:

    * ``call_site`` → ``definition``: both resolved to their containing
      inventory item — the traced hop itself.
    * ``ast_view.calls_made``: body calls of the stepped-into function,
      kept only when the chain-tail name resolves to exactly ONE
      inventory definition (ambiguous names are the obligations pass's
      blind-spot business, not touched extent).
    """
    spans = item_spans(checklist)
    inv_paths = set(spans)
    defs = _name_definitions(checklist)
    edges: list[dict[str, Any]] = []
    seen: set[tuple] = set()

    def _add(caller_file, caller, callee_file, callee, call_line, source) -> None:
        key = (caller_file, caller, callee_file, callee, call_line)
        if key in seen:
            return
        seen.add(key)
        edges.append({
            "caller_file": caller_file, "caller": caller,
            "callee_file": callee_file, "callee": callee,
            "call_line": call_line, "source": source,
        })

    for tf in sorted(Path(run_dir).glob("flow-trace-*.json")):
        trace = load_json(tf)
        if not isinstance(trace, dict):
            continue
        for step in trace.get("steps") or []:
            if not isinstance(step, dict):
                continue
            if step.get("type") not in ("call", "sink"):
                continue
            cs = parse_loc(step.get("call_site"))
            df = parse_loc(step.get("definition"))
            caller_file = caller = None
            if cs:
                caller_file = normalise_trace_path(cs[0], inv_paths)
                if caller_file:
                    caller = containing_item(spans, caller_file, cs[1])
            if caller_file and caller and df:
                callee_file = normalise_trace_path(df[0], inv_paths)
                callee = (
                    containing_item(spans, callee_file, df[1])
                    if callee_file else None
                )
                if callee_file and callee:
                    _add(caller_file, caller, callee_file, callee,
                         cs[1], tf.name)
            # Body-level evidence for the stepped-into function.
            av = step.get("ast_view")
            if not (isinstance(av, dict) and df):
                continue
            av_caller = av.get("function")
            av_file = normalise_trace_path(df[0], inv_paths)
            if not (av_caller and av_file):
                continue
            for call in av.get("calls_made") or []:
                if not isinstance(call, dict):
                    continue
                chain = call.get("chain") or []
                tail = chain[-1] if chain else None
                line = call.get("line")
                if not tail or not isinstance(line, int):
                    continue
                paths = defs.get(tail) or []
                if len(paths) != 1:
                    continue          # unresolved/ambiguous → not extent
                _add(av_file, av_caller, paths[0], tail, line, tf.name)
    return edges


def write_touched(run_dir: Path, edges: list[dict[str, Any]]) -> None:
    """Persist ``edges-touched.json`` (idempotent overwrite)."""
    save_json(Path(run_dir) / EDGES_TOUCHED_FILENAME,
              {"schema_version": 1, "edges": edges})


def load_touched(run_dir: Path) -> list[dict[str, Any]]:
    """Read a run's touched edges; ``[]`` when absent/malformed."""
    raw = load_json(Path(run_dir) / EDGES_TOUCHED_FILENAME)
    if not isinstance(raw, dict):
        return []
    return [e for e in raw.get("edges") or [] if isinstance(e, dict)]

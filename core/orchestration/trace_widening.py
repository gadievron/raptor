"""Enrich flow traces with sibling callers for each intermediate step.

For each function in a flow trace, queries the project call graph for
other callers (siblings) that also invoke that function.  These represent
alternative paths to the same code — if one path is exploitable, siblings
may be too.

This addresses the observation that DFS traces one path but misses
siblings that reach the same internal function via different entry points.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_FUNC_FROM_DEF_RE = re.compile(
    r"^(.+?):(\d+)$",
)


def _function_name_from_step(step: dict[str, Any]) -> str | None:
    """Extract function name from a trace step's definition field.

    The definition field is "file:line" but doesn't carry the function
    name directly.  Falls back to parsing it from the description.
    """
    return step.get("function") or step.get("callee") or None


def _resolve_function_from_checklist(
    definition: str,
    checklist: dict[str, Any],
) -> str | None:
    """Resolve a definition like 'src/auth.py:34' to a function name
    using the checklist inventory."""
    m = _FUNC_FROM_DEF_RE.match(definition or "")
    if not m:
        return None
    file_path = m.group(1)
    line = int(m.group(2))

    for fi in checklist.get("files", []):
        if fi.get("path") != file_path:
            continue
        best_name = None
        best_dist = float("inf")
        for func in fi.get("functions", []):
            func_line = func.get("line", 0)
            if func_line and abs(func_line - line) < best_dist:
                best_dist = abs(func_line - line)
                best_name = func.get("name")
        if best_name and best_dist <= 20:
            return best_name
    return None


def _build_reverse_call_map(
    checklist: dict[str, Any],
) -> dict[str, list[dict[str, str]]]:
    """Build a map of function_name → list of callers from checklist call graphs.

    Each caller entry has {file, function, line}.
    """
    reverse: dict[str, list[dict[str, str]]] = {}

    for fi in checklist.get("files", []):
        cg = fi.get("call_graph")
        if not isinstance(cg, dict):
            continue
        for call in cg.get("calls", []):
            caller = call.get("caller") or "<module>"
            chain = call.get("chain", [])
            line = call.get("line", 0)
            if len(chain) == 1:
                callee = chain[0]
                reverse.setdefault(callee, []).append({
                    "file": fi["path"],
                    "function": caller,
                    "line": str(line),
                })
            elif len(chain) == 2 and chain[0] in ("self", "this"):
                callee = chain[1]
                reverse.setdefault(callee, []).append({
                    "file": fi["path"],
                    "function": caller,
                    "line": str(line),
                })

    return reverse


def enrich_trace_with_siblings(
    trace_data: dict[str, Any],
    checklist: dict[str, Any],
) -> dict[str, Any]:
    """Add ``siblings`` field to each intermediate step in a flow trace.

    For each step that isn't the entry or the final sink, resolves
    the function name and looks up other callers in the call graph.
    The caller that's already ON the trace is excluded.

    Modifies *trace_data* in place and returns it.
    """
    steps = trace_data.get("steps", [])
    if not steps:
        return trace_data

    reverse_map = _build_reverse_call_map(checklist)

    trace_functions: set[str] = set()
    for step in steps:
        defn = step.get("definition", "")
        fname = _function_name_from_step(step) or _resolve_function_from_checklist(
            defn, checklist,
        )
        if fname:
            trace_functions.add(fname)

    for step in steps:
        step_type = step.get("type", "")
        if step_type == "entry":
            continue

        defn = step.get("definition", "")
        func_name = _function_name_from_step(step) or _resolve_function_from_checklist(
            defn, checklist,
        )
        if not func_name:
            continue

        callers = reverse_map.get(func_name, [])
        siblings = [
            c for c in callers
            if c["function"] not in trace_functions
            and c["function"] != "<module>"
        ]

        if siblings:
            seen: set[tuple[str, str]] = set()
            deduped: list[dict[str, str]] = []
            for s in siblings:
                key = (s["file"], s["function"])
                if key not in seen:
                    seen.add(key)
                    deduped.append(s)
            step["siblings"] = deduped

    return trace_data


def enrich_all_traces(
    output_dir: str | Path,
    checklist: dict[str, Any],
) -> int:
    """Enrich all flow-trace-*.json files in *output_dir*.

    Returns the number of traces enriched.
    """
    import json

    out = Path(output_dir)
    count = 0
    for trace_path in sorted(out.glob("flow-trace-*.json")):
        try:
            data = json.loads(trace_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            logger.debug("skipping unreadable trace: %s", trace_path)
            continue

        enriched = enrich_trace_with_siblings(data, checklist)
        trace_path.write_text(
            json.dumps(enriched, indent=2),
            encoding="utf-8",
        )
        count += 1
        n_siblings = sum(
            1 for s in enriched.get("steps", []) if s.get("siblings")
        )
        if n_siblings:
            logger.info(
                "trace widening: %s — %d steps with siblings",
                trace_path.name, n_siblings,
            )

    return count

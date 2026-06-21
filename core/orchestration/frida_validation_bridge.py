"""Bridge frida runtime evidence into the validation pipeline.

Discovers frida evidence for a target and produces runtime_evidence
annotations that Stage B can use to floor proximity scores, and
Stage D can use as independent corroboration.

Pattern follows understand_bridge.py -- discovers output from a prior
/frida run and feeds it into the validation pipeline's data model.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from core.logging import get_logger

log = get_logger("orchestration.frida_validation_bridge")

__all__ = [
    "PROXIMITY_FLOOR",
    "RuntimeEvidence",
    "annotate_attack_paths",
    "collect_runtime_evidence",
]

PROXIMITY_FLOOR = 6


@dataclass
class RuntimeEvidence:
    """Runtime evidence from a frida session for one attack path step."""

    function_observed: bool
    call_count: int = 0
    observed_args: Optional[list] = None
    trace_id: str = ""


def collect_runtime_evidence(
    search_dirs: list[Path],
    target_path: Optional[str] = None,
) -> dict[str, RuntimeEvidence]:
    """Discover frida evidence and build a function->RuntimeEvidence map.

    Searches ``search_dirs`` for frida run directories via the shared
    evidence discovery layer.  When ``target_path`` is given, only runs
    whose metadata target matches are used.

    Returns {function_name: RuntimeEvidence} for all functions frida
    observed.  Empty dict if no frida evidence found.
    """
    try:
        from packages.frida import parse_events
        from packages.frida.evidence import discover_evidence
    except ImportError:
        log.debug("packages.frida not importable; skipping frida evidence")
        return {}

    evidence_list = discover_evidence(search_dirs, target_path=target_path)
    if not evidence_list:
        return {}

    result: dict[str, RuntimeEvidence] = {}

    for ev in evidence_list:
        if not ev.has_events:
            continue
        events_path = ev.run_dir / "events.jsonl"
        trace_id = str(ev.run_dir)

        # Per-run counters: track call_count within this run, then take
        # the max across runs (represents the hottest single run).
        run_counts: dict[str, int] = {}
        run_first_args: dict[str, list | None] = {}

        for record in parse_events(events_path):
            if not isinstance(record, dict):
                continue
            if record.get("type") != "send":
                continue
            payload = record.get("payload")
            if not isinstance(payload, dict):
                continue
            fn = payload.get("fn")
            if not isinstance(fn, str) or not fn:
                continue

            run_counts[fn] = run_counts.get(fn, 0) + 1

            if run_first_args.get(fn) is None:
                args = payload.get("args")
                if isinstance(args, dict):
                    run_first_args[fn] = list(args.values())
                elif isinstance(args, list):
                    run_first_args[fn] = args

        for fn, count in run_counts.items():
            if fn in result:
                existing = result[fn]
                new_args = existing.observed_args
                if new_args is None:
                    new_args = run_first_args.get(fn)
                result[fn] = RuntimeEvidence(
                    function_observed=True,
                    call_count=max(existing.call_count, count),
                    observed_args=new_args,
                    trace_id=existing.trace_id,
                )
            else:
                result[fn] = RuntimeEvidence(
                    function_observed=True,
                    call_count=count,
                    observed_args=run_first_args.get(fn),
                    trace_id=trace_id,
                )

    log.info("collected runtime evidence: %d functions from %d runs",
             len(result), len(evidence_list))
    return result


def annotate_attack_paths(
    attack_paths: list[dict],
    evidence_map: dict[str, RuntimeEvidence],
) -> list[dict]:
    """Annotate attack paths with runtime_evidence from frida.

    For each attack path step whose function appears in the evidence
    map, adds a ``runtime_evidence`` dict to the step.  If any step
    has runtime evidence, floors the path's proximity at
    ``PROXIMITY_FLOOR`` (precedent: SMT feasible:true floor in
    Stage B).

    Returns a deep copy of attack_paths with annotations.  The
    original list is never mutated.
    """
    if not evidence_map:
        return attack_paths

    result = copy.deepcopy(attack_paths)

    for path in result:
        if not isinstance(path, dict):
            continue

        has_evidence = False
        first_trace_id = None

        steps = path.get("steps")
        if not isinstance(steps, list):
            continue

        for step in steps:
            if not isinstance(step, dict):
                continue

            fn_name = _extract_function_name(step)
            if not fn_name:
                continue

            ev = evidence_map.get(fn_name)
            if ev is None:
                continue

            has_evidence = True
            if first_trace_id is None:
                first_trace_id = ev.trace_id
            step["runtime_evidence"] = {
                "function_observed": ev.function_observed,
                "call_count": ev.call_count,
                "observed_args": ev.observed_args,
                "trace_id": ev.trace_id,
            }

        if has_evidence:
            path["runtime_evidence_available"] = True
            if first_trace_id:
                path["frida_trace_id"] = first_trace_id
            current_proximity = path.get("proximity")
            if isinstance(current_proximity, (int, float)):
                if current_proximity < PROXIMITY_FLOOR:
                    path["proximity"] = PROXIMITY_FLOOR
            else:
                path["proximity"] = PROXIMITY_FLOOR

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


_ACTION_FN_RE = re.compile(r'\b([a-zA-Z_]\w*)\s*\(')
_KEYWORDS = frozenset({
    "if", "for", "while", "switch", "catch", "return", "sizeof", "typeof",
    "alignof", "decltype", "throw", "new", "delete",
})


def _extract_function_name(step: dict) -> Optional[str]:
    """Extract a function name from an attack path step.

    Steps use varying formats: some have a ``function`` or ``name``
    key, others have ``action`` strings like ``"call strcpy(buf, in)"``.
    For action strings we take the LAST function-call pattern since
    earlier tokens are typically callers, not the vulnerable callee.
    """
    for key in ("function", "name"):
        val = step.get(key)
        if isinstance(val, str) and val:
            return _strip_parens(val)

    action = step.get("action")
    if isinstance(action, str) and action:
        last_match = None
        for m in _ACTION_FN_RE.finditer(action):
            candidate = m.group(1)
            if candidate not in _KEYWORDS:
                last_match = candidate
        if last_match:
            return last_match

    return None


def _strip_parens(name: str) -> str:
    """Remove trailing parentheses from a function name."""
    name = name.strip()
    if name.endswith("()"):
        return name[:-2]
    idx = name.find("(")
    if idx > 0:
        return name[:idx].strip()
    return name

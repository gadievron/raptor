"""Trace widening — surface sibling callers that lack an enforcer.

After ``/understand --trace`` produces a flow trace, this module
examines the traced path for safety-relevant steps (sanitisers or
enforcers), constructs :class:`SafetyAssumption` objects from them,
and uses :class:`CompositionalAnalyzer` to discover sibling callers
that reach the same target without the enforcer.

The result is appended to the flow-trace JSON as a ``widening``
field: a list of investigation candidates, each naming a caller
function, file, and the enforcer it omits.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def widen_trace(
    trace: dict[str, Any],
    target_path: Path,
    *,
    checklist: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    """Extract assumptions from a trace and find bypass candidates.

    Parameters
    ----------
    trace:
        Parsed flow-trace JSON (with ``steps``, ``summary``, etc.).
    target_path:
        Root of the target codebase.
    checklist:
        Inventory checklist (passed through to ``load_call_graphs``).

    Returns
    -------
    List of widening candidates, each a dict with ``caller_file``,
    ``caller_function``, ``missing_enforcer``, and ``assumption``.
    Also mutates *trace* in place: sets ``trace["widening"]``.
    """
    steps = trace.get("steps")
    if not isinstance(steps, list) or len(steps) < 2:
        return []

    assumptions = _extract_assumptions(trace)
    if not assumptions:
        return []

    try:
        from core.inventory.call_graph import load_call_graphs
        from core.iris.bypass import CompositionalAnalyzer

        call_graphs = load_call_graphs(target_path, checklist)
        if not call_graphs:
            return []
        analyzer = CompositionalAnalyzer(call_graphs)
    except Exception:
        logger.debug("trace widening: call graph load failed", exc_info=True)
        return []

    candidates: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    for assumption in assumptions:
        try:
            bypasses = analyzer.detect_bypasses(assumption)
            for bf in bypasses:
                key = (bf.caller_file, bf.caller_function, bf.missing_enforcer)
                if key not in seen:
                    seen.add(key)
                    candidates.append({
                        "caller_file": bf.caller_file,
                        "caller_function": bf.caller_function,
                        "missing_enforcer": bf.missing_enforcer,
                        "assumption": assumption.assumption,
                        "via_intermediate": bf.via_intermediate or "",
                    })
                    for widened in analyzer.widen_from_finding(bf):
                        wkey = (
                            widened.caller_file,
                            widened.caller_function,
                            widened.missing_enforcer,
                        )
                        if wkey not in seen:
                            seen.add(wkey)
                            candidates.append({
                                "caller_file": widened.caller_file,
                                "caller_function": widened.caller_function,
                                "missing_enforcer": widened.missing_enforcer,
                                "assumption": assumption.assumption,
                                "via_intermediate": widened.via_intermediate or "",
                            })
        except Exception:
            logger.debug(
                "trace widening: bypass detection failed for %s",
                assumption.target, exc_info=True,
            )

    trace["widening"] = candidates
    if candidates:
        logger.info(
            "trace widening: %d candidates from %d assumptions",
            len(candidates), len(assumptions),
        )
    return candidates


def _extract_assumptions(trace: dict[str, Any]) -> list[Any]:
    """Build SafetyAssumptions from the traced flow's structure.

    Looks for sanitiser steps in the trace — functions the trace
    identified as performing sanitisation or validation. For each
    sink step, if a sanitiser was found on the path, creates an
    assumption: "the sink function is safe IF the sanitiser was
    called."
    """
    from core.iris.assumptions import AssumptionCategory, SafetyAssumption

    steps = trace.get("steps", [])
    sanitisers: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []

    for step in steps:
        if not isinstance(step, dict):
            continue
        step_type = step.get("type", "")
        if step_type == "sink":
            sinks.append(step)
        transform = (step.get("transform") or "").lower()
        if any(kw in transform for kw in (
            "sanitiz", "sanitise", "escape", "encode", "validate",
            "filter", "clean", "purif",
        )):
            sanitisers.append(step)

    if not sinks:
        return []

    summary = trace.get("summary", {})
    trace_sanitisers = summary.get("sanitizers") or []

    assumptions: list[SafetyAssumption] = []
    for sink in sinks:
        sink_func = _step_function_name(sink)
        sink_file, _ = _parse_definition(sink.get("definition", ""))
        if not sink_func:
            continue

        enforced_by: list[str] = []
        for san in sanitisers:
            san_func = _step_function_name(san)
            if san_func:
                enforced_by.append(san_func)
        for san_name in trace_sanitisers:
            if isinstance(san_name, str) and san_name not in enforced_by:
                enforced_by.append(san_name)

        if not enforced_by:
            continue

        sink_type = sink.get("sink_type", "unknown")
        assumptions.append(SafetyAssumption(
            target=sink_func,
            file=sink_file,
            assumption=(
                f"{sink_func} is safe IF {', '.join(enforced_by)} "
                f"is called on the path"
            ),
            category=AssumptionCategory.SANITISATION,
            enforced_by=enforced_by,
            bug_class=_sink_cwe(sink_type),
            confidence=0.7,
            source="trace_widening",
        ))
    return assumptions


def _step_function_name(step: dict[str, Any]) -> str:
    """Best-effort function name for a trace step.

    Tries (in order): ``ast_view.name``, function from dotted
    ``definition`` (e.g. ``psycopg2.cursor.execute()``), or the
    ``function`` field some steps carry.
    """
    av = step.get("ast_view")
    if isinstance(av, dict) and av.get("name"):
        return av["name"]
    definition = step.get("definition", "")
    _, func = _parse_definition(definition)
    if func:
        return func
    if step.get("function"):
        return step["function"]
    return ""


def _parse_definition(definition: str) -> tuple[str, str]:
    """Extract ``(file, function_name)`` from a definition string.

    Handles ``module.Class.method()`` (returns the method/function),
    ``file.py:123`` (returns the file and empty function — callers
    should fall back to ``ast_view`` or step description), and bare
    names.
    """
    if not definition:
        return "", ""
    if "." in definition and definition.rstrip("()").rsplit(".", 1)[-1].isidentifier():
        parts = definition.rstrip("()").rsplit(".", 1)
        return "", parts[-1]
    if ":" in definition:
        parts = definition.rsplit(":", 1)
        return parts[0], ""
    return "", definition.rstrip("()")


def _sink_cwe(sink_type: str) -> str:
    return {
        "db_query": "CWE-89",
        "shell": "CWE-78",
        "file": "CWE-22",
        "deserialize": "CWE-502",
        "network": "CWE-918",
        "xss": "CWE-79",
    }.get(sink_type, "")


def widen_dir(
    run_dir: Path,
    target_path: Path,
    *,
    checklist: dict[str, Any] | None = None,
) -> int:
    """Widen all ``flow-trace-*.json`` files in *run_dir*.

    Returns the total number of widening candidates found.
    """
    total = 0
    for trace_path in sorted(run_dir.glob("flow-trace-*.json")):
        try:
            trace = json.loads(trace_path.read_text())
        except Exception:
            logger.debug("trace widening: failed to read %s", trace_path, exc_info=True)
            continue

        if trace.get("widening") is not None:
            continue

        candidates = widen_trace(trace, target_path, checklist=checklist)
        if trace.get("widening") is not None:
            trace_path.write_text(json.dumps(trace, indent=2) + "\n")
        total += len(candidates)

    if total:
        logger.info("trace widening: %d total candidates across %s", total, run_dir)
    return total

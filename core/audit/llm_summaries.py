"""Pre-loop LLM summary extraction for inter-procedural context.

Before the review loop, functions that have callers or callees in the
work queue but lack mechanical (Joern/Python-AST) summaries get a
focused LLM pass that extracts preconditions, taint flows, callees,
and callers.  This guarantees every review has complete callee summary
context regardless of review order.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from core.evidence import EvidenceTier

from core.analysis.summaries import FunctionSummary, Precondition, TaintRule

logger = logging.getLogger(__name__)

_SUMMARY_SYSTEM_PROMPT = (
    "You are a security-focused code analyst.  Given a function's source, "
    "extract its security-relevant summary as JSON.  Be precise and terse."
)

_SUMMARY_USER_TEMPLATE = """\
Analyse the following function and return a JSON object with these fields:

- "preconditions": list of {{"parameter": str, "assumption": str}} — \
what each parameter must satisfy for safe execution (null checks, bounds, \
valid state).
- "taint_flows": list of {{"source_param": str, "source_index": int, \
"sink_call": str, "sink_arg_index": int}} — parameters that flow to \
security-sensitive callees (memcpy, strcpy, system, exec, SQL, etc.).
- "callees": list of "file:function" strings for functions this function calls.
- "callers": list of "file:function" strings if visible from the source.
- "error_paths": list of return-statement strings for error/failure returns.
- "state_transitions": list of strings describing resource state changes \
(lock acquire/release, file open/close, allocation/free).

Return ONLY the JSON object.  No explanation, no markdown fencing.

File: {file}
Function: {function}

```
{source}
```"""

# Cap source length to keep LLM cost reasonable per function.
_MAX_SOURCE_CHARS = 8000

# Cap how many functions get the LLM summary pass.
_MAX_FUNCTIONS = 80


def identify_summary_candidates(
    workqueue: List[Dict[str, Any]],
    taint_summary_results: Optional[Dict[str, Any]],
    checklist: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Find functions that need LLM summaries.

    A function is a candidate when:
    1. It has callers or callees in the work queue (connected).
    2. It does not already have a mechanical summary.
    """
    if not workqueue:
        return []

    existing = set(taint_summary_results or {})
    queue_keys: Set[str] = set()
    queue_by_key: Dict[str, Dict[str, Any]] = {}

    for gap in workqueue:
        key = f"{gap['file']}:{gap['name']}"
        queue_keys.add(key)
        queue_by_key[key] = gap

    connected: Set[str] = set()
    for gap in workqueue:
        for ce in gap.get("callees", []):
            ce_name = ce if isinstance(ce, str) else ce.get("name", "")
            ce_file = "" if isinstance(ce, str) else ce.get("file", gap["file"])
            ce_key = f"{ce_file}:{ce_name}"
            if ce_key in queue_keys:
                key = f"{gap['file']}:{gap['name']}"
                connected.add(key)
                connected.add(ce_key)

    candidates = []
    for key in connected:
        if key in existing:
            continue
        gap = queue_by_key.get(key)
        if gap is None:
            continue
        candidates.append(gap)

    candidates.sort(
        key=lambda g: g.get("priority_score", 0.0), reverse=True,
    )
    return candidates[:_MAX_FUNCTIONS]


def run_llm_summary_pass(
    candidates: List[Dict[str, Any]],
    target_path: Path,
    config: Any,
) -> Dict[str, FunctionSummary]:
    """Run focused LLM calls to extract summaries for candidates.

    Returns a dict of "file:function" → FunctionSummary.
    """
    if not candidates:
        return {}

    try:
        from core.llm.client import LLMClient
        client = LLMClient()
    except Exception:
        logger.debug("LLM client unavailable for summary pass", exc_info=True)
        return {}

    items_with_source = []
    for gap in candidates:
        file_path = gap["file"]
        function_name = gap["name"]
        source = _read_source(target_path, file_path, function_name,
                              gap.get("line_start"), gap.get("line_end"))
        if source:
            items_with_source.append((file_path, function_name, source))

    if not items_with_source:
        return {}

    def _do_one(item: tuple) -> Optional[tuple]:
        file_path, function_name, source = item
        prompt = _SUMMARY_USER_TEMPLATE.format(
            file=file_path,
            function=function_name,
            source=source[:_MAX_SOURCE_CHARS],
        )
        response = client.generate(
            prompt,
            system_prompt=_SUMMARY_SYSTEM_PROMPT,
            task_type="audit",
        )
        text = response.text if hasattr(response, "text") else str(response)
        summary = _parse_summary_response(text, function_name, file_path)
        if summary and not summary.is_empty():
            return (f"{file_path}:{function_name}", summary)
        return None

    from core.llm.concurrency import run_parallel
    raw = run_parallel(
        items_with_source, _do_one,
        max_workers=client.recommended_max_workers,
        label="llm-summaries",
    )

    results: Dict[str, FunctionSummary] = {}
    for r in raw:
        if r is not None:
            results[r[0]] = r[1]

    if results:
        logger.info(
            "llm_summary_pass: %d summaries extracted (%d failed) from %d candidates",
            len(results), len(items_with_source) - len(results),
            len(candidates),
        )

    return results


def _read_source(
    target_path: Path,
    file_path: str,
    function_name: str,
    line_start: Optional[int] = None,
    line_end: Optional[int] = None,
) -> Optional[str]:
    """Read function source from the target directory."""
    full_path = target_path / file_path
    if not full_path.is_file():
        return None

    try:
        text = full_path.read_text(errors="replace")
    except OSError:
        return None

    if len(text) > 500_000:
        return None

    if line_start and line_end and line_start > 0:
        lines = text.splitlines()
        start = max(0, line_start - 1)
        end = min(len(lines), line_end)
        return "\n".join(lines[start:end])

    return text


def _parse_summary_response(
    text: str,
    function: str,
    file: str,
) -> Optional[FunctionSummary]:
    """Parse a JSON summary response into a FunctionSummary."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        lines = [ln for ln in lines if not ln.startswith("```")]
        text = "\n".join(lines)

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                data = json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                return None
        else:
            return None

    if not isinstance(data, dict):
        return None

    preconditions = []
    for pc in data.get("preconditions", []):
        param = pc.get("parameter", pc.get("param", ""))
        assumption = pc.get("assumption", pc.get("condition", ""))
        if param and assumption:
            preconditions.append(Precondition(
                param=param,
                param_index=pc.get("param_index", pc.get("source_index", 0)),
                conditions=[assumption],
                evidence_tier=EvidenceTier.HEURISTIC,
            ))

    taint_rules = []
    for tf in data.get("taint_flows", []):
        source_param = tf.get("source_param", "")
        sink_call = tf.get("sink_call", "")
        if source_param and sink_call:
            taint_rules.append(TaintRule(
                source_param=source_param,
                source_index=tf.get("source_index", 0),
                sink_call=sink_call,
                sink_arg_index=tf.get("sink_arg_index", 0),
                evidence_tier=EvidenceTier.HEURISTIC,
            ))

    callees = data.get("callees", [])
    callers = data.get("callers", [])
    error_paths = data.get("error_paths", [])
    state_transitions = data.get("state_transitions", [])

    if not isinstance(callees, list):
        callees = []
    if not isinstance(callers, list):
        callers = []
    if not isinstance(error_paths, list):
        error_paths = []
    if not isinstance(state_transitions, list):
        state_transitions = []

    return FunctionSummary(
        function=function,
        file=file,
        taint_rules=taint_rules,
        preconditions=preconditions,
        callees=[str(c) for c in callees],
        callers=[str(c) for c in callers],
        error_paths=[str(e) for e in error_paths],
        state_transitions=[str(s) for s in state_transitions],
        source="llm",
        confidence="medium",
        evidence_tier=EvidenceTier.HEURISTIC,
    )

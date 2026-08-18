"""Mechanically confirm or refute a flow trace with Joern taint analysis.

Runs as TRACE-4b in `/understand --trace`. Given a flow trace produced
by the LLM (trace.md output format) and a started Joern server with the
target's CPG imported, asks the dataflow engine whether the traced
source → sink flow actually exists:

* the trace gains a ``joern_verification`` block
  (``verified`` / ``joern_flow_count`` / ``elapsed_ms`` / ``joern_steps``)
* ``summary.confidence`` is upgraded to ``mechanically_confirmed`` when
  Joern reproduces the flow, downgraded to ``mechanical_refuted`` when
  it cannot (the prior value is preserved in the verification block)

A refutation is evidence, not proof of absence — Joern's
inter-procedural depth is bounded — which is why the confidence label
says *refuted*, and the LLM is expected to note the discrepancy rather
than silently drop the trace.

Opt-in — callers skip this entirely when Joern is not installed or no
CPG cache exists. When the source method or sink call name cannot be
resolved from the trace (e.g. a route string like ``POST /api/query``
instead of a function name), the verification block records
``verified: null`` with a ``skipped`` reason instead of guessing.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

logger = logging.getLogger(__name__)

_IDENTIFIER_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*"
)
_CALL_NAME_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def _is_identifier(value: Any) -> bool:
    # fullmatch, not match — a $-anchored match() still admits a
    # trailing newline.
    return isinstance(value, str) and bool(_IDENTIFIER_RE.fullmatch(value))


def _last_call_name(text: Any) -> str | None:
    """Extract the final bare call name from a snippet.

    ``psycopg2.cursor.execute()`` → ``execute``; ``strcpy(dst, src)``
    → ``strcpy``.
    """
    if not isinstance(text, str):
        return None
    names = _CALL_NAME_RE.findall(text)
    return names[-1] if names else None


def extract_source_sink(trace: dict[str, Any]) -> tuple[str | None, str | None]:
    """Best-effort (source_method, sink_call) extraction from a trace.

    Source: ``meta.entry_point`` when it is a plain function name.
    Sink: ``meta.target_sink`` when it is a plain name, else the call
    name parsed from the last sink-type step's ``definition``.
    """
    meta = trace.get("meta") or {}

    source = meta.get("entry_point")
    if not _is_identifier(source):
        source = None

    sink = meta.get("target_sink")
    if not _is_identifier(sink):
        sink = _last_call_name(sink)
    if not sink:
        for step in reversed(trace.get("steps") or []):
            if step.get("type") == "sink":
                sink = _last_call_name(step.get("definition"))
                if not _is_identifier(sink):
                    sink = None
                break

    return source, sink


def _flow_steps(flow: Any) -> list[dict[str, Any]]:
    """Serialise one TaintFlow's steps into the joern_steps shape."""
    steps = getattr(flow, "steps", None) or []
    out = []
    for s in steps:
        if hasattr(s, "to_dict"):
            s = s.to_dict()
        if isinstance(s, dict):
            out.append({
                "file": s.get("file", ""),
                "line": s.get("line", 0),
                "code": s.get("code", ""),
                "function": s.get("function", ""),
            })
    return out


def enrich_trace_with_joern(
    trace: dict[str, Any],
    server: Any,
    *,
    source_method: str | None = None,
    sink_call: str | None = None,
    timeout: int | None = None,
) -> dict[str, Any]:
    """Annotate a flow trace with a Joern taint verification verdict.

    *server* is a started :class:`packages.joern.server.JoernServer`
    with the target's CPG already imported. *source_method* /
    *sink_call* override the names extracted from the trace — pass them
    when the entry point is a route string rather than a function name.

    Mutates and returns *trace*.
    """
    extracted_source, extracted_sink = extract_source_sink(trace)
    source_method = source_method or extracted_source
    sink_call = sink_call or extracted_sink

    if not source_method or not sink_call:
        missing = []
        if not source_method:
            missing.append("source method")
        if not sink_call:
            missing.append("sink call")
        reason = (
            "could not resolve " + " and ".join(missing)
            + " from the trace; pass source_method/sink_call explicitly"
        )
        logger.info("joern trace verification skipped: %s", reason)
        trace["joern_verification"] = {"verified": None, "skipped": reason}
        return trace

    start = time.monotonic()
    try:
        flows = server.run_taint_query(
            source_method, sink_call, timeout=timeout,
        ) or []
    except Exception:
        logger.debug(
            "joern taint query failed for %s -> %s",
            source_method, sink_call, exc_info=True,
        )
        trace["joern_verification"] = {
            "verified": None,
            "skipped": f"joern query failed for {source_method} -> {sink_call}",
        }
        return trace
    elapsed_ms = int((time.monotonic() - start) * 1000)

    verified = len(flows) > 0
    verification: dict[str, Any] = {
        "verified": verified,
        "joern_flow_count": len(flows),
        "elapsed_ms": elapsed_ms,
        "joern_steps": _flow_steps(flows[0]) if flows else [],
        "source_method": source_method,
        "sink_call": sink_call,
    }

    summary = trace.get("summary")
    if isinstance(summary, dict):
        previous = summary.get("confidence")
        if previous:
            verification["previous_confidence"] = previous
        summary["confidence"] = (
            "mechanically_confirmed" if verified else "mechanical_refuted"
        )

    trace["joern_verification"] = verification
    return trace

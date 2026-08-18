"""Flow-trace and caller call-site context for /agentic per-finding prompts.

Mirrors ``source_intel_inject``: a per-repo prepare step caches parsed
/understand flow traces (discovered via the understand bridge's
three-tier search) plus the inventory checklist; a per-finding lookup
returns bounded ``UntrustedBlock``s:

- ``flow-trace-context`` — the traced source→sink flow this finding's
  function sits on (hop chain, tainted variables, attacker control).
  Reachability misjudgment on isolated snippets is the classifier's
  dominant failure mode; the trace shows the finding in its flow.
- ``caller-call-sites`` — the audit-side caller extractor's call-site
  snippets, so the classifier sees how the function is actually
  invoked instead of guessing.

Everything is best-effort and bounded; failures collapse to "no extra
context this run". All content travels as untrusted blocks through the
prompt envelope.
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any

from core.security.prompt_envelope import UntrustedBlock

logger = logging.getLogger(__name__)

MAX_TRACES_PER_FINDING = 2
MAX_HOPS_PER_TRACE = 8
MAX_CALLERS_PER_FINDING = 5
MAX_TRACES_CACHED = 50
_MAX_FIELD_CHARS = 160

# repo path → (flow traces, checklist, context map)
_FC_CACHE: dict[
    str,
    tuple[
        list[dict[str, Any]],
        dict[str, Any] | None,
        dict[str, Any] | None,
    ],
] = {}
_FC_LOCK = threading.RLock()


def prepare_flow_context(
    repo_path: Path,
    *,
    checklist: dict[str, Any] | None = None,
    understand_dir: Path | None = None,
    run_dir: Path | None = None,
) -> None:
    """Pre-seed flow traces + checklist for a repo. Best-effort.

    ``understand_dir`` points straight at a run dir containing
    ``flow-trace-*.json``; otherwise ``run_dir`` (this run's output
    dir) seeds the understand bridge's three-tier discovery.
    """
    resolved = str(Path(repo_path).resolve())
    traces: list[dict[str, Any]] = []
    context_map: dict[str, Any] | None = None
    try:
        source_dir = understand_dir
        if source_dir is None and run_dir is not None:
            from core.orchestration.understand_bridge import (
                find_understand_output,
            )

            source_dir, _stale = find_understand_output(
                Path(run_dir), target_path=resolved,
            )
        if source_dir is not None:
            traces = _load_traces(Path(source_dir))
            context_map = _load_context_map(Path(source_dir))
    except Exception:
        logger.debug("flow-context trace discovery failed", exc_info=True)
        traces = []

    with _FC_LOCK:
        _FC_CACHE[resolved] = (traces, checklist, context_map)
    if traces:
        logger.info(
            "flow-context: %d flow trace(s) available for per-finding "
            "prompts", len(traces),
        )


def _load_traces(source_dir: Path) -> list[dict[str, Any]]:
    traces: list[dict[str, Any]] = []
    seen_ids: set = set()
    for path in sorted(source_dir.glob("flow-trace-*.json")):
        if len(traces) >= MAX_TRACES_CACHED:
            break
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict) or not data.get("steps"):
            continue
        trace_id = data.get("id") or path.stem
        if trace_id in seen_ids:
            continue
        seen_ids.add(trace_id)
        traces.append(data)
    return traces


def _load_context_map(source_dir: Path) -> dict[str, Any] | None:
    path = source_dir / "context-map.json"
    try:
        if path.is_file():
            data = json.loads(path.read_text())
            if isinstance(data, dict):
                return data
    except (OSError, ValueError):
        pass
    return None


def clear_flow_context_cache() -> None:
    """Test hook."""
    with _FC_LOCK:
        _FC_CACHE.clear()


def context_blocks_for_finding(
    finding: dict[str, Any],
) -> tuple[UntrustedBlock, ...]:
    """Flow-trace + caller call-site blocks for one finding.

    Returns () when the repo wasn't prepared, nothing matches, or any
    step fails — never raises.
    """
    repo = finding.get("repo_path")
    if not repo:
        return ()
    with _FC_LOCK:
        entry = _FC_CACHE.get(str(Path(repo).resolve()))
    if entry is None:
        return ()
    traces, checklist, context_map = entry

    file_path = finding.get("file_path", "") or finding.get("file", "")
    metadata = finding.get("metadata") or {}
    function = metadata.get("name") or finding.get("function") or ""

    blocks: list[UntrustedBlock] = []

    try:
        matched = [
            t for t in traces if _trace_matches(t, file_path, function)
        ][:MAX_TRACES_PER_FINDING]
        for trace in matched:
            blocks.append(UntrustedBlock(
                content=_render_trace(trace, file_path, function),
                kind="flow-trace-context",
                origin="understand-flow-trace",
            ))
    except Exception:
        logger.debug("flow-trace block build failed", exc_info=True)

    try:
        if (checklist or context_map) and function and file_path:
            caller_block = _build_caller_block(
                checklist, file_path, function, Path(repo),
                context_map=context_map,
            )
            if caller_block is not None:
                blocks.append(caller_block)
    except Exception:
        logger.debug("caller-call-site block build failed", exc_info=True)

    return tuple(blocks)


# ---------------------------------------------------------------------------
# Flow traces
# ---------------------------------------------------------------------------


def _trace_matches(
    trace: dict[str, Any],
    file_path: str,
    function: str,
) -> bool:
    """Whether the finding's file/function appears on the traced path."""
    if not file_path and not function:
        return False
    for step in trace.get("steps", []):
        if not isinstance(step, dict):
            continue
        step_file = step.get("file", "")
        defn = str(step.get("definition") or "")
        call_site = str(step.get("call_site") or "")
        if file_path and (
            step_file == file_path
            or defn.startswith(f"{file_path}:")
            or call_site.startswith(f"{file_path}:")
        ):
            if not function:
                return True
            if function in str(step.get("function", "")) or _mentions(
                function, defn, step.get("description", ""),
            ):
                return True
            # Same file is a weaker match; accept when the function
            # is unknown to the trace step schema.
            if "function" not in step:
                return True
    return False


def _mentions(function: str, *texts: Any) -> bool:
    return any(function in str(t or "") for t in texts)


def _clip(text: Any, max_len: int = _MAX_FIELD_CHARS) -> str:
    s = " ".join(str(text or "").split())
    return s[: max_len - 3] + "..." if len(s) > max_len else s


def _render_trace(
    trace: dict[str, Any],
    file_path: str,
    function: str,
) -> str:
    """Bounded plain-text rendering of one flow trace."""
    lines: list[str] = []
    name = _clip(trace.get("name", ""))
    trace_id = _clip(trace.get("id", ""), 40)
    header = f"Traced data flow {trace_id}"
    if name:
        header += f": {name}"
    proximity = trace.get("proximity")
    if isinstance(proximity, (int, float)):
        header += f" (proximity {proximity}/10)"
    lines.append(header)

    steps = [s for s in trace.get("steps", []) if isinstance(s, dict)]
    shown = steps[:MAX_HOPS_PER_TRACE]
    for step in shown:
        n = step.get("step", "?")
        kind = _clip(step.get("type", ""), 20)
        where = _clip(step.get("definition") or step.get("file") or "", 80)
        desc = _clip(step.get("description", ""))
        line = f"  {n}. [{kind}] {where}"
        if desc:
            line += f" — {desc}"
        tainted = step.get("tainted_var")
        if tainted:
            line += f" [tainted: {_clip(tainted, 40)}]"
        lines.append(line)
    if len(steps) > len(shown):
        lines.append(f"  ... {len(steps) - len(shown)} more hop(s)")

    control = trace.get("attacker_control")
    if isinstance(control, dict) and control.get("level"):
        lines.append(
            f"  attacker control: {_clip(control.get('level'), 30)}"
            + (
                f" — {_clip(control.get('what'))}"
                if control.get("what") else ""
            )
        )
    summary = trace.get("summary")
    if isinstance(summary, dict) and summary.get("verdict"):
        lines.append(f"  trace verdict: {_clip(summary.get('verdict'), 60)}")

    target = f"{file_path}:{function}" if function else file_path
    lines.append(
        f"This finding ({_clip(target, 120)}) sits on the traced flow "
        "above — weigh reachability accordingly."
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Caller call-sites
# ---------------------------------------------------------------------------


def _build_caller_block(
    checklist: dict[str, Any] | None,
    file_path: str,
    function: str,
    repo_path: Path,
    *,
    context_map: dict[str, Any] | None = None,
) -> UntrustedBlock | None:
    from core.audit.context import collect_caller_call_sites

    callers = collect_caller_call_sites(
        checklist, file_path, function, repo_path,
        max_callers=MAX_CALLERS_PER_FINDING,
        context_map=context_map,
    )
    if not callers:
        return None

    lines = [f"Known callers of {_clip(function, 80)}:"]
    for caller in callers:
        where = f"{caller.get('file', '')}:{caller.get('line_start', 0)}"
        lines.append(f"- {_clip(caller.get('name', ''), 80)} at {where}")
        call_site = caller.get("call_site")
        if call_site:
            for snippet_line in str(call_site).splitlines()[:3]:
                lines.append(f"    {snippet_line}")
    return UntrustedBlock(
        content="\n".join(lines),
        kind="caller-call-sites",
        origin="inventory-call-graph",
    )

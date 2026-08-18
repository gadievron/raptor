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
import re
from pathlib import Path
from typing import Any

from core.analysis.summaries import FunctionSummary, Precondition, TaintRule
from core.evidence import EvidenceTier
from core.security.prompt_framing import with_audit_framing

logger = logging.getLogger(__name__)

# Audit-purpose framing: this class was AUP-refused 18/18 in one
# comparison audit and again 15/15 with the v1 one-paragraph framing;
# the review class, which carries the full audit context, went 36/36
# and 35/35 in the same runs. v2 framing + program-analysis task
# vocabulary below. See core.security.prompt_framing for the history.
_SUMMARY_SYSTEM_PROMPT = with_audit_framing(
    "You are extracting a function's behavioural summary — the same "
    "intermediate facts a static-analysis engine (Joern, CodeQL) "
    "derives mechanically. The summary feeds the audit's verification "
    "tools as inter-procedural context. Be precise and terse.\n\n"
    "Analyse the function provided in the untrusted source-code block "
    "(its file and function name are given in the slots) and return a "
    "JSON object with these fields:\n\n"
    '- "preconditions": list of {"parameter": str, "assumption": str} — '
    "what each parameter must satisfy for correct execution (null "
    "checks, bounds, valid state).\n"
    '- "taint_flows": list of {"source_param": str, "source_index": int, '
    '"sink_call": str, "sink_arg_index": int} — standard dataflow '
    "summaries: parameters whose data reaches memory-, process-, or "
    "query-affecting callees (memcpy, strcpy, system, exec, SQL, "
    "etc.), so the verification tools can check the call sites.\n"
    '- "callees": list of "file:function" strings for functions this function calls.\n'
    '- "callers": list of "file:function" strings if visible from the source.\n'
    '- "error_paths": list of return-statement strings for error/failure returns.\n'
    '- "state_transitions": list of strings describing resource state changes '
    "(lock acquire/release, file open/close, allocation/free).\n\n"
    "Return ONLY the JSON object.  No explanation, no markdown fencing.",
)


def build_summary_prompt(
    file_path: str,
    function_name: str,
    source: str,
    *,
    model_id: str = "",
) -> tuple[str, str]:
    """Envelope the summary-extraction prompt: source code in an
    ``UntrustedBlock``, identifiers in slots, instructions in system.
    Returns ``(user, system)``."""
    from core.security.prompt_envelope import TaintedString, UntrustedBlock

    from ._util import envelope_prompt

    block = UntrustedBlock(
        content=source[:_MAX_SOURCE_CHARS],
        kind="source-code",
        origin=f"{file_path}:{function_name}",
    )
    slots = {
        "file": TaintedString(value=file_path, trust="untrusted"),
        "function": TaintedString(value=function_name, trust="untrusted"),
    }
    # transparent_payload: the taint-extraction ask over an ENCODED
    # payload is hard-refused 100% by Claude models while the same ask
    # over plaintext succeeds (measured; see envelope_prompt's
    # docstring). Compensating injection defences for the plaintext
    # rendering: pre-call preflight over the source, post-parse
    # source-grounding of every extracted claim, envelope-echo
    # discard — see _ground_summary / summarize_functions.
    return envelope_prompt(
        _SUMMARY_SYSTEM_PROMPT, (block,), slots, model_id=model_id,
        transparent_payload=True,
    )

# Cap source length to keep LLM cost reasonable per function.
_MAX_SOURCE_CHARS = 8000

# Cap how many functions get the LLM summary pass.
_MAX_FUNCTIONS = 80


def _edge_endpoints(edge: dict[str, Any]) -> tuple[str, str] | None:
    """Parse one context-map call edge into ``(caller_key, callee_key)``.

    Mirrors the orchestrator's topo-ordering parse: edges carry either
    split fields (``caller_file`` + ``caller``, ``callee_file`` +
    ``callee``) or combined ``"file:function"`` strings; a callee with
    no file defaults to the caller's file (same-TU call).
    """
    caller_file = edge.get("caller_file", "")
    caller_func = edge.get("caller", "")
    if not caller_file and ":" in caller_func:
        caller_file, _, caller_func = caller_func.partition(":")
        caller_func = caller_func.split("(")[0].strip()
    if not caller_file or not caller_func:
        return None
    callee_raw = edge.get("callee", "")
    callee_file = edge.get("callee_file", "")
    callee_name = callee_raw
    if not callee_file and ":" in callee_raw:
        callee_file, _, callee_name = callee_raw.partition(":")
        callee_name = callee_name.split("(")[0].strip()
    if not callee_file:
        callee_file = caller_file
    if not callee_name:
        return None
    return f"{caller_file}:{caller_func}", f"{callee_file}:{callee_name}"


def identify_summary_candidates(
    workqueue: list[dict[str, Any]],
    taint_summary_results: dict[str, Any] | None,
    checklist: dict[str, Any] | None,
    *,
    call_edges: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Find functions that need LLM summaries.

    A function is a candidate when:
    1. It has callers or callees in the work queue (connected).
    2. It does not already have a mechanical summary.

    Connectivity comes from two sources: a gap's own ``callees`` field
    (legacy shape) and, when provided, the context map's ``call_edges``
    — today's workqueue gaps carry no ``callees`` field, so without
    the edges every function looks disconnected and the pass finds
    zero candidates.
    """
    if not workqueue:
        return []

    existing = set(taint_summary_results or {})
    queue_keys: set[str] = set()
    queue_by_key: dict[str, dict[str, Any]] = {}

    for gap in workqueue:
        key = f"{gap['file']}:{gap['name']}"
        queue_keys.add(key)
        queue_by_key[key] = gap

    connected: set[str] = set()
    for gap in workqueue:
        for ce in gap.get("callees", []):
            ce_name = ce if isinstance(ce, str) else ce.get("name", "")
            ce_file = "" if isinstance(ce, str) else ce.get("file", gap["file"])
            ce_key = f"{ce_file}:{ce_name}"
            if ce_key in queue_keys:
                key = f"{gap['file']}:{gap['name']}"
                connected.add(key)
                connected.add(ce_key)

    for edge in call_edges or []:
        endpoints = _edge_endpoints(edge)
        if endpoints is None:
            continue
        caller_key, callee_key = endpoints
        if caller_key in queue_keys and callee_key in queue_keys:
            connected.add(caller_key)
            connected.add(callee_key)

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
    candidates: list[dict[str, Any]],
    target_path: Path,
    config: Any,
) -> dict[str, FunctionSummary]:
    """Run focused LLM calls to extract summaries for candidates.

    Returns a dict of "file:function" → FunctionSummary.
    """
    if not candidates:
        return {}

    try:
        # Prefer the run's budget-governed client so summary spend
        # enters the run ledger and the per-call reservation gate.
        client = getattr(config, "llm_budget_client", None)
        if client is None:
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

    def _do_one(item: tuple) -> tuple | None:
        file_path, function_name, source = item
        # Injection preflight over the source BEFORE spending the
        # call: the summary class renders its payload plaintext (see
        # build_summary_prompt), so a source file carrying known
        # injection phrasing gets no LLM pass at all — the mechanical
        # (Joern/AST) summary path covers it instead. Real code
        # essentially never trips the corpus; a hit is a loud signal.
        from core.security.prompt_input_preflight import preflight

        pf = preflight(source)
        if pf.has_injection_indicators:
            logger.warning(
                "llm_summary: injection indicators (%s) in %s:%s "
                "source — skipping LLM summary for this function "
                "(mechanical summaries only)",
                ",".join(pf.indicators), file_path, function_name,
            )
            return None
        prompt, system_prompt = build_summary_prompt(
            file_path, function_name, source,
            model_id=getattr(client, "model_name", "") or "",
        )
        # Short call class: minimal prompt, small response. The
        # per-call ceiling (honoured by the claudecode transport;
        # SDK providers ignore it) stops one wedged summary call
        # from holding a worker for the transport's full 600s
        # default. Timeout retries keep the client default cap of
        # one — a short call's timeout is usually transient, and an
        # identical retry is cheap.
        from core.audit.llm_review import SHORT_CALL_TIMEOUT_S
        response = client.generate(
            prompt,
            system_prompt=system_prompt,
            task_type="audit",
            timeout_s=SHORT_CALL_TIMEOUT_S,
            call_class="summary",
        )
        # LLMResponse carries output in ``content`` (no ``text``
        # attribute); str(response) is the dataclass repr, which the
        # summary parser cannot read.
        from core.audit.batch_glance import _response_text
        text = _response_text(response)
        summary = _parse_summary_response(text, function_name, file_path)
        if summary is not None:
            # Source-grounding: drop any extracted claim that does not
            # correspond to the code it was extracted from (injection
            # defence for the plaintext payload — see _ground_summary).
            summary = _ground_summary(summary, source)
        if summary and not summary.is_empty():
            return (f"{file_path}:{function_name}", summary)
        return None

    from core.llm.concurrency import run_parallel
    raw = run_parallel(
        items_with_source, _do_one,
        max_workers=client.recommended_max_workers,
        label="llm-summaries",
    )

    results: dict[str, FunctionSummary] = {}
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
    line_start: int | None = None,
    line_end: int | None = None,
) -> str | None:
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


# Strict top-level schema for the summary response — the keys the
# prompt declares, and nothing else. Unknown fields REJECT the whole
# response (schema-invalid == malformed; caller already handles the
# None return by skipping the summary). Same floor policy as
# core.llm.response_validation.unknown_response_fields.
_SUMMARY_RESPONSE_KEYS = frozenset({
    "preconditions",
    "taint_flows",
    "callees",
    "callers",
    "error_paths",
    "state_transitions",
})


_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _ground_summary(
    summary: FunctionSummary, source: str,
) -> FunctionSummary:
    """Drop extracted claims that do not correspond to the source.

    Injection defence for the plaintext-payload summary class: every
    field the model extracts is checkable against the function source
    it was extracted FROM. Parameters and sink calls must be
    identifiers present in the source; callees/callers must name
    identifiers in it (the prompt asks for callers only "if visible
    from the source", so this drops hallucinations too); error paths
    must literally occur in it. A prompt-injected response can then
    at worst SUPPRESS true facts (the same failure mode as a refusal,
    handled by the mechanical fallback) — it cannot insert a
    fabricated flow, precondition, or callee that survives into the
    audit context.

    State transitions are free prose consumed as descriptive context
    only; they carry no identifiers to check and ground no decisions,
    so they pass through.
    """
    idents = set(_IDENT_RE.findall(source))

    def _known_name(raw: str) -> bool:
        # Accept "file.c:function", "function", "function(...)" forms.
        base = str(raw).rsplit(":", 1)[-1].split("(")[0].strip()
        return bool(base) and base in idents

    norm_source = " ".join(source.split())
    summary.taint_rules = [
        t for t in summary.taint_rules
        if t.source_param in idents and _known_name(t.sink_call)
    ]
    summary.preconditions = [
        p for p in summary.preconditions if p.param in idents
    ]
    summary.callees = [c for c in summary.callees if _known_name(c)]
    summary.callers = [c for c in summary.callers if _known_name(c)]
    summary.error_paths = [
        e for e in summary.error_paths
        if " ".join(str(e).split()) in norm_source
    ]
    return summary


def _parse_summary_response(
    text: str,
    function: str,
    file: str,
) -> FunctionSummary | None:
    """Parse a JSON summary response into a FunctionSummary.

    Returns None for malformed responses — including responses that
    carry top-level fields outside :data:`_SUMMARY_RESPONSE_KEYS`
    (strict unknown-field floor), and responses that echo envelope
    structure (``<untrusted-`` — parroted envelope tags are evidence
    the model is replaying attacker-adjacent structure rather than
    answering; discard as contaminated).
    """
    text = text.strip()
    if "<untrusted-" in text:
        logger.warning(
            "summary response for %s:%s discarded — envelope structure "
            "echoed in output (possible injection contamination)",
            file, function,
        )
        return None
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

    unknown = sorted(k for k in data if k not in _SUMMARY_RESPONSE_KEYS)
    if unknown:
        logger.debug(
            "summary response for %s:%s rejected — unknown fields %s",
            file, function, unknown,
        )
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

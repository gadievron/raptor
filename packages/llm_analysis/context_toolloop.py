"""Bounded read-only retrieval tool loop for the per-finding classifier.

Sibling of :mod:`packages.llm_analysis.context_expansion` (the one-shot
second look): under the opt-in ``--context-toolloop`` flag, a finding
whose first verdict is explicitly UNCERTAIN gets a short request loop
instead of a single wider re-ask — each turn the model may either
render its verdict or request specific additional context through a
small CLOSED tool vocabulary, and the requested material rides the next
turn's prompt. This module is the policy layer: the vocabulary, the
mechanical request validation, the containment and volume rails, and
the bounded record shapes. The loop driver lives in the agent.

Contracts, each pinned by tests:

* **Closed vocabulary, read-only** (:data:`TOOL_VOCABULARY`) — exactly
  ``read_span`` / ``list_callers`` / ``list_callees``. A request naming
  anything else is a counted refusal and is NEVER executed: the request
  side of the loop is model output over target-derived prompts, so it
  is hostile input, not an instruction channel. No shell, no writes, no
  network — ``read_span`` reads repo files through a resolved-
  containment check, and the call-graph tools reuse the existing
  bounded inventory seams (``core.audit.context`` collectors via the
  J-series block builders), which resolve from the checklist/context
  map and never execute anything.
* **Resolved containment on every path** — each file argument is
  joined to the analysed repo root and RESOLVED before the prefix
  check (:func:`core.paths.confine`): traversal segments, out-of-root
  absolute paths, and symlinks that point outside the repo are refused
  with the counted ``path_escape`` marker. The check is filesystem-
  aware, not lexical.
* **Every volume knob is a named constant derived from the J-series
  window constants** — no independent literals. Turn, request, span,
  and byte caps below; each is argued in both directions.
* **Counted, never silent** — every refusal carries a reason, every
  served call its byte size; the state object accumulates the
  served/refused totals the agent folds into the run stats.
* **Bounded records** — the ``context_toolloop`` analysis-record entry
  carries capped per-request summaries (tool, status, validated echo,
  byte count) and verdict summaries, never raw tool-result bytes.

All tool results are target-derived text and travel as
``UntrustedBlock``s through the existing prompt-envelope chokepoint
(``core.security.prompt_envelope`` escapes ESC/CSI/OSC, C1 and bidi
controls at bundle egress) — this module adds no new prompt egress
path.
"""

from __future__ import annotations

import logging
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.paths import confine
from core.security.prompt_envelope import UntrustedBlock
from core.source import DEFAULT_MAX_SOURCE_CHARS, read_bytes_capped

from packages.llm_analysis.context_expansion import (
    EXPANDED_FINDING_CONTEXT_LINES,
)

logger = logging.getLogger(__name__)

#: The closed tool vocabulary. Read-only by construction: each name
#: maps to a repo-confined file read or an inventory-seam lookup.
#: Anything else — including near-misses and injection attempts riding
#: the model's structured output — is refused by name, never executed.
TOOL_VOCABULARY: frozenset[str] = frozenset(
    {"read_span", "list_callers", "list_callees"},
)

#: Schema field the request loop adds to the analysis schema on turns
#: where requesting is still allowed. Stripped from every analysis
#: dict before it is stored or joined.
CONTEXT_REQUESTS_FIELD = "context_requests"

#: LLM calls per triggered finding (the wall-clock/spend rail). Too
#: small (1): the loop degenerates to the one-shot expansion — the
#: model can never see a tool result before its forced verdict. Too
#: large: each turn is a full analysis-priced call on a finding the
#: run already paid for once, and a model that keeps requesting would
#: multiply the run bill; three turns = at most two request rounds,
#: enough to follow one lead and one follow-up before the forced
#: verdict.
MAX_TOOLLOOP_TURNS: int = 3

#: Tool requests honoured per turn. Too small (1): the model cannot
#: batch the natural "show me the caller AND the callee" pair and
#: burns a whole turn per item. Too large: per-turn prompt growth is
#: requests x TOOL_RESULT_MAX_BYTES, and every request past the first
#: few is speculative — the model has not seen the earlier results
#: yet. Requests past the cap are refused with one counted summary
#: marker.
MAX_REQUESTS_PER_TURN: int = 3

#: Lines a single read_span may return — derived from the expanded
#: re-run window (itself derived from FINDING_CONTEXT_LINES), so one
#: tool call can show at most what the J2 expansion's widened window
#: shows around one point. Too small: the model cannot read a whole
#: mid-sized function in one request and wastes turns stitching. Too
#: large: a single request re-bills a file-sized blob into every
#: remaining turn's prompt.
READ_SPAN_MAX_LINES: int = EXPANDED_FINDING_CONTEXT_LINES

#: Width cap per rendered source line — the caller-channel ``_clip``
#: discipline (the same 200-column bound the flow/caller and callee
#: blocks apply to raw target lines): a single minified or hostile
#: line must not dominate the block.
RENDERED_LINE_WIDTH: int = 200

#: Per-line rendering overhead allowance (line-number prefix,
#: separator, newline) used ONLY to derive the byte caps below so a
#: full-width, full-height span fits without tripping the defensive
#: truncation.
_LINE_RENDER_OVERHEAD: int = 16

#: Hard byte cap on ONE rendered tool result — derived as the largest
#: legitimate read_span rendering (max lines x max rendered width).
#: Too small: a legal full-window span gets truncated and the model
#: reasons about lines it thinks it received. Too large: the per-call
#: bound stops backing the per-finding total below. Oversize results
#: (a pathological seam rendering) are truncated with an explicit
#: elision marker, never served unbounded.
TOOL_RESULT_MAX_BYTES: int = READ_SPAN_MAX_LINES * (
    RENDERED_LINE_WIDTH + _LINE_RENDER_OVERHEAD
)

#: Per-finding total across ALL turns — the retained-bytes rail (tool
#: results accumulate into every subsequent turn's prompt, so the
#: total, not the per-call size, is what the last turn pays). Four
#: full-size results: with 2 request turns x 3 requests the loop
#: could otherwise retain 6; four bounds the steady-state prompt
#: growth to roughly twice the J2 expanded window's own volume while
#: still letting one full-window span per hop plus call-graph
#: results through. Too small: one legal span exhausts the loop.
#: Too large: the rail stops mattering. The check is a threshold
#: crossed at serve time, so the absolute retained bound is
#: TOOLLOOP_MAX_TOTAL_BYTES + TOOL_RESULT_MAX_BYTES.
TOOLLOOP_MAX_TOTAL_BYTES: int = 4 * TOOL_RESULT_MAX_BYTES

#: Byte cap for reading a target source file into the span cache —
#: the shared real-source-file budget class
#: (``core.source.DEFAULT_MAX_SOURCE_CHARS``), not a new literal.
_MAX_SPAN_FILE_BYTES: int = DEFAULT_MAX_SOURCE_CHARS

#: Parse-side argument bounds. These bound HOSTILE model output before
#: anything touches disk: a file argument is a path-length-scale
#: string (deep repo paths fit well under 512), a function argument is
#: an identifier-scale string (mangled C++ names fit under 200), and a
#: line number past the guard is not a plausible source location. Too
#: small: legitimate deep paths / template names get refused. Too
#: large: the echo fields in records and blocks scale with attacker-
#: chosen lengths.
_MAX_FILE_ARG_CHARS: int = 512
_MAX_FUNCTION_ARG_CHARS: int = 200
_MAX_LINE_ARG: int = 10_000_000

#: Refusal reasons (counted markers). Constants so records and tests
#: never drift on spelling.
REFUSED_UNKNOWN_TOOL = "unknown_tool"
REFUSED_MALFORMED = "malformed_request"
REFUSED_TURN_CAP = "requests_per_turn_cap"
REFUSED_PATH_ESCAPE = "path_escape"
REFUSED_NOT_A_FILE = "not_a_file"
REFUSED_FILE_UNREADABLE = "file_unreadable"
REFUSED_INVALID_RANGE = "invalid_range"
REFUSED_SPAN_TOO_LARGE = "span_too_large"
REFUSED_BEYOND_EOF = "beyond_eof"
REFUSED_DUPLICATE = "duplicate_request"
REFUSED_BYTE_BUDGET = "byte_budget_exhausted"
REFUSED_SEAM_ERROR = "seam_error"

_ELISION_MARKER = "... [truncated]"

_CONTEXT_REQUESTS_SPEC = (
    "list of dicts, or null. OPTIONAL retrieval requests — use ONLY "
    "when the shown context is insufficient to decide; set null and "
    "complete every other field when you can render the verdict now. "
    'Each dict is one of: {"tool": "read_span", "file": "<repo-relative '
    'path>", "start": <line>, "end": <line>} to read source lines '
    f"(at most {READ_SPAN_MAX_LINES} lines per request); "
    '{"tool": "list_callers", "function": "<name>", "file": "<path, '
    'optional>"} or {"tool": "list_callees", "function": "<name>", '
    '"file": "<path, optional>"} for 1-hop call-graph context. '
    f"At most {MAX_REQUESTS_PER_TURN} requests per response; results "
    "arrive in the next message. Your final answer must carry the "
    "full verdict fields."
)


def augment_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """The base analysis schema plus the optional (nullable)
    ``context_requests`` field — a copy, the input is never mutated.

    The description string is crafted for the simple-schema
    validation contract: its first token ("list") types the field as
    an array, and the literal "null" marks it nullable, so a verdict
    response that omits or nulls the field is not penalised by the
    quality score."""
    out = dict(schema)
    out[CONTEXT_REQUESTS_FIELD] = _CONTEXT_REQUESTS_SPEC
    return out


def has_requests(raw: Any) -> bool:
    """Whether a validated ``context_requests`` value asks for
    anything at all (a non-empty list — content validation happens
    per-request in :func:`run_turn_requests`)."""
    return isinstance(raw, list) and len(raw) > 0


@dataclass
class ToolLoopState:
    """Per-finding loop state: budgets, dedup memo, split-file cache.

    One instance per triggered finding — nothing accumulates across
    findings (the retained-bytes rail is per finding), and the file
    cache means a degenerate model re-reading around one file costs
    one disk read, not one per turn.
    """

    repo_root: Path
    checklist: dict[str, Any] | None = None
    context_map: dict[str, Any] | None = None
    finding_file: str = ""
    total_result_bytes: int = 0
    served: int = 0
    refused: int = 0
    _seen: set[tuple] = field(default_factory=set)
    _file_cache: dict[Path, list[str] | None] = field(default_factory=dict)

    @classmethod
    def for_repo(
        cls,
        repo_path: str | Path,
        *,
        checklist: dict[str, Any] | None = None,
        context_map: dict[str, Any] | None = None,
        finding_file: str = "",
    ) -> ToolLoopState:
        return cls(
            repo_root=Path(repo_path).resolve(),
            checklist=checklist,
            context_map=context_map,
            finding_file=finding_file,
        )

    def byte_budget_exhausted(self) -> bool:
        return self.total_result_bytes >= TOOLLOOP_MAX_TOTAL_BYTES


def run_turn_requests(
    raw: Any,
    state: ToolLoopState,
) -> tuple[UntrustedBlock | None, list[dict[str, Any]]]:
    """Validate and execute one turn's ``context_requests`` value.

    Returns ``(results_block, request_records)``. The block carries
    the rendered results (and refusal notes) for the next turn's
    prompt as untrusted content; the records are the bounded per-
    request summaries for the analysis record — at most
    ``MAX_REQUESTS_PER_TURN`` + 1 entries (the +1 is the single
    collapsed over-cap refusal), never raw result bytes. Returns
    ``(None, [])`` when there are no requests (a verdict turn).
    Never raises: a failing seam is a counted ``seam_error`` refusal.
    """
    if not isinstance(raw, list) or not raw:
        return None, []
    records: list[dict[str, Any]] = []
    texts: list[str] = []
    for idx, item in enumerate(raw):
        if idx >= MAX_REQUESTS_PER_TURN:
            extra = len(raw) - MAX_REQUESTS_PER_TURN
            state.refused += extra
            records.append({
                "status": "refused",
                "reason": REFUSED_TURN_CAP,
                "count": extra,
            })
            texts.append(
                f"[{extra} additional request(s) refused: at most "
                f"{MAX_REQUESTS_PER_TURN} per turn]"
            )
            break
        record, text = _execute_one(item, state)
        records.append(record)
        texts.append(text)
    block = UntrustedBlock(
        content="Requested context results:\n" + "\n".join(texts),
        kind="toolloop-results",
        origin="classifier-tool-loop",
    )
    return block, records


def build_toolloop_record(
    *,
    reason: str,
    first: dict[str, Any],
    final: dict[str, Any],
    replaced: bool,
    turns: list[dict[str, Any]],
    end_reason: str,
    total_result_bytes: int,
    window_lines: int,
    caller_context_attached: bool,
    callee_context_attached: bool,
) -> dict[str, Any]:
    """The ``context_toolloop`` entry persisted on the finding's
    analysis record. Bounded by construction: the turn list is capped
    at the turn rail, each turn's request list at the per-turn rail
    (both enforced upstream, re-clamped here defensively), and the
    verdicts are the same bounded summaries the expansion record
    uses — never full analysis dicts or raw tool-result bytes."""
    from packages.llm_analysis.context_expansion import verdict_summary

    return {
        "triggered": True,
        "reason": reason,
        "performed": True,
        "window_lines": window_lines,
        "caller_context_attached": caller_context_attached,
        "callee_context_attached": callee_context_attached,
        "turns": [
            {
                "turn": t.get("turn"),
                "requests": list(t.get("requests", []))[
                    : MAX_REQUESTS_PER_TURN + 1
                ],
            }
            for t in turns[:MAX_TOOLLOOP_TURNS]
        ],
        "end_reason": end_reason,
        "total_result_bytes": total_result_bytes,
        "replaced": replaced,
        "first_verdict": verdict_summary(first),
        "final_verdict": verdict_summary(final),
    }


# ---------------------------------------------------------------------------
# Request execution (all private below here)
# ---------------------------------------------------------------------------


def _refuse(
    state: ToolLoopState,
    tool: str,
    reason: str,
    note: str,
) -> tuple[dict[str, Any], str]:
    """Counted refusal: record + block line. ``tool`` and ``note`` are
    operator-authored constants or already-validated echoes — never
    raw model/target bytes."""
    state.refused += 1
    return (
        {"tool": tool, "status": "refused", "reason": reason},
        f"[{tool} request refused: {reason} — {note}]",
    )


def _serve(
    state: ToolLoopState,
    tool: str,
    target: str,
    text: str,
) -> tuple[dict[str, Any], str]:
    """Counted serve: enforce the per-call byte cap (defensive — the
    renderers are line/width-bounded already), account the retained
    bytes, and return record + block text. ``target`` is a validated
    echo (confined relative path / charset-checked function name)."""
    data = text.encode("utf-8", errors="replace")
    if len(data) > TOOL_RESULT_MAX_BYTES:
        text = (
            data[:TOOL_RESULT_MAX_BYTES].decode("utf-8", errors="replace")
            + _ELISION_MARKER
        )
        data = text.encode("utf-8", errors="replace")
    state.served += 1
    state.total_result_bytes += len(data)
    record = {
        "tool": tool,
        "status": "served",
        "target": target,
        "result_bytes": len(data),
    }
    return record, f"[{tool} {target} — served]\n{text}"


def _has_control_chars(value: str) -> bool:
    """True when ``value`` carries control or format characters:
    C0/C1/DEL (category Cc) or Unicode format characters (category
    Cf — bidi overrides/isolates, zero-width joiners and friends).
    Cf matters because a served target echoes into the analysis
    record: a bidi-override-carrying function name would reorder the
    record's display (trojan-source style), so it is refused at
    validation instead."""
    return any(
        unicodedata.category(ch) in ("Cc", "Cf") for ch in value
    )


def _valid_file_arg(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= _MAX_FILE_ARG_CHARS
        and "\x00" not in value
        and not _has_control_chars(value)
    )


def _valid_function_arg(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value.strip()) <= _MAX_FUNCTION_ARG_CHARS
        and not _has_control_chars(value)
    )


def _valid_line_arg(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 1 <= value <= _MAX_LINE_ARG
    )


def _execute_one(
    item: Any,
    state: ToolLoopState,
) -> tuple[dict[str, Any], str]:
    """Validate one request mechanically, then execute. The request is
    hostile model output: the tool name is checked against the closed
    vocabulary FIRST (unknown names are never executed and never
    echoed raw), and every argument is bounds/charset-checked before
    anything touches disk."""
    if not isinstance(item, dict):
        return _refuse(
            state, "?", REFUSED_MALFORMED, "request is not an object",
        )
    tool = item.get("tool")
    if not isinstance(tool, str) or tool not in TOOL_VOCABULARY:
        return _refuse(
            state, "?", REFUSED_UNKNOWN_TOOL,
            "tool must be one of read_span/list_callers/list_callees",
        )
    if tool == "read_span":
        return _do_read_span(item, state)
    return _do_call_graph(item, state, tool)


def _confined(
    state: ToolLoopState,
    file_arg: str,
) -> tuple[Path, str] | None:
    """Resolve *file_arg* against the repo root with escape refusal.
    Returns ``(resolved_path, relative_echo)`` or ``None`` when the
    resolved path leaves the repo (traversal / absolute / symlink)."""
    resolved = confine(state.repo_root, file_arg)
    if resolved is None:
        return None
    try:
        rel = str(resolved.relative_to(state.repo_root))
    except ValueError:
        rel = resolved.name
    return resolved, rel


def _do_read_span(
    item: dict[str, Any],
    state: ToolLoopState,
) -> tuple[dict[str, Any], str]:
    file_arg = item.get("file")
    start = item.get("start")
    end = item.get("end")
    if not _valid_file_arg(file_arg):
        return _refuse(
            state, "read_span", REFUSED_MALFORMED,
            "file must be a plain relative path string",
        )
    if not _valid_line_arg(start) or not _valid_line_arg(end):
        return _refuse(
            state, "read_span", REFUSED_MALFORMED,
            "start/end must be positive integer line numbers",
        )
    if start > end:
        return _refuse(
            state, "read_span", REFUSED_INVALID_RANGE, "start must be <= end",
        )
    if end - start + 1 > READ_SPAN_MAX_LINES:
        return _refuse(
            state, "read_span", REFUSED_SPAN_TOO_LARGE,
            f"at most {READ_SPAN_MAX_LINES} lines per request",
        )
    confined = _confined(state, file_arg)
    if confined is None:
        return _refuse(
            state, "read_span", REFUSED_PATH_ESCAPE,
            "path resolves outside the analysed repository",
        )
    resolved, rel = confined
    if not resolved.is_file():
        return _refuse(
            state, "read_span", REFUSED_NOT_A_FILE,
            "no such file in the analysed repository",
        )
    key = ("read_span", str(resolved), start, end)
    if key in state._seen:
        return _refuse(
            state, "read_span", REFUSED_DUPLICATE,
            "identical request already answered for this finding",
        )
    if state.byte_budget_exhausted():
        return _refuse(
            state, "read_span", REFUSED_BYTE_BUDGET,
            "per-finding retrieval byte budget exhausted",
        )
    lines = _split_file(state, resolved)
    if lines is None:
        return _refuse(
            state, "read_span", REFUSED_FILE_UNREADABLE,
            "file could not be read",
        )
    if start > len(lines):
        return _refuse(
            state, "read_span", REFUSED_BEYOND_EOF,
            f"file has {len(lines)} line(s)",
        )
    state._seen.add(key)
    rendered = "\n".join(
        f"{start + i}: {_clip_source_line(line)}"
        for i, line in enumerate(lines[start - 1:end])
    )
    return _serve(state, "read_span", f"{rel}:{start}-{end}", rendered)


def _clip_source_line(line: str) -> str:
    """Width-bound one raw source line, preserving indentation (the
    caller-channel ``_clip`` collapses whitespace, which destroys code
    layout — spans are meant to be read as code)."""
    if len(line) > RENDERED_LINE_WIDTH:
        return line[: RENDERED_LINE_WIDTH - 3] + "..."
    return line


def _split_file(state: ToolLoopState, resolved: Path) -> list[str] | None:
    """Split-lines cache: one capped disk read per file per finding,
    however many spans the model requests from it. ``None`` (cached
    too) when the file cannot be read. An over-cap file degrades to
    its capped prefix with the trailing partial line dropped — spans
    past the prefix read as beyond-EOF."""
    if resolved in state._file_cache:
        return state._file_cache[resolved]
    got = read_bytes_capped(resolved, _MAX_SPAN_FILE_BYTES)
    if got is None:
        state._file_cache[resolved] = None
        return None
    data, truncated = got
    text = data.decode("utf-8", errors="replace")
    if truncated and "\n" in text:
        text = text.rsplit("\n", 1)[0]
    lines = text.splitlines()
    state._file_cache[resolved] = lines
    return lines


def _do_call_graph(
    item: dict[str, Any],
    state: ToolLoopState,
    tool: str,
) -> tuple[dict[str, Any], str]:
    function = item.get("function")
    if not _valid_function_arg(function):
        return _refuse(
            state, tool, REFUSED_MALFORMED,
            "function must be a plain identifier string",
        )
    file_arg = item.get("file")
    if file_arg is None or file_arg == "":
        rel = state.finding_file
    else:
        if not _valid_file_arg(file_arg):
            return _refuse(
                state, tool, REFUSED_MALFORMED,
                "file must be a plain relative path string",
            )
        confined = _confined(state, file_arg)
        if confined is None:
            return _refuse(
                state, tool, REFUSED_PATH_ESCAPE,
                "path resolves outside the analysed repository",
            )
        _resolved, rel = confined
    key = (tool, rel, function)
    if key in state._seen:
        return _refuse(
            state, tool, REFUSED_DUPLICATE,
            "identical request already answered for this finding",
        )
    if state.byte_budget_exhausted():
        return _refuse(
            state, tool, REFUSED_BYTE_BUDGET,
            "per-finding retrieval byte budget exhausted",
        )
    try:
        if tool == "list_callers":
            from core.audit.context import MAX_CALL_SITE_CALLERS

            from packages.llm_analysis.flow_context_inject import (
                caller_call_sites_block,
            )
            block = caller_call_sites_block(
                state.checklist, rel, function, state.repo_root,
                context_map=state.context_map,
                max_callers=MAX_CALL_SITE_CALLERS,
            )
        else:
            # Same bounded callee rendering the one-shot expansion
            # attaches — reuse, not a fork (width/height caps live
            # with the expansion module).
            from packages.llm_analysis.context_expansion import (
                _build_callee_block,
            )
            block = _build_callee_block(
                state.checklist, rel, function, state.repo_root,
                context_map=state.context_map,
            )
    except Exception:
        logger.debug("tool-loop %s seam failed", tool, exc_info=True)
        return _refuse(state, tool, REFUSED_SEAM_ERROR, "lookup failed")
    state._seen.add(key)
    relation = "callers" if tool == "list_callers" else "callees"
    text = (
        block.content if block is not None
        else f"(no {relation} found for {function})"
    )
    return _serve(state, tool, function, text)

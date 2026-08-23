"""Generic reachability gates for finding suppression and prioritisation.

Pure query functions that answer "should this finding be suppressed?" based
on call-graph topology, sink reachability, and entry-point reachability.
No audit-specific types — all inputs are plain strings and dicts.

Consumers: /audit orchestrator, /validate demoter, /agentic dedup,
/understand --map annotation synthesis.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ─── Constants ───────────────────────────────────────────────────────────────

# Single authority for the dangerous-sink vocabulary in this module.
# The conduit-call regex and both Joern query sink lists are DERIVED
# from these constants — they used to be four hand-copied literals
# (set, regex, guard-query string, unguarded_sinks.sc) that drifted.
DANGEROUS_LIBC_SINKS: frozenset[str] = frozenset({
    "memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "snprintf", "vsprintf", "vsnprintf",
    "gets", "fgets",
    "system", "popen", "execve", "execvp", "execl", "execlp",
    # Full exec-family coverage (previously only in the regex copy).
    "execv", "execle", "execvpe", "execlpe",
    "scanf", "sscanf", "fscanf",
    "sqlite3_exec", "mysql_query",
})

_CONDUIT_CALL_RE = re.compile(
    r"\b(?:"
    + "|".join(
        re.escape(n)
        for n in sorted(DANGEROUS_LIBC_SINKS, key=len, reverse=True)
    )
    + r")\s*\(",
)

# Sink names used by the Joern query surfaces. A deliberate subset of
# DANGEROUS_LIBC_SINKS: whole-CPG name queries drop the noisy scan /
# vs*printf / rare exec variants and the library-specific SQL names.
_CORE_QUERY_SINKS: tuple[str, ...] = (
    "memcpy", "memmove", "strcpy", "strcat", "sprintf", "gets",
    "strncpy", "strncat", "snprintf", "system", "popen", "execve",
    "execvp",
)

# unguarded_sinks.sc additionally reports file-open sinks — useful as
# per-line LLM context, too noisy for the binary guarded/total verdict.
_UNGUARDED_QUERY_SINKS: tuple[str, ...] = _CORE_QUERY_SINKS + (
    "fopen", "open",
)


def _scala_string_list(names: tuple[str, ...]) -> str:
    """Render a name tuple as the body of a Scala List(...) literal."""
    return ", ".join(f'"{n}"' for n in names)


def guard_tested_sinks() -> tuple[str, ...]:
    """The sink names the guarded/unguarded verdict actually tests.

    Public accessor so evidence emitters can record what a "guarded"
    verdict covered — the verdict is silent on every name outside
    this list.
    """
    return _CORE_QUERY_SINKS

_CONDUIT_PHRASES: tuple[str, ...] = (
    r"passes\b.*\bto\b",
    r"forwards\b.*\bto\b",
    r"\bdelegates\s+to\b",
    r"\bcalls\b.*\bwithout\b",
    r"\binvokes\b.*\bwithout\b",
)

_GUARD_QUERY_TEMPLATE = r'''import io.shiftleft.semanticcpg.language._

val fn = cpg.method.name("__FUNCTION__")
val sinkNames = List(__SINK_NAMES__)
val sinkCalls = fn.call.name(sinkNames.mkString("|"))
val total = sinkCalls.size
val structurallyGuarded = sinkCalls.where(_.dominatedBy.isControlStructure).size
val controlGuarded = sinkCalls.where(_.controlledBy.isControlStructure).size
val guarded = Math.max(structurallyGuarded, controlGuarded)
s"$guarded/$total"
'''

# parents: [0]=analysis, [1]=core, [2]=repo root
_QUERIES_DIR = Path(__file__).resolve().parents[2] / "packages" / "joern" / "queries"


# ─── Sink reachability ───────────────────────────────────────────────────────


def build_sink_reachable_set(
    context_map: dict[str, Any] | None,
) -> set[str] | None:
    """Build the set of functions that transitively reach a known sink.

    Seeds from both the context map's catalogued sinks AND well-known
    dangerous C library functions that appear as callees in the call
    graph.

    Returns None if context_map lacks the required data (caller should
    skip the gate rather than demote everything).
    """
    if not context_map:
        return None
    sinks_list = context_map.get("sinks")
    edges = context_map.get("call_edges")
    if not edges:
        return None

    sink_fns: set[str] = set()
    if sinks_list:
        sink_fns = {s["function"] for s in sinks_list if "function" in s}

    all_callees: set[str] = set()
    forward: dict[str, set[str]] = {}
    for edge in edges:
        caller = edge.get("caller") or edge.get("from")
        callee = edge.get("callee") or edge.get("to")
        if caller and callee:
            forward.setdefault(caller, set()).add(callee)
            all_callees.add(callee)

    libc_sinks_in_graph = all_callees & DANGEROUS_LIBC_SINKS
    sink_fns |= libc_sinks_in_graph

    if not sink_fns:
        return None

    reachable: set[str] = set(sink_fns)
    queue = list(sink_fns)
    reverse: dict[str, set[str]] = {}
    for caller, callees in forward.items():
        for callee in callees:
            reverse.setdefault(callee, set()).add(caller)

    while queue:
        fn = queue.pop()
        for pred in reverse.get(fn, ()):
            if pred not in reachable:
                reachable.add(pred)
                queue.append(pred)

    return reachable


# ─── Entry-point reachability ────────────────────────────────────────────────


def is_entry_unreachable(
    function_name: str,
    context_map: dict[str, Any] | None,
    *,
    joern_server=None,
) -> bool:
    """Return True if the function has no callers and is not an entry point.

    Only fires when BOTH call_edges AND entry_points exist in the context
    map.  Without catalogued entry points we can't distinguish dead code
    from library API surfaces, so we return False (don't demote).

    When the call-graph says "unreachable" and a Joern server is
    available, falls back to a Joern callers query — tree-sitter misses
    indirect calls (function pointers, callbacks) that Joern resolves
    via data-dependence edges.
    """
    if not context_map:
        return False
    call_edges = context_map.get("call_edges")
    if not call_edges:
        return False

    entry_points_raw = context_map.get("entry_points", [])
    if not entry_points_raw:
        return False

    entry_names = {
        ep.get("name") or ep.get("function", "")
        for ep in entry_points_raw
    }
    if function_name in entry_names:
        return False

    callee_set = {edge.get("callee") or edge.get("to") for edge in call_edges}
    if function_name in callee_set:
        return False

    if joern_server is not None:
        joern_callers = _joern_find_callers(function_name, joern_server)
        if joern_callers:
            logger.debug(
                "entry-unreachability overridden by Joern: %s has %d caller(s)",
                function_name, len(joern_callers),
            )
            return False

    return True


def _joern_find_callers(
    function_name: str,
    joern_server,
) -> list[dict[str, str]]:
    """Query Joern for call sites that invoke function_name."""
    if not joern_server.is_alive():
        return []
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", function_name):
        return []

    query_path = _QUERIES_DIR / "callers.sc"
    if not query_path.exists():
        return []

    query = query_path.read_text().replace("__FUNCTION__", function_name)
    try:
        result = joern_server.query(query, timeout=15, validate=False)
        if result.errors:
            return []
        callers = []
        for line in (result.raw_output or "").splitlines():
            if line.startswith("JOERN_CALLER:"):
                try:
                    callers.append(json.loads(line[len("JOERN_CALLER:"):]))
                except (json.JSONDecodeError, ValueError):
                    continue
        return callers
    except Exception:
        logger.debug("joern callers query failed for %s", function_name, exc_info=True)
        return []


# ─── Conduit detection ───────────────────────────────────────────────────────


# Fenced code blocks, inline code spans, and markdown quote lines in a
# finding description are the places where target-repo text (comments,
# string literals, identifiers) is reproduced verbatim. The text-based
# gates below must only read the model's own prose — otherwise a
# scanned repo can plant phrases ("correctly bounded", "passes ... to
# memcpy(") that mechanically demote real findings, and the demotion
# is persisted as a cross-run suppression learning.
_FENCED_CODE_RE = re.compile(r"```.*?(?:```|\Z)", re.DOTALL)
_INLINE_CODE_RE = re.compile(r"`[^`\n]*`")
_QUOTE_LINE_RE = re.compile(r"^[ \t]*>.*$", re.MULTILINE)


def _prose_only(body: str) -> str:
    """Strip quoted target content so gates scan only model prose."""
    body = _FENCED_CODE_RE.sub(" ", body)
    body = _INLINE_CODE_RE.sub(" ", body)
    return _QUOTE_LINE_RE.sub(" ", body)


def is_conduit_candidate(body: str) -> bool:
    """Return True if a finding description looks like a conduit FP.

    A conduit function just passes attacker input to a callee that has
    its own bug.  Two signals:
    1. The body mentions a specific dangerous function call (with parens)
    2. The body uses forwarding/delegation language

    If the finding is about local logic (off-by-one, integer overflow,
    loop bounds), returns False — the function is NOT a conduit even if
    it's sink-unreachable.

    Only the model's prose is scanned; code blocks / inline code /
    quote lines are stripped first (see :func:`_prose_only`).
    """
    body_lower = _prose_only(body).lower()
    if _CONDUIT_CALL_RE.search(body_lower):
        return True
    return any(re.search(phrase, body_lower) for phrase in _CONDUIT_PHRASES)


# ─── Guarded-sink detection (Joern) ─────────────────────────────────────────

#: Distinct guard verdict for TRANSIENT degradation: the run HAS a
#: Joern lane but the guard consultation could not be answered right
#: now (server dead/restarting, query error or timeout, garbled
#: reply).  Consumers that use the guard verdict as a promotion VETO
#: must fail closed on this value — pre-fix it collapsed into the
#: same ``None`` as "function calls no tested sink", so a promotion
#: whose only mechanical counter-evidence channel was down proceeded
#: as if the veto had been consulted and declined.  That asymmetry
#: (a confirming joern:live receipt needs a HEALTHY server, while the
#: guard veto silently evaporated on a sick one) let trap verdicts
#: flap with server state.  ``None`` keeps its deterministic
#: meanings: no Joern server provisioned for this run, an unqueryable
#: function name, or no tested sink called.
GUARD_UNAVAILABLE = "unavailable"


def check_sink_guarded(
    function_name: str,
    joern_server,
) -> str | None:
    """Query Joern: are the TESTED sink calls in this function guarded?

    Tests only the curated ``_CORE_QUERY_SINKS`` subset (see
    ``guard_tested_sinks()``), NOT every name in
    ``DANGEROUS_LIBC_SINKS`` — the whole-CPG name query deliberately
    drops the noisy scan / vs*printf / rare exec variants and the
    library-specific SQL names. Consequence for consumers: "guarded"
    means every *tested* sink is dominated by a conditional; it says
    nothing about calls to the omitted names, so a function pairing a
    guarded tested-sink with an unguarded omitted-sink still reads
    "guarded". Suppression decisions should record the tested list as
    evidence (``compute_demotion_verdict`` does).

    Returns "guarded" if all tested sinks have a dominating
    conditional, "unguarded" if any lacks one,
    :data:`GUARD_UNAVAILABLE` when the consultation degraded (server
    down / query error / unparseable reply — transient; never cached),
    and None for the deterministic non-answers (no server provisioned,
    invalid function name, or no tested sink called).
    """
    if joern_server is None:
        return None
    if not joern_server.is_alive():
        return GUARD_UNAVAILABLE

    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", function_name):
        return None

    query = _GUARD_QUERY_TEMPLATE.replace(
        "__FUNCTION__", function_name,
    ).replace("__SINK_NAMES__", _scala_string_list(_CORE_QUERY_SINKS))

    try:
        result = joern_server.query(query, timeout=30, validate=False)
        if result.errors:
            logger.debug("guard query error for %s: %s", function_name, result.errors)
            return GUARD_UNAVAILABLE
        output = (result.raw_output or "").strip()
        if "/" not in output:
            return GUARD_UNAVAILABLE
        guarded_s, total_s = output.rsplit("/", 1)
        guarded = int(guarded_s)
        total = int(total_s)
        if total == 0:
            return None
        return "guarded" if guarded == total else "unguarded"
    except Exception:
        logger.debug("guard query exception for %s", function_name, exc_info=True)
        return GUARD_UNAVAILABLE


def query_unguarded_sinks(
    function_name: str,
    joern_server,
) -> list[dict[str, Any]]:
    """Return details of unguarded sink calls for LLM context enrichment.

    Unlike check_sink_guarded (which returns a binary verdict for the
    gate), this returns the specific unguarded sinks with line numbers
    and code — useful for the LLM to verify the finding.
    """
    if joern_server is None or not joern_server.is_alive():
        return []
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", function_name):
        return []

    query_path = _QUERIES_DIR / "unguarded_sinks.sc"
    if not query_path.exists():
        return []

    query = query_path.read_text().replace(
        "__FUNCTION__", function_name,
    ).replace("__SINK_NAMES__", _scala_string_list(_UNGUARDED_QUERY_SINKS))
    try:
        result = joern_server.query(query, timeout=30, validate=False)
        if result.errors:
            return []
        sinks = []
        for line in (result.raw_output or "").splitlines():
            if line.startswith("JOERN_UNGUARDED:"):
                try:
                    sinks.append(json.loads(line[len("JOERN_UNGUARDED:"):]))
                except (json.JSONDecodeError, ValueError):
                    continue
        # Deterministic order: Joern's traversal order is not stable
        # across server sessions, and these records feed the review
        # prompt — unordered evidence made reviewer input (and hence
        # sampled verdicts) vary run to run.
        sinks.sort(key=lambda s: (s.get("line") or 0, str(s.get("sink") or "")))
        return sinks
    except Exception:
        logger.debug("unguarded sinks query failed for %s", function_name, exc_info=True)
        return []


def query_sink_arg_index(
    function_name: str,
    sink_name: str,
    joern_server,
) -> list[dict[str, Any]]:
    """Return which argument positions at a sink are tainted by function params.

    For memcpy(dst, src, len), knowing arg 2 (src) vs arg 3 (len) is
    tainted changes the vulnerability class.
    """
    if joern_server is None or not joern_server.is_alive():
        return []
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", function_name):
        return []
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", sink_name):
        return []

    query_path = _QUERIES_DIR / "sink_arg_index.sc"
    if not query_path.exists():
        return []

    query = (
        query_path.read_text()
        .replace("__FUNCTION__", function_name)
        .replace("__SINK__", sink_name)
    )
    try:
        result = joern_server.query(query, timeout=30, validate=False)
        if result.errors:
            return []
        args = []
        for line in (result.raw_output or "").splitlines():
            if line.startswith("JOERN_SINK_ARG:"):
                try:
                    args.append(json.loads(line[len("JOERN_SINK_ARG:"):]))
                except (json.JSONDecodeError, ValueError):
                    continue
        # Deterministic order — same doctrine as query_unguarded_sinks.
        args.sort(key=lambda a: (
            str(a.get("sink") or ""),
            a.get("arg_index") if isinstance(a.get("arg_index"), int) else -1,
            str(a.get("source_param") or ""),
        ))
        return args
    except Exception:
        logger.debug(
            "sink arg index query failed for %s→%s",
            function_name, sink_name, exc_info=True,
        )
        return []


# ─── Composite gate verdicts ─────────────────────────────────────────────────


def compute_demotion_verdict(
    function_name: str,
    body: str,
    context_map: dict[str, Any] | None,
    *,
    sink_reachable: set[str] | None = None,
    joern_server=None,
) -> str | None:
    """Run all applicable gates and return a demotion reason or None.

    This is the single entry point for consumers that want a yes/no
    "should this finding be demoted?" answer without calling each gate
    individually.

    Returns a bracket-prefixed reason string (e.g.
    "[sink-unreachability: ...]") or None if no gate fires.

    Gates are checked in order (cheapest first):
    1. Entry-unreachability (pure graph lookup)
    2. Sink-unreachability + conduit check (graph + text analysis)
    3. Safety self-contradiction (regex over the finding body)
    4. Guarded-sink (Joern query — expensive, runs last)
    """
    if is_entry_unreachable(function_name, context_map, joern_server=joern_server):
        return (
            "[entry-unreachability: function has no callers in the call "
            "graph and is not an entry point — bug may be real but is "
            "unreachable]"
        )

    if sink_reachable is None:
        sink_reachable = build_sink_reachable_set(context_map)

    if (
        sink_reachable is not None
        and function_name not in sink_reachable
        and is_conduit_candidate(body)
    ):
        return "[sink-unreachability: no transitive path to any known sink]"

    if has_safety_self_contradiction(body):
        return (
            "[self-contradiction: the finding description asserts the "
            "code is safe or depends on a hypothetical caller violation]"
        )

    if check_sink_guarded(function_name, joern_server) == "guarded":
        # The tested-sink list IS part of the evidence: a "guarded"
        # verdict covers only these names, and the demotion must be
        # auditable against what was actually checked.
        return (
            "[guarded-sink: all tested sink calls in this function "
            "are dominated by conditionals; tested sinks: "
            + ", ".join(guard_tested_sinks())
            + "]"
        )

    return None


# ─── Self-contradiction detection ──────────────────────────────────────────

_NEGATION_WINDOW = 4

_SAFETY_ASSERTIONS = [
    re.compile(r"\bfixed[- ]size\s+(?:static\s+)?(?:string|constant|copy|value)\b", re.IGNORECASE),
    re.compile(r"\bconstant[- ]size\s+(?:string|copy|value)\b", re.IGNORECASE),
    re.compile(r"\bstatic string\b", re.IGNORECASE),
    re.compile(r"\bconstant string\b", re.IGNORECASE),
    re.compile(r"\bsaturating\s+(?:subtraction|arithmetic|add(?:ition)?)\b", re.IGNORECASE),
    re.compile(r"\bcorrectly\s+bounded\b", re.IGNORECASE),
    re.compile(r"\bproperly\s+bounded\b", re.IGNORECASE),
    re.compile(r"\bsafely\s+bounded\b", re.IGNORECASE),
    re.compile(r"\bcannot\s+(?:overflow|exceed|underflow)\b", re.IGNORECASE),
    re.compile(r"\bnever\s+exceeds?\b", re.IGNORECASE),
    re.compile(r"\bbounds?\s+check\s+(?:prevents?|ensures?)\b", re.IGNORECASE),
]

_NEGATION_WORDS = frozenset({
    "not", "no", "without", "lacks", "missing", "absent",
    "fails", "failed", "however", "but", "although",
    "unfortunately", "incorrectly", "improperly",
})

_HYPOTHETICAL_CALLER_VIOLATION = re.compile(
    r"\bif\s+a\s+caller\b.*\b(?:violates?|provides?|passes?|supplies?)\b",
    re.IGNORECASE | re.DOTALL,
)


def has_safety_self_contradiction(body: str) -> bool:
    """Return True if a finding description asserts the code is safe.

    Detects two patterns:
    1. Safety assertions ("fixed-size", "correctly bounded", "saturating")
       without a preceding negation word within a short window.
    2. Hypothetical caller-violation language ("if a caller violates
       this contract") — the finding depends on a condition the model
       hasn't verified.

    When the model's own words assert correctness but it still emitted
    a finding, that's a mechanical demotion signal.

    Only the model's prose is scanned; code blocks / inline code /
    quote lines are stripped first (see :func:`_prose_only`) so a
    scanned repo cannot plant safety-assertion phrases that get quoted
    into the description and mechanically demote a real finding.
    """
    body_lower = _prose_only(body).lower()

    for pattern in _SAFETY_ASSERTIONS:
        m = pattern.search(body_lower)
        if not m:
            continue
        match_start = m.start()
        preceding = body_lower[max(0, match_start - 80):match_start]
        preceding_words = preceding.split()
        tail = preceding_words[-_NEGATION_WINDOW:] if preceding_words else []
        tail_stripped = {w.strip(",.;:!?()") for w in tail}
        if not _NEGATION_WORDS & tail_stripped:
            return True

    return bool(_HYPOTHETICAL_CALLER_VIOLATION.search(body_lower))


__all__ = [
    "DANGEROUS_LIBC_SINKS",
    "GUARD_UNAVAILABLE",
    "build_sink_reachable_set",
    "check_sink_guarded",
    "compute_demotion_verdict",
    "guard_tested_sinks",
    "has_safety_self_contradiction",
    "is_conduit_candidate",
    "is_entry_unreachable",
]

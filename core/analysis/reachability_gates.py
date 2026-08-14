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
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ─── Constants ───────────────────────────────────────────────────────────────

DANGEROUS_LIBC_SINKS: FrozenSet[str] = frozenset({
    "memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "snprintf", "vsprintf", "vsnprintf",
    "gets", "fgets",
    "system", "popen", "execve", "execvp", "execl", "execlp",
    "scanf", "sscanf", "fscanf",
    "sqlite3_exec", "mysql_query",
})

_CONDUIT_CALL_RE = re.compile(
    r"\b(?:memcpy|memmove|strcpy|strncpy|strcat|strncat|"
    r"sprintf|snprintf|vsprintf|vsnprintf|"
    r"f?gets|system|popen|execle?|execve?|execvpe?|execlpe?|"
    r"scanf|sscanf|fscanf|"
    r"sqlite3_exec|mysql_query)\s*\(",
)

_CONDUIT_PHRASES: Tuple[str, ...] = (
    r"passes\b.*\bto\b",
    r"forwards\b.*\bto\b",
    r"\bdelegates\s+to\b",
    r"\bcalls\b.*\bwithout\b",
    r"\binvokes\b.*\bwithout\b",
)

_GUARD_QUERY_TEMPLATE = r'''import io.shiftleft.semanticcpg.language._

val fn = cpg.method.name("__FUNCTION__")
val sinkNames = List("memcpy", "memmove", "strcpy", "strcat", "sprintf", "gets", "strncpy", "strncat", "snprintf", "system", "popen", "execve", "execvp")
val sinkCalls = fn.call.name(sinkNames.mkString("|"))
val total = sinkCalls.size
val structurallyGuarded = sinkCalls.where(_.dominatedBy.isControlStructure).size
val controlGuarded = sinkCalls.where(_.controlledBy.isControlStructure).size
val guarded = Math.max(structurallyGuarded, controlGuarded)
s"$guarded/$total"
'''

# parents: [0]=inventory, [1]=core, [2]=repo root
_QUERIES_DIR = Path(__file__).resolve().parents[2] / "packages" / "joern" / "queries"


# ─── Sink reachability ───────────────────────────────────────────────────────


def build_sink_reachable_set(
    context_map: Optional[Dict[str, Any]],
) -> Optional[Set[str]]:
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

    sink_fns: Set[str] = set()
    if sinks_list:
        sink_fns = {s["function"] for s in sinks_list if "function" in s}

    all_callees: Set[str] = set()
    forward: Dict[str, Set[str]] = {}
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

    reachable: Set[str] = set(sink_fns)
    queue = list(sink_fns)
    reverse: Dict[str, Set[str]] = {}
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
    context_map: Optional[Dict[str, Any]],
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
) -> List[Dict[str, str]]:
    """Query Joern for call sites that invoke function_name."""
    if not joern_server.is_alive():
        return []
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", function_name):
        return []

    # parents: [0]=inventory, [1]=core, [2]=repo root
    query_path = Path(__file__).resolve().parents[2] / "packages" / "joern" / "queries" / "callers.sc"
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


def is_conduit_candidate(body: str) -> bool:
    """Return True if a finding description looks like a conduit FP.

    A conduit function just passes attacker input to a callee that has
    its own bug.  Two signals:
    1. The body mentions a specific dangerous function call (with parens)
    2. The body uses forwarding/delegation language

    If the finding is about local logic (off-by-one, integer overflow,
    loop bounds), returns False — the function is NOT a conduit even if
    it's sink-unreachable.
    """
    body_lower = body.lower()
    if _CONDUIT_CALL_RE.search(body_lower):
        return True
    for phrase in _CONDUIT_PHRASES:
        if re.search(phrase, body_lower):
            return True
    return False


# ─── Guarded-sink detection (Joern) ─────────────────────────────────────────


def check_sink_guarded(
    function_name: str,
    joern_server,
) -> Optional[str]:
    """Query Joern: are all dangerous sink calls in this function guarded?

    Returns "guarded" if all sinks have a dominating conditional,
    "unguarded" if any sink lacks one, None if query fails or no sinks.
    """
    if joern_server is None or not joern_server.is_alive():
        return None

    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", function_name):
        return None

    query = _GUARD_QUERY_TEMPLATE.replace("__FUNCTION__", function_name)

    try:
        result = joern_server.query(query, timeout=30, validate=False)
        if result.errors:
            logger.debug("guard query error for %s: %s", function_name, result.errors)
            return None
        output = (result.raw_output or "").strip()
        if "/" not in output:
            return None
        guarded_s, total_s = output.rsplit("/", 1)
        guarded = int(guarded_s)
        total = int(total_s)
        if total == 0:
            return None
        return "guarded" if guarded == total else "unguarded"
    except Exception:
        logger.debug("guard query exception for %s", function_name, exc_info=True)
        return None


def query_unguarded_sinks(
    function_name: str,
    joern_server,
) -> List[Dict[str, Any]]:
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

    query = query_path.read_text().replace("__FUNCTION__", function_name)
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
        return sinks
    except Exception:
        logger.debug("unguarded sinks query failed for %s", function_name, exc_info=True)
        return []


def query_sink_arg_index(
    function_name: str,
    sink_name: str,
    joern_server,
) -> List[Dict[str, Any]]:
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
    context_map: Optional[Dict[str, Any]],
    *,
    sink_reachable: Optional[Set[str]] = None,
    joern_server=None,
) -> Optional[str]:
    """Run all applicable gates and return a demotion reason or None.

    This is the single entry point for consumers that want a yes/no
    "should this finding be demoted?" answer without calling each gate
    individually.

    Returns a bracket-prefixed reason string (e.g.
    "[sink-unreachability: ...]") or None if no gate fires.

    Gates are checked in order (cheapest first):
    1. Entry-unreachability (pure graph lookup)
    2. Sink-unreachability + conduit check (graph + text analysis)
    3. Guarded-sink (Joern query — expensive)
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

    if check_sink_guarded(function_name, joern_server) == "guarded":
        return (
            "[guarded-sink: all dangerous sink calls in this function "
            "are dominated by conditionals]"
        )

    if has_safety_self_contradiction(body):
        return (
            "[self-contradiction: the finding description asserts the "
            "code is safe or depends on a hypothetical caller violation]"
        )

    return None


# ─── Self-contradiction detection ──────────────────────────────────────────

_NEGATION_WINDOW = 4

_SAFETY_ASSERTIONS = [
    re.compile(r"\bfixed[- ]size\s+(?:static\s+)?(?:string|constant|copy|value)\b", re.I),
    re.compile(r"\bconstant[- ]size\s+(?:string|copy|value)\b", re.I),
    re.compile(r"\bstatic string\b", re.I),
    re.compile(r"\bconstant string\b", re.I),
    re.compile(r"\bsaturating\s+(?:subtraction|arithmetic|add(?:ition)?)\b", re.I),
    re.compile(r"\bcorrectly\s+bounded\b", re.I),
    re.compile(r"\bproperly\s+bounded\b", re.I),
    re.compile(r"\bsafely\s+bounded\b", re.I),
    re.compile(r"\bcannot\s+(?:overflow|exceed|underflow)\b", re.I),
    re.compile(r"\bnever\s+exceeds?\b", re.I),
    re.compile(r"\bbounds?\s+check\s+(?:prevents?|ensures?)\b", re.I),
]

_NEGATION_WORDS = frozenset({
    "not", "no", "without", "lacks", "missing", "absent",
    "fails", "failed", "however", "but", "although",
    "unfortunately", "incorrectly", "improperly",
})

_HYPOTHETICAL_CALLER_VIOLATION = re.compile(
    r"\bif\s+a\s+caller\b.*\b(?:violates?|provides?|passes?|supplies?)\b",
    re.I | re.DOTALL,
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
    """
    body_lower = body.lower()

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

    if _HYPOTHETICAL_CALLER_VIOLATION.search(body_lower):
        return True

    return False


__all__ = [
    "DANGEROUS_LIBC_SINKS",
    "build_sink_reachable_set",
    "check_sink_guarded",
    "compute_demotion_verdict",
    "has_safety_self_contradiction",
    "is_conduit_candidate",
    "is_entry_unreachable",
]

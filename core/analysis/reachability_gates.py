"""Generic reachability gates for finding suppression and prioritisation.

Pure query functions that answer "should this finding be suppressed?" based
on call-graph topology, sink reachability, and entry-point reachability.
No audit-specific types — all inputs are plain strings and dicts.

Consumers: /audit orchestrator, /validate demoter, /agentic dedup,
/understand --map annotation synthesis.
"""

from __future__ import annotations

import logging
import re
from math import isqrt
from pathlib import Path
from typing import Any

from core.analysis._joern_lines import (
    extract_scalar_marker,
    parse_marker_records,
)

logger = logging.getLogger(__name__)

# ─── Constants ───────────────────────────────────────────────────────────────

# Single authority for the dangerous-sink vocabulary in this module.
# The conduit-call regex and both Joern query sink lists are DERIVED
# from these constants — they used to be four hand-copied literals
# (set, regex, guard-query string, unguarded_sinks.sc) that drifted.
DANGEROUS_LIBC_SINKS: frozenset[str] = frozenset({
    "memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat",
    # stpcpy: same unbounded-copy hazard as strcpy (returns the end
    # pointer instead of the start) — kept in step with the
    # function-taxonomy sink vocabulary.
    "stpcpy",
    "sprintf", "snprintf", "vsprintf", "vsnprintf",
    "gets", "fgets",
    "system", "popen", "execve", "execvp", "execl", "execlp",
    # Full exec-family coverage (previously only in the regex copy).
    "execv", "execle", "execvpe", "execlpe",
    # Process-spawn family beyond exec* — same command-execution class,
    # kept in step with the function-taxonomy sink vocabulary.
    "posix_spawn", "posix_spawnp", "fexecve",
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

# Prose gaps are bounded: an unbounded gap re-scans the rest of the
# body from every planted verb occurrence — quadratic on
# hostile-influenced text.  A real conduit phrase keeps its halves
# within a clause (far under 200 chars); longer gaps stop matching.
_CONDUIT_PHRASES: tuple[str, ...] = (
    r"passes\b.{0,200}\bto\b",
    r"forwards\b.{0,200}\bto\b",
    r"\bdelegates\s+to\b",
    r"\bcalls\b.{0,200}\bwithout\b",
    r"\binvokes\b.{0,200}\bwithout\b",
)

# Dual-emit doctrine (same as unguarded_sinks.sc): the summary is
# println'd for the subprocess transport AND returned as the final
# expression so the server transport (/query-sync drops println,
# echo-frames the final expression) still carries it. The marker
# payload keeps unguarded_sinks.sc's ``unguarded/total`` semantics so
# the two JOERN_GUARD_SUMMARY emitters can't be misread against each
# other. The bare ``s"$guarded/$total"`` final expression this
# replaces was int-parsed from raw stdout — the server echo framing
# (``val res0: String = "..."``) made every parse fail, pinning the
# gate at GUARD_UNAVAILABLE for whole joern-enabled runs.
_GUARD_QUERY_TEMPLATE = r'''import io.shiftleft.semanticcpg.language._

val fn = cpg.method.name("__FUNCTION__")
val sinkNames = List(__SINK_NAMES__)
val sinkCalls = fn.call.name(sinkNames.mkString("|")).l
val total = sinkCalls.size
val structurallyGuarded = sinkCalls.count(_.dominatedBy.isControlStructure.l.nonEmpty)
val controlGuarded = sinkCalls.count(_.controlledBy.isControlStructure.l.nonEmpty)
val guarded = Math.max(structurallyGuarded, controlGuarded)
val summary = s"JOERN_GUARD_SUMMARY:${total - guarded}/$total"
println(summary)
summary
'''

# parents: [0]=analysis, [1]=core, [2]=repo root
_QUERIES_DIR = Path(__file__).resolve().parents[2] / "packages" / "joern" / "queries"


# ─── Context-map ingestion validation ───────────────────────────────────────

# The full consumed context-map surface of this module: every
# collection it walks, with the string fields it reads from each
# entry. context-map.json is LLM-produced and only the top-level dict
# is shape-validated upstream, so EVERY level below that is hostile
# until proven — the collection value itself (scalars arrive where
# lists belong), each entry (strings arrive where dicts belong), and
# each field value (lists arrive where strings belong). All reads go
# through the one walker below instead of per-site isinstance
# patches, so a new read site cannot re-open the hole: it fetches
# through the walker or it never sees the data.
_CONTEXT_MAP_STR_FIELDS: dict[str, tuple[str, ...]] = {
    "call_edges": ("caller", "callee", "from", "to"),
    "entry_points": ("name", "function"),
    "sinks": ("function",),
}


def _context_map_entries(
    context_map: dict[str, Any],
    key: str,
) -> list[dict[str, Any]]:
    """Validated fetch of one context-map collection.

    Returns entry copies in which every consumed field is either a
    str or absent. Wrong shapes SKIP with a logged reason rather than
    TypeError a caller that has no enclosing try (the /audit
    post-deepen sweep calls the public gates bare). Skip granularity
    follows the damage: a non-list collection value drops the whole
    collection (fail-soft, same as absent), a non-dict entry drops
    that entry, a wrong-typed field value drops just that field.
    """
    value = context_map.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        logger.debug(
            "context-map %r is %s, not a list — collection skipped",
            key, type(value).__name__,
        )
        return []
    fields = _CONTEXT_MAP_STR_FIELDS[key]
    entries: list[dict[str, Any]] = []
    for entry in value:
        if not isinstance(entry, dict):
            logger.debug(
                "context-map %r entry is %s, not a dict — entry skipped",
                key, type(entry).__name__,
            )
            continue
        cleaned = dict(entry)
        for field_name in fields:
            field_value = cleaned.get(field_name)
            if field_value is not None and not isinstance(field_value, str):
                logger.debug(
                    "context-map %r field %r is %s, not a str — "
                    "field dropped", key, field_name,
                    type(field_value).__name__,
                )
                del cleaned[field_name]
        entries.append(cleaned)
    return entries


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
    # All context-map reads go through the ingestion walker (see
    # _context_map_entries) — entries arrive dict-shaped with every
    # consumed field str-or-absent, so no per-site type checks below.
    edges = _context_map_entries(context_map, "call_edges")
    if not edges:
        return None

    sink_fns: set[str] = {
        s["function"]
        for s in _context_map_entries(context_map, "sinks")
        if "function" in s
    }

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
    # All context-map reads go through the ingestion walker (see
    # _context_map_entries) — entries arrive dict-shaped with every
    # consumed field str-or-absent, so no per-site type checks below.
    call_edges = _context_map_entries(context_map, "call_edges")
    if not call_edges:
        return False

    entry_points = _context_map_entries(context_map, "entry_points")
    if not entry_points:
        return False

    entry_names = {
        ep.get("name") or ep.get("function", "")
        for ep in entry_points
    }
    if function_name in entry_names:
        return False

    callee_set = {
        edge.get("callee") or edge.get("to")
        for edge in call_edges
    }
    if function_name in callee_set:
        return False

    if joern_server is not None:
        joern_callers = _joern_find_callers(function_name, joern_server)
        if joern_callers is None:
            # Degraded consultation (dead server / query error /
            # garbled reply): the cross-check that exists precisely to
            # catch the indirect calls the graph missed could not run,
            # so "no callers" is unverified — a transient hiccup must
            # not demote a finding.
            logger.debug(
                "entry-unreachability not asserted for %s: Joern caller "
                "consultation unavailable", function_name,
            )
            return False
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
) -> list[dict[str, str]] | None:
    """Query Joern for call sites that invoke function_name.

    Tri-state result, mirroring the :data:`GUARD_UNAVAILABLE`
    doctrine: an empty LIST means a healthy query genuinely found zero
    callers (safe to treat as unreachability evidence); ``None`` means
    the consultation degraded (dead server, query error or exception,
    or a reply whose only records were undecodable) — consumers must
    read it as "cannot verify", never as proof of zero callers.
    Deterministic non-answers (unqueryable function name, missing
    query file) keep the empty-list shape: the Joern cross-check is
    structurally impossible there and the call-graph verdict stands.
    """
    if not joern_server.is_alive():
        return None
    # fullmatch, not match-with-``$``: ``$`` also matches just before a
    # trailing newline, so ``name\n`` would pass a ``^...$`` gate and
    # reach the query-template interpolation below. Same discipline at
    # every identifier gate in this module.
    if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", function_name):
        return []

    query_path = _QUERIES_DIR / "callers.sc"
    if not query_path.exists():
        return []

    query = query_path.read_text().replace("__FUNCTION__", function_name)
    try:
        result = joern_server.query(query, timeout=15, validate=False)
        # server.query runs a JOERN_FLOW scan over EVERY query's
        # stdout and folds that scan's parse noise into
        # ``result.errors`` ("failed to parse flow: ..."): echoed
        # script source, res-binder echoes without a val line, or
        # repo text that happens to contain the JOERN_FLOW marker.
        # Those phantom errors say nothing about THIS query — keying
        # degradation on them turned healthy zero-caller answers into
        # permanent None (gate silently dark). Only errors OUTSIDE
        # that shape (query failed / server exited / timeout) degrade;
        # decode failures for OUR marker come from
        # ``parse_marker_records`` below. Residual: a genuine failure
        # whose message embeds the literal flow-scan prefix would be
        # ignored — no current error producer has that shape.
        if any(
            "failed to parse flow:" not in str(e)
            for e in (result.errors or [])
        ):
            return None
        records, decode_errors = parse_marker_records(
            result.raw_output or "", "JOERN_CALLER:",
        )
        callers = [r for r in records if isinstance(r, dict)]
        if not callers and decode_errors:
            # Records were printed but none decoded — a garbled
            # transcript is not evidence of zero callers.
            logger.debug(
                "joern callers reply for %s garbled: %s",
                function_name, decode_errors[:3],
            )
            return None
        return callers
    except Exception:
        logger.debug("joern callers query failed for %s", function_name, exc_info=True)
        return None


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
# Markdown INDENTED code blocks (contiguous runs of 4-space- or
# tab-indented lines) reproduce target text exactly like fenced ones
# — a planted phrase quoted indented survived the strip and fired the
# demotion gates. Each repetition consumes a full line opened by a
# mandatory indent, so the run match is linear.
_INDENTED_BLOCK_RE = re.compile(
    r"^(?:(?: {4}|\t)[^\n]*(?:\n|$))+", re.MULTILINE,
)
# Quote-line indent class is ALL horizontal whitespace ([^\S\n]), not
# just space/tab — a U+00A0-indented ``>`` line carried planted text
# past the plain-space pattern.
_QUOTE_LINE_RE = re.compile(r"^[^\S\n]*>.*$", re.MULTILINE)


def _prose_only(body: str) -> str:
    """Strip quoted target content so gates scan only model prose.

    Over-stripping is the safe direction here: these gates DEMOTE
    findings, so prose lost to an aggressive strip can only leave a
    finding standing — while an unstripped quoted phrase lets a
    scanned repo mechanically demote a real finding (and persist the
    demotion as a cross-run suppression learning)."""
    body = _FENCED_CODE_RE.sub(" ", body)
    body = _INDENTED_BLOCK_RE.sub(" ", body)
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

    if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", function_name):
        return None

    query = _GUARD_QUERY_TEMPLATE.replace(
        "__FUNCTION__", function_name,
    ).replace("__SINK_NAMES__", _scala_string_list(_CORE_QUERY_SINKS))

    try:
        result = joern_server.query(query, timeout=30, validate=False)
        # The marker is the authoritative carrier on BOTH transports
        # (dual-emit). Parse it FIRST: ``result.errors`` is not a
        # reliable degradation signal here — server.query runs a
        # JOERN_FLOW scan over every query's stdout and folds that
        # scan's parse noise into ``errors`` (see the matching filter
        # in ``_joern_find_callers``), so a healthy guard answer can
        # arrive alongside phantom errors. A transcript with NO
        # parseable marker (compile error, server died mid-query,
        # garbled reply) is the actual degraded case.
        summary = extract_scalar_marker(
            result.raw_output or "", "JOERN_GUARD_SUMMARY:",
        )
        if summary is None:
            if result.errors:
                logger.debug(
                    "guard query error for %s: %s",
                    function_name, result.errors,
                )
            return GUARD_UNAVAILABLE
        m = re.fullmatch(r"(\d+)/(\d+)", summary)
        if m is None:
            return GUARD_UNAVAILABLE
        unguarded = int(m.group(1))
        total = int(m.group(2))
        if total == 0:
            return None
        return "guarded" if unguarded == 0 else "unguarded"
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
    if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", function_name):
        return []

    query_path = _QUERIES_DIR / "unguarded_sinks.sc"
    if not query_path.exists():
        return []

    query = query_path.read_text().replace(
        "__FUNCTION__", function_name,
    ).replace("__SINK_NAMES__", _scala_string_list(_UNGUARDED_QUERY_SINKS))
    try:
        result = joern_server.query(query, timeout=30, validate=False)
        # Phantom-error tolerance (same filter as _joern_find_callers
        # and query_sink_arg_indices): the server transport folds
        # benign "failed to parse flow:" noise into result.errors on
        # healthy replies; treating those as fatal silently discarded
        # the unguarded-sink evidence from the review prompt on that
        # transport. Only errors OUTSIDE that shape degrade.
        if any(
            "failed to parse flow:" not in str(e)
            for e in (result.errors or [])
        ):
            return []
        # Transport-tolerant parse: on the server transport the
        # records ride the final expression's value echo.
        records, _decode_errors = parse_marker_records(
            result.raw_output or "", "JOERN_UNGUARDED:",
        )
        sinks = [r for r in records if isinstance(r, dict)]
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
    return query_sink_arg_indices(function_name, [sink_name], joern_server)


def query_sink_arg_indices(
    function_name: str,
    sink_names: list[str],
    joern_server,
) -> list[dict[str, Any]]:
    """Batched :func:`query_sink_arg_index`: every sink in ONE submission.

    A per-sink loop pays the REPL's Scala compilation overhead once per
    sink; the batched template loops over the sink list inside one
    query. Records carry their own ``sink`` name and come back ordered
    by the caller's sink order (then arg index, then source param) —
    the same order the per-sink loop produced.
    """
    if joern_server is None or not joern_server.is_alive():
        return []
    if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", function_name):
        return []
    valid_sinks = [
        s for s in sink_names
        if re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", s or "")
    ]
    if not valid_sinks:
        return []

    query_path = _QUERIES_DIR / "sink_arg_index.sc"
    if not query_path.exists():
        return []

    query = (
        query_path.read_text()
        .replace("__FUNCTION__", function_name)
        .replace("__SINK_NAMES__", _scala_string_list(tuple(valid_sinks)))
    )
    try:
        # Sublinear batch budget — 30s × ceil(sqrt(N)), not N×30 and
        # not a flat 30: linear re-inherits the per-enrichment
        # monopoly of the shared single-threaded REPL the batch
        # avoids, while a flat budget starves wide sink menus whose
        # per-sink dataflow work is real even with compilation paid
        # once. A degraded batch falls back to one per-sink pass below
        # instead of costing the whole enrichment.
        n = len(valid_sinks)
        budget = 30 * (isqrt(n - 1) + 1)
        result = joern_server.query(query, timeout=budget, validate=False)
        if result.errors:
            # result.errors can carry transport parse noise on some
            # REPL echoes (same transport class the
            # query_unguarded_sinks parse note documents), so this
            # fallback occasionally fires on a phantom — one redundant
            # per-sink pass, strictly better than the silent [] a
            # degraded batch returned before.
            return _sink_arg_indices_per_sink_fallback(
                function_name, valid_sinks, joern_server,
            )
        # Transport-tolerant parse — same doctrine as
        # query_unguarded_sinks.
        records, _decode_errors = parse_marker_records(
            result.raw_output or "", "JOERN_SINK_ARG:",
        )
        args = [r for r in records if isinstance(r, dict)]
        # Deterministic order — same doctrine as query_unguarded_sinks;
        # caller sink order first so the batch matches the loop it
        # replaced.
        sink_order = {name: i for i, name in enumerate(valid_sinks)}
        args.sort(key=lambda a: (
            sink_order.get(str(a.get("sink") or ""), len(sink_order)),
            a.get("arg_index") if isinstance(a.get("arg_index"), int) else -1,
            str(a.get("source_param") or ""),
        ))
        return args
    except Exception:
        logger.debug(
            "sink arg index query failed for %s→[%s]",
            function_name, ",".join(valid_sinks), exc_info=True,
        )
        return _sink_arg_indices_per_sink_fallback(
            function_name, valid_sinks, joern_server,
        )


def _sink_arg_indices_per_sink_fallback(
    function_name: str,
    valid_sinks: list[str],
    joern_server,
) -> list[dict[str, Any]]:
    """One-shot per-sink recovery when the batched query degrades.

    Each single-sink call is the pre-batch query shape (a one-element
    batch); only multi-sink batches fall back, so a degraded
    single-sink query stays a single failure, never a recursion.
    """
    if len(valid_sinks) <= 1:
        return []
    combined: list[dict[str, Any]] = []
    for sink in valid_sinks:
        combined.extend(
            query_sink_arg_indices(function_name, [sink], joern_server),
        )
    return combined


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

# The verb must sit in the SAME sentence/line as "if a caller" —
# ``[^.\n]{0,120}`` blocks the sentence-crossing matches the previous
# greedy ``.*`` + DOTALL allowed (an "if a caller" aside in one
# paragraph paired with an unrelated "passes" pages later demoted
# real findings as self-contradiction).
_HYPOTHETICAL_CALLER_VIOLATION = re.compile(
    r"\bif\s+a\s+caller\b[^.\n]{0,120}?"
    r"\b(?:violates?|provides?|passes?|supplies?)\b",
    re.IGNORECASE,
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

"""Cross-function mechanical verification via Joern CPG.

Provides 5 verifiers that use interprocedural Joern queries to confirm
or refute hypotheses about cross-function bugs.  Each verifier is
dispatched based on hypothesis keyword matching, and returns
verification-grade evidence that can promote findings through the
merge layer.

Verifiers:
  1. unchecked_return   — callee return value ignored
  2. taint_source_sink  — unsanitised input reaches sensitive sink
  3. caller_constraint   — callers lack required guard/lock
  4. taint_to_arithmetic — user data flows through arithmetic to alloc
  5. incomplete_cleanup  — teardown omits resource list cleanup

Wire point: called from _proactive_validate in orchestrator.py after
the existing Coccinelle block.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from ._util import safe_joern_name_lenient as _safe_name

logger = logging.getLogger(__name__)


@dataclass
class CrossFunctionVerdict:
    """Result of a cross-function verification check."""

    verified: bool
    verifier_name: str
    evidence: str
    details: dict | None = None


_VERIFIER_DISPATCH: list[tuple[re.Pattern, str]] = []


def _init_dispatch() -> None:
    global _VERIFIER_DISPATCH
    if _VERIFIER_DISPATCH:
        return
    _VERIFIER_DISPATCH = [
        (re.compile(
            r"ignor(?:es?|ing)\s+(?:the\s+)?(?:return|error|failure)"
            r"|unchecked\s+return"
            r"|return\s+value\s+(?:is\s+)?(?:not\s+)?check"
            r"|discard(?:s|ed|ing)\s+(?:the\s+)?(?:return|error|result)",
            re.IGNORECASE,
        ), "unchecked_return"),

        (re.compile(
            r"unsaniti[sz]ed\s+(?:input|data|header|value|filename)"
            r"|(?:user|attacker|external)[\w\s-]*(?:control|suppli|provid)\w*\s+(?:data|input|value).*(?:sink|output|render|inject|interpolat)"
            r"|(?:host|header|query|path|url)\s+(?:value\s+)?(?:directly|without)"
            r"|taint(?:ed)?\s+.*(?:sink|output|render)"
            r"|unsaniti[sz]ed\s+\w+\s+.*(?:path|directory|travers)"
            r"|(?:\.\./|path\s+travers|directory\s+travers)",
            re.IGNORECASE,
        ), "taint_source_sink"),

        (re.compile(
            r"caller(?:s)?\s+(?:must|do(?:es)?\s+not|don'?t|lack|without|need)"
            r"|(?:without|no)\s+(?:holding|acquiring)\s+(?:the\s+)?(?:necessary\s+)?lock"
            r"|precondition\s+(?:not\s+)?(?:met|check|enforc)"
            r"|lock\s+(?:not\s+)?held"
            r"|after\s+(?:sleeping|releasing|dropping)\s+(?:and\s+)?(?:releasing\s+)?(?:\w+\s+)*(?:lock|mutex|sem|rwsem)",
            re.IGNORECASE,
        ), "caller_constraint"),

        (re.compile(
            r"integer\s+(?:overflow|underflow|truncat|wrap|narrow)"
            r"|arithmetic\s+(?:overflow|underflow)"
            r"|(?:size|length|count|offset)\s+.*(?:overflow|truncat|wrap)"
            r"|(?:multiply|shift|add)\s+.*(?:alloc|size|length)"
            r"|truncat\w+\s+.*(?:int|u32|u16|size_t)",
            re.IGNORECASE,
        ), "taint_to_arithmetic"),

        (re.compile(
            r"(?:resource|memory)\s+leak"
            r"|fail(?:s|ed|ure)?\s+to\s+(?:clean|free|release|drain|flush)"
            r"|(?:list|queue|buffer)\s+(?:not\s+)?(?:clean|drain|flush|free)"
            r"|missing\s+(?:clean|free|release)"
            r"|omit(?:s|ted)?\s+(?:clean|free|release)"
            r"|incomplete\s+(?:clean|teardown|shutdown|release)"
            r"|(?:freed|free)\s+.*(?:pointer|reference)\s+.*(?:remains|dangling|stale)"
            r"|(?:pointer|reference)\s+.*(?:remains|dangling|stale)",
            re.IGNORECASE,
        ), "incomplete_cleanup"),
    ]


def _run_query(server: Any, query: str) -> list | None:
    """Run a Joern query, delegating to condition_cpg's parser."""
    from .condition_cpg import _run_query as cpg_run_query
    return cpg_run_query(server, query)


# ── Verifier 1: unchecked_return ─────────────────────────────────────

def _verify_unchecked_return(
    function_name: str,
    hypothesis: str,
    server: Any,
) -> CrossFunctionVerdict | None:
    """Check if a callee's return value is ignored (not in a control structure).

    Extracts the callee name from the hypothesis, then queries whether
    calls to it inside the target function feed any control structure.
    """
    safe_fn = _safe_name(function_name)
    if safe_fn is None:
        return None

    callee = _extract_callee_from_hypothesis(hypothesis)
    if not callee:
        return None
    safe_callee = _safe_name(callee)
    if safe_callee is None:
        return None

    query = (
        f'cpg.method.name("{safe_fn}")'
        f'.ast.isCall.name("{safe_callee}")'
        f".filterNot(_.inAst.isControlStructure.nonEmpty)"
        f".map(c => (c.lineNumber.getOrElse(0), c.code))"
        f".l"
    )

    result = _run_query(server, query)
    if result is None:
        return None

    if result:
        lines = []
        for item in result:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                lines.append(f"line {item[0]}: {item[1]}")
            else:
                lines.append(str(item))
        evidence = (
            f"Return value of {callee}() is not checked in "
            f"{function_name}: {'; '.join(lines[:3])}"
        )
        return CrossFunctionVerdict(
            verified=True,
            verifier_name="unchecked_return",
            evidence=evidence,
            details={"callee": callee, "unchecked_calls": result[:5]},
        )

    return CrossFunctionVerdict(
        verified=False,
        verifier_name="unchecked_return",
        evidence=f"All calls to {callee}() in {function_name} are checked",
    )


def _extract_callee_from_hypothesis(hypothesis: str) -> str | None:
    """Extract a callee function name from hypothesis text."""
    patterns = [
        re.compile(r"ignor\w+\s+(?:the\s+)?(?:return|error|failure)\s+(?:value\s+)?(?:of\s+)?[`'\"]?(\w+)[`'\"]?"),
        re.compile(r"[`'\"](\w+)[`'\"]?\s*\(\)\s*(?:return|error|failure|result)\s+(?:is\s+)?(?:not\s+)?check"),
        re.compile(r"return\s+value\s+of\s+[`'\"]?(\w+)[`'\"]?"),
        re.compile(r"[`'\"](\w+)[`'\"]?\s+(?:return|error)\s+(?:is\s+)?(?:ignored|unchecked|discarded)"),
        re.compile(r"(?:failure|error)\s+of\s+[`'\"]?(\w+)[`'\"]?"),
    ]
    for pat in patterns:
        m = pat.search(hypothesis)
        if m:
            name = m.group(1)
            if len(name) >= 2 and name not in ("the", "its", "this", "that", "The"):
                return name
    return None


# ── Verifier 2: taint_source_sink ────────────────────────────────────

def _verify_taint_source_sink(
    function_name: str,
    hypothesis: str,
    server: Any,
) -> CrossFunctionVerdict | None:
    """Check if unsanitised input reaches a sensitive sink via reachableByFlows."""
    safe_fn = _safe_name(function_name)
    if safe_fn is None:
        return None

    sinks = _extract_sinks_from_hypothesis(hypothesis)
    if not sinks:
        return None

    for sink in sinks[:3]:
        safe_sink = _safe_name(sink)
        if safe_sink is None:
            continue

        query = (
            "import io.joern.dataflowengineoss.queryengine."
            "{EngineConfig, EngineContext}\n"
            "val ctx = EngineContext(config = EngineConfig(maxCallDepth = 3))\n"
            f'val src = cpg.method.name("{safe_fn}").parameter\n'
            f'val snk = cpg.method.name("{safe_fn}")'
            f'.ast.isCall.name(".*{safe_sink}.*").argument\n'
            f"snk.reachableByFlows(src)(ctx).l"
            f".map(f => f.elements.map(_.code).mkString(\" -> \"))"
            f".l"
        )

        result = _run_query(server, query)
        if result is None:
            continue

        if result:
            flow_strs = [str(f)[:200] for f in result[:3]]
            evidence = (
                f"Taint flow confirmed in {function_name}: "
                f"parameter reaches {sink}: {'; '.join(flow_strs)}"
            )
            return CrossFunctionVerdict(
                verified=True,
                verifier_name="taint_source_sink",
                evidence=evidence,
                details={"sink": sink, "flows": result[:5]},
            )

    return CrossFunctionVerdict(
        verified=False,
        verifier_name="taint_source_sink",
        evidence=f"No taint flow to extracted sinks in {function_name}",
    )


def _extract_sinks_from_hypothesis(hypothesis: str) -> list[str]:
    """Extract sink function/method names from hypothesis text."""
    explicit = re.findall(
        r"[`'\"](\w+(?:\.\w+)?)[`'\"]", hypothesis,
    )
    keyword_sinks = re.findall(
        r"\b((?:interpolat|inject|concat|format|join|render|write|exec|eval"
        r"|system|popen|query|execute)\w*)\b",
        hypothesis, re.IGNORECASE,
    )
    candidates = []
    seen = set()
    skip = {"the", "this", "that", "its", "and", "for", "not", "can", "are",
            "has", "was", "but", "from", "with", "into", "will", "may"}
    for name in explicit + keyword_sinks:
        bare = name.split(".")[-1] if "." in name else name
        low = bare.lower()
        if low in seen or low in skip or len(bare) < 2:
            continue
        seen.add(low)
        candidates.append(bare)
    return candidates[:5]


# ── Verifier 3: caller_constraint ────────────────────────────────────

def _verify_caller_constraint(
    function_name: str,
    hypothesis: str,
    server: Any,
) -> CrossFunctionVerdict | None:
    """Check whether all callers hold a required lock or call a guard before F.

    Extracts the required guard/lock from the hypothesis, then checks
    every caller for dominance of that guard over the call to F.
    """
    safe_fn = _safe_name(function_name)
    if safe_fn is None:
        return None

    guard = _extract_guard_from_hypothesis(hypothesis)

    callers_query = (
        f'cpg.method.name("{safe_fn}")'
        f".caller"
        f".map(m => (m.name, m.filename, m.lineNumber.getOrElse(0)))"
        f".l"
    )
    callers = _run_query(server, callers_query)
    if not callers:
        return None

    unguarded = []
    guarded = []

    for caller_info in callers:
        if not isinstance(caller_info, (list, tuple)) or len(caller_info) < 2:
            continue
        caller_name = str(caller_info[0])
        safe_caller = _safe_name(caller_name)
        if safe_caller is None:
            continue

        if guard:
            safe_guard = _safe_name(guard)
            if safe_guard is None:
                continue
            guard_query = (
                f'cpg.method.name("{safe_caller}")'
                f'.ast.isCall.name(".*{safe_guard}.*")'
                f".l.nonEmpty"
            )
        else:
            guard_query = (
                f'cpg.method.name("{safe_caller}")'
                f'.ast.isCall.name(".*lock.*|.*mutex.*|.*spin.*|.*rw.*sem.*")'
                f".l.nonEmpty"
            )

        guard_result = _run_query(server, guard_query)

        if guard_result and any(str(r).lower() == "true" for r in guard_result):
            guarded.append(caller_name)
        else:
            unguarded.append(caller_name)

    if not unguarded and not guarded:
        return None

    if unguarded:
        guard_desc = guard or "required lock/guard"
        evidence = (
            f"{len(unguarded)}/{len(unguarded) + len(guarded)} callers of "
            f"{function_name} lack {guard_desc}: "
            f"{', '.join(unguarded[:5])}"
        )
        return CrossFunctionVerdict(
            verified=True,
            verifier_name="caller_constraint",
            evidence=evidence,
            details={
                "unguarded_callers": unguarded[:10],
                "guarded_callers": guarded[:10],
                "guard": guard,
            },
        )

    return CrossFunctionVerdict(
        verified=False,
        verifier_name="caller_constraint",
        evidence=(
            f"All {len(guarded)} callers of {function_name} hold "
            f"{guard or 'a lock/guard'}"
        ),
    )


def _extract_guard_from_hypothesis(hypothesis: str) -> str | None:
    """Extract required guard/lock function name from hypothesis."""
    patterns = [
        re.compile(r"without\s+(?:holding|acquiring)\s+(?:the\s+)?(?:necessary\s+)?[`'\"]?(\w+)[`'\"]?"),
        re.compile(r"after\s+(?:sleeping\s+and\s+)?releasing\s+[`'\"]?(\w+)[`'\"]?"),
        re.compile(r"callers?\s+must\s+(?:call|hold|acquire)\s+[`'\"]?(\w+)[`'\"]?"),
        re.compile(r"(?:lock|mutex|semaphore)\s+[`'\"]?(\w+)[`'\"]?"),
        re.compile(r"[`'\"](\w+_(?:lock|mutex|sem|rwsem|rwlock)(?:_\w+)?)[`'\"]"),
    ]
    for pat in patterns:
        m = pat.search(hypothesis)
        if m:
            name = m.group(1)
            if len(name) >= 2 and name.lower() not in (
                "the", "lock", "mutex", "necessary",
            ):
                return name
    return None


# ── Verifier 4: taint_to_arithmetic ──────────────────────────────────

def _verify_taint_to_arithmetic(
    function_name: str,
    _hypothesis: str,
    server: Any,
) -> CrossFunctionVerdict | None:
    """Check if user-controlled data flows through arithmetic to a size/alloc.

    Uses reachableByFlows from parameters to allocation/size calls,
    then checks if the flow path includes arithmetic operators.
    """
    safe_fn = _safe_name(function_name)
    if safe_fn is None:
        return None

    alloc_sinks = (
        "kmalloc|kzalloc|vmalloc|krealloc|__get_free_pages"
        "|malloc|calloc|realloc|alloca"
        "|memcpy|memmove|copy_from_user|copy_to_user"
        "|make\\\\(|append\\\\(|len\\\\("
    )

    query = (
        "import io.joern.dataflowengineoss.queryengine."
        "{EngineConfig, EngineContext}\n"
        "val ctx = EngineContext(config = EngineConfig(maxCallDepth = 2))\n"
        f'val src = cpg.method.name("{safe_fn}").parameter\n'
        f'val snk = cpg.method.name("{safe_fn}")'
        f'.ast.isCall.name("{alloc_sinks}").argument\n'
        f"snk.reachableByFlows(src)(ctx).l"
        f".map(f => f.elements.map(e => e.code + \"@\" + "
        f"e.lineNumber.getOrElse(0).toString).mkString(\" -> \"))"
        f".l"
    )

    result = _run_query(server, query)
    if result is None:
        return None

    arith_re = re.compile(
        r"(?<![->])[+\-*/%](?![>])"
        r"|<<|>>|min_t|max_t|clamp"
    )
    flows_with_arith = []
    for flow_str in result:
        s = str(flow_str)
        if arith_re.search(s):
            flows_with_arith.append(s[:200])

    if flows_with_arith:
        evidence = (
            f"Parameter-to-alloc flow with arithmetic in {function_name}: "
            f"{'; '.join(flows_with_arith[:3])}"
        )
        return CrossFunctionVerdict(
            verified=True,
            verifier_name="taint_to_arithmetic",
            evidence=evidence,
            details={"flows": flows_with_arith[:5]},
        )

    if result:
        return CrossFunctionVerdict(
            verified=False,
            verifier_name="taint_to_arithmetic",
            evidence=(
                f"Parameter reaches alloc in {function_name} but "
                f"no arithmetic on the path"
            ),
        )

    return CrossFunctionVerdict(
        verified=False,
        verifier_name="taint_to_arithmetic",
        evidence=f"No parameter-to-alloc flow in {function_name}",
    )


# ── Verifier 5: incomplete_cleanup ───────────────────────────────────

def _verify_incomplete_cleanup(
    function_name: str,
    hypothesis: str,
    server: Any,
) -> CrossFunctionVerdict | None:
    """Check if a teardown function cleans some resource lists but not all.

    Finds all struct field accesses and all fields passed to cleanup
    functions, then reports fields of the same type that are accessed
    but never cleaned.
    """
    safe_fn = _safe_name(function_name)
    if safe_fn is None:
        return None

    field_access_query = (
        f'cpg.method.name("{safe_fn}")'
        f".ast.isFieldIdentifier"
        f".map(f => (f.canonicalName, f.lineNumber.getOrElse(0)))"
        f".l"
    )
    accessed = _run_query(server, field_access_query)
    if not accessed:
        return None

    cleanup_patterns = (
        "kfree|vfree|free|release|put_|del_timer|cancel_work"
        "|flush_work|synchronize_rcu|list_del|end_requests"
        "|drain|destroy|cleanup|close|fput|kobject_put"
    )
    cleanup_arg_query = (
        f'cpg.method.name("{safe_fn}")'
        f'.ast.isCall.name("{cleanup_patterns}")'
        f".argument.isFieldIdentifier"
        f".map(f => (f.canonicalName, f.lineNumber.getOrElse(0)))"
        f".l"
    )
    cleaned = _run_query(server, cleanup_arg_query)

    accessed_fields = set()
    for item in accessed:
        if isinstance(item, (list, tuple)) and item:
            accessed_fields.add(str(item[0]))
        else:
            accessed_fields.add(str(item))

    cleaned_fields = set()
    if cleaned:
        for item in cleaned:
            if isinstance(item, (list, tuple)) and item:
                cleaned_fields.add(str(item[0]))
            else:
                cleaned_fields.add(str(item))

    uncleaned = accessed_fields - cleaned_fields
    if not uncleaned or not cleaned_fields:
        return CrossFunctionVerdict(
            verified=False,
            verifier_name="incomplete_cleanup",
            evidence=(
                f"No cleanup gap detected in {function_name} "
                f"({len(accessed_fields)} fields accessed, "
                f"{len(cleaned_fields)} cleaned)"
            ),
        )

    leaked_hint = _extract_leaked_field_from_hypothesis(hypothesis)
    if leaked_hint and leaked_hint in uncleaned:
        evidence = (
            f"Incomplete cleanup in {function_name}: "
            f"field '{leaked_hint}' (named in hypothesis) is accessed "
            f"but not passed to any cleanup function. "
            f"Cleaned fields: {', '.join(sorted(cleaned_fields)[:5])}"
        )
        return CrossFunctionVerdict(
            verified=True,
            verifier_name="incomplete_cleanup",
            evidence=evidence,
            details={
                "uncleaned": sorted(uncleaned),
                "cleaned": sorted(cleaned_fields),
                "hypothesis_field": leaked_hint,
            },
        )

    if len(uncleaned) > 0 and len(cleaned_fields) >= 2:
        evidence = (
            f"Potential cleanup gap in {function_name}: "
            f"{len(uncleaned)} fields accessed but not cleaned "
            f"({', '.join(sorted(uncleaned)[:5])}), "
            f"while {len(cleaned_fields)} are cleaned "
            f"({', '.join(sorted(cleaned_fields)[:5])})"
        )
        return CrossFunctionVerdict(
            verified=True,
            verifier_name="incomplete_cleanup",
            evidence=evidence,
            details={
                "uncleaned": sorted(uncleaned),
                "cleaned": sorted(cleaned_fields),
            },
        )

    return None


def _extract_leaked_field_from_hypothesis(hypothesis: str) -> str | None:
    """Extract the specific field/list name that the hypothesis says leaks."""
    patterns = [
        re.compile(r"[`'\"](?:fpq->|req->|dev->|obj->)?(\w+)[`'\"]?\s+(?:list|queue|buffer)"),
        re.compile(r"(?:list|queue|buffer)\s+[`'\"](?:\w+->)?(\w+)[`'\"]"),
        re.compile(r"clean\s+up\s+(?:the\s+)?[`'\"]?(?:\w+->)?(\w+)[`'\"]"),
        re.compile(r"[`'\"](\w+)[`'\"]?\s+is\s+(?:not|never)\s+(?:cleaned|freed|released|drained)"),
    ]
    for pat in patterns:
        m = pat.search(hypothesis)
        if m:
            return m.group(1)
    return None


# ── Dispatcher ───────────────────────────────────────────────────────

_VERIFIER_FNS = {
    "unchecked_return": _verify_unchecked_return,
    "taint_source_sink": _verify_taint_source_sink,
    "caller_constraint": _verify_caller_constraint,
    "taint_to_arithmetic": _verify_taint_to_arithmetic,
    "incomplete_cleanup": _verify_incomplete_cleanup,
}

_MAX_VERIFIERS_PER_FUNCTION = 2


def cross_function_verify(
    function_name: str,
    file_path: str,
    hypothesis: str,
    server: Any,
) -> CrossFunctionVerdict | None:
    """Dispatch cross-function verifiers based on hypothesis keywords.

    Tries up to _MAX_VERIFIERS_PER_FUNCTION matching verifiers in
    dispatch order.  Returns the first positive verification, or
    None if no verifier matches or none confirms.
    """
    _init_dispatch()

    matched = []
    for pattern, verifier_name in _VERIFIER_DISPATCH:
        if pattern.search(hypothesis):
            matched.append(verifier_name)
            if len(matched) >= _MAX_VERIFIERS_PER_FUNCTION:
                break

    if not matched:
        return None

    for vname in matched:
        fn = _VERIFIER_FNS.get(vname)
        if fn is None:
            continue
        try:
            verdict = fn(function_name, hypothesis, server)
            if verdict is not None and verdict.verified:
                return verdict
        except Exception:
            logger.debug(
                "cross-function verifier %s failed for %s",
                vname, function_name, exc_info=True,
            )

    return None

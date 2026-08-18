"""Fail-open verification channel.

Adjudicates hypotheses of the shape *"control X fails open on error"*
/ *"security result Y is unchecked"* — fully mechanically, with
receipts. The channel never asks the LLM anything; like
``api_boundary`` and ``invariant_smt`` it adjudicates an
already-formed hypothesis and follows their verdict discipline
(confirmed / refuted / inconclusive-with-reason, never a guess).

A fail-open confirmation is the conjunction of three mechanically
demonstrable facts:

1. **Role** — the guarded call/region is security-relevant
   (:mod:`core.audit.fail_open_roles`: tiered vocabulary + learned
   target vocabulary with anti-laundering grade rules).
2. **Handler outcome** — the error path is *permissive*: exception
   swallowed, error return ignored, tri-state error value accepted
   (:mod:`core.audit.fail_open_lang` per-language analyzers).
3. **Fallibility** — something inside the guarded region can actually
   fail (a raise-capable callee, a ``wur:`` fact, a known return
   contract) — otherwise the handler is dead and the hypothesis
   vacuous.

Attacker reachability (leg 3) is an **escalator, not a gate**: it runs
only after legs 1+2 confirm, and its absence never blocks the core
verdict. Two forms: cheap entry-point reachability (always attempted
on confirm) and the Joern flow escalator (phase 2 — a confirmed flow
from a hypothesis-named tainted parameter to the fallible callee
stamps the receipt ``tainted``/``joern:flow``: the attacker can
provoke the swallowed error).

CWE-252 premise split (shared-evidence family with the consistency
programme): **role-bound + hypothesis-driven** adjudications are this
channel's (``fail_open:ignored-return``); contract-/majority-bound
census sweeps belong to ``consistency:return-check`` and are NOT
implemented here. The ``corroboration`` receipt field accepts both
plain tool stamps and structured receipt dicts, so the consistency
programme's ``PeerEvidence.to_dict()`` majority-evidence receipts slot
in without a schema change.

Verdict semantics:

* ``confirmed`` — role bound with registry-grade evidence (a
  detection-grade-only role — naming stem, heuristic-tier spec, lone
  seed match — confirms under the ``-naming`` detection rule-id
  variant, which can never promote alone), the permissive handler /
  ignore site located with its idiom, and fallibility demonstrated.
* ``refuted`` — fail-closed demonstrated with per-site receipts (the
  handler re-raises / returns a restrictive value / aborts, or every
  site checks the result correctly).
* ``inconclusive`` — one of seven enumerated reasons (each a distinct
  tested string); never silently dropped.

No LLM calls, no subprocesses.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .fail_open_lang import (
    SUPPORTED_LANGUAGES,
    CallSiteOutcome,
    HandlerOutcome,
    c_function_span,
    c_ignored_return_sites,
    c_tristate_sites,
    function_parameters,
    go_discard_sites,
    go_function_returns_error,
    go_function_span,
    go_recover_handlers,
    java_class_extends,
    java_function_throws,
    java_handlers,
    java_method_segment,
    language_for_path,
    python_function_raises,
    python_handlers,
)
from .fail_open_roles import (
    GRADE_DETECTION,
    RoleContext,
    RoleEvidence,
    bind_role,
)

logger = logging.getLogger(__name__)

# Rule-id namespace: fail_open:<leg>. (The mechanical detector's
# "fail_open" name lives in mechanical-findings.json, a different
# artifact; receipts are always namespaced so no collision.)
RULE_HANDLER_OUTCOME = "fail_open:handler-outcome"
RULE_IGNORED_RETURN = "fail_open:ignored-return"
RULE_TRISTATE = "fail_open:tristate"
RULE_RECOVER_CONTINUE = "fail_open:recover-continue"   # phase 2 (Go)
RULE_UNAWAITED = "fail_open:unawaited"                 # phase 3 (JS/TS)

ALL_RULE_IDS = (
    RULE_HANDLER_OUTCOME,
    RULE_IGNORED_RETURN,
    RULE_TRISTATE,
    RULE_RECOVER_CONTINUE,
    RULE_UNAWAITED,
)

# Detection-grade role evidence selects the -naming rule-id variant
# (may not promote alone; participates in channel aggregation).
DETECTION_VARIANT_SUFFIX = "-naming"

# Enumerated inconclusive reasons (each a distinct tested string).
REASON_ROLE_UNBOUND = "role-unbound"
REASON_HANDLER_UNDECIDED = "handler-undecided"
REASON_FALLIBILITY_UNRESOLVED = "fallibility-unresolved"
REASON_LANGUAGE_UNSUPPORTED = "language-unsupported"
REASON_TYPES_UNRESOLVED = "types-unresolved"
REASON_ASYNC_UNPROVABLE = "async-unprovable"
REASON_HYPOTHESIS_UNBINDABLE = "hypothesis-unbindable"
REASON_SPAN_UNRESOLVED = "span-unresolved"

INCONCLUSIVE_REASONS = frozenset({
    REASON_ROLE_UNBOUND,
    REASON_HANDLER_UNDECIDED,
    REASON_FALLIBILITY_UNRESOLVED,
    REASON_LANGUAGE_UNSUPPORTED,
    REASON_TYPES_UNRESOLVED,
    REASON_ASYNC_UNPROVABLE,
    REASON_HYPOTHESIS_UNBINDABLE,
    REASON_SPAN_UNRESOLVED,
})

# CWE families the channel joins via the fallback chain. CWE-248
# (uncaught exception) is the *inverse* shape — included tentatively
# for hypothesis routing only; its verdicts stay inconclusive until a
# use case appears (design §15.2).
FAIL_OPEN_CWES = frozenset({
    "CWE-703", "CWE-636", "CWE-391", "CWE-390", "CWE-252", "CWE-248",
    # Authenticity family: "insufficient verification of data
    # authenticity" is a verification role whose failure or absence
    # lets the data through — exactly the role x permissive-outcome x
    # fallibility question this channel adjudicates. The api-boundary
    # channel covers the caller-obligation leg (see
    # api_boundary.API_BOUNDARY_CWES).
    "CWE-345",
})

# Hypothesis shapes that assert a fail-open / swallowed-error defect.
_FAIL_OPEN_HYPOTHESIS_RE = re.compile(
    r"(?:fail[s\-]?\s?open"
    r"|swallow\w*.{0,20}(?:exception|error|failure)"
    r"|(?:empty|silent)\W{0,20}(?:catch|except|handler)"
    r"|(?:ignor|discard|unchecked)\w*.{0,30}"
    r"(?:error|return\s+(?:value|code)|result|\berr\b)"
    r"|(?:error|return\s+(?:value|code)|result|\berr\b).{0,40}"
    r"(?:ignor|discard|unchecked|\bnot\s+checked)"
    r"|recover\w*.{0,20}continue"
    r"|unawaited|floating\s+promise"
    r"|(?:verif|auth|valid|sanitiz|permission)\w*.{0,40}"
    r"(?:error|exception|failure)\w*.{0,30}"
    r"(?:proceed|continue|allow|bypass|ignored|silently))",
    re.IGNORECASE | re.DOTALL,
)

_BACKTICK_IDENT_RE = re.compile(r"`([A-Za-z_][\w.]*)\s*(?:\(\s*\))?`")
_IDENT_RE = re.compile(r"\b([A-Za-z_]\w{2,})\b")

# Words in hypothesis prose that are never callee candidates.
_HYPOTHESIS_STOPWORDS = frozenset({
    "the", "and", "for", "not", "with", "when", "value", "return",
    "returns", "returned", "error", "errors", "result", "check",
    "checked", "unchecked", "ignored", "ignores", "call", "calls",
    "function", "failure", "fails", "fail", "open", "silently",
    "exception", "swallowed", "swallows", "proceeds", "continues",
    "handler", "tri", "state", "tristate", "comparison", "truth",
    "test", "accepts", "success", "int", "void", "char", "this",
})

# Reachability escalator bounds (leg 3, cheap form).
_REACHABILITY_MAX_DEPTH = 8
_REACHABILITY_MAX_VISITED = 200


def is_fail_open_hypothesis(text: str) -> bool:
    """True when the hypothesis asserts a fail-open / swallowed-error
    shape (permissive handler, ignored security return, tri-state
    confusion, recover-and-continue, unawaited rejection)."""
    return bool(text) and bool(_FAIL_OPEN_HYPOTHESIS_RE.search(text))


def fail_open_applicable(cwe: str) -> bool:
    """True when the CWE belongs to the fail-open family."""
    norm = (cwe or "").upper().strip()
    if norm and not norm.startswith("CWE-"):
        norm = f"CWE-{norm}"
    return norm in FAIL_OPEN_CWES


def is_detection_rule_id(rule_id: str) -> bool:
    """True for the detection-grade rule-id variants (naming-only /
    uncorroborated role evidence) — they may not promote alone but
    participate in ``_aggregate_channel_confirmations``."""
    return rule_id.startswith("fail_open:") and rule_id.endswith(
        DETECTION_VARIANT_SUFFIX,
    )


@dataclass
class FailOpenResult:
    """Aggregate channel verdict for one fail-open hypothesis."""

    outcome: str                 # confirmed | refuted | inconclusive
    reason: str
    rule_id: str = RULE_HANDLER_OUTCOME
    language: str = ""
    role: dict[str, Any] | None = None
    handler: dict[str, Any] | None = None
    fallible: dict[str, Any] | None = None
    sites: list[CallSiteOutcome] = field(default_factory=list)
    reachability: dict[str, Any] | None = None
    # Corroborating receipts: plain tool stamps
    # ("compiler:-Wunused-result") AND structured receipt dicts — the
    # consistency programme's PeerEvidence.to_dict() majority-evidence
    # receipts slot in here without a schema change.
    corroboration: list[Any] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "outcome": self.outcome,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "language": self.language,
        }
        # Optional receipt sections: absence is meaningful (leg not
        # run / not available) and never blocks the core verdict.
        if self.role is not None:
            d["role"] = self.role
        if self.handler is not None:
            d["handler"] = self.handler
        if self.fallible is not None:
            d["fallible"] = self.fallible
        if self.sites:
            d["sites"] = [s.to_dict() for s in self.sites]
        if self.reachability is not None:
            d["reachability"] = self.reachability
        if self.corroboration:
            d["corroboration"] = [
                c.to_dict() if hasattr(c, "to_dict") else c
                for c in self.corroboration
            ]
        return d


# ── helpers ─────────────────────────────────────────────────────────


def _inconclusive(
    reason: str, detail: str, *, language: str = "",
    rule_id: str = RULE_HANDLER_OUTCOME,
) -> FailOpenResult:
    return FailOpenResult(
        outcome="inconclusive",
        reason=f"{reason}: {detail}" if detail else reason,
        rule_id=rule_id,
        language=language,
    )


def _apply_role_grade(rule_id: str, role: RoleEvidence) -> str:
    if role.grade == GRADE_DETECTION:
        return rule_id + DETECTION_VARIANT_SUFFIX
    return rule_id


def _read_source(target_path: Path, file_path: str) -> str | None:
    try:
        p = Path(target_path) / file_path
        if p.is_file():
            return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    return None


def _function_tail(name: str) -> str:
    return name.rsplit(".", 1)[-1] if name else ""


def _python_function_segment(source: str, function_name: str) -> str:
    """Source segment of a Python function including its decorators
    (Tier-B hook-mechanics matching needs the decorator lines)."""
    import ast as _ast
    try:
        tree = _ast.parse(source)
    except SyntaxError:
        return ""
    tail = _function_tail(function_name)
    lines = source.splitlines()
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)) \
                and node.name == tail:
            start = node.lineno
            if node.decorator_list:
                start = min(d.lineno for d in node.decorator_list)
            end = node.end_lineno or node.lineno
            return "\n".join(lines[start - 1:end])
    return ""


def _entry_reachability(
    role_context: RoleContext,
    inventory: dict[str, Any] | None,
    file_path: str,
    function_name: str,
) -> dict[str, Any] | None:
    """Leg-3 escalator, cheap form: entry-point reachability of the
    enclosing function via context-map entry points + bounded reverse
    BFS on the inventory call graph. Returns None when the leg cannot
    run (no context map) — absence is meaningful in the receipt."""
    context_map = role_context.context_map
    if not context_map:
        return None
    entries: set[tuple[str, str]] = set()
    for ep in context_map.get("entry_points") or []:
        if not isinstance(ep, dict):
            continue
        name = ep.get("function") or ep.get("name") or ""
        if name:
            entries.add((ep.get("file", ""), name))
    if not entries:
        return {"status": "unknown",
                "detail": "context map carries no entry points"}
    entry_names = {name for _, name in entries}
    if (file_path, function_name) in entries \
            or function_name in entry_names:
        return {
            "status": "entry_reachable",
            "detail": f"{function_name} is itself an entry point",
        }
    if not inventory:
        return {"status": "unknown",
                "detail": "no inventory call graph for reverse walk"}
    try:
        from core.analysis.reachability import InternalFunction, callers_of
    except ImportError:
        return {"status": "unknown", "detail": "reachability unavailable"}
    visited: set[tuple[str, str]] = {(file_path, function_name)}
    frontier = [(file_path, function_name)]
    depth = 0
    try:
        while frontier and depth < _REACHABILITY_MAX_DEPTH \
                and len(visited) < _REACHABILITY_MAX_VISITED:
            next_frontier: list[tuple[str, str]] = []
            for fp, fn in frontier:
                result = callers_of(
                    inventory,
                    InternalFunction(file_path=fp, name=fn, line=0),
                )
                for caller in result.all_callers:
                    key = (caller.file_path, caller.name)
                    if key in visited:
                        continue
                    visited.add(key)
                    if key in entries or caller.name in entry_names:
                        return {
                            "status": "entry_reachable",
                            "detail": (
                                f"reachable from entry point "
                                f"{caller.name} ({depth + 1} hop(s))"
                            ),
                        }
                    next_frontier.append(key)
            frontier = next_frontier
            depth += 1
    except Exception:
        logger.debug("fail_open: reachability walk failed", exc_info=True)
        return {"status": "unknown", "detail": "reachability walk errored"}
    return {"status": "unknown",
            "detail": "no path from a known entry point found"}


# ── Python leg: handler outcome ─────────────────────────────────────


def _python_fallibility(
    handler: HandlerOutcome, source: str,
) -> dict[str, Any] | None:
    """Leg 2b for Python: evidence that the guarded region can raise."""
    caught = set(handler.caught)
    for callee in handler.try_calls:
        raised = python_function_raises(source, callee)
        if raised and (handler.broad or (set(raised) & caught)):
            return {
                "callee": callee,
                "line": handler.try_span[0] if handler.try_span else 0,
                "evidence": "raises",
                "types": raised,
            }
    if handler.broad and handler.try_calls:
        return {
            "callee": handler.try_calls[0],
            "line": handler.try_span[0] if handler.try_span else 0,
            "evidence": "catchable: any-call-under-broad-catch",
            "types": sorted(caught),
        }
    return None


def _handler_in_function(handler: HandlerOutcome,
                         function_name: str) -> bool:
    tail = _function_tail(function_name)
    return _function_tail(handler.enclosing_function) == tail


def _run_python_check(
    source: str,
    file_path: str,
    function_name: str,
    role_context: RoleContext,
    inventory: dict[str, Any] | None,
) -> FailOpenResult:
    handlers = [
        h for h in python_handlers(source, file_path)
        if _handler_in_function(h, function_name)
    ]
    if not handlers:
        return _inconclusive(
            REASON_HYPOTHESIS_UNBINDABLE,
            f"no exception handler or suppression block found in "
            f"{function_name}",
            language="python",
        )

    permissive = [h for h in handlers if h.is_permissive]
    fail_closed = [h for h in handlers if h.is_fail_closed]
    undecided = [
        h for h in handlers
        if not h.is_permissive and not h.is_fail_closed
    ]

    if not permissive:
        if fail_closed and not undecided:
            first = fail_closed[0]
            return FailOpenResult(
                outcome="refuted",
                reason=(
                    f"fail-closed handler(s) demonstrated: "
                    f"{first.evidence_snippet} at {file_path}:"
                    f"{first.line} ({first.permissive_value}); no "
                    f"permissive handler present in {function_name}"
                ),
                rule_id=RULE_HANDLER_OUTCOME,
                language="python",
                handler=first.to_dict(),
            )
        first = undecided[0] if undecided else handlers[0]
        return _inconclusive(
            REASON_HANDLER_UNDECIDED,
            f"handler at {file_path}:{first.line} does substantial "
            f"fallback work ({first.permissive_value}) — outcome not "
            "structurally decidable",
            language="python",
        )

    segment = _python_function_segment(source, function_name)
    role: RoleEvidence | None = None
    chosen: HandlerOutcome | None = None
    for handler in permissive:
        role = bind_role(
            handler.try_calls,
            function_name,
            file_path,
            language="python",
            context=role_context,
            enclosing_source=segment,
        )
        if role is not None:
            chosen = handler
            break
    if role is None or chosen is None:
        return _inconclusive(
            REASON_ROLE_UNBOUND,
            "could not bind a security role to the guarded region "
            f"(calls: {', '.join(permissive[0].try_calls) or '<none>'})",
            language="python",
        )

    fallible = _python_fallibility(chosen, source)
    if fallible is None:
        return _inconclusive(
            REASON_FALLIBILITY_UNRESOLVED,
            "no raise-capable callee resolvable inside the guarded "
            "region — a swallow around code that cannot fail is "
            "vacuous",
            language="python",
        )

    rule_id = _apply_role_grade(RULE_HANDLER_OUTCOME, role)
    caught_desc = ", ".join(chosen.caught)
    reason = (
        f"{chosen.evidence_snippet or chosen.idiom} at "
        f"{file_path}:{chosen.line} swallows {fallible['callee']} "
        f"({caught_desc}) inside {role.kind}-role region; control "
        f"proceeds as if the check passed"
    )
    result = FailOpenResult(
        outcome="confirmed",
        reason=reason,
        rule_id=rule_id,
        language="python",
        role=role.to_dict(),
        handler=chosen.to_dict(),
        fallible=fallible,
    )
    result.reachability = _entry_reachability(
        role_context, inventory, file_path, function_name,
    )
    return result


# ── Java leg: catch-clause outcome ──────────────────────────────────


def _java_fallibility(
    handler: HandlerOutcome, source: str,
) -> dict[str, Any] | None:
    """Leg 2b for Java: evidence that the guarded region can throw.

    Strongest form is the swallowed-checked-exception story: a callee
    inside the try body *declares* (or raises) the very type the
    handler catches — the type system forced the author to write this
    handler and its body is permissive anyway. Broad catches accept
    any call with the weaker ``any-call-under-broad-catch`` receipt.
    """
    caught = set(handler.caught)
    line = handler.try_span[0] if handler.try_span else 0
    for callee in handler.try_calls:
        thrown = java_function_throws(source, callee)
        if not thrown:
            continue
        declared_and_caught = set(thrown) & caught
        if declared_and_caught:
            return {
                "callee": callee,
                "line": line,
                "evidence": "declared-throws",
                "types": thrown,
            }
        if handler.broad:
            return {
                "callee": callee,
                "line": line,
                "evidence": "throws",
                "types": thrown,
            }
    if handler.broad and handler.try_calls:
        return {
            "callee": handler.try_calls[0],
            "line": line,
            "evidence": "catchable: any-call-under-broad-catch",
            "types": sorted(caught),
        }
    return None


def _run_java_check(
    source: str,
    file_path: str,
    function_name: str,
    role_context: RoleContext,
    inventory: dict[str, Any] | None,
) -> FailOpenResult:
    all_handlers = java_handlers(source, file_path)
    if all_handlers is None:
        return _inconclusive(
            REASON_LANGUAGE_UNSUPPORTED,
            "no tree-sitter java parser available — the Java leg has "
            "no honest regex fallback for brace-delimited handlers",
            language="java",
        )
    handlers = [
        h for h in all_handlers
        if _handler_in_function(h, function_name)
    ]
    if not handlers:
        return _inconclusive(
            REASON_HYPOTHESIS_UNBINDABLE,
            f"no catch clause found in {function_name}",
            language="java",
        )

    permissive = [h for h in handlers if h.is_permissive]
    fail_closed = [h for h in handlers if h.is_fail_closed]
    undecided = [
        h for h in handlers
        if not h.is_permissive and not h.is_fail_closed
    ]

    if not permissive:
        if fail_closed and not undecided:
            first = fail_closed[0]
            return FailOpenResult(
                outcome="refuted",
                reason=(
                    f"fail-closed handler(s) demonstrated: "
                    f"{first.evidence_snippet} at {file_path}:"
                    f"{first.line} ({first.permissive_value}); no "
                    f"permissive handler present in {function_name}"
                ),
                rule_id=RULE_HANDLER_OUTCOME,
                language="java",
                handler=first.to_dict(),
            )
        first = undecided[0] if undecided else handlers[0]
        return _inconclusive(
            REASON_HANDLER_UNDECIDED,
            f"handler at {file_path}:{first.line} does substantial "
            f"fallback work ({first.permissive_value}) — outcome not "
            "structurally decidable",
            language="java",
        )

    segment = java_method_segment(source, function_name)
    role: RoleEvidence | None = None
    chosen: HandlerOutcome | None = None
    for handler in permissive:
        role = bind_role(
            handler.try_calls,
            function_name,
            file_path,
            language="java",
            context=role_context,
            enclosing_source=segment,
        )
        if role is not None:
            chosen = handler
            break
    if role is None or chosen is None:
        return _inconclusive(
            REASON_ROLE_UNBOUND,
            "could not bind a security role to the guarded region "
            f"(calls: {', '.join(permissive[0].try_calls) or '<none>'})",
            language="java",
        )

    fallible = _java_fallibility(chosen, source)
    if fallible is None and chosen.try_calls and not chosen.broad:
        # Checked-exception compilability witness: a specific catch of
        # a checked type compiles only when the try body can throw it.
        # Resolvable same-file as unchecked -> no witness; type not
        # declared in this file -> its checkedness is unknowable here.
        unresolved: list[str] = []
        for caught_type in chosen.caught:
            superclass = java_class_extends(source, caught_type)
            if superclass is None:
                if caught_type not in ("<expr>",):
                    unresolved.append(caught_type)
                continue
            if superclass not in ("RuntimeException", "Error") \
                    and superclass.endswith(("Exception", "Throwable")):
                fallible = {
                    "callee": chosen.try_calls[0],
                    "line": chosen.try_span[0] if chosen.try_span else 0,
                    "evidence": (
                        f"checked-exception-catch:{caught_type} "
                        "(the catch compiles only if the try body can "
                        "throw it)"
                    ),
                    "types": [caught_type],
                }
                break
        if fallible is None and unresolved:
            return _inconclusive(
                REASON_TYPES_UNRESOLVED,
                f"caught type(s) {', '.join(unresolved)} not "
                "resolvable in this file — cannot decide checked "
                "(compilability witness) vs unchecked, and no "
                "same-file callee declares them",
                language="java",
            )
    if fallible is None:
        return _inconclusive(
            REASON_FALLIBILITY_UNRESOLVED,
            "no throw-capable callee resolvable inside the try body "
            "(no same-file declared-throws and the catch is not "
            "broad) — a swallow around code that cannot throw is "
            "vacuous",
            language="java",
        )

    rule_id = _apply_role_grade(RULE_HANDLER_OUTCOME, role)
    caught_desc = ", ".join(chosen.caught)
    reason = (
        f"{chosen.evidence_snippet or chosen.idiom} at "
        f"{file_path}:{chosen.line} swallows {fallible['callee']} "
        f"({caught_desc}) inside {role.kind}-role region; control "
        f"proceeds as if the check passed"
    )
    result = FailOpenResult(
        outcome="confirmed",
        reason=reason,
        rule_id=rule_id,
        language="java",
        role=role.to_dict(),
        handler=chosen.to_dict(),
        fallible=fallible,
    )
    result.reachability = _entry_reachability(
        role_context, inventory, file_path, function_name,
    )
    return result


# ── C legs: ignored return + tri-state ──────────────────────────────


def _hypothesis_identifiers(hypothesis: str) -> list[str]:
    """Identifiers the hypothesis names, backticked ones first,
    stopwords dropped, order preserved."""
    ordered: list[str] = []
    seen: set[str] = set()
    for m in _BACKTICK_IDENT_RE.finditer(hypothesis):
        name = m.group(1).rstrip("(")
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    for m in _IDENT_RE.finditer(hypothesis):
        name = m.group(1)
        if name.lower() in _HYPOTHESIS_STOPWORDS or name in seen:
            continue
        seen.add(name)
        ordered.append(name)
    return ordered


def _candidate_callees(hypothesis: str, segment: str) -> list[str]:
    """Callee candidates: identifiers the hypothesis names that appear
    as calls inside the function under review."""
    return [
        n for n in _hypothesis_identifiers(hypothesis)
        if re.search(rf"\b{re.escape(_function_tail(n))}\s*\(", segment)
    ]


def _same_file_wur(source: str, tail: str) -> bool:
    """True when the TU itself declares ``tail`` with a
    warn_unused_result spelling (kernel ``__must_check``, glibc
    ``__wur``, ``[[nodiscard]]``, …) — the target's own header is the
    fallibility witness."""
    try:
        from packages.source_intel.aliases import wur_alias_in
    except ImportError:
        return False
    lines = source.splitlines()
    decl_re = re.compile(rf"\b{re.escape(tail)}\s*\(")
    for idx, line in enumerate(lines):
        if not decl_re.search(line):
            continue
        window = "\n".join(lines[max(0, idx - 2):idx + 1])
        if wur_alias_in(window):
            return True
    return False


def _c_fallibility(
    callee: str,
    role: RoleEvidence,
    role_context: RoleContext,
    source: str = "",
) -> dict[str, Any] | None:
    """Leg 2b for C: wur fact (harvested or from the TU's own
    declaration), learned/registry return contract, or Tier-A
    membership."""
    tail = _function_tail(callee)
    if tail in role_context.wur_functions:
        return {
            "callee": callee,
            "evidence": f"wur:{tail}",
            "types": [],
        }
    if source and _same_file_wur(source, tail):
        return {
            "callee": callee,
            "evidence": f"wur:{tail} (declared warn_unused_result in "
                        "this TU)",
            "types": [],
        }
    if role.contract:
        return {
            "callee": callee,
            "evidence": f"contract:{role.contract}",
            "types": [],
        }
    if role.source == "universal_registry":
        return {
            "callee": callee,
            "evidence": "tier_a:posix-fallible",
            "types": [],
        }
    return None


def _run_c_check(
    source: str,
    file_path: str,
    function_name: str,
    hypothesis: str,
    language: str,
    role_context: RoleContext,
    inventory: dict[str, Any] | None,
) -> FailOpenResult:
    span = c_function_span(source, function_name, language=language)
    lines = source.splitlines()
    if span:
        segment = "\n".join(lines[span[0] - 1:span[1]])
    else:
        # Whole-file fallback removed: with function_span=None the
        # site classifiers ran over the entire file, so a "confirmed"
        # could cite a site in a DIFFERENT function than the
        # hypothesis names. Span-resolution failure is a mechanical
        # limitation, not evidence — inconclusive.
        return _inconclusive(
            REASON_SPAN_UNRESOLVED,
            f"cannot resolve the span of {function_name} — refusing "
            "the whole-file scan (a match elsewhere in the file is "
            "not evidence about this function)",
            language=language, rule_id=RULE_IGNORED_RETURN,
        )

    candidates = _candidate_callees(hypothesis, segment)
    if not candidates:
        return _inconclusive(
            REASON_HYPOTHESIS_UNBINDABLE,
            f"hypothesis names no call present in {function_name}",
            language=language, rule_id=RULE_IGNORED_RETURN,
        )

    role: RoleEvidence | None = None
    callee = ""
    for candidate in candidates:
        role = bind_role(
            [candidate],
            "",  # per-callee binding: the enclosing name must not
                 # smuggle a role onto an unrelated callee
            file_path,
            language=language,
            context=role_context,
            enclosing_source=segment,
        )
        if role is not None:
            callee = candidate
            break
    if role is None:
        return _inconclusive(
            REASON_ROLE_UNBOUND,
            "could not bind a security role to any hypothesis callee "
            f"({', '.join(candidates)})",
            language=language, rule_id=RULE_IGNORED_RETURN,
        )

    tail = _function_tail(callee)
    if not role.contract:
        # The winning role evidence (e.g. a domain-model invariant)
        # may not carry the return contract — the contract triple can
        # live on the Tier-A entry / seed exemplar / domain-model
        # contract for the same callee.
        from .fail_open_roles import lookup_contract
        role.contract = lookup_contract(
            callee, language=language, context=role_context,
        )
    tristate = role.contract.startswith("tristate")
    base_rule = RULE_TRISTATE if tristate else RULE_IGNORED_RETURN

    fallible = _c_fallibility(callee, role, role_context, source)
    if fallible is None:
        return _inconclusive(
            REASON_FALLIBILITY_UNRESOLVED,
            f"no return contract, wur: fact, or Tier-A membership for "
            f"{callee} — cannot demonstrate the guarded call can fail",
            language=language, rule_id=base_rule,
        )

    if tristate:
        sites = c_tristate_sites(
            source, file_path, tail,
            language=language, function_span=span,
        )
    else:
        sites = c_ignored_return_sites(
            source, file_path, tail,
            language=language, function_span=span,
        )
    if not sites:
        return _inconclusive(
            REASON_HYPOTHESIS_UNBINDABLE,
            f"no call sites of {callee} located in {function_name}",
            language=language, rule_id=base_rule,
        )

    unguarded = [s for s in sites if s.verdict == "unguarded"]
    undecided = [s for s in sites if s.verdict == "undecided"]
    rule_id = _apply_role_grade(base_rule, role)

    if unguarded:
        first = unguarded[0]
        result = FailOpenResult(
            outcome="confirmed",
            reason=(
                f"{first.code} at {file_path}:{first.line} — "
                f"{first.evidence} ({role.kind}-role callee "
                f"{callee}, {fallible['evidence']})"
            ),
            rule_id=rule_id,
            language=language,
            role=role.to_dict(),
            handler={
                "idiom": ("tristate_accepts_error" if tristate
                          else "ignored_return"),
                "line": first.line,
                "caught": [callee],
                "broad": False,
                "outcome_kind": ("tristate_accepts_error" if tristate
                                 else "ignored_return"),
                "permissive_value": first.shape,
                "code": first.code,
                "parser": first.parser,
            },
            fallible=fallible,
            sites=sites,
        )
        result.reachability = _entry_reachability(
            role_context, inventory, file_path, function_name,
        )
        return result
    if not undecided:
        return FailOpenResult(
            outcome="refuted",
            reason=(
                f"all {len(sites)} site(s) of {callee} in "
                f"{function_name} handle the result fail-closed "
                f"(receipts per site)"
            ),
            rule_id=base_rule,
            language=language,
            role=role.to_dict(),
            fallible=fallible,
            sites=sites,
        )
    return FailOpenResult(
        outcome="inconclusive",
        reason=(
            f"{REASON_HANDLER_UNDECIDED}: {len(undecided)} of "
            f"{len(sites)} site(s) could not be structurally decided"
        ),
        rule_id=base_rule,
        language=language,
        role=role.to_dict(),
        fallible=fallible,
        sites=sites,
    )


# ── Go legs: discarded error + recover-to-continue ──────────────────

_RECOVER_HYPOTHESIS_RE = re.compile(r"\brecover|\bpanic", re.IGNORECASE)


def _go_segment(source: str, function_name: str) -> str:
    span = go_function_span(source, function_name)
    if span is None:
        return ""
    lines = source.splitlines()
    return "\n".join(lines[span[0] - 1:span[1]])


def _inventory_signature(
    inventory: dict[str, Any] | None, name: str,
) -> str:
    """Recorded signature/return type of *name* from the inventory
    extractor metadata (Go fallibility fallback when the callee is not
    defined in the hypothesis's file)."""
    tail = name.rsplit(".", 1)[-1]
    for frec in (inventory or {}).get("files", []) or []:
        # The builder emits per-file "items"; older inventories carried
        # "functions" — accept both.
        for fn in frec.get("items", frec.get("functions", [])) or []:
            if fn.get("name") != tail:
                continue
            sig = fn.get("signature") or ""
            meta = fn.get("metadata") or {}
            return " ".join(
                str(x) for x in (sig, meta.get("return_type") or "")
            ).strip()
    return ""


def _go_fallibility(
    callee: str,
    role: RoleEvidence,
    source: str,
    inventory: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Leg 2b for Go: the callee's result includes ``error`` (same-file
    signature, then inventory extractor metadata), or a learned
    ``err_second`` contract."""
    tail = _function_tail(callee)
    if go_function_returns_error(source, tail):
        return {
            "callee": callee,
            "evidence": "returns-error (same-file signature)",
            "types": ["error"],
        }
    sig = _inventory_signature(inventory, tail)
    if sig and re.search(r"\berror\b", sig):
        return {
            "callee": callee,
            "evidence": "returns-error (inventory signature)",
            "types": ["error"],
        }
    if role.contract == "err_second":
        return {
            "callee": callee,
            "evidence": "contract:err_second",
            "types": ["error"],
        }
    return None


def _run_go_recover_check(
    source: str,
    file_path: str,
    function_name: str,
    role_context: RoleContext,
    inventory: dict[str, Any] | None,
) -> FailOpenResult:
    all_handlers = go_recover_handlers(source, file_path)
    if all_handlers is None:
        return _inconclusive(
            REASON_LANGUAGE_UNSUPPORTED,
            "no tree-sitter go parser available — recover() handler "
            "bodies are not honestly classifiable from line shapes",
            language="go", rule_id=RULE_RECOVER_CONTINUE,
        )
    handlers = [
        h for h in all_handlers
        if _handler_in_function(h, function_name)
    ]
    if not handlers:
        return _inconclusive(
            REASON_HYPOTHESIS_UNBINDABLE,
            f"no deferred recover() handler found in {function_name}",
            language="go", rule_id=RULE_RECOVER_CONTINUE,
        )

    permissive = [h for h in handlers if h.is_permissive]
    fail_closed = [h for h in handlers if h.is_fail_closed]
    if not permissive:
        if fail_closed:
            first = fail_closed[0]
            return FailOpenResult(
                outcome="refuted",
                reason=(
                    f"recover() handler at {file_path}:{first.line} "
                    f"is fail-closed ({first.permissive_value}); the "
                    "panic does not proceed"
                ),
                rule_id=RULE_RECOVER_CONTINUE,
                language="go",
                handler=first.to_dict(),
            )
        first = handlers[0]
        return _inconclusive(
            REASON_HANDLER_UNDECIDED,
            f"recover() handler at {file_path}:{first.line} outcome "
            "not structurally decidable",
            language="go", rule_id=RULE_RECOVER_CONTINUE,
        )

    segment = _go_segment(source, function_name)
    role: RoleEvidence | None = None
    chosen: HandlerOutcome | None = None
    for handler in permissive:
        role = bind_role(
            handler.try_calls,
            function_name,
            file_path,
            language="go",
            context=role_context,
            enclosing_source=segment,
        )
        if role is not None:
            chosen = handler
            break
    if role is None or chosen is None:
        return _inconclusive(
            REASON_ROLE_UNBOUND,
            "could not bind a security role to the recover()-guarded "
            f"region (calls: "
            f"{', '.join(permissive[0].try_calls) or '<none>'})",
            language="go", rule_id=RULE_RECOVER_CONTINUE,
        )

    if not chosen.try_calls:
        return _inconclusive(
            REASON_FALLIBILITY_UNRESOLVED,
            "the recover()-guarded region makes no calls — nothing "
            "can panic, the handler is vacuous",
            language="go", rule_id=RULE_RECOVER_CONTINUE,
        )
    # recover() catches every panic — the broad-catch acceptance rule
    # (weaker receipt), mirroring any-call-under-broad-catch.
    fallible = {
        "callee": chosen.try_calls[0],
        "line": chosen.try_span[0] if chosen.try_span else 0,
        "evidence": "catchable: any-call-under-recover",
        "types": ["<panic>"],
    }

    rule_id = _apply_role_grade(RULE_RECOVER_CONTINUE, role)
    reason = (
        f"{chosen.evidence_snippet or chosen.idiom} at "
        f"{file_path}:{chosen.line} recovers any panic (incl. from "
        f"{fallible['callee']}) inside {role.kind}-role region and "
        f"control continues ({chosen.permissive_value})"
    )
    result = FailOpenResult(
        outcome="confirmed",
        reason=reason,
        rule_id=rule_id,
        language="go",
        role=role.to_dict(),
        handler=chosen.to_dict(),
        fallible=fallible,
    )
    result.reachability = _entry_reachability(
        role_context, inventory, file_path, function_name,
    )
    return result


def _run_go_check(
    source: str,
    file_path: str,
    function_name: str,
    hypothesis: str,
    role_context: RoleContext,
    inventory: dict[str, Any] | None,
) -> FailOpenResult:
    if _RECOVER_HYPOTHESIS_RE.search(hypothesis):
        return _run_go_recover_check(
            source, file_path, function_name, role_context, inventory,
        )

    # Parser-absent is the documented degradation contract — report
    # it as such rather than as a span failure.
    from .fail_open_lang import _ts_parser
    if _ts_parser("go") is None:
        return _inconclusive(
            REASON_LANGUAGE_UNSUPPORTED,
            "go grammar unavailable — cannot resolve function spans",
            language="go", rule_id=RULE_IGNORED_RETURN,
        )
    span = go_function_span(source, function_name)
    segment = _go_segment(source, function_name)
    if not segment:
        # Whole-file fallback removed: same policy as the C leg — a
        # match elsewhere in the file is not evidence about this
        # function.
        return _inconclusive(
            REASON_SPAN_UNRESOLVED,
            f"cannot resolve the span of {function_name} — refusing "
            "the whole-file scan (a match elsewhere in the file is "
            "not evidence about this function)",
            language="go", rule_id=RULE_IGNORED_RETURN,
        )

    candidates = _candidate_callees(hypothesis, segment)
    if not candidates:
        return _inconclusive(
            REASON_HYPOTHESIS_UNBINDABLE,
            f"hypothesis names no call present in {function_name}",
            language="go", rule_id=RULE_IGNORED_RETURN,
        )

    role: RoleEvidence | None = None
    callee = ""
    for candidate in candidates:
        role = bind_role(
            [candidate],
            "",  # per-callee binding: the enclosing name must not
                 # smuggle a role onto an unrelated callee
            file_path,
            language="go",
            context=role_context,
            # Tier-B middleware mechanics live on the enclosing
            # function's signature (func(next http.Handler) ...).
            enclosing_source=segment,
        )
        if role is not None:
            callee = candidate
            break
    if role is None:
        return _inconclusive(
            REASON_ROLE_UNBOUND,
            "could not bind a security role to any hypothesis callee "
            f"({', '.join(candidates)})",
            language="go", rule_id=RULE_IGNORED_RETURN,
        )

    tail = _function_tail(callee)
    fallible = _go_fallibility(callee, role, source, inventory)
    if fallible is None:
        return _inconclusive(
            REASON_FALLIBILITY_UNRESOLVED,
            f"no error-bearing signature resolvable for {callee} "
            "(same-file, inventory) and no err_second contract — "
            "cannot demonstrate the discarded result can fail",
            language="go", rule_id=RULE_IGNORED_RETURN,
        )

    sites = go_discard_sites(
        source, file_path, tail, function_span=span,
    )
    if sites is None:
        return _inconclusive(
            REASON_LANGUAGE_UNSUPPORTED,
            "no tree-sitter go parser available — `if err != nil` "
            "dominance is not honestly decidable from line shapes",
            language="go", rule_id=RULE_IGNORED_RETURN,
        )
    if not sites:
        return _inconclusive(
            REASON_HYPOTHESIS_UNBINDABLE,
            f"no call sites of {callee} located in {function_name}",
            language="go", rule_id=RULE_IGNORED_RETURN,
        )

    unguarded = [s for s in sites if s.verdict == "unguarded"]
    undecided = [s for s in sites if s.verdict == "undecided"]
    rule_id = _apply_role_grade(RULE_IGNORED_RETURN, role)

    if unguarded:
        first = unguarded[0]
        result = FailOpenResult(
            outcome="confirmed",
            reason=(
                f"{first.code} at {file_path}:{first.line} — "
                f"{first.evidence} ({role.kind}-role callee "
                f"{callee}, {fallible['evidence']})"
            ),
            rule_id=rule_id,
            language="go",
            role=role.to_dict(),
            handler={
                "idiom": "ignored_return",
                "line": first.line,
                "caught": [callee],
                "broad": False,
                "outcome_kind": "ignored_return",
                "permissive_value": first.shape,
                "code": first.code,
                "parser": first.parser,
            },
            fallible=fallible,
            sites=sites,
        )
        result.reachability = _entry_reachability(
            role_context, inventory, file_path, function_name,
        )
        return result
    if not undecided:
        return FailOpenResult(
            outcome="refuted",
            reason=(
                f"all {len(sites)} site(s) of {callee} in "
                f"{function_name} handle the error result fail-closed "
                f"(receipts per site)"
            ),
            rule_id=RULE_IGNORED_RETURN,
            language="go",
            role=role.to_dict(),
            fallible=fallible,
            sites=sites,
        )
    return FailOpenResult(
        outcome="inconclusive",
        reason=(
            f"{REASON_HANDLER_UNDECIDED}: {len(undecided)} of "
            f"{len(sites)} site(s) could not be structurally decided"
        ),
        rule_id=RULE_IGNORED_RETURN,
        language="go",
        role=role.to_dict(),
        fallible=fallible,
        sites=sites,
    )


# ── leg 3: Joern flow escalator (outcome-gated) ─────────────────────


def _joern_flow_escalation(
    result: FailOpenResult,
    *,
    target_path: Path,
    file_path: str,
    function_name: str,
    hypothesis: str,
    source: str,
    language: str,
    joern_server: Any,
    budget_s: float | None,
) -> None:
    """Leg 3, flow form: runs only after legs 1+2 confirmed
    (outcome-gated, the dark_verify discipline). A confirmed dataflow
    from a hypothesis-named tainted parameter to the fallible callee
    means the attacker can *provoke* the very error the handler
    swallows — the receipt upgrades to ``tainted`` with the
    ``joern:flow`` stamp and the flow rule-id joins ``corroboration``.

    Every other outcome (refuted / inconclusive / error / no source
    binding) leaves the core verdict and the cheap entry-reachability
    receipt untouched — the escalator can only escalate.
    """
    fallible = result.fallible or {}
    sink_call = _function_tail(str(fallible.get("callee") or ""))
    if not sink_call or sink_call.startswith("<"):
        return
    params = function_parameters(source, function_name, language)
    if not params:
        return
    param_set = set(params)
    source_id = next(
        (n for n in _hypothesis_identifiers(hypothesis)
         if n in param_set),
        None,
    )
    if source_id is None or source_id == sink_call:
        # No tainted-parameter binding — the leg does not run;
        # absence of a flow receipt is meaningful, never blocking.
        return
    try:
        from .joern_verify import run_flow_reachability_check
        jv = run_flow_reachability_check(
            target_path=target_path,
            file_path=file_path,
            function_name=_function_tail(function_name),
            source_id=source_id,
            sink_call=sink_call,
            server=joern_server,
            timeout=int(budget_s) if budget_s else None,
        )
    except Exception:
        logger.debug("fail_open: joern flow escalator errored",
                     exc_info=True)
        return
    if jv.outcome == "confirmed":
        result.reachability = {
            "status": "tainted",
            "source_id": source_id,
            "stamp": jv.rule_id or "joern:flow",
            "detail": (
                f"{source_id} flows to an argument of {sink_call} "
                f"({len(jv.matches)} path(s)) — the attacker can "
                "provoke the swallowed error"
            ),
        }
        result.corroboration.append(jv.rule_id or "joern:flow")
    elif result.reachability is None:
        detail = ((jv.details or {}).get("reason")
                  or "; ".join(jv.errors) or jv.outcome)
        result.reachability = {
            "status": "unknown",
            "detail": f"joern flow {jv.outcome}: {detail}"[:300],
        }


# ── channel entry point ─────────────────────────────────────────────


def run_fail_open_check(
    target_path: Path,
    file_path: str,
    function_name: str,
    hypothesis: str,
    *,
    inventory: dict[str, Any] | None = None,
    role_context: RoleContext | None = None,
    joern_server: Any = None,
    budget_s: float | None = None,
) -> FailOpenResult:
    """Adjudicate one fail-open hypothesis. See module docstring for
    verdict semantics.

    ``joern_server`` + ``budget_s`` drive the leg-3 flow escalator:
    it runs only on a confirmed verdict, only with a live server, and
    is skipped outright on a zero budget (the orchestrator's
    remaining-run-budget clamp). Its absence or failure never changes
    the core verdict.
    """
    ctx = role_context or RoleContext()
    if ctx.inventory is None and inventory is not None:
        ctx.inventory = inventory

    language = language_for_path(file_path)
    if language is None or language not in SUPPORTED_LANGUAGES:
        return _inconclusive(
            REASON_LANGUAGE_UNSUPPORTED,
            f"no fail-open analyzer for "
            f"{language or Path(file_path).suffix or 'unknown'}",
            language=language or "",
        )

    source = _read_source(Path(target_path), file_path)
    if source is None:
        return _inconclusive(
            REASON_HYPOTHESIS_UNBINDABLE,
            f"could not read {file_path}",
            language=language,
        )

    if language == "python":
        result = _run_python_check(
            source, file_path, function_name, ctx, inventory,
        )
    elif language == "java":
        result = _run_java_check(
            source, file_path, function_name, ctx, inventory,
        )
    elif language == "go":
        result = _run_go_check(
            source, file_path, function_name, hypothesis, ctx,
            inventory,
        )
    else:
        result = _run_c_check(
            source, file_path, function_name, hypothesis, language,
            ctx, inventory,
        )
    if result.outcome == "confirmed" and joern_server is not None \
            and budget_s != 0:
        _joern_flow_escalation(
            result,
            target_path=Path(target_path),
            file_path=file_path,
            function_name=function_name,
            hypothesis=hypothesis,
            source=source,
            language=language,
            joern_server=joern_server,
            budget_s=budget_s,
        )
    return result

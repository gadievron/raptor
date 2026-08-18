"""Consistency verification channel — return-check dimension (§3.1).

Adjudicates "n peers check X, this site doesn't" claims fully
mechanically, with :class:`~core.audit.peer_evidence.PeerEvidence`
receipts. Dual mode, like the census itself:

* **standing pre-pass** — the prep phase feeds every census deviant
  through :func:`census_verdict` (leads + LLM-free findings);
* **hypothesis adjudication** — the dispatcher routes "9/10 callers
  check …" hypotheses to :func:`run_consistency_check`, which
  recomputes the arithmetic and the exhibits instead of trusting the
  claim.

Verdict discipline follows ``api_boundary`` / ``fail_open``:
confirmed / refuted / inconclusive-with-reason, never a guess. The
graduated axis (§2.3):

* registry-grade contract witness (wur / annotation / domain model /
  Tier-A / corroborated IRIS) ⇒ ``consistency:return-check``,
  promote-capable with n ≥ 1 — the contract is the premise, the
  majority exhibit is corroboration;
* majority-only ⇒ ``consistency:return-check-majority``,
  detection-grade (n ≥ 4, ratio ≥ 0.9), promotes only through
  ≥ 2-independent-namespace aggregation;
* ``acknowledged`` sites refute the majority leg and are handed to
  the fail_open channel when a security role binds (the CWE-252
  premise split, §5.1: role-bound is fail_open territory).

No LLM calls, no subprocesses.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .callsite_consistency import (
    USAGE_ACKNOWLEDGED,
    USAGE_TESTED,
    CalleeCensus,
    CallSite,
    build_return_census,
)
from .fail_open_roles import RoleContext, bind_role
from .peer_evidence import PeerEvidence, PeerExhibit, rule_id
from .return_contracts import bind_return_contract

logger = logging.getLogger(__name__)

DIMENSION_RETURN_CHECK = "return-check"
DIMENSION_CLEANUP = "cleanup"
DIMENSION_ARGUMENT_SHAPE = "argument-shape"
DIMENSION_CLONE_DRIFT = "clone-drift"
DIMENSION_SANITIZE_SINK = "sanitize-sink"
DIMENSION_GUARD_PRESENCE = "guard-presence"

RULE_RETURN_CHECK = rule_id(DIMENSION_RETURN_CHECK, detection=False)
RULE_RETURN_CHECK_MAJORITY = rule_id(DIMENSION_RETURN_CHECK, detection=True)
RULE_CLEANUP = rule_id(DIMENSION_CLEANUP, detection=False)
RULE_ARGUMENT_SHAPE = rule_id(DIMENSION_ARGUMENT_SHAPE, detection=False)
RULE_CLONE_DRIFT = rule_id(DIMENSION_CLONE_DRIFT, detection=False)
RULE_SANITIZE_SINK = rule_id(DIMENSION_SANITIZE_SINK, detection=False)
RULE_GUARD_PRESENCE = rule_id(DIMENSION_GUARD_PRESENCE, detection=False)

# Mechanical-path thresholds (§2.3 — stricter than the lead path).
VERDICT_MIN_SITES = 4
VERDICT_MAJORITY_RATIO = 0.9

# Enumerated inconclusive reasons (each a distinct tested string).
REASON_CONTRACT_UNRESOLVED = "contract-unresolved"
REASON_GROUP_TOO_SMALL = "group-too-small"
REASON_RATIO_BELOW_THRESHOLD = "ratio-below-threshold"
REASON_PYTHON_EXCEPTION_SEMANTICS = "python-exception-semantics"
REASON_DEVIANT_ON_ERROR_PATH = "deviant-on-error-path"
REASON_EXTRACTOR_UNAVAILABLE = "extractor-unavailable"
REASON_HYPOTHESIS_UNBINDABLE = "hypothesis-unbindable"
REASON_OWNERSHIP_UNRESOLVED = "ownership-unresolved"
REASON_GUARD_ELSEWHERE = "guard-elsewhere"

INCONCLUSIVE_REASONS = frozenset({
    REASON_CONTRACT_UNRESOLVED,
    REASON_GROUP_TOO_SMALL,
    REASON_RATIO_BELOW_THRESHOLD,
    REASON_PYTHON_EXCEPTION_SEMANTICS,
    REASON_DEVIANT_ON_ERROR_PATH,
    REASON_EXTRACTOR_UNAVAILABLE,
    REASON_HYPOTHESIS_UNBINDABLE,
    REASON_OWNERSHIP_UNRESOLVED,
    REASON_GUARD_ELSEWHERE,
})

# Enumerated refutation reasons.
REFUTED_ACKNOWLEDGED = "acknowledged-discard"
REFUTED_DISCARD_OK = "majority-discard-convention"
REFUTED_SITE_CHECKS = "site-tests-the-value"
REFUTED_VOID_CALLEE = "void-return-callee"
REFUTED_PATH_INFEASIBLE = "deviant-path-infeasible"

# CWE families the channel joins via the fallback chain (§4.3).
# CWE-252 keeps its existing cocci entry; consistency joins its chain
# (contract-/majority-bound premise — role-bound stays fail_open).
CONSISTENCY_CWES = frozenset({
    "CWE-252", "CWE-393", "CWE-467", "CWE-131", "CWE-732", "CWE-276",
    "CWE-295", "CWE-401", "CWE-415", "CWE-416", "CWE-459", "CWE-667",
    "CWE-193", "CWE-862",
    # Uninitialised-resource family: the census adjudicates the
    # peer-majority leg ("every other caller of getpeername checks the
    # returned length; this one doesn't") that fed the family's first
    # promoted finding.
    "CWE-908",
})

# Hypothesis shapes asserting a peer-majority deviation. Plain
# "unchecked return" phrasing deliberately does NOT dispatch here —
# without a majority/peer claim that is fail_open (role premise) or
# CWE-seeded territory.
_PEER_NOUN = r"(?:callers?|call\s?-?sites?|sites?|implementations?|branches?|usages?)"
_CONSISTENCY_HYPOTHESIS_RE = re.compile(
    rf"(?:\b\d+\s*/\s*\d+\s+(?:other\s+)?{_PEER_NOUN}\b"
    rf"|\b(?:most|all\s+other|every\s+other|the\s+other|other)\s+"
    rf"(?:\d+\s+)?{_PEER_NOUN}[^.]{{0,80}}?"
    r"\b(?:check|test|validat|verif|saniti|handle|free|unlock|lock|"
    r"releas|clos)"
    r"|\binconsistent\s+with\s+(?:its\s+)?(?:peers?|siblings?|other)"
    r"|\bdeviates?\s+from\s+(?:the\s+)?(?:majority|its\s+peers?|"
    r"the\s+(?:project\s+)?convention))",
    re.IGNORECASE | re.DOTALL,
)

_BACKTICK_IDENT_RE = re.compile(r"`([A-Za-z_][\w.]*)\s*(?:\(\s*\))?`")
_IDENT_CALL_RE = re.compile(r"\b([A-Za-z_]\w{2,})\s*\(\s*\)")
_IDENT_RE = re.compile(r"\b([A-Za-z_]\w{2,})\b")

_HYPOTHESIS_STOPWORDS = frozenset({
    "the", "and", "for", "not", "with", "when", "value", "return",
    "returns", "returned", "error", "errors", "result", "check",
    "checked", "checks", "unchecked", "ignored", "ignores", "call",
    "calls", "callers", "caller", "sites", "site", "function",
    "functions", "other", "this", "that", "one", "most", "all",
    "every", "discard", "discards", "discarded", "majority",
    "inconsistent", "peers", "siblings", "convention", "deviates",
    "deviate", "int", "void", "char", "bool",
})

# Bounded on-the-fly census scan (hypothesis adjudication with no
# prep census available).
_MAX_SCAN_FILES = 40
_MAX_FILE_BYTES = 400_000
_SOURCE_SUFFIXES = (
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".go", ".py", ".rs",
    ".java", ".js", ".ts",
)


def is_consistency_hypothesis(text: str) -> bool:
    """True when the hypothesis asserts a peer-majority deviation
    ("9/10 callers check…", "other sites free the buffer; this one
    doesn't", "inconsistent with its peers")."""
    return bool(text) and bool(_CONSISTENCY_HYPOTHESIS_RE.search(text))


def consistency_applicable(cwe: str) -> bool:
    """True when the CWE belongs to the consistency family (§4.3)."""
    norm = (cwe or "").upper().strip()
    if norm and not norm.startswith("CWE-"):
        norm = f"CWE-{norm}"
    return norm in CONSISTENCY_CWES


@dataclass
class ConsistencyResult:
    """Channel verdict for one consistency claim."""

    outcome: str                  # confirmed | refuted | inconclusive
    reason: str
    rule_id: str = RULE_RETURN_CHECK
    dimension: str = DIMENSION_RETURN_CHECK
    callee: str = ""
    peer_evidence: PeerEvidence | None = None
    contract: dict[str, Any] | None = None
    reachability: dict[str, Any] | None = None
    #: The acknowledged-discard premise split: True when this site is
    #: fail_open territory (a security role binds to the acknowledged
    #: callee) — the caller seeds a fail-open hypothesis instead.
    fail_open_handoff: bool = False
    corroboration: list[Any] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "outcome": self.outcome,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "dimension": self.dimension,
        }
        if self.callee:
            d["callee"] = self.callee
        if self.peer_evidence is not None:
            d["peer_evidence"] = self.peer_evidence.to_dict()
        if self.contract is not None:
            d["contract"] = self.contract
        if self.reachability is not None:
            d["reachability"] = self.reachability
        if self.fail_open_handoff:
            d["fail_open_handoff"] = True
        if self.corroboration:
            d["corroboration"] = [
                c.to_dict() if hasattr(c, "to_dict") else c
                for c in self.corroboration
            ]
        return d


def _inconclusive(reason: str, detail: str = "",
                  callee: str = "") -> ConsistencyResult:
    return ConsistencyResult(
        outcome="inconclusive",
        reason=f"{reason}: {detail}" if detail else reason,
        callee=callee,
    )


def _snippet(source_texts: dict[str, str] | None,
             file_path: str, line: int) -> str:
    if not source_texts:
        return ""
    source = source_texts.get(file_path)
    if not source:
        return ""
    lines = source.splitlines()
    if 1 <= line <= len(lines):
        return lines[line - 1].strip()[:200]
    return ""


def _exhibit(site: CallSite,
             source_texts: dict[str, str] | None) -> PeerExhibit:
    return PeerExhibit(
        file=site.file,
        line=site.line,
        snippet=_snippet(source_texts, site.file, site.line),
    )


def _language_of(file_path: str) -> str:
    try:
        from core.inventory.languages import detect_language
        return detect_language(file_path) or ""
    except ImportError:
        return ""


_VOID_DECL_TMPL = r"\bvoid\s+[*\s]*{name}\s*\("


def _callee_returns_void(
    callee: str,
    source_texts: dict[str, str] | None,
    inventory: dict[str, Any] | None,
) -> bool:
    """FP control (§2.3): a void-return callee has nothing to check."""
    tail = callee.rsplit(".", 1)[-1]
    if inventory:
        for frec in inventory.get("files", []) or []:
            # The builder emits per-file "items"; older inventories
            # carried "functions" — accept both (builder-side compat
            # reads both too).
            for fn in frec.get("items", frec.get("functions", [])) or []:
                if fn.get("name") == tail:
                    ret = str(
                        (fn.get("metadata") or {}).get("return_type")
                        or fn.get("return_type") or "",
                    ).strip()
                    if ret == "void":
                        return True
    if source_texts:
        pattern = re.compile(_VOID_DECL_TMPL.format(name=re.escape(tail)))
        for source in source_texts.values():
            if tail not in source:
                continue
            for m in pattern.finditer(source):
                # `void *name(` returns a pointer, not void.
                if "*" not in m.group(0):
                    return True
    return False


def _entry_reachability(
    context: RoleContext,
    inventory: dict[str, Any] | None,
    file_path: str,
    function_name: str,
) -> dict[str, Any] | None:
    """Outcome-gated escalator, identical to the fail-open channel's
    (§2.3): entry reachability decides ``finding`` vs ``suspicious``,
    never the verdict itself."""
    try:
        from .fail_open_verify import _entry_reachability as _fo_reach
    except ImportError:
        return None
    try:
        return _fo_reach(context, inventory, file_path, function_name)
    except Exception:
        logger.debug("consistency: reachability escalator failed",
                     exc_info=True)
        return None


# Joern-flow leg of the escalator (§2.3 "Joern flow only
# budget-permitting"): bounded caller-closure query, consulted only
# when the cheap leg answers unknown AND the verdict is a
# promote-capable confirmation. Depth mirrors the cheap leg's reverse
# BFS; the name cap keeps the response bounded.
_JOERN_FLOW_MAX_DEPTH = 6
_JOERN_FLOW_NAME_CAP = 500


def _joern_flow_reachability(
    joern_server: Any,
    context: RoleContext,
    function_name: str,
) -> dict[str, Any] | None:
    """Caller-closure reachability on the CPG. Fail-open: any error
    or missing input degrades to ``unknown`` — the escalator never
    blocks or flips a verdict."""
    context_map = context.context_map or {}
    entry_names = {
        str(ep.get("function") or ep.get("name") or "")
        for ep in context_map.get("entry_points") or []
        if isinstance(ep, dict)
    } - {""}
    if not entry_names:
        return None
    from . import cross_function_verify as _cfv
    safe = _cfv._safe_name(function_name.rsplit(".", 1)[-1])
    if safe is None:
        return None
    query = (
        f'cpg.method.nameExact("{safe}")'
        f".repeat(_.caller)(_.emit.maxDepth({_JOERN_FLOW_MAX_DEPTH}))"
        f".name.dedup.take({_JOERN_FLOW_NAME_CAP}).l"
    )
    try:
        raw = _cfv._run_query(joern_server, query)
    except Exception:
        logger.debug("consistency: joern flow escalator failed",
                     exc_info=True)
        return {"status": "unknown", "via": "joern_flow",
                "detail": "joern flow query errored"}
    if raw is None:
        return {"status": "unknown", "via": "joern_flow",
                "detail": "joern flow query returned nothing"}
    callers = {str(item) for item in raw}
    hit = sorted(callers & entry_names)
    if hit:
        return {
            "status": "entry_reachable",
            "via": "joern_flow",
            "detail": (
                f"joern caller closure reaches entry point {hit[0]} "
                f"(≤ {_JOERN_FLOW_MAX_DEPTH} hops)"
            ),
        }
    return {
        "status": "unknown",
        "via": "joern_flow",
        "detail": (
            f"joern caller closure ({len(callers)} callers) contains "
            f"no known entry point"
        ),
    }


def _escalate_reachability(
    context: RoleContext,
    inventory: dict[str, Any] | None,
    file_path: str,
    function_name: str,
    joern_server: Any = None,
) -> dict[str, Any] | None:
    """Cheap leg first; the Joern flow leg only when the cheap leg
    answers unknown and a server was budgeted (the fail-open escalator
    seam, extended)."""
    cheap = _entry_reachability(
        context, inventory, file_path, function_name,
    )
    if cheap is not None and cheap.get("status") == "entry_reachable":
        return cheap
    if joern_server is None:
        return cheap
    flow = _joern_flow_reachability(joern_server, context, function_name)
    if flow is None:
        return cheap
    if flow.get("status") == "entry_reachable" or cheap is None:
        return flow
    return {**cheap, "joern_flow": flow.get("detail", "")}


def _build_peer_evidence(
    entry: CalleeCensus,
    deviant: CallSite,
    contract_source: str,
    provenance: str,
    source_texts: dict[str, str] | None,
) -> PeerEvidence:
    return PeerEvidence(
        dimension=DIMENSION_RETURN_CHECK,
        formation="same_callee",
        group_key=entry.callee,
        n=entry.n,
        conforming=len(entry.conforming),
        ratio=entry.check_ratio,
        deviant=_exhibit(deviant, source_texts),
        exhibits=[
            _exhibit(s, source_texts) for s in entry.conforming[:3]
        ],
        contract_source=contract_source,
        provenance=provenance,
    )


def census_verdict(
    entry: CalleeCensus,
    deviant: CallSite,
    *,
    context: RoleContext | None = None,
    inventory: dict[str, Any] | None = None,
    source_texts: dict[str, str] | None = None,
    joern_server: Any = None,
) -> ConsistencyResult:
    """Adjudicate one deviant site against its callee census (§2.3)."""
    ctx = context or RoleContext()
    callee = entry.callee
    language = _language_of(deviant.file)

    if deviant.usage == USAGE_ACKNOWLEDGED:
        role = bind_role(
            [callee], "", deviant.file,
            language=language or "c", context=ctx,
        )
        return ConsistencyResult(
            outcome="refuted",
            reason=(
                f"{REFUTED_ACKNOWLEDGED}: explicit-discard idiom at "
                f"{deviant.file}:{deviant.line} — the author saw the "
                f"return"
                + (
                    "; security role binds — fail_open territory"
                    if role is not None else ""
                )
            ),
            callee=callee,
            fail_open_handoff=role is not None,
        )

    if deviant.usage == USAGE_TESTED:
        return ConsistencyResult(
            outcome="refuted",
            reason=(
                f"{REFUTED_SITE_CHECKS}: the site at "
                f"{deviant.file}:{deviant.line} tests the value"
            ),
            callee=callee,
        )

    if _callee_returns_void(callee, source_texts, inventory):
        return ConsistencyResult(
            outcome="refuted",
            reason=(
                f"{REFUTED_VOID_CALLEE}: {callee} returns void — "
                f"nothing to check"
            ),
            callee=callee,
        )

    if entry.majority_says_discard_ok:
        return ConsistencyResult(
            outcome="refuted",
            reason=(
                f"{REFUTED_DISCARD_OK}: "
                f"{entry.n - len(entry.conforming)}/{entry.n} sites "
                f"discard {callee}'s return — the project convention "
                f"is discard-ok"
            ),
            callee=callee,
        )

    if deviant.on_error_path:
        return _inconclusive(
            REASON_DEVIANT_ON_ERROR_PATH,
            f"the deviant at {deviant.file}:{deviant.line} sits in an "
            f"error handler where acting on the value may be impossible",
            callee=callee,
        )

    contract = bind_return_contract(
        callee, language=language, context=ctx, census_entry=entry,
    )

    if contract is not None and contract.registry_grade:
        pe = _build_peer_evidence(
            entry, deviant, contract.source, contract.provenance,
            source_texts,
        )
        exhibits_note = (
            f"; {len(entry.conforming)}/{entry.considered} considered "
            f"sites check" if entry.conforming else ""
        )
        result = ConsistencyResult(
            outcome="confirmed",
            reason=(
                f"return of {callee}() is {deviant.usage} at "
                f"{deviant.file}:{deviant.line}; contract witness "
                f"{contract.provenance} ({contract.source})"
                f"{exhibits_note}"
            ),
            rule_id=RULE_RETURN_CHECK,
            callee=callee,
            peer_evidence=pe,
            contract=contract.to_dict(),
        )
        result.reachability = _escalate_reachability(
            ctx, inventory, deviant.file, deviant.enclosing_function,
            joern_server,
        )
        return result

    # Majority leg (detection-grade), stricter thresholds (§2.3).
    if entry.considered < VERDICT_MIN_SITES:
        return _inconclusive(
            REASON_GROUP_TOO_SMALL,
            f"{entry.considered} considered site(s) < "
            f"{VERDICT_MIN_SITES}",
            callee=callee,
        )
    if entry.check_ratio < VERDICT_MAJORITY_RATIO:
        if contract is None and entry.all_python:
            return _inconclusive(
                REASON_PYTHON_EXCEPTION_SEMANTICS,
                f"{callee} is Python and no return contract source "
                f"exists — failure may be exception-borne",
                callee=callee,
            )
        if contract is None:
            return _inconclusive(
                REASON_CONTRACT_UNRESOLVED,
                f"no contract source for {callee} and check ratio "
                f"{entry.check_ratio:.2f} < {VERDICT_MAJORITY_RATIO}",
                callee=callee,
            )
        return _inconclusive(
            REASON_RATIO_BELOW_THRESHOLD,
            f"check ratio {entry.check_ratio:.2f} < "
            f"{VERDICT_MAJORITY_RATIO}",
            callee=callee,
        )

    pe = _build_peer_evidence(
        entry, deviant, "majority",
        contract.provenance if contract else
        f"majority:{entry.count(USAGE_TESTED)}/{entry.considered}",
        source_texts,
    )
    result = ConsistencyResult(
        outcome="confirmed",
        reason=(
            f"return of {callee}() is {deviant.usage} at "
            f"{deviant.file}:{deviant.line}; "
            f"{entry.count(USAGE_TESTED)}/{entry.considered} sites "
            f"check (majority evidence only — detection grade)"
        ),
        rule_id=RULE_RETURN_CHECK_MAJORITY,
        callee=callee,
        peer_evidence=pe,
        contract=contract.to_dict() if contract else None,
    )
    # Detection-grade can never reach `finding`, so the Joern flow
    # leg is deliberately not consulted here — cheap leg only.
    result.reachability = _entry_reachability(
        ctx, inventory, deviant.file, deviant.enclosing_function,
    )
    return result


def cleanup_verdict(
    deviation: Any,
    *,
    context: RoleContext | None = None,
    inventory: dict[str, Any] | None = None,
    joern_server: Any = None,
) -> ConsistencyResult:
    """Adjudicate one cleanup deviation (§3.2).

    Provably wrong without an LLM only when the pair contract is
    learned AND the binding does not escape the function; ownership
    transfer is the classic intentional deviation →
    ``ownership-unresolved``.
    """
    ctx = context or RoleContext()
    pair = deviation.pair
    if deviation.ownership_transfer:
        return ConsistencyResult(
            outcome="inconclusive",
            reason=(
                f"{REASON_OWNERSHIP_UNRESOLVED}: "
                f"{deviation.binding or 'the resource'} acquired via "
                f"{pair.acquire}() escapes "
                f"{deviation.enclosing_function} — ownership may "
                f"transfer to the caller"
            ),
            rule_id=RULE_CLEANUP,
            dimension=DIMENSION_CLEANUP,
            callee=pair.acquire,
            peer_evidence=deviation.peer_evidence,
        )
    result = ConsistencyResult(
        outcome="confirmed",
        reason=(
            f"{deviation.description} — learned pair "
            f"{pair.acquire}/{pair.release} ({pair.provenance}), "
            f"no escape"
        ),
        rule_id=RULE_CLEANUP,
        dimension=DIMENSION_CLEANUP,
        callee=pair.acquire,
        peer_evidence=deviation.peer_evidence,
        contract={
            "source": pair.source,
            "provenance": pair.provenance,
            "grade": "registry",
        },
    )
    result.reachability = _escalate_reachability(
        ctx, inventory, deviation.file, deviation.enclosing_function,
        joern_server,
    )
    return result


def argument_shape_verdict(
    deviation: Any,
    *,
    context: RoleContext | None = None,
    inventory: dict[str, Any] | None = None,
    joern_server: Any = None,
) -> ConsistencyResult:
    """Adjudicate one argument-shape deviation (§3.6).

    The ``sizeof(ptr)``-among-buffer-sizes sub-case carries a
    deterministic declared-type witness and is promote-capable
    (CWE-467) — the type fact is the premise, the sibling majority is
    corroboration. Every other shape deviation is detection-grade
    (``-majority`` rule-id): legitimate shape variance is high, so a
    statistical outlier alone never promotes.
    """
    ctx = context or RoleContext()
    if deviation.type_witness:
        result = ConsistencyResult(
            outcome="confirmed",
            reason=(
                f"{deviation.description} — declared-type witness: "
                f"sizeof over a pointer measures the pointer, not the "
                f"buffer"
            ),
            rule_id=RULE_ARGUMENT_SHAPE,
            dimension=DIMENSION_ARGUMENT_SHAPE,
            callee=deviation.callee,
            peer_evidence=deviation.peer_evidence,
            contract={
                "source": "type_witness",
                "provenance": f"type_witness:{deviation.detail}",
                "grade": "registry",
            },
        )
        result.reachability = _escalate_reachability(
            ctx, inventory, deviation.file,
            deviation.enclosing_function, joern_server,
        )
        return result
    return ConsistencyResult(
        outcome="confirmed",
        reason=(
            f"{deviation.description} (majority evidence only — "
            f"detection grade)"
        ),
        rule_id=rule_id(DIMENSION_ARGUMENT_SHAPE, detection=True),
        dimension=DIMENSION_ARGUMENT_SHAPE,
        callee=deviation.callee,
        peer_evidence=deviation.peer_evidence,
    )


def sanitize_sink_verdict(
    deviation: Any,
    *,
    context: RoleContext | None = None,
    inventory: dict[str, Any] | None = None,
    joern_server: Any = None,
) -> ConsistencyResult:
    """Adjudicate one sanitize-before-sink deviation (§3.3).

    Escalation-only by default — context may sanitize upstream and
    strength differences can be deliberate, so a majority-only
    deviation is detection-grade
    (``consistency:sanitize-sink-majority``) and promotes only
    through cross-namespace aggregation. The single promote-capable
    shape: the sink convention is operator-annotated (human-grade
    ``status: sink`` annotation — a registry-grade convention
    witness) and the majority meets the promote-adjacent floor.

    Premise split (§5.1): this verdict adjudicates sanitizer-call
    *presence* only. It never binds a security role and never sets
    ``fail_open_handoff`` — failure-handling premises (an ignored
    sanitizer return, a fall-open handler) are fail_open /
    return-check territory, and the orchestrator's
    fail_open-adjudicated (file, line) dedup keeps the two channels
    off each other's sites.
    """
    ctx = context or RoleContext()
    if deviation.registry_grade:
        result = ConsistencyResult(
            outcome="confirmed",
            reason=(
                f"{deviation.description} — the sink convention is an "
                f"operator annotation (registry-grade convention "
                f"witness); the sanitizing siblings are the exhibits"
            ),
            rule_id=RULE_SANITIZE_SINK,
            dimension=DIMENSION_SANITIZE_SINK,
            callee=deviation.sink,
            peer_evidence=deviation.peer_evidence,
            contract={
                "source": "annotation",
                "provenance": f"annotation:sink:{deviation.sink}",
                "grade": "registry",
            },
        )
        result.reachability = _escalate_reachability(
            ctx, inventory, deviation.file,
            deviation.enclosing_function, joern_server,
        )
        return result
    return ConsistencyResult(
        outcome="confirmed",
        reason=(
            f"{deviation.description} (majority evidence only — "
            f"detection grade; upstream sanitization not ruled out)"
        ),
        rule_id=rule_id(DIMENSION_SANITIZE_SINK, detection=True),
        dimension=DIMENSION_SANITIZE_SINK,
        callee=deviation.sink,
        peer_evidence=deviation.peer_evidence,
    )


# Guard-elsewhere caller walk (§3.4): depth / visited caps per the
# resource_bounds precedent ("caller walk depth 3 / 200 visited");
# the receipt always names how far the search went.
GUARD_WALK_MAX_DEPTH = 3
GUARD_WALK_MAX_VISITED = 200
_GUARD_WALK_NAMED = 8  # searched-set names quoted in the receipt


def _caller_guard_walk(
    deviation: Any,
    inventory: dict[str, Any] | None,
    source_texts: dict[str, str] | None,
) -> dict[str, Any]:
    """Depth-3 caller walk deciding guard-elsewhere vs
    genuinely-unguarded for a parameter-derived guard target.

    For every caller reached within ``GUARD_WALK_MAX_DEPTH`` hops of
    the deviant's enclosing function, the caller's body is searched
    for a kind-appropriate guard shape preceding its call into the
    walked-from function. Returns ``{"status": "unavailable" |
    "searched", "searched": [names], "guarding": [{caller, file,
    line}]}`` — the caller puts the searched set on the receipt
    either way (the honesty rule the resource_bounds design states:
    a negative claim must name how far the search went)."""
    if not inventory or not source_texts:
        return {"status": "unavailable", "searched": [], "guarding": []}
    try:
        from core.analysis.reachability import InternalFunction, callers_of
    except ImportError:
        return {"status": "unavailable", "searched": [], "guarding": []}
    from .consistency_dimensions import (
        GUARD_KIND_NULL,
        _function_spans,
    )
    from .sibling_analysis import _BOUNDS_GUARD_RE, _NULL_GUARD_RE
    guard_re = (
        _NULL_GUARD_RE if deviation.kind == GUARD_KIND_NULL
        else _BOUNDS_GUARD_RE
    )
    by_key: dict[tuple[str, str], list[str]] = {}
    by_name: dict[str, tuple[str, list[str]]] = {}
    for fp, fn, _start, body in _function_spans(source_texts):
        by_key.setdefault((fp, fn), body)
        by_name.setdefault(fn, (fp, body))

    def _seed_candidates() -> list[Any]:
        """Canonicalise the deviant's enclosing function to its
        inventory item record(s) — ``InternalFunction`` identity
        includes the definition line, so a synthetic line-0 node
        would never hit the reverse-edge index."""
        exact: list[Any] = []
        by_name_only: list[Any] = []
        for frec in inventory.get("files", []) or []:
            if not isinstance(frec, dict):
                continue
            path = frec.get("path") or ""
            for it in frec.get("items", []) or []:
                if not isinstance(it, dict):
                    continue
                if it.get("kind") not in (None, "function"):
                    continue
                if it.get("name") != deviation.enclosing_function:
                    continue
                node = InternalFunction(
                    file_path=path,
                    name=deviation.enclosing_function,
                    line=int(it.get("line_start") or 0),
                )
                if path == deviation.file:
                    exact.append(node)
                else:
                    by_name_only.append(node)
        return exact or by_name_only

    seeds = _seed_candidates()
    if not seeds:
        return {"status": "unavailable", "searched": [], "guarding": []}

    searched: list[str] = []
    guarding: list[dict[str, Any]] = []
    visited: set[tuple[str, str]] = {
        (s.file_path, s.name) for s in seeds
    }
    frontier: list[Any] = list(seeds)
    depth = 0
    try:
        while frontier and depth < GUARD_WALK_MAX_DEPTH \
                and len(visited) < GUARD_WALK_MAX_VISITED:
            next_frontier: list[Any] = []
            for node in frontier:
                result = callers_of(inventory, node)
                call_re = re.compile(
                    rf"\b{re.escape(node.name)}\s*\(",
                )
                for caller in result.all_callers:
                    key = (caller.file_path, caller.name)
                    if key in visited:
                        continue
                    visited.add(key)
                    searched.append(caller.name)
                    body = by_key.get(key)
                    if body is None:
                        named = by_name.get(caller.name)
                        body = named[1] if named else None
                    next_frontier.append(caller)
                    if body is None:
                        continue
                    call_idx = next(
                        (i for i, ln in enumerate(body)
                         if call_re.search(ln)),
                        len(body),
                    )
                    for i in range(call_idx):
                        if guard_re.search(body[i]):
                            guarding.append({
                                "caller": caller.name,
                                "file": caller.file_path,
                                "line": i + 1,
                            })
                            break
            frontier = next_frontier
            depth += 1
    except Exception:
        logger.debug("guard presence: caller walk failed",
                     exc_info=True)
        return {"status": "unavailable", "searched": searched,
                "guarding": guarding}
    return {"status": "searched", "searched": searched,
            "guarding": guarding}


def _searched_set_note(walk: dict[str, Any]) -> str:
    names = walk.get("searched") or []
    if walk.get("status") != "searched":
        return "caller walk unavailable (no inventory call graph)"
    if not names:
        return (
            f"no callers found within {GUARD_WALK_MAX_DEPTH} hops"
        )
    quoted = ", ".join(sorted(names)[:_GUARD_WALK_NAMED])
    more = len(names) - min(len(names), _GUARD_WALK_NAMED)
    suffix = f" (+{more} more)" if more > 0 else ""
    return (
        f"searched {len(names)} caller(s) within "
        f"{GUARD_WALK_MAX_DEPTH} hops: {quoted}{suffix}"
    )


def _default_guard_smt(deviation: Any) -> Any:
    """Hand the deviant's own dominating guards to the existing
    ``condition_smt`` sufficiency machinery (§3.4): feasible = the
    path to the access is reachable under every guard that IS there,
    so the missing majority guard is load-bearing."""
    guards = list(getattr(deviation, "deviant_guards", []) or [])
    if not guards:
        return None
    try:
        from .condition_smt import check_path_feasibility
        return check_path_feasibility(guards)
    except Exception:
        logger.debug("guard presence: SMT escalation failed",
                     exc_info=True)
        return None


def guard_presence_verdict(
    deviation: Any,
    *,
    context: RoleContext | None = None,
    inventory: dict[str, Any] | None = None,
    source_texts: dict[str, str] | None = None,
    joern_server: Any = None,
    smt_check: Any = None,
) -> ConsistencyResult:
    """Adjudicate one bounds/null-guard presence deviation (§3.4).

    Order of business:

    1. **guard-elsewhere vs genuinely-unguarded** — when the guard
       target derives from a function parameter, the obligation may
       live in a caller: a depth-3 caller walk (the resource_bounds
       precedent) searches the caller set for the guard shape. A
       guarding caller ⇒ enumerated ``guard-elsewhere`` inconclusive;
       either way the receipt names the searched set.
    2. **SMT escalation** — the deviant's own dominating guards go to
       the ``condition_smt`` sufficiency checker. Feasible ⇒ the
       statistical outlier is upgraded to a witnessed promote-capable
       confirmation (``consistency:guard-presence``, contract source
       ``smt_witness``) when the majority meets the promote-adjacent
       floor; infeasible ⇒ refuted (``deviant-path-infeasible``);
       solver unavailable / unconstrained ⇒ the confirmation stays
       detection-grade (``-majority``), aggregation-eligible only.
    """
    ctx = context or RoleContext()
    walk_note = ""
    walk: dict[str, Any] | None = None
    if deviation.param_derived:
        walk = _caller_guard_walk(deviation, inventory, source_texts)
        walk_note = _searched_set_note(walk)
        if walk["status"] == "searched" and walk["guarding"]:
            g = walk["guarding"][0]
            result = ConsistencyResult(
                outcome="inconclusive",
                reason=(
                    f"{REASON_GUARD_ELSEWHERE}: "
                    f"{g['caller']} ({g['file']}:{g['line']}) applies "
                    f"the {deviation.kind} guard before calling into "
                    f"{deviation.enclosing_function} — caller-guarded; "
                    f"{walk_note}"
                ),
                rule_id=RULE_GUARD_PRESENCE,
                dimension=DIMENSION_GUARD_PRESENCE,
                callee=deviation.group_key,
                peer_evidence=deviation.peer_evidence,
            )
            result.corroboration.append({"caller_guard_walk": walk})
            return result

    smt = smt_check(deviation) if smt_check is not None \
        else _default_guard_smt(deviation)
    feasible = getattr(smt, "feasible", None)
    smt_reason = getattr(smt, "reasoning", "") or ""
    witness = getattr(smt, "witness", None)

    if feasible is False:
        result = ConsistencyResult(
            outcome="refuted",
            reason=(
                f"{REFUTED_PATH_INFEASIBLE}: the guards dominating "
                f"{deviation.file}:{deviation.line} make the "
                f"unguarded path unsatisfiable ({smt_reason})"
            ),
            rule_id=RULE_GUARD_PRESENCE,
            dimension=DIMENSION_GUARD_PRESENCE,
            callee=deviation.group_key,
        )
        return result

    unguarded_note = (
        "genuinely-unguarded within the searched caller set — "
        f"{walk_note}; " if walk is not None and not walk["guarding"]
        else ""
    )
    from .consistency_dimensions import RATIO_PROMOTE
    if feasible is True and deviation.ratio >= RATIO_PROMOTE:
        pe = deviation.peer_evidence
        if pe is not None:
            pe.contract_source = "smt_witness"
            pe.provenance = f"condition_smt:{witness or 'feasible'}"
        detail = f" (witness: {witness})" if witness else ""
        result = ConsistencyResult(
            outcome="confirmed",
            reason=(
                f"{deviation.description} — {unguarded_note}"
                f"condition_smt proves the path feasible under the "
                f"deviant's own guards{detail}: the missing majority "
                f"guard is load-bearing"
            ),
            rule_id=RULE_GUARD_PRESENCE,
            dimension=DIMENSION_GUARD_PRESENCE,
            callee=deviation.group_key,
            peer_evidence=pe,
            contract={
                "source": "smt_witness",
                "provenance": (
                    f"condition_smt:{witness or 'feasible'}"
                ),
                "grade": "registry",
            },
        )
        if walk is not None:
            result.corroboration.append({"caller_guard_walk": walk})
        result.reachability = _escalate_reachability(
            ctx, inventory, deviation.file,
            deviation.enclosing_function, joern_server,
        )
        return result

    result = ConsistencyResult(
        outcome="confirmed",
        reason=(
            f"{deviation.description} — {unguarded_note}"
            f"majority evidence only (detection grade"
            + (
                f"; SMT feasible but ratio "
                f"{deviation.ratio:.2f} < {RATIO_PROMOTE}"
                if feasible is True else "; no SMT witness"
            )
            + ")"
        ),
        rule_id=rule_id(DIMENSION_GUARD_PRESENCE, detection=True),
        dimension=DIMENSION_GUARD_PRESENCE,
        callee=deviation.group_key,
        peer_evidence=deviation.peer_evidence,
    )
    if walk is not None:
        result.corroboration.append({"caller_guard_walk": walk})
    # Detection-grade never reaches `finding` — cheap leg only.
    result.reachability = _entry_reachability(
        ctx, inventory, deviation.file, deviation.enclosing_function,
    )
    return result


def clone_drift_verdict(
    deviation: Any,
    *,
    context: RoleContext | None = None,
    inventory: dict[str, Any] | None = None,
    joern_server: Any = None,
) -> ConsistencyResult:
    """Adjudicate one clone-drift deviation (§3.9).

    The fix-anchored leg is promote-capable: the fix commit is a
    registry-grade contract witness (the project asserted "this shape
    was a bug"), the token facts (region containment + guard absence)
    are the evidence — the namespace stays ``consistency`` per
    ``git_oracle``'s corroboration-only rule. The generic winnowing
    leg is detection-grade: a two-member clone group is not a
    majority, so it aggregates and never promotes alone.
    """
    ctx = context or RoleContext()
    if deviation.registry_grade:
        result = ConsistencyResult(
            outcome="confirmed",
            reason=deviation.description,
            rule_id=RULE_CLONE_DRIFT,
            dimension=DIMENSION_CLONE_DRIFT,
            callee=deviation.token,
            peer_evidence=deviation.peer_evidence,
            contract={
                "source": "fix_commit",
                "provenance": f"fix_commit:{deviation.fix_sha[:12]}",
                "grade": "registry",
            },
        )
        result.reachability = _escalate_reachability(
            ctx, inventory, deviation.file,
            deviation.enclosing_function, joern_server,
        )
        return result
    return ConsistencyResult(
        outcome="confirmed",
        reason=(
            f"{deviation.description} (clone-pair evidence only — "
            f"detection grade)"
        ),
        rule_id=rule_id(DIMENSION_CLONE_DRIFT, detection=True),
        dimension=DIMENSION_CLONE_DRIFT,
        callee=deviation.token,
        peer_evidence=deviation.peer_evidence,
    )


# ── hypothesis adjudication ─────────────────────────────────────────


def _candidate_callees(hypothesis: str) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for regex in (_BACKTICK_IDENT_RE, _IDENT_CALL_RE, _IDENT_RE):
        for m in regex.finditer(hypothesis):
            name = m.group(1).rstrip("(")
            if name.lower() in _HYPOTHESIS_STOPWORDS or name in seen:
                continue
            seen.add(name)
            ordered.append(name)
    return ordered


def _gather_source_texts(
    target_path: Path,
    file_path: str,
    callee_candidates: list[str],
) -> dict[str, str]:
    """Bounded scan: the hypothesis's own file plus files mentioning a
    candidate callee (the same-callee peer group lives across files)."""
    texts: dict[str, str] = {}
    target = Path(target_path)
    own = target / file_path
    try:
        if own.is_file():
            texts[file_path] = own.read_text(
                encoding="utf-8", errors="replace",
            )
    except OSError:
        pass
    try:
        paths = sorted(
            p for p in target.rglob("*")
            if p.is_file() and p.suffix in _SOURCE_SUFFIXES
        )
    except OSError:
        return texts
    for p in paths:
        if len(texts) >= _MAX_SCAN_FILES:
            break
        try:
            rel = str(p.relative_to(target))
        except ValueError:
            continue
        if rel in texts:
            continue
        try:
            if p.stat().st_size > _MAX_FILE_BYTES:
                continue
            content = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if any(c in content for c in callee_candidates):
            texts[rel] = content
    return texts


def run_consistency_check(
    target_path: Path,
    file_path: str,
    function_name: str,
    hypothesis: str,
    *,
    inventory: dict[str, Any] | None = None,
    context: RoleContext | None = None,
    source_texts: dict[str, str] | None = None,
    census: dict[str, CalleeCensus] | None = None,
    joern_server: Any = None,
) -> ConsistencyResult:
    """Adjudicate one consistency hypothesis.

    The channel never trusts the claimed arithmetic: it recomputes the
    census for the named callee over the (bounded) peer group and
    re-derives majority, exhibits and contract.
    """
    ctx = context or RoleContext()
    if ctx.inventory is None and inventory is not None:
        ctx.inventory = inventory

    candidates = _candidate_callees(hypothesis)
    if not candidates:
        return _inconclusive(
            REASON_HYPOTHESIS_UNBINDABLE,
            "hypothesis names no callee candidate",
        )

    if census is None:
        if source_texts is None:
            source_texts = _gather_source_texts(
                Path(target_path), file_path, candidates,
            )
        if not source_texts:
            return _inconclusive(
                REASON_EXTRACTOR_UNAVAILABLE,
                f"no sources readable under {target_path}",
            )
        census = build_return_census(source_texts)

    if source_texts:
        # The scanned TUs' own warn_unused_result declarations are
        # contract witnesses (§2.2.1) — harvest them into the context.
        from .return_contracts import harvest_wur_declarations
        ctx.wur_functions = frozenset(ctx.wur_functions) | \
            harvest_wur_declarations(source_texts)

    entry = None
    callee = ""
    for candidate in candidates:
        found = census.get(candidate)
        if found is not None and found.n >= 1:
            entry, callee = found, candidate
            break
    if entry is None:
        return _inconclusive(
            REASON_HYPOTHESIS_UNBINDABLE,
            f"no census entry for any hypothesis callee "
            f"({', '.join(candidates[:5])})",
        )

    # The site under adjudication: a deviant (or acknowledged) site of
    # the callee inside the function under review, else any deviant.
    tail = function_name.rsplit(".", 1)[-1]
    local_sites = [
        s for s in entry.sites
        if s.file == file_path
        and s.enclosing_function.rsplit(".", 1)[-1] == tail
    ]
    site = None
    for s in local_sites:
        if s.usage in (USAGE_ACKNOWLEDGED,) or s.is_deviant_eligible:
            site = s
            break
    if site is None and local_sites:
        # Every local site checks/uses the value — the claim is wrong
        # for this function.
        return ConsistencyResult(
            outcome="refuted",
            reason=(
                f"{REFUTED_SITE_CHECKS}: every {callee} site in "
                f"{function_name} consumes the value "
                f"({', '.join(s.usage for s in local_sites)})"
            ),
            callee=callee,
        )
    if site is None:
        deviants = entry.deviants
        if not deviants:
            return ConsistencyResult(
                outcome="refuted",
                reason=(
                    f"no deviant site of {callee} exists — "
                    f"{len(entry.conforming)}/{entry.n} sites check, "
                    f"rest consume the value"
                ),
                callee=callee,
            )
        site = deviants[0]

    return census_verdict(
        entry, site,
        context=ctx,
        inventory=inventory,
        source_texts=source_texts,
        joern_server=joern_server,
    )

"""Caller-side gate on clean-refuted SMT promotions.

An SMT receipt earned against a self-refuted hypothesis is
intra-procedural by construction: the solver models one function's
arithmetic and guards and cannot see caller-side invariants (an
entry-check helper pinning a size parameter, call sites passing only
compile-time constants, callers passing lengths bounded by real
objects).  Before such a receipt lifts a clean outcome to finding,
this gate re-derives the receipt's own precondition — the parameter
the verb actually solved over — and adjudicates it at the in-repo
call sites through the api_boundary channel.

Decision semantics (promotion-only — nothing here demotes below
suspicious, and the receipt itself is never weakened):

* a concrete in-repo call site does NOT uphold the precondition →
  ``promote``, with the violating site cited;
* every in-repo call site upholds it (channel ``refuted``) → ``hold``:
  the outcome stays suspicious with the receipt;
* external-only callers, undecidable sites, or a receipt that binds
  no callee parameter → ``hold`` with the honest reason — never a
  silent pass-through in either direction;
* an evaluation error → ``hold`` (fail-closed) with the error class
  on the decision: an errored check is not caller evidence in either
  direction, and on this lane a wrongly-promoted receipt mints a
  false finding while a wrongly-held one keeps everything at
  suspicious-with-receipt.

Operand re-derivation deliberately reuses the sweep layer's own
extraction helpers so the gate checks exactly the variables the verb
solved over, not a fresh guess from the hypothesis text.  Operands
that appear in the mechanism only as member accesses (``x->y`` /
``x.y``) never bind: a same-named parameter would make the gate
adjudicate the wrong variable, promoting or holding on evidence about
a different value.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

from .api_boundary import (
    BOUNDED_CONST_EVIDENCE_MARKER,
    ApiBoundaryResult,
    Contract,
    adjudicate_contract,
    parse_param_names,
)
from .sweep import (
    _extract_arithmetic_operands,
    _extract_oob_operands,
    _extract_ptr_operand,
)

logger = logging.getLogger(__name__)

#: suppressions.jsonl verdict tag for held promotions.
GATE_VERDICT = "smt_promotion_caller_gate"

#: Cap on distinct parameter contracts adjudicated per receipt (each
#: adjudication is a bounded tree scan).
_MAX_CONTRACTS = 3


@dataclass
class CallerGateDecision:
    """Outcome of one caller-side gate evaluation."""

    action: str            # "promote" | "hold"
    reason: str            # journal-ready, names sites/counts
    precondition: str = ""  # contract description ("" when unbindable)
    site_count: int = 0
    citation: str = ""     # violating-site citation on promote
    # confirmed | refuted | inconclusive | unbindable | error
    channel_outcome: str = ""
    error_class: str = ""  # exception class name on channel_outcome=error


def _appears_bare(operand: str, text: str) -> bool:
    """True when *operand* occurs in *text* outside a member access.

    An operand seen only as ``x->operand`` / ``x.operand`` names a
    field, not the callee parameter of the same name — binding it
    would adjudicate the wrong variable.
    """
    for m in re.finditer(rf"\b{re.escape(operand)}\b", text):
        prefix = text[max(0, m.start() - 2):m.start()]
        if prefix.endswith("->") or prefix.endswith("."):
            continue
        return True
    return False


def receipt_preconditions(
    verb: str,
    mechanism: str,
    param_names: list[str],
    source: str,
) -> list[Contract]:
    """Caller obligations implied by an SMT receipt's own claim.

    Binds the operands the verb solved over (re-derived with the same
    extraction the verb used) to the callee's parameters.  Only
    parameter-valued operands that appear bare in the mechanism yield
    contracts — a wrap driven purely by locals or struct fields has
    no caller-checkable precondition, and a member-access operand
    (``c->cb``) must not bind a same-named parameter.  Verbs whose
    checks range over whole-function structure rather than named
    operands (lock discipline, path validation, integer narrowing)
    bind nothing here.
    """
    if not param_names or not verb:
        return []
    bare_verb = verb.split(":")[-1] if verb.startswith("smt:") else verb
    operands: list[str] = []
    kind = "bounded"
    if bare_verb == "check-null-deref":
        kind = "null"
        ptr = _extract_ptr_operand(mechanism)
        if ptr:
            operands = [ptr]
    elif bare_verb == "check-overflow":
        operands = list(_extract_arithmetic_operands(mechanism, source))
    elif bare_verb == "check-oob":
        index, size = _extract_oob_operands(mechanism, source)
        operands = [op for op in (index, size) if op]
    contracts: list[Contract] = []
    for op in operands:
        if op not in param_names:
            continue
        if not _appears_bare(op, mechanism):
            continue
        if any(c.param == op for c in contracts):
            continue
        contracts.append(Contract(
            kind=kind, param=op, param_index=param_names.index(op),
        ))
        if len(contracts) >= _MAX_CONTRACTS:
            break
    return contracts


def _hold(
    reason: str,
    *,
    precondition: str = "",
    site_count: int = 0,
    channel_outcome: str = "",
    error_class: str = "",
) -> CallerGateDecision:
    return CallerGateDecision(
        action="hold",
        reason=reason,
        precondition=precondition,
        site_count=site_count,
        channel_outcome=channel_outcome,
        error_class=error_class,
    )


def _inconclusive_reason(result: ApiBoundaryResult) -> str:
    """Hold prose for an inconclusive channel outcome.

    When every undecided site is a compile-time constant the generic
    "could not be structurally decided" reads as caller doubt; what is
    actually known is stronger and different — the callers pin the
    value, and only the missing numeric bound blocks adjudication.
    """
    undecided = [s for s in result.sites if s.verdict == "undecided"]
    pinned = [
        s for s in undecided
        if BOUNDED_CONST_EVIDENCE_MARKER in (s.evidence or "")
    ]
    if undecided and len(pinned) == len(undecided):
        return (
            f"caller-contract gate: {len(pinned)} call site(s) bind "
            "the operand to constants; no numeric bound available to "
            "adjudicate"
        )
    return f"caller-contract gate: {result.reason}"


def evaluate_caller_gate(
    target_path: Path,
    file_path: str,
    function_name: str,
    verb: str,
    mechanism: str,
    *,
    source: str = "",
    def_span: tuple[int, int] | None = None,
    inventory: dict | None = None,
) -> CallerGateDecision:
    """Adjudicate one clean-refuted SMT receipt's precondition at the
    reviewed function's in-repo call sites.  See module docstring for
    the decision semantics.  Never raises: an evaluation error
    fail-closes to a hold carrying the error class, so the caller can
    stamp the errored consult distinctly from a knob-off run."""
    try:
        return _evaluate_caller_gate(
            target_path,
            file_path,
            function_name,
            verb,
            mechanism,
            source=source,
            def_span=def_span,
            inventory=inventory,
        )
    except Exception as e:
        logger.warning(
            "caller gate evaluation errored for %s:%s — holding the "
            "promotion (fail-closed)",
            file_path, function_name, exc_info=True,
        )
        return _hold(
            f"caller-contract gate: evaluation errored "
            f"({type(e).__name__}) — receipt held at suspicious; an "
            "errored check is not caller evidence in either direction",
            channel_outcome="error",
            error_class=type(e).__name__,
        )


def _evaluate_caller_gate(
    target_path: Path,
    file_path: str,
    function_name: str,
    verb: str,
    mechanism: str,
    *,
    source: str = "",
    def_span: tuple[int, int] | None = None,
    inventory: dict | None = None,
) -> CallerGateDecision:
    target_path = Path(target_path)
    defining_source = ""
    try:
        p = target_path / file_path
        if p.is_file():
            defining_source = p.read_text(errors="replace")
    except OSError:
        pass
    param_names = (
        parse_param_names(defining_source, function_name)
        if defining_source else []
    )
    contracts = receipt_preconditions(verb, mechanism, param_names, source)
    if not contracts:
        return _hold(
            f"caller-contract gate: the {verb} receipt binds no "
            f"caller-checkable precondition (no solved operand is a "
            f"parameter of {function_name})",
            channel_outcome="unbindable",
        )

    adjudicated: list[tuple[Contract, ApiBoundaryResult]] = []
    for contract in contracts:
        res = adjudicate_contract(
            target_path,
            file_path,
            function_name,
            contract,
            inventory=inventory,
            def_span=def_span,
        )
        if res.outcome == "confirmed":
            return CallerGateDecision(
                action="promote",
                reason=res.reason,
                precondition=contract.describe(),
                site_count=len(res.sites),
                citation=res.reason,
                channel_outcome="confirmed",
            )
        if res.outcome == "skipped":
            # A did-not-look result adjudicates nothing: it must not
            # join the all-refuted quantifier below (a skip-only set
            # would vacuously read "all call sites uphold the
            # precondition" and mint a refuted-grade hold from zero
            # adjudications).
            continue
        adjudicated.append((contract, res))

    if not adjudicated:
        return _hold(
            "caller-contract gate: no contract could be adjudicated "
            "(every channel result was a did-not-look skip)",
            precondition="; ".join(c.describe() for c in contracts),
            channel_outcome="inconclusive",
        )

    described = "; ".join(c.describe() for c, _ in adjudicated)
    if all(res.outcome == "refuted" for _, res in adjudicated):
        n = max(len(res.sites) for _, res in adjudicated)
        reason = (
            f"caller-contract gate: all {n} call site(s) uphold the "
            f"precondition ({described})"
        )
        if any(not res.enumeration_complete for _, res in adjudicated):
            reason += " — enumeration not verified complete"
        return _hold(
            reason,
            precondition=described,
            site_count=n,
            channel_outcome="refuted",
        )

    first_inconclusive = next(
        res for _, res in adjudicated if res.outcome != "refuted"
    )
    return _hold(
        _inconclusive_reason(first_inconclusive),
        precondition=described,
        site_count=len(first_inconclusive.sites),
        channel_outcome="inconclusive",
    )

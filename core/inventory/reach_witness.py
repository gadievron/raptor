"""Proof-carrying reachability verdicts.

The reachability accessors return string verdicts (``classify_reachability``
in :mod:`core.inventory.reach_audit`). This module wraps that into a
structured :class:`ReachabilityVerdict` carrying a *witness* — the kind of
evidence and its *soundness* — and a single ``may_suppress()`` predicate
that is the ONLY thing allowed to authorise hard-suppression of a finding
on reachability grounds.

Why a soundness axis: a verdict produced by structural facts that hold
under every build configuration (``raise ImportError`` at module top,
``if False:`` guard) is a proof; one produced by a 1-hop call-edge
heuristic (``not_called``) or an entry-completeness assumption
(``no_path_from_entry`` — see its known address-of limitation) is evidence,
not proof. Only proof may suppress.

Important: the ``soundness`` label here is the *candidate* class. Actual
enforce-eligibility is gated empirically — a witness kind earns the right
to suppress only once a labelled corpus shows zero false-suppress for it
(see :mod:`core.inventory.reach_audit`). This module defines the chokepoint;
the enforcement consumer wires it together with the corpus gate. Today no
consumer hard-suppresses — the substrate is surface-only.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional


class Reachability(str, Enum):
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    UNCERTAIN = "uncertain"


class WitnessKind(str, Enum):
    # unreachable
    MODULE_ABORTS = "module_aborts"
    LEXICAL_DEAD = "lexical_dead"
    BINARY_ORACLE_ABSENT = "binary_oracle_absent"
    BUILD_EXCLUDED = "build_excluded"
    NO_PATH_FROM_ENTRY = "no_path_from_entry"
    NOT_CALLED = "not_called"
    # reachable
    HAS_CALLER = "has_caller"
    FRAMEWORK_CALLABLE = "framework_callable"
    REGISTERED_VIA_CALL = "registered_via_call"
    REACHABLE_FROM_ENTRY = "reachable_from_entry"
    BINARY_CALL_EDGE = "binary_call_edge"
    # uncertain
    UNCERTAIN = "uncertain"


class Soundness(str, Enum):
    SOUND = "sound"          # config-independent structural witness — a
                             # CANDIDATE for suppression, not a licence
    HEURISTIC = "heuristic"  # evidence, not proof — surface only


@dataclass(frozen=True)
class Witness:
    kind: WitnessKind
    soundness: Soundness
    summary: str

    def to_priority_reason(self) -> str:
        """The legacy ``reachability:<kind>`` string the prepass / prompt
        consumers already key on — preserved so the witness layer doesn't
        force a consumer migration."""
        return f"reachability:{self.kind.value}"


@dataclass(frozen=True)
class ReachabilityVerdict:
    status: Reachability
    witness: Witness

    def may_suppress(self, earned_kinds: "frozenset" = frozenset()) -> bool:
        """The ONLY predicate authorising skip / hard-demote / auto-resolve
        on reachability grounds. Returns True iff ALL of:

          1. status is UNREACHABLE,
          2. the witness is a SOUND (config-independent structural) kind,
          3. that kind is in ``earned_kinds`` — the set of witness kinds a
             labelled corpus has shown zero false-suppress for.

        ``earned_kinds`` defaults to empty, so the chokepoint is
        **safe-by-construction**: nothing is suppressed until a corpus has
        earned a kind the right to enforce. This is deliberate — the SOUND
        witnesses are produced by heuristic detectors (regex / partial AST),
        so a static "sound" label must NOT, on its own, be able to authorise
        a false negative. The enforcement consumer passes the corpus-earned
        set; callers that pass nothing can never suppress.
        """
        return (self.status is Reachability.UNREACHABLE
                and self.witness.soundness is Soundness.SOUND
                and self.witness.kind in earned_kinds)


@dataclass(frozen=True)
class VerdictSpec:
    """All metadata for one ``classify_reachability`` verdict string — the
    single source of truth that subsumes the old ``_VERDICT_MAP``, the
    ``/validate`` demoter blocker strings, and the analysis-prompt verdict
    lines. Adding a witness's metadata is one entry here."""
    status: Reachability
    kind: WitnessKind
    soundness: Soundness
    # Can this kind EARN hard-suppression? SOUND is necessary-but-not-
    # sufficient; this is explicit so a sound-but-config-dependent witness
    # can never qualify by inference.
    earns_suppression: bool
    summary: str
    # /validate demoter blocker template. ``{fq}`` = ``module.func``;
    # ``{detail}`` = the file-witness summary (only for verdicts whose blocker
    # embeds one — see ``blocker_detail``). "" ⇒ verdict isn't a demotable
    # dead verdict.
    blocker_template: str = ""
    # Which file-witness summary fills ``{detail}``: "module_aborts" |
    # "build_excluded" | "" (none).
    blocker_detail: str = ""
    # analysis-prompt "Verdict: …" line. "" ⇒ rendered by a special-case
    # branch (not_called catch-all / framework REACHABLE rendering).
    prompt_verdict: str = ""


# Candidate soundness: only the structural, config-independent dead witnesses
# (module-load abort, always-false lexical guard) are SOUND and earn
# suppression. build_excluded / no_path_from_entry / not_called are
# UNREACHABLE but HEURISTIC (build-config dependence, entry-set completeness,
# or 1-hop assumptions can miss reflection, cross-file, or address-of edges).
# Reachable/uncertain are never suppress-eligible.
VERDICTS: Dict[str, VerdictSpec] = {
    "module_aborts": VerdictSpec(
        Reachability.UNREACHABLE, WitnessKind.MODULE_ABORTS, Soundness.SOUND,
        earns_suppression=True,
        summary="file aborts on load before this function binds",
        blocker_template=(
            "reachability:module_aborts — entry function {fq} is in a file "
            "whose top-level execution aborts on load ({detail}) before the "
            "function binds"),
        blocker_detail="module_aborts",
        prompt_verdict=(
            "Verdict: MODULE_ABORTS_ON_LOAD — file aborts at load before this "
            "function binds; never importable/callable"),
    ),
    "lexical_dead": VerdictSpec(
        Reachability.UNREACHABLE, WitnessKind.LEXICAL_DEAD, Soundness.SOUND,
        earns_suppression=True,
        summary="defined inside an always-false guard",
        blocker_template=(
            "reachability:lexical_dead — entry function {fq} is defined inside "
            "an always-false guard (if False / #[cfg(any())]) and never binds"),
        prompt_verdict=(
            "Verdict: LEXICAL_DEAD — defined inside an always-false guard "
            "(if False / #[cfg(any())]); never binds"),
    ),
    "binary_oracle_absent": VerdictSpec(
        Reachability.UNREACHABLE, WitnessKind.BINARY_ORACLE_ABSENT,
        Soundness.SOUND, earns_suppression=True,
        summary=(
            "classifier verdict ``absent`` on the analysed binary — "
            "neither a standalone symbol nor an inlined-subroutine "
            "instance was found at classification time"),
        blocker_template=(
            "reachability:binary_oracle_absent — entry function {fq} has no "
            "symbol and no inlined-subroutine instance in the analysed binary "
            "(--binary); the compiler/linker eliminated it from this build"),
        prompt_verdict=(
            "Verdict: BINARY_ORACLE_ABSENT — function eliminated from the "
            "analysed binary by --gc-sections / DCE; no symbol present and no "
            "inlined-subroutine instance survives. Build-specific (this "
            "binary's build_id); not a universal source claim"),
    ),
    "build_excluded": VerdictSpec(
        Reachability.UNREACHABLE, WitnessKind.BUILD_EXCLUDED,
        Soundness.HEURISTIC, earns_suppression=False,
        summary="translation unit excluded from the build (never compiled)",
        blocker_template=(
            "reachability:build_excluded — entry function {fq} is in a file "
            "excluded from the build ({detail}) and is never compiled"),
        blocker_detail="build_excluded",
        prompt_verdict=(
            "Verdict: BUILD_EXCLUDED — file is excluded from the build "
            "(e.g. //go:build ignore); never compiled in this configuration"),
    ),
    "no_path_from_entry": VerdictSpec(
        Reachability.UNREACHABLE, WitnessKind.NO_PATH_FROM_ENTRY,
        Soundness.HEURISTIC, earns_suppression=False,
        summary="no path from any entry point (orphaned dead-island)",
        blocker_template=(
            "reachability:no_path_from_entry — entry function {fq} has "
            "callers, but none reachable from any entry point "
            "(orphaned dead-island)"),
        prompt_verdict=(
            "Verdict: NO_PATH_FROM_ENTRY — has callers, but none reachable "
            "from any entry point (orphaned dead-island)"),
    ),
    "not_called": VerdictSpec(
        Reachability.UNREACHABLE, WitnessKind.NOT_CALLED, Soundness.HEURISTIC,
        earns_suppression=False,
        summary="no caller found in non-test project source",
        blocker_template=(
            "reachability:not_called — entry function {fq} is not called from "
            "any non-test project source"),
        # prompt_verdict: rendered by the ``priority == low`` catch-all branch.
    ),
    "called": VerdictSpec(
        Reachability.REACHABLE, WitnessKind.HAS_CALLER, Soundness.HEURISTIC,
        earns_suppression=False, summary="called from project source"),
    "framework_callable": VerdictSpec(
        Reachability.REACHABLE, WitnessKind.FRAMEWORK_CALLABLE,
        Soundness.HEURISTIC, earns_suppression=False,
        summary="registered via framework dispatch"),
    "registered_via_call": VerdictSpec(
        Reachability.REACHABLE, WitnessKind.REGISTERED_VIA_CALL,
        Soundness.HEURISTIC, earns_suppression=False,
        summary="passed as a framework registration argument"),
    "binary_call_edge": VerdictSpec(
        Reachability.REACHABLE, WitnessKind.BINARY_CALL_EDGE,
        Soundness.HEURISTIC, earns_suppression=False,
        summary=(
            "binary call graph shows the function is called from another "
            "binary-resident symbol (direct call edge — Inc 2b Tier 1)"),
        prompt_verdict=(
            "Verdict: BINARY_CALL_EDGE — the analysed binary's direct "
            "call graph proves this function is invoked from another "
            "binary-resident symbol. Source-graph extraction may have "
            "missed this edge (header-inline, partial resolution); the "
            "binary provides affirmative reachability evidence."),
    ),
    "reachable": VerdictSpec(
        Reachability.REACHABLE, WitnessKind.REACHABLE_FROM_ENTRY,
        Soundness.HEURISTIC, earns_suppression=False,
        summary="reachable from an entry point"),
    "uncertain": VerdictSpec(
        Reachability.UNCERTAIN, WitnessKind.UNCERTAIN, Soundness.HEURISTIC,
        earns_suppression=False,
        summary="reachability could not be determined"),
}

_UNCERTAIN_SPEC = VERDICTS["uncertain"]

# Derived: the witness kinds that CAN earn suppression (membership necessary,
# not sufficient — ``may_suppress`` still requires the corpus-earned set).
STRUCTURALLY_SUPPRESSIBLE_KINDS = frozenset(
    spec.kind for spec in VERDICTS.values() if spec.earns_suppression
)


def verdict_from_classification(verdict: str) -> ReachabilityVerdict:
    """Wrap a ``classify_reachability`` string verdict in a structured
    ReachabilityVerdict. Unknown strings → UNCERTAIN (fail safe)."""
    spec = VERDICTS.get(verdict, _UNCERTAIN_SPEC)
    return ReachabilityVerdict(
        status=spec.status,
        witness=Witness(kind=spec.kind, soundness=spec.soundness,
                        summary=spec.summary))


def blocker_for(verdict: str, fq: str, detail: str = "") -> Optional[str]:
    """The /validate demoter blocker string for a dead ``verdict``, or ``None``
    when the verdict has no blocker template. ``fq`` = ``module.func``;
    ``detail`` = the witness summary for verdicts whose blocker embeds one
    (the caller fetches it per ``VERDICTS[verdict].blocker_detail``)."""
    spec = VERDICTS.get(verdict)
    if spec is None or not spec.blocker_template:
        return None
    return spec.blocker_template.format(fq=fq, detail=detail)


def prompt_verdict_for(verdict: str) -> str:
    """The analysis-prompt 'Verdict: …' line for a verdict, or '' when the
    verdict is rendered by a special-case branch (not_called / framework)."""
    spec = VERDICTS.get(verdict)
    return spec.prompt_verdict if spec else ""


def resolve_reachability(
    inventory: Dict[str, object],
    file_path: str,
    name: str,
    line: int,
    module: str,
) -> ReachabilityVerdict:
    """Structured reachability verdict for one function. Composes the
    accessors via :func:`core.inventory.reach_audit.classify_reachability`,
    then wraps the result as a proof-carrying witness."""
    from core.inventory.reach_audit import classify_reachability
    return verdict_from_classification(
        classify_reachability(inventory, file_path, name, line, module))


__all__ = [
    "Reachability",
    "WitnessKind",
    "Soundness",
    "Witness",
    "ReachabilityVerdict",
    "VerdictSpec",
    "VERDICTS",
    "STRUCTURALLY_SUPPRESSIBLE_KINDS",
    "verdict_from_classification",
    "blocker_for",
    "prompt_verdict_for",
    "resolve_reachability",
]

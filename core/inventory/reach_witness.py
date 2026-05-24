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
from typing import Dict, Tuple


class Reachability(str, Enum):
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    UNCERTAIN = "uncertain"


class WitnessKind(str, Enum):
    # unreachable
    MODULE_ABORTS = "module_aborts"
    LEXICAL_DEAD = "lexical_dead"
    NO_PATH_FROM_ENTRY = "no_path_from_entry"
    NOT_CALLED = "not_called"
    # reachable
    HAS_CALLER = "has_caller"
    FRAMEWORK_CALLABLE = "framework_callable"
    REGISTERED_VIA_CALL = "registered_via_call"
    REACHABLE_FROM_ENTRY = "reachable_from_entry"
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


# The witness kinds that CAN earn suppression (config-independent structural
# deadness). A kind here still suppresses only once a corpus has validated
# it (passed to ``may_suppress`` as ``earned_kinds``) — membership here is
# necessary, not sufficient.
STRUCTURALLY_SUPPRESSIBLE_KINDS = frozenset({
    WitnessKind.MODULE_ABORTS,
    WitnessKind.LEXICAL_DEAD,
})


# Map a classify_reachability() string verdict → (status, kind, soundness,
# summary). Candidate soundness: only the structural, config-independent
# dead witnesses (module-load abort, always-false lexical guard) are SOUND.
# no_path_from_entry and not_called are UNREACHABLE but HEURISTIC (entry-set
# completeness / 1-hop assumptions can miss reflection, cross-file, or
# address-of edges). Reachable/uncertain are never suppress-eligible, so
# their soundness is immaterial (recorded HEURISTIC).
_VERDICT_MAP: Dict[str, Tuple[Reachability, WitnessKind, Soundness, str]] = {
    "module_aborts": (
        Reachability.UNREACHABLE, WitnessKind.MODULE_ABORTS, Soundness.SOUND,
        "file aborts on load before this function binds",
    ),
    "lexical_dead": (
        Reachability.UNREACHABLE, WitnessKind.LEXICAL_DEAD, Soundness.SOUND,
        "defined inside an always-false guard",
    ),
    "no_path_from_entry": (
        Reachability.UNREACHABLE, WitnessKind.NO_PATH_FROM_ENTRY,
        Soundness.HEURISTIC,
        "no path from any entry point (orphaned dead-island)",
    ),
    "not_called": (
        Reachability.UNREACHABLE, WitnessKind.NOT_CALLED, Soundness.HEURISTIC,
        "no caller found in non-test project source",
    ),
    "called": (
        Reachability.REACHABLE, WitnessKind.HAS_CALLER, Soundness.HEURISTIC,
        "called from project source",
    ),
    "framework_callable": (
        Reachability.REACHABLE, WitnessKind.FRAMEWORK_CALLABLE,
        Soundness.HEURISTIC, "registered via framework dispatch",
    ),
    "registered_via_call": (
        Reachability.REACHABLE, WitnessKind.REGISTERED_VIA_CALL,
        Soundness.HEURISTIC, "passed as a framework registration argument",
    ),
    "reachable": (
        Reachability.REACHABLE, WitnessKind.REACHABLE_FROM_ENTRY,
        Soundness.HEURISTIC, "reachable from an entry point",
    ),
    "uncertain": (
        Reachability.UNCERTAIN, WitnessKind.UNCERTAIN, Soundness.HEURISTIC,
        "reachability could not be determined",
    ),
}


def verdict_from_classification(verdict: str) -> ReachabilityVerdict:
    """Wrap a ``classify_reachability`` string verdict in a structured
    ReachabilityVerdict. Unknown strings → UNCERTAIN (fail safe)."""
    status, kind, soundness, summary = _VERDICT_MAP.get(
        verdict,
        (Reachability.UNCERTAIN, WitnessKind.UNCERTAIN, Soundness.HEURISTIC,
         "reachability could not be determined"),
    )
    return ReachabilityVerdict(
        status=status, witness=Witness(kind=kind, soundness=soundness,
                                       summary=summary))


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
    "STRUCTURALLY_SUPPRESSIBLE_KINDS",
    "verdict_from_classification",
    "resolve_reachability",
]

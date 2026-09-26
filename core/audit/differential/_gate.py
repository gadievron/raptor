"""Eligibility gate for differential family execution.

Dimension/family-keyed, deliberately NOT routed through the CWE
dispatch table: eligibility is a property of the lead's receipt (a
census dimension whose family members are executable functions), not
of a hypothesis's CWE class. The gate refuses loudly with a reason so
telemetry can enumerate why leads were skipped.
"""

from __future__ import annotations

from typing import Any, Mapping

from ..dark_verify import language_for_file
from ..dark_verify._types import _SUPPORTED_LANGS
from ._rails import MIN_CONFORMING_EXECUTED

#: The census dimensions whose deviations name a deviant FUNCTION and
#: a family of conforming peer FUNCTIONS — the shape member execution
#: needs. Values are the floors-registry keys the promotion gate
#: holds the executed conforming subset to.
DIMENSION_FLOOR_KEY: dict[str, str] = {
    "guard-predicate": "guard-predicate.min_sites",
    "interface": "interface.min_group",
    "boundary-unit": "boundary-unit.min_sites",
}

#: Languages whose witness harnesses take one spec-level argument
#: vector verbatim (args/kwargs applied to a resolved callable).
#: The native lanes (c, cpp, go, rust, java) are excluded: their
#: harnesses need per-member typed argument EXPRESSIONS, which would
#: have to be authored per member — breaking the guarantee that
#: every family member executed the IDENTICAL shared vector, which
#: is the whole basis of the comparison.
_NATIVE_LANGS = frozenset({"c", "cpp", "go", "rust", "java"})
#: Excluded on a second axis: languages whose call boundary REFUSES a
#: mis-shaped vector with an error the harness cannot tell apart from
#: the member's own guard rejecting the input (Ruby raises
#: ArgumentError, PHP ArgumentCountError, Perl signatures croak — all
#: at entry, all reported by their harnesses as a plain exception).
#: Including them would mint reject-divergence out of signature
#: heterogeneity: a peer whose arity cannot bind the shared vector
#: would read as semantically rejecting it. Excluding them costs only
#: those lanes' differential coverage — the census dimensions still
#: flag their deviations; only member EXECUTION is withheld.
#: JavaScript/TypeScript/Lua stay in: their call boundaries
#: undefined/nil-fill missing arguments, so the member body genuinely
#: executes and what it does with the vector is a real observation.
#: Python stays in because its harness classifies binding refusals
#: as a distinct protocol status the classifier maps to member error.
_UNCLASSIFIED_BOUNDARY_LANGS = frozenset({"ruby", "php", "perl"})
ARGS_SHAPED_LANGS = (
    frozenset(_SUPPORTED_LANGS)
    - _NATIVE_LANGS
    - _UNCLASSIFIED_BOUNDARY_LANGS
)


def differential_applicable(
    lead: Mapping[str, Any],
) -> tuple[bool, str]:
    """Whether one consistency lead is eligible for differential
    execution — ``(True, "")`` or ``(False, reason)``."""
    dimension = str(lead.get("dimension") or "")
    if dimension not in DIMENSION_FLOOR_KEY:
        return False, f"dimension {dimension!r} has no executable family"

    file = str(lead.get("file") or "")
    function = str(lead.get("function") or "")
    if not file or not function:
        return False, "lead names no deviant file/function"

    family = lead.get("family_functions")
    if not isinstance(family, list):
        return False, "lead discloses no family members"
    members = [
        m for m in family
        if isinstance(m, Mapping)
        and m.get("file") and m.get("function")
        # The deviant is never its own peer.
        and not (m.get("file") == file and m.get("function") == function)
    ]
    if len(members) < MIN_CONFORMING_EXECUTED:
        return False, (
            f"family discloses {len(members)} usable member(s); "
            f"need {MIN_CONFORMING_EXECUTED}"
        )

    lang = language_for_file(file)
    if lang not in ARGS_SHAPED_LANGS:
        return False, (
            f"language {lang or 'unknown'!s} takes no shared "
            f"argument vector"
        )
    for m in members:
        if language_for_file(str(m["file"])) != lang:
            return False, (
                f"family language is not uniform "
                f"({m['file']} != {lang})"
            )
    return True, ""


def usable_family(
    lead: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """The lead's usable conforming members (same filter the gate
    applied), in disclosed order."""
    file = str(lead.get("file") or "")
    function = str(lead.get("function") or "")
    family = lead.get("family_functions")
    if not isinstance(family, list):
        return []
    return [
        dict(m) for m in family
        if isinstance(m, Mapping)
        and m.get("file") and m.get("function")
        and not (m.get("file") == file and m.get("function") == function)
    ]

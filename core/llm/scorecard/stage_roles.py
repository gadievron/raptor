"""Canonical stage-role tags for scorecard decision-class strings.

The scorecard's ``decision_class`` field is deliberately free-form
so callers can encode role + sub-topic. Originally the tagging was
ad-hoc across producers — mutator writes recorded as
``"exploit_chain_closure"``, but there was no consistent naming for
refuter / judge / oracle-critic / verification-critic writes. That
made "which model wins at which stage" impossible to compute.

This module fixes the convention. Every scorecard write from the
exploit_engine's per-stage substrates goes through
:func:`stage_role_decision_class` so the resulting decision-class
strings are grep-able and pivotable.

Motivated by CVE-Genie (arXiv:2509.01835 §4) which evaluated 10
LLMs across 5 stage roles and picked o3 vs o4-mini per role by
measured TPR/TNR. Without a per-stage tag on our scorecard writes
we can't run the equivalent measurement.

Naming rule:

  * ``role`` is a stable, short lowercase identifier for the loop
    substrate that produced the event. Extend this module's
    :data:`KNOWN_STAGE_ROLES` when adding a new substrate.
  * ``sub_topic`` is an optional short qualifier (e.g. the CWE the
    substrate was handling). Empty ``sub_topic`` yields just
    ``role``.
  * Rendered form: ``"role"`` or ``"role:sub_topic"``. Both lowercase.

Reports pivot on the ``role:`` prefix to aggregate across sub-topics.
"""

from __future__ import annotations

# Extend when a new substrate calls the scorecard. Keeping the set
# small and enumerated so a typo in a producer doesn't create a
# rogue role that never rolls up in reports.
KNOWN_STAGE_ROLES: frozenset[str] = frozenset({
    # Emits brain edits — the FM-routed specialist that proposes
    # per-target intel or per-CWE lesson updates.
    "mutator",
    # Cross-family swap-eval refuter that gates mutator emissions.
    "refuter",
    # Per-attempt judge that reads the actor's claim vs oracle
    # evidence and emits a consistency verdict.
    "judge",
    # Verification critic — adversarial reviewer of succeeded fires
    # ("did this ACTUALLY exploit the CVE?").
    "verification_critic",
    # The engine's actor turn — the model producing the exploit
    # itself. Legacy writes use "exploit_chain_closure"; new writes
    # tag this way for consistency.
    "actor",
    # Success-lifter (post-loop cross-target lesson distiller).
    "success_lifter",
    # Extract-lesson mutator specialist. Distinct from ``mutator``
    # because its Wilson calibration is different — it fires much
    # less frequently and on a different oracle signal.
    "extract_lesson",
})


def stage_role_decision_class(role: str, sub_topic: str = "") -> str:
    """Build a canonical scorecard ``decision_class`` string.

    Enforces ``role in KNOWN_STAGE_ROLES`` case-sensitively; a typo
    or unknown role raises ``ValueError`` immediately at the producer
    instead of silently landing in the scorecard as an unpivotable
    cell. Callers pass roles VERBATIM from the enum (all lowercase);
    ``"MUTATOR"`` fails validation rather than silently case-folding.
    ``sub_topic`` may be empty (canonical form: bare ``role``) or a
    short identifier (canonical form: ``role:sub_topic``); it IS
    lowercased and stripped before rendering so ``"CWE-121"``
    round-trips as ``"cwe-121"``.

    Whitespace, control chars, and non-printable chars inside
    ``sub_topic`` are rejected — they would break log-line
    greppability and CLI table rendering that splits on newlines.
    """
    if role not in KNOWN_STAGE_ROLES:
        raise ValueError(
            f"unknown stage_role {role!r}; add to KNOWN_STAGE_ROLES if "
            f"introducing a new substrate. Known: "
            f"{sorted(KNOWN_STAGE_ROLES)}",
        )
    role_norm = role.strip().lower()
    if not role_norm:
        raise ValueError("empty role after normalisation")
    if sub_topic:
        sub_norm = sub_topic.strip().lower()
        if any(c.isspace() for c in sub_norm):
            # ``isspace`` catches ``" "``, ``"\t"``, ``"\n"``, ``"\r"``,
            # form-feed, vertical-tab, and Unicode whitespace runes.
            raise ValueError(
                f"whitespace not allowed in sub_topic {sub_topic!r}",
            )
        if not sub_norm.isprintable():
            # Non-printable control chars would render as gibberish in
            # logs and break greppability. ``isprintable`` returns
            # False for control chars, DEL, and category-Cc runes.
            raise ValueError(
                f"non-printable character in sub_topic {sub_topic!r}",
            )
        if not sub_norm:
            return role_norm
        return f"{role_norm}:{sub_norm}"
    return role_norm


def parse_stage_role(decision_class: str) -> tuple[str, str]:
    """Split a decision-class string back into ``(role, sub_topic)``.

    Returns ``("", "")`` when the input isn't in the ``role`` or
    ``role:sub_topic`` shape — a permissive parser so legacy or
    unrelated decision_classes (e.g. ``"cheap_short_circuit"``)
    don't raise here. Callers wanting hard validation should check
    ``role in KNOWN_STAGE_ROLES`` themselves.
    """
    if not decision_class:
        return "", ""
    if ":" not in decision_class:
        return decision_class.strip().lower(), ""
    role, sub = decision_class.split(":", 1)
    return role.strip().lower(), sub.strip().lower()


__all__ = [
    "KNOWN_STAGE_ROLES",
    "parse_stage_role",
    "stage_role_decision_class",
]

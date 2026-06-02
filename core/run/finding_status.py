"""Unified per-finding status enum + helpers.

Substrate for QoL #19. Replaces the null-field-detection pattern
that downstream consumers (``raptor_agentic`` summary,
``orchestrated_report.json`` readers, reporting renderers) used to
decide ''was this finding analysed?'' / ''was it skipped?'' / ''does
it need human review?'' / ''did the analysis crash?''. Each consumer
re-implemented the detection from a different mix of fields
(``is_true_positive is None``, ``self_contradictory``, ``error``,
absent keys); each got it slightly wrong.

A single ``status`` value on each finding dict is the source of
truth. Helpers (``is_actionable``, ``needs_review``, ``is_skipped``)
let consumers ask the question they actually care about without
re-deriving the rules.

## Status values

* ``analysed`` — LLM processed the finding; verdict is trustworthy.
  Headline ''Exploitable / FP'' counts come from this bucket.
* ``analysis_inconsistent`` — LLM processed but reasoning /
  verdict contradicted itself (``self_contradictory=True``)
  post-Stage-F retry AND no judge resolved it. Counted as
  ''Inconsistent (review needed)'' in operator output.
* ``skipped_over_budget`` — cost or count cap hit before this
  finding got dispatched.
* ``skipped_duplicate`` — dedup against another finding kept this
  out of the analysed set.
* ``skipped_dead_code`` — binary-oracle filtered: function not in
  the analysed binary.
* ``skipped_filtered`` — operator ``--exclude-dir`` or filter rule
  excluded this path.
* ``skipped_tool_absent`` — tool that would have analysed this
  finding wasn't available (e.g. codeql skipped because
  ``autoreconf`` was missing).
* ``error`` — analysis crashed; see ``error`` field on the finding
  for detail.

## Backwards compatibility

``derive_status(finding)`` infers the status from existing fields
(``is_true_positive``, ``self_contradictory``, ``error``,
``contradiction_resolved_by_judge``) when a finding doesn't carry
an explicit ``status`` key — so pre-existing emit paths continue
to work without per-emit-site changes. New emit sites (orchestrator
backfill, scan-time skip records) call ``set_status`` explicitly so
consumers see the canonical value.

``bucket_orchestration_results`` in ``core/orchestration/funnel.py``
prefers the explicit status when present and falls back to the
derive path otherwise. No flag day; consumers using the helpers
work across the transition.
"""

from __future__ import annotations

from typing import Dict


# String-valued for direct JSON serialisation. No Enum() — keeps
# the dict shape grep-able and avoids the standard-library enum
# import burden on every consumer.
ANALYSED = "analysed"
ANALYSIS_INCONSISTENT = "analysis_inconsistent"
SKIPPED_OVER_BUDGET = "skipped_over_budget"
SKIPPED_DUPLICATE = "skipped_duplicate"
SKIPPED_DEAD_CODE = "skipped_dead_code"
SKIPPED_FILTERED = "skipped_filtered"
SKIPPED_TOOL_ABSENT = "skipped_tool_absent"
SKIPPED = "skipped"   # generic skip when the reason wasn't recorded
ERROR = "error"

ALL_STATUSES = frozenset({
    ANALYSED,
    ANALYSIS_INCONSISTENT,
    SKIPPED_OVER_BUDGET,
    SKIPPED_DUPLICATE,
    SKIPPED_DEAD_CODE,
    SKIPPED_FILTERED,
    SKIPPED_TOOL_ABSENT,
    SKIPPED,
    ERROR,
})

# All ``skipped_*`` values + the generic ``skipped`` — used by
# ``is_skipped`` and skip-reason filters in reporting.
_SKIPPED_STATUSES = frozenset({
    SKIPPED_OVER_BUDGET,
    SKIPPED_DUPLICATE,
    SKIPPED_DEAD_CODE,
    SKIPPED_FILTERED,
    SKIPPED_TOOL_ABSENT,
    SKIPPED,
})


def derive_status(finding: Dict) -> str:
    """Infer status from a finding's existing fields.

    Used as the fallback when the finding doesn't carry an explicit
    ``status`` key (backwards-compat for emit paths that pre-date
    #19). Detection order:

      1. ``error`` field present → ``error``
      2. ``is_true_positive`` key absent → ``skipped`` (generic;
         caller didn't record a specific skip reason)
      3. ``is_exploitable=True`` AND ``self_contradictory=True``
         (and not resolved by judge) → ``analysis_inconsistent``
      4. Otherwise → ``analysed``
    """
    if "error" in finding:
        return ERROR
    if "is_true_positive" not in finding:
        return SKIPPED
    if (finding.get("is_exploitable")
            and finding.get("self_contradictory")
            and not finding.get("contradiction_resolved_by_judge")):
        return ANALYSIS_INCONSISTENT
    return ANALYSED


def set_status(finding: Dict, status: str,
               *, skip_reason: str = None) -> None:
    """Stamp ``status`` (and optionally ``skip_reason``) on the
    finding dict. Validates against ``ALL_STATUSES`` to catch
    typos — an unknown status string would silently propagate
    otherwise and break downstream filters that ``in``-check the
    enum.

    Raises ``ValueError`` on unknown status (deliberate — the
    audit trail's value depends on the enum being closed)."""
    if status not in ALL_STATUSES:
        raise ValueError(
            f"finding_status.set_status: unknown status "
            f"{status!r} (valid: {sorted(ALL_STATUSES)})"
        )
    finding["status"] = status
    if skip_reason is not None:
        finding["skip_reason"] = skip_reason


def get_status(finding: Dict) -> str:
    """Return the finding's status — prefer the explicit ``status``
    field; fall back to ``derive_status`` for pre-#19 emit paths."""
    explicit = finding.get("status")
    if explicit in ALL_STATUSES:
        return explicit
    return derive_status(finding)


def is_actionable(finding: Dict) -> bool:
    """True when the finding was successfully analysed and its
    verdict is trustworthy. Headline ''Exploitable / FP'' counts
    derive from this set."""
    return get_status(finding) == ANALYSED


def needs_review(finding: Dict) -> bool:
    """True when the LLM produced internally-contradictory
    reasoning and no judge resolved it — operator-facing
    ''Inconsistent (review needed)'' bucket."""
    return get_status(finding) == ANALYSIS_INCONSISTENT


def is_skipped(finding: Dict) -> bool:
    """True for any ``skipped_*`` status (regardless of reason).
    Used by reporting to separate ''we looked at this'' from
    ''we didn't get to this''."""
    return get_status(finding) in _SKIPPED_STATUSES


def is_errored(finding: Dict) -> bool:
    """True when the analysis attempt crashed. Distinct from
    ``is_skipped`` because the operator may want to retry errored
    findings (transient infra issues) vs investigate skipped
    findings (budget / dedup / filter decisions)."""
    return get_status(finding) == ERROR


def is_terminal(finding: Dict) -> bool:
    """True for any final status (analysed / inconsistent /
    skipped / errored). False only for the in-flight case where no
    status has been derived yet."""
    return get_status(finding) in ALL_STATUSES


__all__ = [
    # status values
    "ANALYSED", "ANALYSIS_INCONSISTENT",
    "SKIPPED_OVER_BUDGET", "SKIPPED_DUPLICATE", "SKIPPED_DEAD_CODE",
    "SKIPPED_FILTERED", "SKIPPED_TOOL_ABSENT", "SKIPPED",
    "ERROR",
    "ALL_STATUSES",
    # operations
    "derive_status", "set_status", "get_status",
    # predicates
    "is_actionable", "needs_review", "is_skipped", "is_errored",
    "is_terminal",
]

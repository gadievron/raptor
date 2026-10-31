"""Post-pipeline invariant checks for the audit orchestrator.

Called at the end of ``run_orchestrator`` (debug mode) and from tests.
Every check raises ``InvariantViolation`` with a diagnostic message on
failure.  The checks are deliberately strict — a violation means a bug
in the pipeline, not a borderline condition.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .orchestrator import OrchestratorResult

logger = logging.getLogger(__name__)


class InvariantViolation(AssertionError):
    """A pipeline invariant was violated."""


def check_pipeline_invariants(result: OrchestratorResult) -> list[str]:
    """Run all invariant checks.  Returns a list of violation messages
    (empty if all pass).  Does NOT raise — the caller decides whether
    to raise, log, or both."""
    violations: list[str] = []
    violations.extend(_check_counter_consistency(result))
    violations.extend(_check_no_double_dispatch(result))
    violations.extend(_check_exhaustion_finality(result))
    violations.extend(_check_tool_evidence_preservation(result))
    violations.extend(_check_synthesis_cap(result))
    return violations


def assert_pipeline_invariants(result: OrchestratorResult) -> None:
    """Check all invariants and raise on the first violation."""
    violations = check_pipeline_invariants(result)
    if violations:
        raise InvariantViolation(
            f"{len(violations)} pipeline invariant(s) violated:\n"
            + "\n".join(f"  - {v}" for v in violations)
        )


def _check_counter_consistency(result: OrchestratorResult) -> list[str]:
    """Verify status counters match actual outcome statuses."""
    violations: list[str] = []
    actual_clean = 0
    actual_suspicious = 0
    actual_findings = 0
    for o in result.outcomes:
        if o.status == "clean":
            actual_clean += 1
        elif o.status == "suspicious":
            actual_suspicious += 1
        elif o.status == "finding":
            actual_findings += 1
    if result.clean != actual_clean:
        violations.append(
            f"counter drift: result.clean={result.clean} but "
            f"actual clean outcomes={actual_clean}"
        )
    if result.suspicious != actual_suspicious:
        violations.append(
            f"counter drift: result.suspicious={result.suspicious} but "
            f"actual suspicious outcomes={actual_suspicious}"
        )
    if result.findings != actual_findings:
        violations.append(
            f"counter drift: result.findings={result.findings} but "
            f"actual finding outcomes={actual_findings}"
        )
    return violations


def _check_no_double_dispatch(result: OrchestratorResult) -> list[str]:
    """No outcome should have both immediate_verified and a post-loop
    sweep receipt."""
    violations: list[str] = []
    for o in result.outcomes:
        rr = o.review_result or {}
        if not rr.get("immediate_verified"):
            continue
        sweep_markers = (
            "[sweep-promotion:" in (o.body or ""),
            "[secondary-dispatch:" in (o.body or ""),
            "[hypothesis-consistency:" in (o.body or ""),
        )
        if any(sweep_markers):
            violations.append(
                f"double-dispatch: {o.file}:{o.function} has "
                f"immediate_verified=True AND a post-loop sweep marker"
            )
    return violations


def _check_exhaustion_finality(result: OrchestratorResult) -> list[str]:
    """chain_exhausted outcomes must not have been re-verified
    post-loop."""
    violations: list[str] = []
    for o in result.outcomes:
        rr = o.review_result or {}
        if not rr.get("chain_exhausted"):
            continue
        if "[sweep-promotion:" in (o.body or ""):
            violations.append(
                f"exhaustion re-attempt: {o.file}:{o.function} has "
                f"chain_exhausted=True but received a sweep-promotion"
            )
    return violations


def _check_tool_evidence_preservation(result: OrchestratorResult) -> list[str]:
    """Outcomes with tool receipts should not have been silently
    stripped of their evidence.  We check that evidence_tool is still
    set when the review_result records a tool confirmation."""
    violations: list[str] = []
    for o in result.outcomes:
        rr = o.review_result or {}
        confirmed_tools = rr.get("tools_confirmed") or []
        if confirmed_tools and not (o.evidence_tool or "").strip():
            violations.append(
                f"evidence stripped: {o.file}:{o.function} has "
                f"tools_confirmed={confirmed_tools} but "
                f"evidence_tool is empty"
            )
    return violations


def _check_synthesis_cap(result: OrchestratorResult) -> list[str]:
    """On-demand synthesis count must not exceed the run cap."""
    violations: list[str] = []
    try:
        from .checker_synthesis import MAX_ONDEMAND_SYNTHESIS_PER_RUN
    except ImportError:
        return violations
    if result.ondemand_synthesized > MAX_ONDEMAND_SYNTHESIS_PER_RUN:
        violations.append(
            f"synthesis cap exceeded: {result.ondemand_synthesized} > "
            f"{MAX_ONDEMAND_SYNTHESIS_PER_RUN}"
        )
    return violations

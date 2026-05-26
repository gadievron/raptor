"""Operator-facing descriptions for SCA pipeline phases.

The pipeline calls ``progress.stage(<short_name>)`` at each phase
boundary; the short names are tight (``osv``, ``reach``,
``cascade``) so they fit the in-place stage line. When something
goes wrong, operators want a more discursive description in the
error message so they know what the phase actually does without
reading the source.

The mapping intentionally lives outside ``pipeline.py`` so the
same descriptions can be reused by anything that catches a
pipeline exception (CLI, agent driver, gate script) without
re-importing the entire pipeline module."""

from __future__ import annotations

from typing import Optional

# Short-name → operator-facing description. Keep each one to a
# single short clause so the error line stays readable.
_PHASE_DESCRIPTIONS: dict[str, str] = {
    "discovery": "discovering manifests + parsing dependencies",
    "cascade": "expanding transitive dependencies",
    "hygiene": "evaluating dependency hygiene heuristics",
    "supply-chain": "evaluating supply-chain risk heuristics",
    "license": "enriching + evaluating license metadata",
    "osv": "querying OSV / KEV / EPSS for vulnerability advisories",
    "reach": "scanning project source for reachable use of vulnerable deps",
    "findings": "building vulnerability findings",
    "llm-review": "running LLM behavioural review on supply-chain + vuln findings",
    "triage": "running LLM triage ranking",
    "impact-analysis": "running LLM upgrade-impact analysis",
    "emit": "writing findings.json / report.md / SBOM / SARIF artefacts",
}


def describe_phase(name: str) -> Optional[str]:
    """Return a one-line operator-facing description for the named
    pipeline phase, or ``None`` for an unknown phase.

    The name ``None`` covers two cases — phases not in the table
    (forward-compat: a new phase ships before the description
    catches up) and the bar's "no stage active" state. Callers
    fall back to the short name in either case.
    """
    return _PHASE_DESCRIPTIONS.get(name)

"""Finding-kind predicates shared across tasks and prompt builders.

Leaf module (no intra-package imports) so both ``tasks.py`` and the
``prompts/`` builders can share ONE copy of the SCA-dispatch
predicates — the previous four verbatim copies drifted independently
and each carried the same latent crash.

None-safety: ``f.get("vuln_type", "")`` only defaults for an ABSENT
key. Present-but-None values are real — ``FINDING_RESULT_SCHEMA``
types ``vuln_type`` / ``rule_id`` as ``["string", "null"]``, the web
scanner emits possibly-None ``vuln_type``, and the validated-findings
converter builds ``rule_id`` as ``f.rule_id or f.vuln_type`` (None
when both are unset). ``None.startswith`` then aborts the whole
exploit / patch stage from ``select_items``. Coalesce with
``or ""`` instead.
"""

from __future__ import annotations

from typing import Any


def is_sca_finding(f: dict[str, Any]) -> bool:
    """Canonical "is this an SCA finding?" check.

    Recognises three identification methods because the SCA pipeline
    has tagged findings differently over time:
      * ``source_type == "dependency"`` (the post-2026 canonical
        marker — set by ``packages/sca/findings.py``)
      * ``vuln_type`` starting with ``sca:`` (set on the
        ``JoinedFinding`` wrapper at serialisation)
      * ``rule_id`` starting with ``sca:`` (older code path, still
        emitted by some consumers that bypass the joiner)

    Broad-by-design: ANY SCA-shaped finding (vulnerable-dependency,
    hygiene, license, supply-chain) matches. Dispatch sites that only
    act on vuln-dep findings should use :func:`is_sca_vuln_finding`
    instead — that's the narrower check.
    """
    return (
        f.get("source_type") == "dependency"
        or (f.get("vuln_type") or "").startswith("sca:")
        or (f.get("rule_id") or "").startswith("sca:")
    )


def is_sca_vuln_finding(f: dict[str, Any]) -> bool:
    """Narrower companion to :func:`is_sca_finding`: only
    ``sca:vulnerable_dependency`` findings, NOT hygiene / license /
    supply-chain.

    ExploitTask + PatchTask both want this narrower predicate — you
    don't generate an exploit-PoC or a manifest patch for
    "lockfile_missing" or "low_bus_factor". Hygiene findings are
    SCA-shaped but not actionable in those task families.

    Does NOT key on ``source_type == "dependency"`` alone — that
    field is set on every SCA finding (hygiene included) and wouldn't
    discriminate.
    """
    return (
        (f.get("vuln_type") or "").startswith("sca:vulnerable_dependency")
        or (f.get("rule_id") or "").startswith("sca:vulnerable_dependency")
    )


__all__ = ["is_sca_finding", "is_sca_vuln_finding"]

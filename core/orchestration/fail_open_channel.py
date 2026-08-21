"""Fail-open channel as a refute/corroborate channel beyond /audit.

Reuses ``core.audit.fail_open_verify.run_fail_open_check`` — the
mechanical role × handler-outcome × fallibility adjudicator with
receipts — for /agentic's per-finding analysis loop, mirroring the
guard-dominance (P23) consumption shape:

* ``refuted`` — the finding's fail-open claim is mechanically
  disproven (fail-closed handler / every site consumes the result);
  the pre-LLM chokepoint skips the LLM call with the receipt in the
  analysis record and a ``suppressions.jsonl`` entry — explicit
  disqualifier semantics, never a silent drop.
* ``confirmed`` — the channel's receipt (role binding, handler idiom,
  fallibility witness) rides onto the finding as ``fail_open``
  corroboration. Evidence, never a verdict: the LLM still rules on
  exploitability, and ``verification_tier`` grades the reported
  verdict ``tool_backed``.
* ``inconclusive`` — nothing recorded (the reasons are enumerated in
  the channel; absence of a receipt is meaningful, never blocking).

Cheaper than guard-dominance: no server, no subprocess — one source
read + tree-sitter/ast parse per checked finding, so the cap is
correspondingly higher. Findings must LOOK like a fail-open /
swallowed-error claim before the channel spends the parse
(``is_fail_open_hypothesis`` on the claim prose).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Per-run cap on channel dispatches outside /audit. Pure-AST checks,
# but pathological finding floods should not re-parse the same tree
# hundreds of times.
FAIL_OPEN_CHANNEL_CAP = 200


def _finding_claim_text(finding: dict[str, Any]) -> str:
    parts = [
        finding.get("candidate_reasoning") or "",
        finding.get("dataflow_summary") or "",
        finding.get("message") or "",
        finding.get("hypothesis") or "",
    ]
    return " ".join(p for p in parts if p)


def _finding_coords(finding: dict[str, Any]) -> tuple[str, str] | None:
    file_path = finding.get("file") or finding.get("file_path") or ""
    function = (
        finding.get("function")
        or (finding.get("metadata") or {}).get("function_name")
        or (finding.get("metadata") or {}).get("name")
        or ""
    )
    if not file_path or not function:
        return None
    return file_path, function


def fail_open_binding(finding: dict[str, Any]) -> str | None:
    """The finding's claim text when it reads as a fail-open /
    swallowed-error hypothesis, else ``None`` (no binding, no
    dispatch)."""
    text = _finding_claim_text(finding)
    if not text:
        return None
    from core.audit.fail_open_verify import is_fail_open_hypothesis
    return text if is_fail_open_hypothesis(text) else None


def check_finding(
    finding: dict[str, Any],
    target: Path,
    *,
    out_dir: Path | None = None,
    inventory: dict[str, Any] | None = None,
) -> Any | None:
    """Adjudicate one finding through the channel. Returns the
    ``FailOpenResult`` or ``None`` when the finding doesn't bind
    (no fail-open-shaped claim, or no file/function coordinates).

    ``out_dir`` feeds the learned-vocabulary surfaces (annotations,
    domain model, IRIS specs, discovered sinks) into role binding —
    the same RoleContext the /audit dispatch builds.
    """
    hypothesis = fail_open_binding(finding)
    coords = _finding_coords(finding)
    if hypothesis is None or coords is None:
        return None
    file_path, function = coords
    from core.audit.fail_open_roles import RoleContext
    from core.audit.fail_open_verify import run_fail_open_check
    return run_fail_open_check(
        Path(target),
        file_path,
        function,
        hypothesis,
        inventory=inventory,
        role_context=RoleContext(
            out_dir=Path(out_dir) if out_dir else None,
            inventory=inventory,
        ),
    )


def adjudicate_finding(
    finding: dict[str, Any],
    target: Path,
    *,
    out_dir: Path | None = None,
    inventory: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """/agentic pre-LLM adjudicator: the channel receipt dict for a
    ``refuted`` or ``confirmed`` verdict, else ``None``.

    The receipt is ``FailOpenResult.to_dict()`` — outcome, reason,
    rule id, language, and the role/handler/fallibility/site receipts
    — so the skip (or corroboration) is explicit and reviewable.
    """
    result = check_finding(
        finding, target, out_dir=out_dir, inventory=inventory,
    )
    if result is None or result.outcome not in ("refuted", "confirmed"):
        return None
    return result.to_dict()


__all__ = [
    "FAIL_OPEN_CHANNEL_CAP",
    "adjudicate_finding",
    "check_finding",
    "fail_open_binding",
]

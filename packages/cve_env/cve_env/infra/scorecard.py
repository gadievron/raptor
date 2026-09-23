"""Scorecard feed for environment builds.

SIBLING MODULE: ``cve_diff/infra/scorecard.py`` — the discovery-side
feed with the same no-record policy over ``core/llm/scorecard``. A
feed-policy fix here usually applies there.

Records one ``TOOL_EVIDENCE`` observation per adjudicated build onto
the ``(model, "cve-env:build")`` cell of RAPTOR's model scorecard
(``core/llm/scorecard``). Adjudication is mechanical: the verify DAG
(container status / version-assertion exec_check / functional smoke /
payload probes) is the oracle —

  * verify passed (``success`` / ``verified_partial``) → ``correct``
  * verify ran and refuted the build (``verify_failed``) → ``incorrect``
  * everything else (unresolvable, budget/turn caps, interruption,
    rate limiting, launched-without-verify, errors) → NO record —
    those are infrastructure or no-oracle outcomes, and recording them
    would poison the reliability cells (the cve-diff precedent).

The feed is invoked only by the RAPTOR shim (``libexec/raptor-cve-env``)
after a build run — ``bin/cve-env`` (the operator facade) and the bench
never write the operator's scorecard sidecar as a side effect.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover — type-only import
    from core.llm.scorecard.scorecard import ModelScorecard

logger = logging.getLogger(__name__)

DECISION_CLASS = "cve-env:build"
#: Operator-described (--describe) builds are a WEAKER oracle than
#: CVE-pinned ones (the verify plan asserts only what the operator
#: described) — a separate decision class keeps their reliability
#: stats from inflating or diluting the CVE-build cell.
DECISION_CLASS_DESCRIBED = "cve-env:build-described"

# status → outcome. Absent statuses record nothing.
_ADJUDICATION: dict[str, str] = {
    "success": "correct",
    "verified_partial": "correct",
    "success_partial": "correct",   # legacy alias
    "verify_failed": "incorrect",
    "no_verify_pass": "incorrect",  # legacy alias
}


def _default_scorecard() -> ModelScorecard:
    """Resolve the shared scorecard sidecar through the shared
    resolver (RAPTOR_SCORECARD_PATH override, then RAPTOR_DIR/out,
    then bare) — see ``core/llm/scorecard/paths.py``."""
    from core.llm.scorecard.paths import default_scorecard_path
    from core.llm.scorecard.scorecard import ModelScorecard

    return ModelScorecard(default_scorecard_path())


def record_build_outcome(
    model_id: str,
    cve_id: str,
    status: str,
    *,
    scorecard: ModelScorecard | None = None,
) -> bool:
    """Record one adjudicated build. Never raises.

    Returns True when an event was recorded; False on skip (no model,
    non-verdict status) or scorecard I/O trouble — telemetry must never
    change a run's result.
    """
    outcome = _ADJUDICATION.get(status)
    if not model_id or outcome is None:
        return False
    try:
        from core.llm.scorecard.scorecard import EventType

        sc = scorecard if scorecard is not None else _default_scorecard()
        decision_class = (DECISION_CLASS_DESCRIBED
                          if cve_id.startswith("DESC-")
                          else DECISION_CLASS)
        sc.record_event(decision_class, model_id, EventType.TOOL_EVIDENCE, outcome)
        return True
    except Exception:  # noqa: BLE001 — telemetry must never break the run
        logger.debug(
            "scorecard: build outcome record failed for %s", cve_id, exc_info=True,
        )
        return False

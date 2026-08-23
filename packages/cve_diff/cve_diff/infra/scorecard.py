"""Scorecard feed for the discovery agent.

Records one ``TOOL_EVIDENCE`` observation per adjudicated discovery
pick onto the ``(model, "cve-diff:discovery")`` cell of RAPTOR's
model scorecard (``core/llm/scorecard``). Adjudication is mechanical,
not model-graded: stages 2-5 of the pipeline (acquire → resolve →
diff → shape check) verify the submitted ``(repo, sha)`` by actually
cloning and diffing it —

  * the pick survives extraction        → ``correct``
  * the pick is refuted by those stages → ``incorrect``

Transient failures (network, rate limits) are NOT recorded — only
verdict-shaped refutations (see ``Pipeline.run``'s classification),
so infrastructure noise never poisons the reliability cells.

The feed is opt-in from the entry points (``Pipeline.scorecard_enabled``)
so library callers, the bench, and unit tests never write to the
operator's scorecard sidecar as a side effect.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover — type-only import
    from core.llm.scorecard.scorecard import ModelScorecard

logger = logging.getLogger(__name__)

DECISION_CLASS = "cve-diff:discovery"


def _default_scorecard() -> ModelScorecard:
    """Resolve the shared scorecard sidecar.

    Same convention as ``core/llm/scorecard/tool_evidence.py``:
    ``RAPTOR_SCORECARD_PATH`` override first (tests, sandboxed runs),
    then ``RAPTOR_DIR/out/llm_scorecard.json`` so a run started from
    any cwd writes to the sidecar the rest of RAPTOR reads, then a
    bare relative default.
    """
    from core.llm.scorecard.scorecard import ModelScorecard

    override = os.environ.get("RAPTOR_SCORECARD_PATH")
    if override:
        return ModelScorecard(Path(override))
    raptor_dir = os.environ.get("RAPTOR_DIR")
    if raptor_dir:
        return ModelScorecard(Path(raptor_dir) / "out" / "llm_scorecard.json")
    return ModelScorecard(Path("out/llm_scorecard.json"))


def record_discovery_outcome(
    model_id: str,
    cve_id: str,
    *,
    verified: bool,
    scorecard: ModelScorecard | None = None,
) -> bool:
    """Record one adjudicated discovery pick. Never raises.

    Returns True when an event was recorded, False on skip (no model)
    or scorecard I/O trouble — the pipeline result must never depend
    on telemetry succeeding.
    """
    if not model_id:
        return False
    try:
        from core.llm.scorecard.scorecard import EventType

        sc = scorecard if scorecard is not None else _default_scorecard()
        sc.record_event(
            DECISION_CLASS,
            model_id,
            EventType.TOOL_EVIDENCE,
            "correct" if verified else "incorrect",
        )
        return True
    except Exception:  # noqa: BLE001 — telemetry must never break the pipeline
        logger.debug(
            "scorecard: discovery outcome record failed for %s",
            cve_id, exc_info=True,
        )
        return False

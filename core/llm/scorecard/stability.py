"""Producer wiring for ``EventType.CROSS_RUN_STABILITY``.

Compares the current run's per-finding verdicts against the most
recent prior agentic run on the same target.  For each finding
analysed in both runs by the same model:

  * Same normalised verdict → ``correct``
  * Different normalised verdict → ``incorrect``

This captures model reliability across runs — a model that flips
on the same finding under identical conditions is less trustworthy
than one that holds steady.

Prior run discovery is lightweight: scan sibling directories for
the newest completed agentic run with the same target path.
"""

from __future__ import annotations

import logging
from typing import Any, TYPE_CHECKING

from . import _MAX_REASONING_CHARS
from .scorecard import EventType, ModelScorecard

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


def _find_prior_run(out_dir: Path) -> Path | None:
    """Find the most recent completed agentic sibling run.

    Scans ``out_dir.parent`` for directories matching ``agentic_*``,
    sorted reverse-lexicographic (timestamp in the name gives
    newest-first ordering).  Returns the first that:

    * is not ``out_dir`` itself
    * has ``.raptor-run.json`` with ``status == "completed"``
      and ``command == "agentic"``
    * has ``orchestrated_report.json``

    Returns None when no qualifying prior run exists.
    """
    parent = out_dir.parent
    if not parent.is_dir():
        return None

    from core.run import load_run_metadata

    candidates = sorted(parent.glob("agentic_*"), reverse=True)
    for candidate in candidates:
        if not candidate.is_dir():
            continue
        if candidate.resolve() == out_dir.resolve():
            continue
        meta = load_run_metadata(candidate)
        if meta is None:
            continue
        if meta.get("status") != "completed":
            continue
        if meta.get("command") != "agentic":
            continue
        if not (candidate / "orchestrated_report.json").is_file():
            continue
        return candidate
    return None


def _targets_match(current_dir: Path, prior_dir: Path) -> bool:
    """Check that both runs targeted the same codebase."""
    from core.run import load_run_metadata

    current_meta = load_run_metadata(current_dir)
    prior_meta = load_run_metadata(prior_dir)
    if current_meta is None or prior_meta is None:
        return False
    current_target = current_meta.get("target") or ""
    prior_target = prior_meta.get("target") or ""
    if not current_target or not prior_target:
        return False
    return current_target == prior_target


def record_cross_run_stability(
    scorecard: ModelScorecard | None,
    *,
    out_dir: Path,
    results_by_id: dict[str, dict[str, Any]],
    decision_class_prefix: str = "agentic",
) -> int:
    """Compare current verdicts against the prior run and record
    stability events.

    Returns the number of events recorded (0 when no prior run
    exists, targets differ, or no overlapping analysed findings).
    """
    if scorecard is None:
        return 0

    prior_dir = _find_prior_run(out_dir)
    if prior_dir is None:
        return 0

    if not _targets_match(out_dir, prior_dir):
        logger.debug(
            "cross-run stability: targets differ (%s vs %s), skipping",
            out_dir.name, prior_dir.name,
        )
        return 0

    from core.json import load_json
    from core.project.correlate import get_finding_status, normalize_verdict

    prior_report = load_json(prior_dir / "orchestrated_report.json")
    if prior_report is None:
        return 0
    prior_results = prior_report.get("results") or []

    # Keyed by finding id, value = (verdict, analysed-by model). The
    # producer measures whether ONE model holds its verdict across
    # runs — comparing against a prior verdict from a different model
    # would book cross-model disagreement as this model's instability.
    prior_verdicts: dict[str, tuple[str, str]] = {}
    for pf in prior_results:
        fid = pf.get("finding_id")
        if fid is None:
            continue
        prior_model = str(pf.get("analysed_by") or "")
        if not prior_model:
            # Unattributed prior verdict: it can't be matched to the
            # current model, so it yields no stability signal.
            continue
        status = get_finding_status(pf)
        normalised = normalize_verdict(status)
        if normalised != "unknown":
            prior_verdicts[fid] = (normalised, prior_model)

    if not prior_verdicts:
        return 0

    n_recorded = 0
    for fid, result in results_by_id.items():
        if result.get("is_exploitable") is None:
            continue

        prior_entry = prior_verdicts.get(fid)
        if prior_entry is None:
            continue
        prior_verdict, prior_model = prior_entry

        model = str(result.get("analysed_by") or "")
        if not model:
            continue
        if model != prior_model:
            # A different model produced the prior verdict. A flip
            # between two models is cross-model disagreement, not this
            # model's cross-run instability — record nothing.
            continue

        current_status = get_finding_status(result)
        current_verdict = normalize_verdict(current_status)
        if current_verdict == "unknown":
            continue

        stable = current_verdict == prior_verdict
        outcome = "correct" if stable else "incorrect"

        rule_id = str(result.get("rule_id") or "unknown")
        decision_class = f"{decision_class_prefix}:{rule_id}"
        model_version = result.get("resolved_model")

        sample = None
        if not stable:
            reasoning = str(result.get("reasoning") or "")
            sample = {
                "this_verdict": current_verdict,
                "prior_verdict": prior_verdict,
                "this_reasoning": reasoning[:_MAX_REASONING_CHARS],
            }

        try:
            scorecard.record_event(
                decision_class,
                model,
                EventType.CROSS_RUN_STABILITY,
                outcome,
                model_version=model_version,
                sample=sample,
            )
            n_recorded += 1
        except Exception:
            logger.warning(
                "cross-run stability: record_event failed for %s",
                fid, exc_info=True,
            )

    return n_recorded

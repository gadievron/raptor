"""Producer for ``EventType.CROSS_FAMILY_CONSISTENCY``.

When a finding triggers a cross-family re-analysis (different model
family from the primary), the checker either agrees or disputes.
Records one consistency event per cross-family-checked finding:

  * Checker agreed with primary → ``correct`` (consistent pair)
  * Checker disputed primary → ``incorrect`` (unresolved dispute)

This is an observability axis, NOT a correctness verdict: the pair is
1-vs-1 with no ground truth, so a dispute never establishes which side
was wrong (same reasoning as the consensus producer's even-split
skip). The event type is therefore kept out of the correctness-graded
reliability pools — recording it under a reliability-pooled type would
let mere disagreement penalise dissent and reward agreeing with the
primary.

Skips findings where the checker fell back to the same family
(no independent signal).
"""

from __future__ import annotations

import logging
from typing import Any

from . import _MAX_REASONING_CHARS
from ._batch import record_event_batch
from .scorecard import EventType, ModelScorecard

logger = logging.getLogger(__name__)


def record_cross_family_outcomes(
    scorecard: ModelScorecard | None,
    *,
    results_by_id: dict[str, dict[str, Any]],
    decision_class_prefix: str = "agentic",
) -> int:
    """Record cross-family check outcomes on the scorecard.

    Returns the number of events recorded.
    """
    if scorecard is None:
        return 0

    pending: list[dict] = []
    for fid, result in results_by_id.items():
        cf = result.get("cross_family_check")
        if not isinstance(cf, dict):
            continue

        # `or ""` (not a .get default): a present-but-None verdict —
        # e.g. a checker that errored out upstream — must degrade to
        # a skip, not AttributeError the walk and drop every
        # remaining finding's event.
        verdict = str(cf.get("verdict") or "")
        if verdict.startswith("skipped"):
            continue

        checker_model = cf.get("checker_model")
        if not checker_model:
            continue

        # Derive agreed/disputed from the verdict string; the
        # separate top-level boolean flags are set by a different
        # code path and can fall out of sync — an out-of-sync True
        # flag must never mint ``correct`` past a present-but-unknown
        # verdict (the flag pre-empted the grammar here once). The
        # flag remains only as the backstop for legacy records that
        # carry no verdict string at all. Either way the event is a
        # consistency observation: with one primary and one checker a
        # dispute is an even split with no ground truth, so neither
        # side earns a correctness attribution from it.
        #
        # Prefix-anchored matching against the producer's exact
        # grammar ({"skipped — …", "disputed — conservative override",
        # "agreed"}): a bare substring test read any future
        # "disagreed" verdict as agreement.
        if verdict.startswith("disputed"):
            outcome = "incorrect"
        elif verdict.startswith("agreed"):
            outcome = "correct"
        elif not verdict and result.get("cross_family_agreed"):
            outcome = "correct"
        else:
            continue

        rule_id = str(result.get("rule_id") or "unknown")
        decision_class = f"{decision_class_prefix}:{rule_id}"
        # model_version is the CONCRETE served snapshot per the family
        # convention (consensus.py) — "None when unavailable so the
        # cell stays alias-keyed, never guessed". The check record
        # carries no resolved_model, and stamping the checker ALIAS
        # here made the cell lie about its snapshot and polluted
        # cross-event model_version drift comparisons.
        model_version = None

        sample = None
        if outcome == "incorrect":
            sample = {
                # str-coerced like every sibling field: an upstream
                # list/dict in this slot must persist as one flat
                # string, not smuggle nested values into the sample.
                "trigger": str(cf.get("trigger") or ""),
                "checker_ruling": str(
                    cf.get("checker_ruling", "")
                )[:_MAX_REASONING_CHARS],
            }

        pending.append({
            "decision_class": decision_class,
            "model": str(checker_model),
            "event_type": EventType.CROSS_FAMILY_CONSISTENCY,
            "outcome": outcome,
            "model_version": model_version,
            "sample": sample,
        })

    # One lock/load/verify/rewrite cycle for the whole walk instead of
    # one per event (see _batch's rationale).
    return record_event_batch(
        scorecard, pending, log=logger, producer="cross-family check",
    )

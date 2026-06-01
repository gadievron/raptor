"""Orchestration-result funnel classification.

Pure-data helper used by the ``/agentic`` console summary (via
``raptor_agentic.main``) and available to any future consumer that
needs to bucket a list of per-finding LLM dispatch results.

Lives here rather than inline in ``raptor_agentic.py`` so the
classification can be unit-tested without pulling in the
``raptor_agentic`` module's transitive imports (every ``core.*`` and
``packages.*`` it touches), and so report writers / dashboards can
reuse the same bucketing logic.
"""

from __future__ import annotations

from typing import Any


def bucket_orchestration_results(results: list[dict]) -> dict[str, Any]:
    """Classify orchestration results into funnel counts.

    Splits ``is_true_positive`` into three buckets:

    * ``True``  → ``true_positives``
    * ``False`` → ``false_positives`` (also tracked in
      ``severity_mismatches`` when scanner level == ``"error"``)
    * any other value, most commonly ``None`` from a q<0.5 empty
      ``cc_dispatch`` response → ``unverdicted``

    Pre-fix the inline loop in ``raptor_agentic`` treated everything
    except ``False`` as a true positive, so a per-finding LLM call that
    returned ``is_true_positive: None`` was silently counted as a
    confirmed finding — masking total dispatch failure behind a
    successful-looking funnel (gh #549).

    Errored / blocked items are counted separately and skip the
    verdict-classification path entirely; results without the
    ``is_true_positive`` key at all are not counted (pre-existing
    "not analysed" semantics preserved).

    Self-contradictory findings (where ``check_self_consistency`` in
    ``packages/llm_analysis/validation.py`` flagged the LLM's structured
    fields or reasoning text as internally inconsistent post-retry) are
    EXCLUDED from ``exploitable`` and counted in ``inconsistent``
    instead. Pre-fix the same finding could appear in both buckets, so
    the headline "Exploitable: N" disagreed with the per-finding table's
    "X Exploitable, Y FP" totals in the same output — an accounting bug
    visible to anyone reading the report carefully.

    Returns a dict with keys:
      - ``true_positives``    (int)
      - ``false_positives``   (int)
      - ``unverdicted``       (int)
      - ``exploitable``       (int — excludes ``inconsistent``)
      - ``inconsistent``      (int — self_contradictory verdicts needing
        human review; never overlaps with ``exploitable``)
      - ``failed``            (int)
      - ``blocked``           (int)
      - ``severity_mismatches`` (list[dict] — full result dicts for
        scanner-error findings the LLM ruled false-positive; the
        caller surfaces these for review)
      - ``inconsistent_findings`` (list[dict] — full result dicts for
        the ``inconsistent`` bucket above so callers can render the
        per-finding list operator-side without re-filtering)
    """
    buckets: dict[str, Any] = {
        "true_positives": 0,
        "false_positives": 0,
        "unverdicted": 0,
        "exploitable": 0,
        "inconsistent": 0,
        "failed": 0,
        "blocked": 0,
        "severity_mismatches": [],
        "inconsistent_findings": [],
    }
    for r in results:
        if "error" in r:
            if r.get("error_type") == "blocked":
                buckets["blocked"] += 1
            else:
                buckets["failed"] += 1
            continue
        if "is_true_positive" not in r:
            continue
        verdict = r.get("is_true_positive")
        if verdict is True:
            buckets["true_positives"] += 1
        elif verdict is False:
            buckets["false_positives"] += 1
            if r.get("level") == "error":
                buckets["severity_mismatches"].append(r)
        else:
            buckets["unverdicted"] += 1
        if r.get("is_exploitable"):
            if r.get("self_contradictory"):
                buckets["inconsistent"] += 1
                buckets["inconsistent_findings"].append(r)
            else:
                buckets["exploitable"] += 1
    return buckets

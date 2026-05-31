"""Freshness-weighting core for the model scorecard.

The scorecard accumulates correct/incorrect counts per
``(model, decision_class, event_type)``. To let a model's *recent* reliability
dominate its stale history — model aliases float behind unchanged names
(notably Gemini, which exposes no version signal at all), so a cell silently
blends reliability across whatever versions the provider served over time — the
counts are stratified into **monthly age buckets** and weighted by an
exponential decay at *read* time. Read-time means the half-life can be set
conservatively now and re-tuned once real drift data exists, without reprocessing
(an EMA baked at write time could not).

This module is pure: no I/O, no scorecard state. ``scorecard.py`` wires these
into the bucketed ``events`` shape and the Wilson verdict. ``half_life_days``
of ``None``/``<=0`` means decay is DISABLED — every bucket counts fully, which
is exactly the pre-freshness behaviour (back-compat by construction).

Bucket key format: ``"YYYY-MM"``. Age is measured from the bucket's first day.
See ``~/design/scorecard-model-versioning.md``.
"""
from __future__ import annotations

from datetime import datetime
from typing import Mapping, Tuple, Union

# A very large age (days) assigned to an unparseable bucket key so it decays to
# ~0 under any positive half-life rather than raising. Defensive: a hand-edited
# or corrupt key must never crash the verdict path.
_UNPARSEABLE_AGE_DAYS = 1.0e9

# Mean Gregorian month length — converts whole-month bucket differences to days
# so the half-life (expressed in days) applies uniformly.
_MEAN_MONTH_DAYS = 30.44


def bucket_key(when: Union[str, datetime]) -> str:
    """Return the ``"YYYY-MM"`` bucket for an ISO-8601 timestamp or datetime.

    A bare ``str`` is parsed as ISO-8601; anything unparseable falls back to
    its first 7 chars if they look like ``YYYY-MM`` (ISO timestamps start that
    way), else raises ``ValueError`` (callers pass ``_now_iso()`` output, which
    is always well-formed).
    """
    if isinstance(when, datetime):
        dt = when
    else:
        try:
            dt = datetime.fromisoformat(when)
        except (ValueError, TypeError):
            s = str(when)
            if len(s) >= 7 and s[4] == "-" and s[:4].isdigit() and s[5:7].isdigit():
                return s[:7]
            raise ValueError(f"unparseable timestamp for bucket_key: {when!r}")
    return f"{dt.year:04d}-{dt.month:02d}"


def bucket_age_days(bucket: str, now: datetime) -> float:
    """Age in days of a ``"YYYY-MM"`` bucket relative to ``now``, computed as the
    whole-month difference × the mean month length — so the *current* month is
    age 0 (fully weighted) and last month ≈ 30 days. Floored at 0 (future
    buckets → 0). Unparseable → a huge age so it decays away rather than
    crashing the verdict path."""
    try:
        year_s, month_s = bucket.split("-", 1)
        by, bm = int(year_s), int(month_s)
    except (ValueError, IndexError):
        return _UNPARSEABLE_AGE_DAYS
    months = (now.year - by) * 12 + (now.month - bm)
    if months <= 0:
        return 0.0
    return months * _MEAN_MONTH_DAYS


def decay_weight(age_days: float, half_life_days: Union[float, None]) -> float:
    """Exponential decay ``0.5 ** (age_days / half_life_days)``.

    ``half_life_days`` of ``None`` or ``<= 0`` disables decay (returns 1.0):
    every bucket counts fully, i.e. the pre-freshness behaviour.
    """
    if not half_life_days or half_life_days <= 0:
        return 1.0
    if age_days <= 0:
        return 1.0
    return 0.5 ** (age_days / half_life_days)


def flatten_counts(
    buckets: Mapping[str, object],
) -> Tuple[int, int]:
    """Sum ``(correct, incorrect)`` across all buckets, unweighted. The
    decay-disabled / back-compat read path. Defensive: a flat v1-shaped
    ``{"correct", "incorrect"}`` that slips past migration is returned as-is
    (treated as a single bucket) rather than crashing."""
    if not is_bucketed(buckets):
        return int(buckets.get("correct", 0)), int(buckets.get("incorrect", 0))
    correct = 0
    incorrect = 0
    for counts in buckets.values():
        correct += int(counts.get("correct", 0))
        incorrect += int(counts.get("incorrect", 0))
    return correct, incorrect


def weighted_counts(
    buckets: Mapping[str, Mapping[str, int]],
    half_life_days: Union[float, None],
    now: datetime,
) -> Tuple[float, float]:
    """Decay-weighted ``(correct, incorrect)`` sums over age buckets.

    With ``half_life_days`` None/<=0 this equals :func:`flatten_counts` (every
    weight is 1.0), so the verdict path is identical to today when decay is off.
    Returns floats — Wilson's interval is valid for a fractional effective
    sample size.
    """
    if not half_life_days or half_life_days <= 0 or not is_bucketed(buckets):
        # Decay disabled, or a flat (ageless) entry → no decay possible.
        c, i = flatten_counts(buckets)
        return float(c), float(i)
    correct = 0.0
    incorrect = 0.0
    for bucket, counts in buckets.items():
        w = decay_weight(bucket_age_days(bucket, now), half_life_days)
        correct += w * int(counts.get("correct", 0))
        incorrect += w * int(counts.get("incorrect", 0))
    return correct, incorrect


def is_bucketed(event_counts: Mapping[str, object]) -> bool:
    """True if an event-type entry is the v2 bucketed shape
    (``{"YYYY-MM": {...}}``) rather than the v1 flat
    ``{"correct": int, "incorrect": int}``. Used by the migration."""
    if not event_counts:
        return True  # empty {} is a valid (empty) bucketed shape
    return "correct" not in event_counts and "incorrect" not in event_counts

"""Threshold-free ranking metrics for precision harnesses.

Home for dependency-free score-vs-label primitives shared by the
measurement harnesses (``binary_oracle_precision``,
``sanitizer_cut_precision``, corpus drivers). These evaluate how well a
scalar score *ranks* positives above negatives without committing to a
threshold, which is the right question when comparing candidate metrics
head-to-head.
"""

from __future__ import annotations

from collections.abc import Sequence


def auc(scored: Sequence[tuple[float, bool]]) -> float | None:
    """Area under the ROC curve via the Mann-Whitney statistic, tie-aware.

    ``scored`` is a sequence of ``(score, is_positive)`` pairs. The
    result is P(a uniformly random positive outranks a uniformly random
    negative), with ties counted half — 0.5 is chance, 1.0 is perfect
    separation, 0.0 is perfectly inverted. Returns ``None`` when either
    class is empty (AUC is undefined, not zero).
    When both classes are present, NaN scores raise ``ValueError``.

    Tie-aware: tied scores receive their average rank, so a constant
    score yields exactly 0.5 rather than an order-dependent artefact.
    Dependency-free by design — no NumPy/SciPy.
    """
    pairs = list(scored)
    n_pos = sum(1 for _, lab in pairs if lab)
    n_neg = len(pairs) - n_pos
    if n_pos == 0 or n_neg == 0:
        return None
    if any(score != score for score, _ in pairs):
        raise ValueError("AUC cannot rank NaN scores")
    order = sorted(range(len(pairs)), key=lambda i: pairs[i][0])
    ranks = [0.0] * len(pairs)
    i = 0
    while i < len(order):
        j = i
        while j < len(order) and pairs[order[j]][0] == pairs[order[i]][0]:
            j += 1
        avg_rank = (i + j - 1) / 2.0 + 1.0          # 1-based average rank
        for k in range(i, j):
            ranks[order[k]] = avg_rank
        i = j
    sum_ranks_pos = sum(ranks[k] for k in range(len(pairs)) if pairs[k][1])
    return (sum_ranks_pos - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


__all__ = ["auc"]

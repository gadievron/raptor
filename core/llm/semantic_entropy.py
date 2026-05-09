"""Semantic-entropy / reasoning-divergence math for multi-model panels.

Detects when N models on the same finding agreed on the verdict but
their reasoning text diverges substantially — i.e. they landed on the
same answer for noticeably different reasons. Crude proxy for the
``semantic entropy'' approach (Farquhar et al., Nature 2024) using
token-set Jaccard distance over reasoning text rather than
NLI-clustered samples.

The module is intentionally pure-Python and dependency-free. No
numpy, no sentence-transformers, no provider embedding API calls.
The cost of the upgrade path is one new dependency once we have
evidence the signal is worth investing in. See the
``project_semantic_entropy`` memory for that decision.

Why Jaccard on token sets and not TF-IDF cosine or sentence
embeddings:
    * The signal we want is divergent *substance*: different sinks,
      different CWE classes, different identifiers. "Did they cite
      the same things?" is fundamentally a set-membership question,
      not a frequency one.
    * TF-IDF on small panels (N=3) is unstable: rare terms in any
      single doc dominate IDF and inflate distances even when the
      panel is aligned on substance. Empirically gave ~0.41 distance
      on aligned reasoning vs ~0.42 on fully divergent — useless.
    * Sentence embeddings tend to rate any two pieces of "security
      analysis prose" as similar because their high-level register
      matches, even when they describe different bugs. That is the
      *opposite* of the discrimination we want.
    * Jaccard is free, local, no model download, no PII concerns.

Known limitation — tokenisation is ASCII-biased. ``re.compile(r"\\w+")``
does match Unicode word characters in Python 3, but for scripts
without word separators (Chinese, Japanese, Thai) a whole phrase
collapses to a single token, killing Jaccard discrimination.
Acceptable for English-language codebases and English LLM outputs;
international consumers need a script-aware tokeniser before relying
on this metric.

Public API:
    divergence(reasonings) -> Optional[Dict]
        Compute pairwise dispersion + per-model outlier scores.
        Returns None when the panel is too small or the inputs are
        too short for the metric to be meaningful — callers should
        treat None as "no signal", not "no divergence".
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set


_TOKEN_RE = re.compile(r"\w+")

# Per-string floor. Jaccard on a handful of words is statistical
# noise — the token set is too small for overlap ratios to mean
# anything. 50 chars is roughly one short sentence; below that
# we'd rather emit no signal than a misleading one.
_DEFAULT_MIN_CHARS = 50

# Minimum panel size. With two models we get one pairwise distance
# but no "outlier vs rest" structure (each model is equidistant
# from the other by construction). Outlier detection needs at least
# three points.
_DEFAULT_MIN_MODELS = 3

# Minimum token-set size after tokenisation. Below this Jaccard
# overlap is dominated by chance — a single shared-or-not stop word
# flips the distance by tens of percent. Mirrors the per-string
# char floor at the post-tokenisation stage.
_MIN_TOKENS_PER_DOC = 8


def _tokenize(text: str) -> Set[str]:
    """Lowercase, regex-extract word tokens, dedupe.

    No stem, no stopword removal. For technical security text the
    "stop words" we care about are the bug-class identifiers and
    function names that overlap (or don't) between models — ordinary
    English filler ("the", "a", "is") shows up in every doc and
    contributes equally to numerator and denominator of Jaccard, so
    its effect on the ratio is small.
    """
    return set(_TOKEN_RE.findall(text.lower()))


def _jaccard_distance(a: Set[str], b: Set[str]) -> float:
    """Jaccard distance: ``1 - |a ∩ b| / |a ∪ b|``. Range ``[0, 1]``.

    Two empty sets are considered identical (distance 0). One empty
    plus one non-empty is orthogonal (distance 1).
    """
    if not a and not b:
        return 0.0
    union = a | b
    if not union:
        return 0.0
    return 1.0 - len(a & b) / len(union)


def divergence(
    reasonings: Dict[str, str],
    *,
    min_chars: int = _DEFAULT_MIN_CHARS,
    min_models: int = _DEFAULT_MIN_MODELS,
) -> Optional[Dict[str, object]]:
    """Compute reasoning divergence over a multi-model panel.

    Args:
        reasonings: Mapping ``{model_name: reasoning_text}``. Models
            with empty / whitespace-only / too-short text are filtered
            out before measurement.
        min_chars: Per-string floor; reasoning shorter than this is
            dropped. See ``_DEFAULT_MIN_CHARS``.
        min_models: Minimum surviving panel size after filtering.
            Below this, returns ``None``. See ``_DEFAULT_MIN_MODELS``.

    Returns:
        ``None`` when the panel is too small, the texts are too short,
        or any surviving model's token set is too sparse for Jaccard
        to be meaningful. Caller must treat ``None`` as "no signal",
        not "no divergence".

        Otherwise a dict with:

        * ``mean_pairwise_distance`` — arithmetic mean of all pairwise
          Jaccard distances. Range ``[0, 1]``. Higher = more
          dispersed panel overall.
        * ``max_pairwise_distance`` — largest pairwise Jaccard distance
          between any two models. Range ``[0, 1]``.
        * ``outlier_model`` — model whose mean distance to peers is
          highest. The first candidate to attain the max wins
          (deterministic by sort order).
        * ``per_model_distance`` — ``{model: mean_distance_to_peers}``
          for every surviving model.
        * ``n_models`` — number of surviving models the metric was
          computed over. May be smaller than ``len(reasonings)``.
    """
    valid = {
        m: r for m, r in reasonings.items()
        if isinstance(r, str) and len(r.strip()) >= min_chars
    }
    if len(valid) < min_models:
        return None

    models = sorted(valid)
    token_sets = [_tokenize(valid[m]) for m in models]
    if any(len(ts) < _MIN_TOKENS_PER_DOC for ts in token_sets):
        return None

    n = len(models)
    pairwise: List[List[float]] = [[0.0] * n for _ in range(n)]
    distances: List[float] = []
    for i in range(n):
        for j in range(i + 1, n):
            d = _jaccard_distance(token_sets[i], token_sets[j])
            pairwise[i][j] = d
            pairwise[j][i] = d
            distances.append(d)

    # Per-model: mean distance to all OTHER models on the panel.
    # Self-distance is excluded (would dilute toward 0).
    per_model: Dict[str, float] = {}
    for i, m in enumerate(models):
        peer_distances = [pairwise[i][j] for j in range(n) if j != i]
        per_model[m] = sum(peer_distances) / len(peer_distances)

    # Iteration order on per_model matches `models = sorted(valid)`
    # because Python dicts preserve insertion order. ``max`` keeps the
    # first element it sees that ties the running max — so ties resolve
    # to the alphabetically-first name, matching the docstring's
    # "first candidate to attain the max wins (deterministic by sort
    # order)" promise. Don't add a secondary key like ``(distance, m)``
    # — that flips the tiebreak to alphabetically-LAST.
    outlier = max(per_model, key=lambda m: per_model[m])
    mean_pairwise = sum(distances) / len(distances) if distances else 0.0
    max_pairwise = max(distances) if distances else 0.0

    return {
        "mean_pairwise_distance": mean_pairwise,
        "max_pairwise_distance": max_pairwise,
        "outlier_model": outlier,
        "per_model_distance": per_model,
        "n_models": n,
    }


def pairwise_distance(
    a: str,
    b: str,
    *,
    min_chars: int = _DEFAULT_MIN_CHARS,
) -> Optional[float]:
    """Jaccard distance between two reasoning strings.

    The N=2 specialisation of :func:`divergence`. Use this from
    consumers that always have exactly two reasonings to compare
    (e.g. the cross-family checker: primary model's reasoning vs
    cross-family checker's reasoning). With N=2 the
    "outlier vs panel" structure that :func:`divergence` returns is
    meaningless — each input is the outlier of the other — so we
    just return the scalar distance.

    Args:
        a, b: Reasoning strings. Either being shorter than
            ``min_chars`` causes the function to return ``None``
            (signal-free inputs are treated as "no measurement",
            consistent with :func:`divergence`).
        min_chars: Per-string floor. See ``_DEFAULT_MIN_CHARS``.

    Returns:
        ``None`` when either input is too short or its token set is
        too sparse for Jaccard to be meaningful. Caller must treat
        ``None`` as "no signal", not "no divergence".

        Otherwise a float in ``[0, 1]``: 0 = identical token sets,
        1 = completely disjoint vocabularies.
    """
    if not isinstance(a, str) or not isinstance(b, str):
        return None
    if len(a.strip()) < min_chars or len(b.strip()) < min_chars:
        return None
    set_a = _tokenize(a)
    set_b = _tokenize(b)
    if (len(set_a) < _MIN_TOKENS_PER_DOC
            or len(set_b) < _MIN_TOKENS_PER_DOC):
        return None
    return _jaccard_distance(set_a, set_b)


__all__ = ["divergence", "pairwise_distance"]

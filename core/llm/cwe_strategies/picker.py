"""Mechanical strategy picking from function signals.

Given a target function (file path, name, includes, calls made, and
known CWEs), score every loaded strategy and return the top N.
The ``general`` strategy is always included by default — it's the
trust/assumption baseline that fits everything; specialised
strategies layer on top.

Scoring is **specificity-weighted**: each match contributes
``len(matched_token)`` points. ``fs/splice.c`` (12 chars) outscores
``fs/`` (3 chars) for the same file path; this prevents a narrow,
purpose-built signal from being drowned by broad ones declared on
multiple strategies.

Five signal dimensions, in roughly descending strength:

  1. ``cwes`` — exact CWE id from upstream classifier. Direct
     evidence: if /agentic already classified the finding as CWE-78,
     ``input_handling`` should win automatically.
  2. ``function_calls`` — token-equality match against names of
     functions the target calls. The strongest mechanical signal
     — a function calling ``mutex_lock`` IS concurrency-relevant
     regardless of path or name.
  3. ``includes`` — substring match on the function's headers.
  4. ``paths`` — substring match on the file path.
  5. ``function_keywords`` — token match against components of the
     function name. Token semantics (split on ``_``/``-``) prevent
     ``parse`` from matching ``is_sparse_array``.

Matching is case-insensitive throughout. Only ``cwes`` and
``function_calls`` use exact-token equality; ``includes`` and
``paths`` use substring matching because operators write fragments
(``fs/``, ``linux/skbuff.h``) that are meant to match prefixes.

Caller's job: pass the function context they have. ``/audit``
Phase A's driver fills these from inventory metadata + tree-sitter
call graph + any /agentic-emitted finding CWEs.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Tuple

from .loader import load_all
from .models import Strategy

# Sentinel name for the always-on default strategy.
GENERAL = "general"

# Identifier-component splitter: any run of non-word characters.
# ``parse_packet-locked`` → {"parse", "packet", "locked"}.
_TOKEN_SPLIT = re.compile(r"[^a-zA-Z0-9]+")


def _tokenise(name: str) -> set[str]:
    """Split an identifier into lowercase token components.

    ``parse_packet`` → {"parse", "packet"}. Empty string + empty
    components are dropped so trailing ``_`` in a keyword (operator
    convention for "matches as a prefix") doesn't pollute the set.
    """
    if not name:
        return set()
    return {t.lower() for t in _TOKEN_SPLIT.split(name) if t}


def _path_score(file_path: str, paths: Iterable[str]) -> int:
    """Substring match (case-insensitive). Specificity-weighted.

    Path fragments (``fs/``, ``kernel/locking/``) are designed to
    match as prefixes / mid-path substrings, so substring match is
    correct here despite token semantics being applied to keyword
    fields.
    """
    if not file_path:
        return 0
    fp = file_path.lower()
    return sum(len(p) for p in paths if p and p.lower() in fp)


def _include_score(file_includes: Iterable[str], includes: Iterable[str]) -> int:
    """Exact include-name match (case-insensitive). Specificity-weighted."""
    targets = {i.lower() for i in file_includes if i}
    return sum(len(i) for i in includes if i and i.lower() in targets)


def _keyword_score(function_name: str, keywords: Iterable[str]) -> int:
    """Token-equality match against function-name components.

    ``parse`` matches ``parse_packet`` (token "parse" present) but
    NOT ``is_sparse_array`` (no standalone "parse" component). This
    is the bulk of the false-positive reduction over substring
    matching. Trailing ``_``/``-`` on operator-written keywords is
    stripped because it's a convention for "matches as a prefix" —
    that semantic is built into tokenisation already.
    """
    tokens = _tokenise(function_name)
    if not tokens:
        return 0
    score = 0
    for k in keywords:
        if not k:
            continue
        # Strip trailing separator chars; tokens never carry them.
        kl = k.lower().rstrip("_-")
        if not kl:
            continue
        if kl in tokens:
            score += len(kl)
    return score


def _call_score(
    function_calls_made: Iterable[str], strategy_calls: Iterable[str],
) -> int:
    """Exact-name match (case-insensitive) against the function's
    callees. Specificity-weighted by callee name length."""
    callees = {c.lower() for c in function_calls_made if c}
    if not callees:
        return 0
    return sum(len(c) for c in strategy_calls if c and c.lower() in callees)


def _cwe_score(
    candidate_cwes: Iterable[str], strategy_cwes: Iterable[str],
) -> int:
    """Exact CWE-id match. Heavy-weighted: a CWE hit is direct
    evidence and dominates fragmentary signal stacks.

    Each match contributes 100 points. Typical aggregate
    path+include+keyword scores sit around 20-50 chars; a CWE pin
    reliably outranks them. This is intentional — when an upstream
    classifier (a /agentic finding, a /understand sink type) tells
    us the bug class, we should weight that ahead of inferred
    heuristics."""
    have = {c.lower() for c in candidate_cwes if c}
    if not have:
        return 0
    return 100 * sum(1 for c in strategy_cwes if c and c.lower() in have)


def _score_strategy(
    strategy: Strategy,
    *,
    file_path: str,
    function_name: str,
    file_includes: Iterable[str],
    function_calls_made: Iterable[str],
    candidate_cwes: Iterable[str],
) -> int:
    """Combined score across all five signal dimensions."""
    s = strategy.signals
    return (
        _path_score(file_path, s.paths)
        + _include_score(file_includes, s.includes)
        + _keyword_score(function_name, s.function_keywords)
        + _call_score(function_calls_made, s.function_calls)
        + _cwe_score(candidate_cwes, s.cwes)
    )


def pick_strategies(
    *,
    file_path: str,
    function_name: str = "",
    file_includes: Iterable[str] = (),
    function_calls_made: Iterable[str] = (),
    candidate_cwes: Iterable[str] = (),
    strategies: Iterable[Strategy] | None = None,
    max_strategies: int = 3,
    always_include_general: bool = True,
) -> List[Strategy]:
    """Pick the highest-signal-scoring strategies for a function.

    Args:
        file_path: repo-relative path of the source file under
            review (used for path signals).
        function_name: identifier of the function under review
            (used for keyword signals).
        file_includes: header includes seen in the source file
            (used for include signals). May be empty when the
            inventory doesn't track includes for the language.
        strategies: optional pre-loaded strategy list. Defaults to
            ``load_all()`` for the bundled strategies dir.
        max_strategies: maximum number of strategies to return
            (default 3). The general strategy counts toward this
            cap when ``always_include_general`` is True.
        always_include_general: if True, the ``general`` strategy
            is always included in the result regardless of score.

    Returns:
        List of strategies sorted by score descending, with
        alphabetical tiebreaker. ``general`` (if included by the
        always-on flag and present in ``strategies``) is the first
        element of the result regardless of score so callers can
        rely on its position.
    """
    if max_strategies <= 0:
        return []

    pool: List[Strategy] = list(strategies) if strategies is not None else load_all()
    if not pool:
        return []

    # Score each strategy.
    scored: List[Tuple[Strategy, int]] = [
        (
            s,
            _score_strategy(
                s,
                file_path=file_path,
                function_name=function_name,
                file_includes=file_includes,
                function_calls_made=function_calls_made,
                candidate_cwes=candidate_cwes,
            ),
        )
        for s in pool
    ]

    # Identify the general strategy if present.
    general = next((s for s in pool if s.name == GENERAL), None)

    # Filter zero-score strategies (general handled separately).
    nonzero = [
        (s, score) for (s, score) in scored
        if score > 0 and s.name != GENERAL
    ]
    # Sort by score desc, then name asc for stable tiebreaking.
    nonzero.sort(key=lambda item: (-item[1], item[0].name))

    out: List[Strategy] = []
    if always_include_general and general is not None:
        out.append(general)

    # Fill remaining slots with non-general matches.
    remaining = max_strategies - len(out)
    for s, _score in nonzero[:remaining]:
        out.append(s)

    # When general is NOT pinned, allow it to compete on score 0
    # only if there's room and nothing else scored.
    if not always_include_general and general is not None:
        if not out and len(out) < max_strategies:
            out.append(general)

    return out

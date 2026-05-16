"""Prompt rendering for CWE-specialised strategies.

The picker chooses strategies; this module turns them into prompt
text for the LLM. /audit's driver composes:

    [system prompt — base review instructions]
    [function context — source, callers, callees, etc.]
    [render_strategies(picked) — strategy blocks from this module]
    [task instructions]

Two rendering primitives:

  * ``render_strategy(strategy)`` — single strategy as a markdown
    section. Skips empty fields cleanly so a minimal strategy
    (just name + description) produces just the header + intro.

  * ``render_strategies(strategies, max_bytes=None)`` — concatenates
    multiple strategy blocks with section breaks. Optionally caps
    total UTF-8 bytes; when exceeded, exemplars are dropped first,
    then questions, then later-strategy content. Caller gets a
    truncation marker so the LLM knows the prompt was clipped.

The rendered output is plain markdown. No escaping is done on
strategy content — strategies are operator-curated YAML, trusted
input from this module's perspective. (Loader-level validation
already rejected the most pathological structural inputs.)
"""

from __future__ import annotations

from typing import Iterable, List, Optional

from .models import Exemplar, Strategy


# Default soft cap on rendered output. Picked-strategies × addenda +
# questions + exemplars typically sit under 8KB; the cap protects
# against pathological cases (long strategy chains, oversized
# exemplars) without bothering normal callers.
DEFAULT_MAX_BYTES = 16_384

_TRUNCATION_MARKER = "\n\n_(strategy block truncated to fit prompt budget)_\n"


def _render_exemplar(e: Exemplar) -> str:
    parts = [f"**{e.cve} — {e.title}**", ""]
    if e.pattern:
        parts += ["Vulnerable pattern:", e.pattern.rstrip(), ""]
    if e.why_buggy:
        parts += ["Why it's a bug:", e.why_buggy.rstrip(), ""]
    return "\n".join(parts).rstrip() + "\n"


def render_strategy(
    strategy: Strategy, *, include_exemplars: bool = True,
    include_questions: bool = True,
) -> str:
    """Render one strategy as a markdown section.

    ``include_exemplars`` and ``include_questions`` let the
    truncation logic in ``render_strategies`` drop sub-sections
    progressively when the budget is tight.
    """
    parts: List[str] = []
    parts.append(f"## Strategy: {strategy.name}")
    if strategy.description:
        # Description may already be multi-line from YAML | block.
        parts.append("")
        parts.append(strategy.description.rstrip())

    if include_questions and strategy.key_questions:
        parts.append("")
        parts.append("### Key questions")
        for q in strategy.key_questions:
            parts.append(f"- {q}")

    if strategy.prompt_addendum:
        parts.append("")
        parts.append("### Approach")
        parts.append(strategy.prompt_addendum.rstrip())

    if include_exemplars and strategy.exemplars:
        parts.append("")
        parts.append("### Worked examples")
        for e in strategy.exemplars:
            parts.append("")
            parts.append(_render_exemplar(e).rstrip())

    return "\n".join(parts).rstrip() + "\n"


def _byte_len(text: str) -> int:
    return len(text.encode("utf-8"))


def render_strategies(
    strategies: Iterable[Strategy],
    *,
    max_bytes: Optional[int] = DEFAULT_MAX_BYTES,
) -> str:
    """Render multiple strategies as a single markdown block.

    When ``max_bytes`` is set and the full rendering exceeds it,
    progressively drop content in this order:

      1. Exemplars from the last-listed strategies (lower priority)
      2. Exemplars from all strategies
      3. Key questions from the last-listed strategies
      4. Key questions from all strategies
      5. Drop later strategies entirely

    A ``_(strategy block truncated...)_`` marker is appended when
    truncation occurs so the LLM sees the budget was tight.
    """
    pool = list(strategies)
    if not pool:
        return ""

    # Try full render first — most calls fit.
    full = "\n\n".join(render_strategy(s) for s in pool)
    if max_bytes is None or _byte_len(full) <= max_bytes:
        return full

    # Tier 1: drop exemplars from later strategies first.
    for keep_exemplars_through in range(len(pool) - 1, -1, -1):
        candidate = "\n\n".join(
            render_strategy(s, include_exemplars=(i <= keep_exemplars_through))
            for i, s in enumerate(pool)
        ) + _TRUNCATION_MARKER
        if _byte_len(candidate) <= max_bytes:
            return candidate

    # Tier 2: also drop questions from later strategies.
    for keep_questions_through in range(len(pool) - 1, -1, -1):
        candidate = "\n\n".join(
            render_strategy(
                s,
                include_exemplars=False,
                include_questions=(i <= keep_questions_through),
            )
            for i, s in enumerate(pool)
        ) + _TRUNCATION_MARKER
        if _byte_len(candidate) <= max_bytes:
            return candidate

    # Tier 3: drop later strategies entirely.
    for n in range(len(pool), 0, -1):
        candidate = "\n\n".join(
            render_strategy(
                s, include_exemplars=False, include_questions=False,
            )
            for s in pool[:n]
        ) + _TRUNCATION_MARKER
        if _byte_len(candidate) <= max_bytes:
            return candidate

    # Last resort: just the first strategy's name + description, no
    # frills. The caller's budget is unrealistically tight, but the
    # function still produces something parseable.
    s = pool[0]
    return f"## Strategy: {s.name}\n\n{s.description.rstrip()}\n" + _TRUNCATION_MARKER

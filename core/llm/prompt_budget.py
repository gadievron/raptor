"""Prompt budget: estimate token cost and shed low-priority sections.

Reusable across any prompt-assembly site — /audit context, /agentic
analysis bundles, tool-use loop preambles.  The estimator uses the
same 4-chars-per-token heuristic as ``providers.estimate_tokens``
(intentionally over-estimates; the safe direction).

Usage
-----
::

    from core.llm.prompt_budget import PromptSection, fit_to_budget

    sections = [
        PromptSection("source",    source_text,   priority=0),
        PromptSection("evidence",  evidence_text,  priority=0),
        PromptSection("callers",   callers_text,   priority=3),
        PromptSection("exemplars", exemplar_text,  priority=5),
    ]
    kept, shed = fit_to_budget(sections, budget_tokens=60_000)
    prompt = "\\n".join(s.text for s in kept)

Lower ``priority`` = more important (never shed priority 0).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Tuple

logger = logging.getLogger(__name__)


def estimate_tokens(text: str) -> int:
    """Cheap token estimate: 4 chars per token, minimum 1."""
    return max(len(text) // 4, 1)


@dataclass(frozen=True)
class PromptSection:
    """One labelled section of a prompt.

    ``priority``: 0 = must-keep (source, mechanical evidence),
    higher = shed first.  Sections at the same priority are shed
    largest-first to reclaim the most space per drop.
    """

    label: str
    text: str
    priority: int = 0

    @property
    def token_estimate(self) -> int:
        return estimate_tokens(self.text)


def fit_to_budget(
    sections: List[PromptSection],
    budget_tokens: int,
    *,
    reserve_tokens: int = 0,
) -> Tuple[List[PromptSection], List[PromptSection]]:
    """Keep sections that fit within *budget_tokens*, shedding the rest.

    Returns ``(kept, shed)`` — both in original order.

    *reserve_tokens* is subtracted from *budget_tokens* before fitting
    (use for system prompt + response headroom that the caller knows
    about but that isn't in *sections*).

    Shedding order: highest ``priority`` first; within a priority tier,
    largest section first (reclaims the most space per drop).
    Sections with ``priority == 0`` are never shed.
    """
    effective_budget = budget_tokens - reserve_tokens
    total = sum(s.token_estimate for s in sections)

    if total <= effective_budget:
        return list(sections), []

    sheddable = sorted(
        [(i, s) for i, s in enumerate(sections) if s.priority > 0],
        key=lambda pair: (-pair[1].priority, -pair[1].token_estimate),
    )

    shed_indices: set[int] = set()
    overshoot = total - effective_budget

    for idx, sec in sheddable:
        if overshoot <= 0:
            break
        shed_indices.add(idx)
        overshoot -= sec.token_estimate
        logger.debug(
            "prompt_budget: shed [%s] (%d tokens, priority %d), "
            "remaining overshoot %d",
            sec.label, sec.token_estimate, sec.priority, max(0, overshoot),
        )

    if overshoot > 0:
        logger.warning(
            "prompt_budget: still %d tokens over budget after shedding "
            "all sheddable sections", overshoot,
        )

    kept = [s for i, s in enumerate(sections) if i not in shed_indices]
    shed = [s for i, s in enumerate(sections) if i in shed_indices]
    return kept, shed


def shed_blocks(
    blocks: list,
    budget_tokens: int,
    priority_map: dict,
    *,
    reserve_tokens: int = 0,
    content_attr: str = "content",
    kind_attr: str = "kind",
    priority_prefixes: list = None,
) -> Tuple[list, list]:
    """Shed UntrustedBlock-like objects by priority.

    Works with any object that has a *content_attr* (text) and
    *kind_attr* (label used for priority lookup).  Blocks whose
    kind is missing from *priority_map* default to priority 2
    (or match via *priority_prefixes* ``[(prefix, pri), ...]``).
    Blocks at priority 0 are never shed.

    Returns ``(kept, shed)`` in original order.
    """
    sections = []
    for block in blocks:
        kind = getattr(block, kind_attr, "unknown")
        pri = priority_map.get(kind)
        if pri is None and priority_prefixes:
            for prefix, prefix_pri in priority_prefixes:
                if kind.startswith(prefix):
                    pri = prefix_pri
                    break
        if pri is None:
            pri = 2
        text = getattr(block, content_attr, "")
        sections.append(PromptSection(kind, text, pri))

    _, shed_sec = fit_to_budget(
        sections, budget_tokens, reserve_tokens=reserve_tokens,
    )
    shed_indices = set()
    for s in shed_sec:
        for i, sec in enumerate(sections):
            if i not in shed_indices and sec is s:
                shed_indices.add(i)
                break

    kept = [b for i, b in enumerate(blocks) if i not in shed_indices]
    shed = [b for i, b in enumerate(blocks) if i in shed_indices]
    return kept, shed


def context_budget_for_model(
    model: str,
    system_prompt_tokens: int = 0,
    response_headroom: int = 8_000,
) -> int:
    """How many tokens the user-message content can occupy.

    ``response_headroom`` accounts for max_tokens + thinking budget.
    """
    try:
        from core.llm.model_data import context_window_for
        window = context_window_for(model)
    except (KeyError, ImportError):
        window = 200_000
    return window - system_prompt_tokens - response_headroom

r"""Prompt budget: estimate token cost and shed low-priority sections.

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
    prompt = "\n".join(s.text for s in kept)

Lower ``priority`` = more important (never shed priority 0).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

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


# Priority-0 elision floor: never tail-truncate a must-keep section
# below this many tokens (~4 chars/token, so ~2 KB of text).  Not
# lower: the priority-0 tail IS the evidence the review exists to
# read — a source/decompilation section cut below this leaves too
# little of the function body for any verdict to be grounded in it.
# Not higher: multi-section priority-0 prompts (source + evidence +
# block analysis) each need enough truncation headroom that the
# combined prompt can still reach the budget — a higher floor defeats
# the elision on exactly the oversized prompts it exists for.
_P0_ELISION_FLOOR_TOKENS = 512


@dataclass(frozen=True)
class SectionElision:
    """Record of one priority-0 tail truncation."""

    label: str
    tokens_elided: int


@dataclass(frozen=True)
class FitReport:
    """Structured result of :func:`fit_to_budget_report`.

    ``overshoot_tokens`` is the residual AFTER any elision — 0 when
    the kept sections fit the effective budget.  ``elisions`` records
    each priority-0 tail truncation (empty unless ``elide_priority0``
    was set and shedding alone could not reach the budget).
    """

    kept: list[PromptSection]
    shed: list[PromptSection]
    overshoot_tokens: int
    elisions: list[SectionElision]


_FENCE_LINE_RE = re.compile(r"^(`{3,})")
_ENVELOPE_OPEN_RE = re.compile(r"^<(untrusted-[\w-]+)\b")
_ENVELOPE_CLOSE_RE = re.compile(r"^</(untrusted-[\w-]+)>$")


def _severed_closers(prefix: str, original: str) -> list[str]:
    """Closer lines for structural constructs a tail cut left open.

    A structure-blind tail truncation severs (a) the closing code
    fence of a fenced body — everything after the cut then renders
    INSIDE the fence, and a later backtick run in the (untrusted)
    remainder can flip fence parity and surface target-derived text
    as live prose — and (b) the close tag of an ``<untrusted-...>``
    envelope, leaving the untrusted region unterminated.  This scans
    *prefix* (the truncated body) with a single line-state pass and
    returns the closer lines to re-append, innermost-first:

    * Code fences: CommonMark closes a fence only with a backtick run
      AT LEAST as long as the opener (assemblers pick openers longer
      than any run in the body), so the re-appended closer replays
      the OPENER's run length — a bare 3-backtick line could not
      close a longer fence.  Fence-body lines are literal text, so
      envelope tags seen inside an open fence are not counted as
      real envelope boundaries.
    * Envelope close tags are re-appended only when the ORIGINAL
      section text carries that exact close line — the per-call nonce
      makes close tags unforgeable from the content side, and this
      function must never mint one the envelope layer did not write.
    """
    stack: list[str] = []  # pending closer lines, in open order
    in_fence = False
    fence_len = 0
    for line in prefix.split("\n"):  # line-model: lines are .strip()ed before every match — CRLF \r tolerated
        stripped = line.strip()
        m = _FENCE_LINE_RE.match(stripped)
        if m:
            run = len(m.group(1))
            if not in_fence:
                in_fence = True
                fence_len = run
                stack.append("`" * run)
            elif run >= fence_len and set(stripped) == {"`"}:
                in_fence = False
                for k in range(len(stack) - 1, -1, -1):
                    if set(stack[k]) == {"`"}:
                        del stack[k]
                        break
            continue
        if in_fence:
            continue  # fence body is literal text
        mo = _ENVELOPE_OPEN_RE.match(stripped)
        if mo:
            stack.append(f"</{mo.group(1)}>")
            continue
        mc = _ENVELOPE_CLOSE_RE.match(stripped)
        if mc:
            closer = f"</{mc.group(1)}>"
            for k in range(len(stack) - 1, -1, -1):
                if stack[k] == closer:
                    del stack[k]
                    break
    return [
        c for c in reversed(stack)
        if not c.startswith("</") or c in original
    ]


def _compose_elided_section(
    sec: PromptSection, overshoot: int,
) -> tuple[str, int] | None:
    """Compose the tail-elided replacement text for one section.

    Returns ``(composed_text, tokens_reclaimed)``, or ``None`` when
    elision cannot truthfully reclaim anything here (the structural
    closer + marker overhead would eat the whole cut, or the
    fix-point below fails to settle — the caller then skips this
    section and the residual stays in ``overshoot_tokens``).

    Composition order: truncated body, re-appended structural
    closer(s), elision marker LAST — the marker always lands OUTSIDE
    any code fence or untrusted envelope, in trusted context.  That
    placement also blunts marker forgery: untrusted section content
    can never end the section with a mimic marker sitting in trusted
    context, because anything inside the body stays inside the
    re-closed fence/envelope where it renders as data.

    The closers' byte cost joins the marker cost in the fit
    arithmetic: the composed text is sized so its token estimate
    lands exactly on ``tokens - reclaim`` — neither the marker nor a
    re-appended closer ever free-rides into a still-over-budget
    result (the body shrinks to pay for them).  The elision floor
    applies to the BODY (the kept evidence text), never to the
    overhead.
    """
    text, label = sec.text, sec.label
    tokens = sec.token_estimate
    floor_chars = _P0_ELISION_FLOOR_TOKENS * 4
    reclaim = min(overshoot, tokens - _P0_ELISION_FLOOR_TOKENS)
    if reclaim <= 0:
        return None
    closers_text = ""
    # Fix-point over (reclaim digits, severed closers): the marker
    # length depends on the reclaim figure, and the closers depend on
    # where the cut lands, which depends on both.  Settles in 2-3
    # iterations in practice; bounded defensively.
    for _ in range(8):
        marker = (
            f"\n[... prompt budget: {reclaim} tokens elided "
            f"from {label} ...]"
        )
        overhead = len(marker) + len(closers_text)
        target = tokens - reclaim
        cut = target * 4 - overhead
        if cut < floor_chars:
            # Floor applies to the BODY: push the composed target up
            # so the kept evidence text never shrinks below it.
            target = (floor_chars + overhead + 3) // 4
            cut = target * 4 - overhead
            reclaim_next = tokens - target
            if reclaim_next <= 0:
                return None  # overhead eats the whole cut
        else:
            reclaim_next = reclaim
        new_closers = "".join(
            "\n" + c for c in _severed_closers(text[:cut], text)
        )
        if new_closers == closers_text and reclaim_next == reclaim:
            composed = text[:cut] + closers_text + marker
            reclaimed = tokens - estimate_tokens(composed)
            if reclaimed <= 0:
                return None
            return composed, reclaimed
        closers_text = new_closers
        reclaim = reclaim_next
    return None


def _elide_priority0(
    kept: list[PromptSection],
    overshoot: int,
) -> tuple[list[PromptSection], list[SectionElision], int]:
    """Tail-truncate priority-0 sections largest-first until fit.

    Each truncated section gets any severed structural closers (code
    fence / untrusted-envelope close tags) re-appended and an
    explicit elision marker appended LAST — composition and cost
    accounting in :func:`_compose_elided_section`.  No section body
    goes below ``_P0_ELISION_FLOOR_TOKENS``.

    Returns ``(sections, elisions, remaining_overshoot)`` with
    *sections* in original order.
    """
    result = list(kept)
    elisions: list[SectionElision] = []
    order = sorted(
        range(len(result)), key=lambda i: -result[i].token_estimate,
    )
    for i in order:
        if overshoot <= 0:
            break
        sec = result[i]
        if sec.priority != 0:
            continue
        if sec.token_estimate <= _P0_ELISION_FLOOR_TOKENS:
            continue  # floored — nothing left to reclaim here
        composed = _compose_elided_section(sec, overshoot)
        if composed is None:
            continue
        new_text, reclaimed = composed
        result[i] = PromptSection(sec.label, new_text, sec.priority)
        elisions.append(SectionElision(sec.label, reclaimed))
        overshoot -= reclaimed
        logger.debug(
            "prompt_budget: elided %d tokens from priority-0 [%s] "
            "(now %d tokens), remaining overshoot %d",
            reclaimed, sec.label, estimate_tokens(new_text),
            max(0, overshoot),
        )
    return result, elisions, overshoot


def fit_to_budget_report(
    sections: list[PromptSection],
    budget_tokens: int,
    *,
    reserve_tokens: int = 0,
    elide_priority0: bool = False,
) -> FitReport:
    """Fit *sections* into *budget_tokens*, reporting what happened.

    Sheds priority>0 sections exactly like :func:`fit_to_budget`.
    When *elide_priority0* is true and the priority-0 sections alone
    still exceed the effective budget, tail-truncates them
    largest-first (never below ``_P0_ELISION_FLOOR_TOKENS``) with an
    explicit elision marker whose token cost is counted in the fit.
    Any residual is reported truthfully in ``overshoot_tokens`` and
    keeps the send-anyway warning.
    """
    effective_budget = budget_tokens - reserve_tokens
    total = sum(s.token_estimate for s in sections)

    if total <= effective_budget:
        return FitReport(list(sections), [], 0, [])

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

    kept = [s for i, s in enumerate(sections) if i not in shed_indices]
    shed = [s for i, s in enumerate(sections) if i in shed_indices]

    elisions: list[SectionElision] = []
    if overshoot > 0 and elide_priority0:
        kept, elisions, overshoot = _elide_priority0(kept, overshoot)

    if overshoot > 0:
        logger.warning(
            "prompt_budget: still %d tokens over budget after shedding "
            "all sheddable sections", overshoot,
        )

    return FitReport(kept, shed, max(0, overshoot), elisions)


def fit_to_budget(
    sections: list[PromptSection],
    budget_tokens: int,
    *,
    reserve_tokens: int = 0,
) -> tuple[list[PromptSection], list[PromptSection]]:
    """Keep sections that fit within *budget_tokens*, shedding the rest.

    Returns ``(kept, shed)`` — both in original order.

    *reserve_tokens* is subtracted from *budget_tokens* before fitting
    (use for system prompt + response headroom that the caller knows
    about but that isn't in *sections*).

    Shedding order: highest ``priority`` first; within a priority tier,
    largest section first (reclaims the most space per drop).
    Sections with ``priority == 0`` are never shed.
    """
    report = fit_to_budget_report(
        sections, budget_tokens, reserve_tokens=reserve_tokens,
    )
    return report.kept, report.shed


def shed_blocks(
    blocks: list,
    budget_tokens: int,
    priority_map: dict,
    *,
    reserve_tokens: int = 0,
    content_attr: str = "content",
    kind_attr: str = "kind",
    priority_prefixes: list | None = None,
) -> tuple[list, list]:
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
    # Identity map instead of an O(n²) linear re-scan per shed
    # section — each PromptSection above is a fresh object, so id()
    # is unique per index.
    shed_ids = {id(s) for s in shed_sec}
    kept = [b for b, sec in zip(blocks, sections, strict=True)
            if id(sec) not in shed_ids]
    shed = [b for b, sec in zip(blocks, sections, strict=True)
            if id(sec) in shed_ids]
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
    return max(0, window - system_prompt_tokens - response_headroom)

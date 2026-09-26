"""Verdict-triggered context expansion for the per-finding classifier.

The classifier (``packages.llm_analysis.agent``) analyses each finding
once, with a fixed line window around the flagged lines
(``core.llm.context_window.FINDING_CONTEXT_LINES``) and no tools. When
that single pass ends in an explicitly UNCERTAIN verdict, the missing
evidence is usually just outside what the prompt showed — the guard a
screen above the window, the caller that sanitises the argument, the
callee that bounds the copy. This module is the policy layer for the
opt-in second look (``--context-expansion``): one re-run of the same
finding with a wider window plus 1-hop caller/callee context, joined
back under a replace-only-when-more-confident rule.

Three contracts, each pinned by tests:

* **Trigger** (:func:`expansion_trigger`) — conservative by
  construction: only an explicit ``confidence == "low"``
  self-assessment or a full verdict abstention (BOTH verdict fields
  nulled by response validation) triggers. Confident and
  medium-confidence verdicts, partial verdicts with stated
  confidence, unrecognised confidence strings, and every mechanical
  suppression record never trigger — expansion is paid spend, and a
  confident first verdict must never be re-litigated.
* **Join** (:func:`join_verdicts`) — the re-run REPLACES the first
  verdict only when the second is strictly MORE confident: it must
  carry a full genuine verdict (both bool fields) AND outrank the
  first's stated confidence (an abstained first is outranked by any
  full verdict; a low-confidence first only by medium/high). A second
  verdict that is equally uncertain, unranked, or abstained never
  replaces — and a first verdict that would not have triggered is
  never replaced at all, so a confident first verdict cannot be
  demoted through this seam even if a caller misroutes one here.
* **Rails** — :data:`MAX_EXPANSIONS_PER_RUN` bounds the added spend
  per run; every per-expansion volume knob is DERIVED from the named
  window constants (``core.llm.context_window`` /
  ``core.audit.context``), never a new literal.

All expansion content (wider window, caller call-sites, callee
bodies) is target-derived and travels as ``UntrustedBlock``s / the
prompt bundle's untrusted slots through the existing prompt-envelope
chokepoint — this module adds no new prompt egress path.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from core.llm.context_window import FINDING_CONTEXT_LINES
from core.run.finding_status import read_verdict
from core.security.prompt_envelope import UntrustedBlock

logger = logging.getLogger(__name__)

#: Width multiplier for the re-run's surrounding-context window: the
#: expanded window is ``EXPANSION_WINDOW_MULTIPLIER *
#: FINDING_CONTEXT_LINES`` before and after the finding — derived
#: from the shared classifier window, never an independent literal.
#: Too small (1): the re-run shows the model the same lines that
#: already produced an uncertain verdict and pays a full second
#: analysis call for it. Too large: the second prompt's token bill
#: scales with the multiplier on every triggered finding, and a very
#: wide window pushes the flagged lines even further from the model's
#: focus — the same dilution argument as FINDING_CONTEXT_LINES
#: itself, amplified; past 2x the extra lines are mostly NEIGHBOURING
#: functions, which the caller/callee channel already covers with
#: targeted bodies instead of raw adjacency.
EXPANSION_WINDOW_MULTIPLIER: int = 2

#: The re-run's surrounding-context window (lines before AND after).
#: Derived twin — kept as a module name so consumers and the analysis
#: record cite one value, but the coupling to the J-series constants
#: is live (a FINDING_CONTEXT_LINES change moves this with it).
EXPANDED_FINDING_CONTEXT_LINES: int = (
    EXPANSION_WINDOW_MULTIPLIER * FINDING_CONTEXT_LINES
)

#: Hard per-run cap on performed expansions. Expansion is paid spend
#: — each one is a full extra analysis call on a finding the run
#: already paid to analyse once. Too small: on an uncertain-heavy run
#: the budget exhausts on the first few findings in queue order, and
#: whether a finding gets its second look is decided by queue-position
#: luck rather than by its verdict. Too large: a run whose classifier
#: is SYSTEMATICALLY uncertain (wrong model for the language, degraded
#: transport, hostile inputs engineered to read ambiguous) would
#: re-bill a large fraction of the whole run — the cap bounds the
#: worst case to a known number of extra calls regardless of what the
#: verdicts do. Findings past the cap are counted (``skipped_cap``)
#: and annotated, never silently passed over.
MAX_EXPANSIONS_PER_RUN: int = 10

#: Stated-confidence value that expresses explicit uncertainty. The
#: schema's CONFIDENCE_LEVELS enum is high/medium/low; only the
#: bottom rung triggers. medium is deliberately NOT uncertain — it is
#: the model's ordinary working confidence, and triggering on it
#: would expand a large share of every run.
_UNCERTAIN_CONFIDENCE = "low"

#: Analysis-record marker keys stamped by the mechanical pre-LLM
#: chokepoints (fixture / reachability / SAGE / guard-dominance /
#: fail-open). Those records are synthesised, not LLM verdicts — they
#: carry no confidence field and must never trigger a paid re-run.
#: Belt-and-braces: the agent only evaluates the trigger on the LLM
#: path, but the predicate refuses them independently.
_MECHANICAL_RECORD_KEYS = (
    "fixture_demotion",
    "reachability_suppression",
    "sage_fp_suppression",
    "guard_dominance_refutation",
    "fail_open_refutation",
)

_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}

_TRIGGER_LOW_CONFIDENCE = "low_confidence"
_TRIGGER_VERDICT_ABSTAINED = "verdict_abstained"


def _normalised_confidence(analysis: dict[str, Any]) -> str | None:
    """The stated confidence, lower/stripped; ``None`` when absent or
    not one of the schema's enum values (an unrecognised string is
    not an explicit signal in either direction)."""
    raw = analysis.get("confidence")
    if not isinstance(raw, str):
        return None
    value = raw.strip().lower()
    return value if value in _CONFIDENCE_RANK else None


def _confidence_rank(analysis: dict[str, Any]) -> int:
    """Rank of the stated confidence; -1 when unstated/unrecognised —
    an unstated confidence never outranks a stated one."""
    value = _normalised_confidence(analysis)
    return _CONFIDENCE_RANK[value] if value is not None else -1


def _has_full_verdict(analysis: dict[str, Any]) -> bool:
    """Both verdict fields are genuine bools (``read_verdict``
    tri-state contract — abstentions and junk shapes read None)."""
    return (
        read_verdict(analysis, "is_true_positive") is not None
        and read_verdict(analysis, "is_exploitable") is not None
    )


def expansion_trigger(analysis: Any) -> str | None:
    """Whether this analysis verdict warrants the expanded re-run.

    Returns the trigger reason string, or ``None`` (the common case).
    Conservative in every direction — see the module docstring; the
    two reasons, most-specific first:

    * ``verdict_abstained`` — BOTH verdict fields read ``None``
      through :func:`read_verdict`: response validation nulled them
      (an abstention, not a verdict). A partial verdict (one genuine
      field) only triggers via the confidence path below.
    * ``low_confidence`` — the model itself stated ``confidence:
      "low"``. Exact enum value after normalisation; "uncertain",
      "unknown" and other near-synonyms do NOT trigger (structured
      output constrains the enum — an off-enum string is a degraded
      response, and the quality-retry seam owns those).
    """
    if not isinstance(analysis, dict):
        return None
    if any(analysis.get(key) for key in _MECHANICAL_RECORD_KEYS):
        return None
    if (
        read_verdict(analysis, "is_true_positive") is None
        and read_verdict(analysis, "is_exploitable") is None
    ):
        return _TRIGGER_VERDICT_ABSTAINED
    if _normalised_confidence(analysis) == _UNCERTAIN_CONFIDENCE:
        return _TRIGGER_LOW_CONFIDENCE
    return None


def join_verdicts(
    first: dict[str, Any],
    second: dict[str, Any],
) -> tuple[dict[str, Any], bool]:
    """Choose between the first verdict and the expanded re-run's.

    Returns ``(chosen_analysis, replaced)``. The second REPLACES the
    first only when ALL of:

    * the first would have triggered at all (defensive re-check — a
      confident first verdict is never replaced through this seam,
      whatever a caller passes);
    * the second carries a FULL genuine verdict (both bool fields) —
      a second abstention or partial verdict never replaces;
    * the second is strictly MORE confident: any stated-or-not rank
      beats an abstained first (a cast verdict always outranks no
      verdict), while a low-confidence first is only replaced by a
      stated medium/high second.

    Ties and downgrades keep the first verdict — the expansion then
    rides the record as evidence, not as a verdict change.
    """
    reason = expansion_trigger(first)
    if reason is None:
        return first, False
    if not _has_full_verdict(second):
        return first, False
    if reason == _TRIGGER_VERDICT_ABSTAINED:
        # No genuine first verdict: a full verdict at any stated
        # confidence (or none) replaces the abstention.
        return second, True
    if _confidence_rank(second) > _confidence_rank(first):
        return second, True
    return first, False


def verdict_summary(analysis: Any) -> dict[str, Any]:
    """Bounded summary of one verdict for the expansion record —
    enough to audit the join without persisting a second full
    analysis dict."""
    if not isinstance(analysis, dict):
        return {
            "is_true_positive": None,
            "is_exploitable": None,
            "confidence": None,
            "exploitability_score": None,
            "ruling": None,
        }
    score = analysis.get("exploitability_score")
    ruling = analysis.get("ruling")
    return {
        "is_true_positive": read_verdict(analysis, "is_true_positive"),
        "is_exploitable": read_verdict(analysis, "is_exploitable"),
        "confidence": _normalised_confidence(analysis),
        "exploitability_score": (
            score if isinstance(score, (int, float)) else None
        ),
        "ruling": ruling if isinstance(ruling, str) else None,
    }


def build_expansion_record(
    *,
    reason: str,
    first: dict[str, Any],
    second: dict[str, Any],
    replaced: bool,
    window_lines: int,
    caller_context_attached: bool,
    callee_context_attached: bool,
) -> dict[str, Any]:
    """The ``context_expansion`` entry persisted on the finding's
    analysis record: both verdicts (summaries), the join outcome, and
    what the expanded prompt actually carried."""
    return {
        "triggered": True,
        "reason": reason,
        "window_lines": window_lines,
        "caller_context_attached": caller_context_attached,
        "callee_context_attached": callee_context_attached,
        "replaced": replaced,
        "first_verdict": verdict_summary(first),
        "second_verdict": verdict_summary(second),
    }


def expansion_context_blocks(
    checklist: dict[str, Any] | None,
    file_path: str,
    function: str,
    repo_path: Path,
    *,
    context_map: dict[str, Any] | None = None,
) -> tuple[UntrustedBlock, ...]:
    """The +1-hop caller/callee blocks for the expanded prompt.

    Reuses the existing context-assembly seams — the caller channel's
    block builder (``flow_context_inject.caller_call_sites_block``)
    widened to the audit-side caller cap, and the audit-side callee
    seam (``core.audit.context.collect_callee_sources``) rendered
    with the same width/height discipline as the caller channel.
    Every volume knob is one of the named window constants. Returns
    ``()`` when nothing resolves or any step fails — the re-run then
    proceeds on the wider window alone.
    """
    if not function or not file_path:
        return ()
    blocks: list[UntrustedBlock] = []
    try:
        from core.audit.context import MAX_CALL_SITE_CALLERS

        from packages.llm_analysis.flow_context_inject import (
            caller_call_sites_block,
        )
        caller_block = caller_call_sites_block(
            checklist, file_path, function, repo_path,
            context_map=context_map,
            max_callers=MAX_CALL_SITE_CALLERS,
        )
        if caller_block is not None:
            blocks.append(caller_block)
    except Exception:
        logger.debug("expansion caller block build failed", exc_info=True)
    try:
        callee_block = _build_callee_block(
            checklist, file_path, function, repo_path,
            context_map=context_map,
        )
        if callee_block is not None:
            blocks.append(callee_block)
    except Exception:
        logger.debug("expansion callee block build failed", exc_info=True)
    return tuple(blocks)


def _build_callee_block(
    checklist: dict[str, Any] | None,
    file_path: str,
    function: str,
    repo_path: Path,
    *,
    context_map: dict[str, Any] | None = None,
) -> UntrustedBlock | None:
    from core.audit.context import (
        CALLEE_SNIPPET_SPAN_LINES,
        collect_callee_sources,
    )

    from packages.llm_analysis.flow_context_inject import _clip

    callees = collect_callee_sources(
        checklist, file_path, function, repo_path,
        context_map=context_map,
    )
    if not callees:
        return None

    lines = [f"Known callees of {_clip(function, 80)} (1-hop):"]
    for callee in callees:
        where = f"{callee.get('file', '')}:{callee.get('line_start', 0)}"
        lines.append(
            f"- {_clip(callee.get('name', ''), 80)} at {_clip(where, 120)}"
        )
        snippet = callee.get("source_snippet")
        if snippet:
            # Width + height caps mirror the caller channel: each
            # snippet line is raw target source, so bound the width
            # per line; the height cap DERIVES from the enricher's
            # own per-callee span so a hostile/pathological snippet
            # cannot exceed the seam's contract height.
            lines.extend(
                f"    {_clip(snippet_line, 200)}"
                for snippet_line in
                str(snippet).splitlines()[:CALLEE_SNIPPET_SPAN_LINES]
            )
    return UntrustedBlock(
        content="\n".join(lines),
        kind="callee-sources",
        origin="inventory-call-graph",
    )

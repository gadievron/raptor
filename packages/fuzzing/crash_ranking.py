"""Opt-in LLM re-rank of the fuzzer crash queue before deep analysis.

The legacy AFL path collects unique crashes, orders them by a static
signal heuristic (SIGSEGV > SIGABRT > ...), and spends the expensive
per-crash budget (GDB triage + LLM analysis + exploit generation) on
the first ``--max-crashes`` only. That cap cuts a heuristic tail;
this stage reorders the queue with listwise LLM ranking
(``core.llm.ranking``) so the cap cuts the least promising tail
instead.

Signal is pre-triage only: at ranking time a crash record carries
its signal, input size, the AFL filename metadata (mutation op,
source id), and the head of the crashing input — no stack identity
(that exists only after the GDB step this stage is trying to
allocate). Same-stack duplicates can therefore cluster at the top;
the caller compensates by collecting a multiple of the cap when
ranking is enabled and letting the post-GDB stack-hash dedup absorb
them.

Ordering only, best-effort: any failure keeps the heuristic order.
Crash input bytes are attacker-controlled by definition; the
rendered head is a fixed-size hexdump and the ranking module
nonce-envelopes and escapes every document.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Fraction of the analysis client's budget the ranking pass may use.
_RANK_BUDGET_FRACTION = 0.10
# Hexdump head of the crashing input shown to the ranker.
_HEX_HEAD_BYTES = 48
_MAX_NAME_CHARS = 160

_SIGNAL_NAMES = {
    "4": "SIGILL",
    "6": "SIGABRT",
    "8": "SIGFPE",
    "11": "SIGSEGV",
}

_CRASH_QUERY = (
    "Rank these fuzzer crashes by expected value for deep root-cause "
    "analysis and exploitability assessment. Prefer memory-safety "
    "signals (SIGSEGV, SIGILL) over aborts and arithmetic faults, "
    "small or structured inputs over huge random ones, and mutation "
    "metadata or input content that suggests attacker-shapeable "
    "state (lengths, offsets, structured headers) over noise."
)


def _signal_name(signal: Any) -> str:
    raw = str(signal or "?").lstrip("0") or "0"
    return _SIGNAL_NAMES.get(raw, f"signal {signal}") if signal else "?"


def _render_crash(crash: Any) -> str:
    """Pre-triage rendering of one CrashCollector Crash record."""
    input_file = getattr(crash, "input_file", None)
    name = str(getattr(input_file, "name", "") or "")
    name = name.replace("\n", " ").replace("\r", " ")[:_MAX_NAME_CHARS]
    head = ""
    try:
        if input_file is not None:
            from pathlib import Path

            path = Path(input_file)
            # A hostile target could plant symlinks in its own crash
            # dir; never follow one into arbitrary readable files.
            if path.is_symlink() or not path.is_file():
                head = "(unreadable)"
            else:
                with open(path, "rb") as f:
                    head = f.read(_HEX_HEAD_BYTES).hex(" ")
    except OSError:
        head = "(unreadable)"
    return "\n".join([
        f"signal: {_signal_name(getattr(crash, 'signal', None))}",
        f"input_size: {getattr(crash, 'size', '?')} bytes",
        f"afl_meta: {name or '?'}",
        f"input_head_hex: {head or '?'}",
    ])


def rank_crash_queue(
    crashes: list[Any],
    *,
    llm_config: Any = None,
    client: Any = None,
    seed: int | None = None,
    max_workers: int | None = None,
) -> tuple[list[Any], str]:
    """Re-rank the crash queue most-promising-first.

    ``llm_config`` is the crash agent's LLMConfig (None under the
    stub/claude-code-only provider — the stage skips there, matching
    the agent's own external-LLM gate). Returns ``(crashes, note)``;
    best-effort throughout.
    """
    if len(crashes) < 3:
        return crashes, "crash ranking skipped (too few crashes)"
    if client is None and llm_config is None:
        return crashes, "crash ranking skipped (needs an external analysis model)"

    try:
        from core.llm.ranking import rank_items

        if client is None:
            import copy

            from core.llm.client import LLMClient

            rank_config = llm_config
            cap = float(getattr(llm_config, "max_cost_per_scan", 0) or 0)
            if cap > 0:
                rank_config = copy.copy(llm_config)
                rank_config.max_cost_per_scan = cap * _RANK_BUDGET_FRACTION
            client = LLMClient(rank_config)

        result = rank_items(
            crashes, _CRASH_QUERY, client=client, render=_render_crash,
            seed=seed, max_workers=max_workers,
        )
        stats = result.stats
        if stats.ranked_batches == 0:
            return crashes, (
                "crash ranking produced no signal — heuristic order "
                f"kept ({stats.llm_calls} LLM calls, ${stats.cost:.2f})"
            )
        note = (
            f"ranked {len(crashes)} crashes for analysis order "
            f"({stats.llm_calls} LLM calls, ${stats.cost:.2f})"
        )
        return [r.item for r in result.ranked], note
    except Exception as e:  # noqa: BLE001 — ordering refinement must
        # never break the crash loop; the heuristic order is always a
        # valid fallback.
        logger.warning("crash ranking failed (%s); heuristic order kept", e)
        return crashes, f"crash ranking failed ({e}); heuristic order kept"

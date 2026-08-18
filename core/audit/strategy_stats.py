"""Strategy effectiveness aggregation from past audit logs.

Reads audit-log.jsonl files from prior runs (same project or output
directory) and computes per-strategy win rates. A "win" is a finding
or suspicious outcome; a "miss" is a clean outcome. Error outcomes
are excluded.

The aggregated stats feed back into strategy selection: strategies
with high win rates get priority boosts; strategies that consistently
produce only clean results on a target get deprioritized (not dropped).
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path

logger = logging.getLogger(__name__)

_POSITIVE_STATUSES = frozenset({"finding", "suspicious"})
_NEGATIVE_STATUSES = frozenset({"clean"})


def aggregate_strategy_stats(
    log_dirs: list[Path],
) -> dict[str, dict[str, int]]:
    """Aggregate strategy effectiveness across multiple audit log dirs.

    Args:
        log_dirs: Directories containing ``.audit-log.jsonl`` files.

    Returns:
        Mapping of strategy name to {wins, misses, total} counts.
    """
    stats: dict[str, dict[str, int]] = defaultdict(
        lambda: {"wins": 0, "misses": 0, "total": 0},
    )

    for log_dir in log_dirs:
        log_path = log_dir / ".audit-log.jsonl"
        if not log_path.exists():
            continue
        try:
            with open(log_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if entry.get("action") != "orchestrator_review":
                        continue
                    status = entry.get("status", "")
                    strategies = entry.get("strategies", [])
                    if not strategies:
                        continue
                    for strat in strategies:
                        stats[strat]["total"] += 1
                        if status in _POSITIVE_STATUSES:
                            stats[strat]["wins"] += 1
                        elif status in _NEGATIVE_STATUSES:
                            stats[strat]["misses"] += 1
        except OSError:
            continue

    return dict(stats)


def compute_strategy_weights(
    stats: dict[str, dict[str, int]],
    *,
    min_samples: int = 10,
    default_weight: float = 1.0,
) -> dict[str, float]:
    """Convert raw stats into priority weight multipliers.

    Strategies with fewer than ``min_samples`` observations keep the
    default weight (no adjustment from sparse data).

    Weight range: 0.5 (strategy always misses) to 2.0 (strategy
    always finds something). The formula uses a Bayesian prior of
    1 win + 1 miss (Laplace smoothing) so a strategy with 0/10
    gets 0.55 not 0.5.

    Args:
        stats: Output of ``aggregate_strategy_stats``.
        min_samples: Minimum reviews before adjusting weight.
        default_weight: Weight for strategies with insufficient data.

    Returns:
        Mapping of strategy name to weight multiplier.
    """
    weights: dict[str, float] = {}
    for strat, counts in stats.items():
        total = counts["total"]
        if total < min_samples:
            weights[strat] = default_weight
            continue
        wins = counts["wins"]
        rate = (wins + 1) / (total + 2)
        weights[strat] = 0.5 + 1.5 * rate
    return weights


def find_project_log_dirs(
    out_dir: Path,
    *,
    max_dirs: int = 20,
    target_path: Path | None = None,
) -> list[Path]:
    """Find audit log directories from prior runs in a project.

    Searches sibling directories of ``out_dir`` for audit logs,
    excluding the current run. When *target_path* is given, only
    includes siblings whose manifest records the same target —
    prevents cross-project contamination in shared parent dirs.

    Returns at most ``max_dirs`` most recent directories (sorted
    by mtime descending).
    """
    parent = out_dir.parent
    if not parent.is_dir():
        return []

    candidates: list[Path] = []
    try:
        for child in parent.iterdir():
            if not child.is_dir():
                continue
            if child == out_dir:
                continue
            log_path = child / ".audit-log.jsonl"
            if not log_path.exists():
                continue
            if target_path is not None:
                manifest = child / ".raptor-run.json"
                if manifest.exists():
                    try:
                        with open(manifest, encoding="utf-8") as f:
                            m = json.load(f)
                        sibling_target = m.get("target_path") or m.get("target", "")
                        if sibling_target and Path(sibling_target).resolve() != target_path.resolve():
                            continue
                    except (json.JSONDecodeError, OSError):
                        continue
                else:
                    continue
            candidates.append(child)
    except OSError:
        return []

    # A sibling can be deleted between iterdir() and the sort (e.g. a
    # concurrent `/project clean --keep N`); an unguarded stat() would
    # raise and crash the audit prep phase.
    candidates.sort(key=_safe_mtime, reverse=True)
    return candidates[:max_dirs]


def _safe_mtime(p: Path) -> float:
    """mtime that survives the path racing away (same as binary_bridge)."""
    try:
        return p.stat().st_mtime
    except OSError:
        return 0.0


def load_strategy_weights(
    out_dir: Path,
    *,
    min_samples: int = 10,
    target_path: Path | None = None,
) -> dict[str, float] | None:
    """Load strategy weights from prior runs in the same project.

    Returns None when no prior data is available. Returns a weight
    dict when at least one prior run has strategy-annotated entries.
    """
    log_dirs = find_project_log_dirs(out_dir, target_path=target_path)
    if not log_dirs:
        return None
    stats = aggregate_strategy_stats(log_dirs)
    if not stats:
        return None
    weights = compute_strategy_weights(stats, min_samples=min_samples)
    logger.info(
        "strategy weights from %d prior runs: %s",
        len(log_dirs),
        {k: f"{v:.2f}" for k, v in sorted(weights.items())},
    )
    return weights

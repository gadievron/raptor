"""Bump-time supply-chain evaluation.

The scan-time supply-chain detectors (in ``packages/sca/supply_chain/``)
fire against the CURRENT state of a target's dep graph. The bumper
needs a different shape: given a proposed ``(current, target)``
version pair for one dep, what supply-chain red flags fire on the
proposed bump SPECIFICALLY?

This module provides ``evaluate_bump_supply_chain`` — the bumper
calls it once per dep it's considering bumping, and the resulting
findings flow into ``review._compute_verdict``'s
``bump_supply_chain_findings=`` parameter to gate the bump.

Detectors ship incrementally. Phase 1.b only emits
``recent_publish`` on the target version (rapid-release attack
class). Phase 1.c will add maintainer-change-between-versions
once the per-version maintainer extraction is sorted per
ecosystem. Phase 1.d adds install-hook delta (npm-specific
initially)."""

from packages.sca.bump.evaluator import (
    evaluate_bump_supply_chain,
)

__all__ = ["evaluate_bump_supply_chain"]

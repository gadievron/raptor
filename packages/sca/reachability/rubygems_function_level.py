"""RubyGems function-level reachability tier.

Sibling of the PyPI / npm / Go / Java / Cargo tiers. Consumes
Ruby call-graph data emitted by
``core.inventory.call_graph.extract_call_graph_ruby`` and runs
the cross-language resolver against OSV symbol data.

## Verdict transitions

  * Any affected symbol CALLED -> ``likely_called``
  * All affected symbols NOT_CALLED, none UNCERTAIN ->
    ``not_function_reachable``
  * Any UNCERTAIN OR mixed -> preserve existing verdict

## Qualified-name shape

Ruby OSV records ship symbols as Ruby module / class paths
(``ActionDispatch::Routing::Mapper#draw``). We construct
``<gem>.<symbol>`` and let the resolver match. The Ruby extractor
produces chains like ``["JSON", "parse"]`` for ``JSON.parse(s)``;
the resolver tail-matches against ``json.parse``.

Limitation: Ruby's metaprogramming (define_method, method_missing,
send) defeats static analysis; the extractor flags ``send`` /
``eval`` as ``INDIRECTION_REFLECT`` so the resolver returns
UNCERTAIN rather than NOT_CALLED in those cases.
"""

from __future__ import annotations

import logging
from typing import Any, TYPE_CHECKING

from ..models import Confidence, Dependency, Reachability
from ._shared import extract_qualified_symbols as _extract_qualified

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

logger = logging.getLogger(__name__)


def build_rubygems_symbol_map(
    osv_results: Iterable[Any] | None,
) -> dict[str, list[str]]:
    if not osv_results:
        return {}
    out: dict[str, list[str]] = {}
    for r in osv_results:
        if not hasattr(r, "advisories"):
            continue
        dep_key = getattr(r, "dep_key", None)
        if not dep_key or not dep_key.startswith("RubyGems:"):
            continue
        dep_name = dep_key.split(":", 1)[1].split("@", 1)[0]
        qualified: list[str] = []
        for adv in r.advisories:
            qualified.extend(_extract_qualified(adv, dep_name))
        if qualified:
            out.setdefault(dep_key, []).extend(qualified)
    return {k: list(dict.fromkeys(v)) for k, v in out.items()}


def refine_rubygems_verdicts(
    deps: list[Dependency],
    out: dict[str, Reachability],
    *,
    target: Path,
    rubygems_symbol_map: dict[str, list[str]],
    inventory: dict[str, Any] | None = None,
) -> None:
    candidates = [
        d for d in deps
        if d.ecosystem == "RubyGems"
        and out.get(d.key()) is not None
        and out[d.key()].verdict == "imported"
        and rubygems_symbol_map.get(d.key())
    ]
    if not candidates:
        return

    if inventory is None:
        try:
            from core.inventory.builder import build_inventory
            import tempfile
            with tempfile.TemporaryDirectory() as td:
                inventory = build_inventory(str(target), td)
        except Exception:                           # noqa: BLE001
            logger.warning(
                "sca.reachability.rubygems_function_level: inventory "
                "build failed; skipping function-level tier",
                exc_info=True,
            )
            return

    from core.analysis.reachability import Verdict, function_called

    for d in candidates:
        qualified_names = rubygems_symbol_map[d.key()]
        paired = []
        for qn in qualified_names:
            if "." not in qn:
                continue
            try:
                paired.append((qn, function_called(inventory, qn)))
            except ValueError:
                continue
        if not paired:
            continue
        verdicts = {r.verdict for _, r in paired}
        if Verdict.CALLED in verdicts:
            evidence: list[str] = []
            called: list[str] = []
            for qn, r in paired:
                if r.verdict == Verdict.CALLED:
                    called.append(qn)
                    evidence.extend(f"{p}:{ln}" for p, ln in r.evidence)
            from ._host_reachability import classify_called_or_dead
            affected = ", ".join(sorted(set(called)))
            out[d.key()] = classify_called_or_dead(
                inventory, evidence,
                likely_called_reason=(
                    "OSV-listed affected symbol called from "
                    f"project Ruby source: {affected}"
                ),
                affected_summary=affected,
            )
        elif Verdict.UNCERTAIN in verdicts:
            continue
        else:
            out[d.key()] = Reachability(
                verdict="not_function_reachable",
                confidence=Confidence(
                    "high",
                    reason=(
                        f"gem imported but the {len(paired)} "
                        f"OSV-listed affected symbol(s) are not called "
                        f"from non-test Ruby source"
                    ),
                ),
                evidence=[],
            )


__all__ = ["build_rubygems_symbol_map", "refine_rubygems_verdicts"]

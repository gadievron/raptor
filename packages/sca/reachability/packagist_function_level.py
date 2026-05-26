"""Packagist (PHP / Composer) function-level reachability tier.

Sibling of the PyPI / npm / Go / Java / Cargo / RubyGems / NuGet
tiers. Consumes PHP call-graph data emitted by
``core.inventory.call_graph.extract_call_graph_php`` and runs the
cross-language resolver against OSV symbol data.

## Verdict transitions

  * Any affected symbol CALLED -> ``likely_called``
  * All affected symbols NOT_CALLED, none UNCERTAIN ->
    ``not_function_reachable``
  * Any UNCERTAIN OR mixed -> preserve existing verdict

## Qualified-name shape

PHP / Packagist OSV records ship symbols as fully-qualified
namespace paths (``Symfony\\Component\\HttpFoundation\\Request::create``).
The PHP extractor binds ``use Foo\\Bar\\Baz;`` ->
``imports["Baz"] = "Foo\\Bar\\Baz"``; chains like
``["Baz", "method"]`` resolve via the import map.

Limitation: ``call_user_func`` / variable callables / ``$$var``
indirection is flagged as ``INDIRECTION_REFLECT`` so the resolver
returns UNCERTAIN. Direct static class/method calls work cleanly.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from ..models import Confidence, Dependency, Reachability

logger = logging.getLogger(__name__)


def build_packagist_symbol_map(
    osv_results: Optional[Iterable[Any]],
) -> Dict[str, List[str]]:
    if not osv_results:
        return {}
    out: Dict[str, List[str]] = {}
    for r in osv_results:
        if not hasattr(r, "advisories"):
            continue
        dep_key = getattr(r, "dep_key", None)
        if not dep_key or not dep_key.startswith("Packagist:"):
            continue
        dep_name = dep_key.split(":", 1)[1].split("@", 1)[0]
        qualified: List[str] = []
        for adv in r.advisories:
            qualified.extend(_extract_qualified(adv, dep_name))
        if qualified:
            out.setdefault(dep_key, []).extend(qualified)
    return {k: list(dict.fromkeys(v)) for k, v in out.items()}


def _extract_qualified(advisory: Any, dep_name: str) -> List[str]:
    out: List[str] = []
    es = getattr(advisory, "ecosystem_specific", None) or {}
    ds = getattr(advisory, "database_specific", None) or {}
    for source in (es, ds):
        if not isinstance(source, dict):
            continue
        for imp in source.get("imports") or []:
            if not isinstance(imp, dict):
                continue
            path = imp.get("path") or dep_name
            symbols = imp.get("symbols") or []
            for s in symbols:
                if isinstance(s, str) and s and isinstance(path, str):
                    out.append(f"{path}.{s}")
        for key in ("affected_symbols", "affected_functions"):
            v = source.get(key)
            if isinstance(v, list) and dep_name:
                for s in v:
                    if isinstance(s, str):
                        out.append(f"{dep_name}.{s}")
    return out


def refine_packagist_verdicts(
    deps: List[Dependency],
    out: Dict[str, Reachability],
    *,
    target: Path,
    packagist_symbol_map: Dict[str, List[str]],
    inventory: Optional[Dict[str, Any]] = None,
) -> None:
    candidates = [
        d for d in deps
        if d.ecosystem == "Packagist"
        and out.get(d.key()) is not None
        and out[d.key()].verdict == "imported"
        and packagist_symbol_map.get(d.key())
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
                "sca.reachability.packagist_function_level: inventory "
                "build failed; skipping function-level tier",
                exc_info=True,
            )
            return

    from core.inventory.reachability import Verdict, function_called

    for d in candidates:
        qualified_names = packagist_symbol_map[d.key()]
        results = []
        for qn in qualified_names:
            if "." not in qn:
                continue
            try:
                results.append(function_called(inventory, qn))
            except ValueError:
                continue
        if not results:
            continue
        verdicts = {r.verdict for r in results}
        if Verdict.CALLED in verdicts:
            evidence: List[str] = []
            called: List[str] = []
            for qn, r in zip(qualified_names, results):
                if r.verdict == Verdict.CALLED:
                    called.append(qn)
                    evidence.extend(f"{p}:{ln}" for p, ln in r.evidence)
            from ._host_reachability import classify_called_or_dead
            affected = ", ".join(sorted(set(called)))
            out[d.key()] = classify_called_or_dead(
                inventory, evidence,
                likely_called_reason=(
                    "OSV-listed affected symbol called from "
                    f"project PHP source: {affected}"
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
                        f"package imported but the {len(qualified_names)} "
                        f"OSV-listed affected symbol(s) are not called "
                        f"from non-test PHP source"
                    ),
                ),
                evidence=[],
            )


__all__ = ["build_packagist_symbol_map", "refine_packagist_verdicts"]

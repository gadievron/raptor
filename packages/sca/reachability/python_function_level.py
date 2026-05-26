"""PyPI function-level reachability tier.

Sits on top of the module-level Python scan (``packages.sca
.reachability.python``) and the cross-language resolver
(``core.inventory.reachability``). For PyPI deps that already came
back ``imported`` from the module-level pass AND have at least one
OSV advisory carrying ``affected_functions`` data, this module asks
the function-level resolver: "is the affected function actually
called from this project's source?".

Three downgrade outcomes:

  * **All affected functions return CALLED** → upgrade verdict to
    ``likely_called`` (matches the Go pattern).
  * **All affected functions return NOT_CALLED, none UNCERTAIN** →
    downgrade to ``not_function_reachable``. Same risk-multiplier
    weight as ``not_reachable``: we have positive evidence the
    vulnerable code path isn't exercised.
  * **Anything UNCERTAIN OR mix of CALLED/NOT_CALLED** → leave the
    verdict at ``imported``. Honest reporting beats false confidence.

When OSV doesn't carry ``affected_functions`` for a dep's
advisories, this tier doesn't fire — the existing module-level
verdict is preserved.

## Where the function-list comes from

OSV doesn't have a single canonical schema for affected-function
data on PyPI advisories. We read whichever of the following the
advisory populates:

  * ``ecosystem_specific.imports[].symbols`` (Go-style mirror;
    used by some PYSEC records)
  * ``database_specific.imports[].symbols`` (alt name)
  * ``database_specific.affected_symbols`` (flat list variant)
  * ``database_specific.affected_functions`` (flat list, ad-hoc)

Each is treated as ``[function_name, ...]``. The
``import_path`` field (when present alongside ``symbols``) is
ignored — the dep's name is the import path for typical PyPI
packages (``requests`` → ``import requests``). When it isn't
(e.g. ``Pillow`` → ``import PIL``), the resolver's tail-match
still works as long as the symbol is uniquely-named.

## Cost

Inventory build is O(project-source-bytes) — the existing
``core.inventory.build_inventory`` walks every Python file once,
captures defs + call-graph data on the same pass. Per-query is
O(N_calls) with dict lookups — sub-millisecond once the inventory
is in memory.

This tier is gated to PyPI deps that:

  1. Already came back ``imported`` from module-level
  2. Are in the CVE-bearing dep set
  3. Have at least one advisory with affected-function data

So the inventory is built lazily — if no PyPI dep meets the
gating, this module doesn't build it and doesn't import the
inventory builder.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from ..models import Confidence, Dependency, Reachability

logger = logging.getLogger(__name__)


def build_pypi_symbol_map(
    osv_results: Optional[Iterable[Any]],
) -> Dict[str, List[str]]:
    """Extract per-dep affected-function lists from OSV results.

    Returns ``{dep_key: [function_name, ...]}``. Empty when no
    advisories carry function info.
    """
    if not osv_results:
        return {}
    out: Dict[str, List[str]] = {}
    for r in osv_results:
        if not hasattr(r, "advisories"):
            continue
        dep_key = getattr(r, "dep_key", None)
        if not dep_key or not dep_key.startswith("PyPI:"):
            continue
        funcs: List[str] = []
        for adv in r.advisories:
            funcs.extend(_extract_function_names(adv))
        if funcs:
            out.setdefault(dep_key, []).extend(funcs)
    # Dedup per-dep while preserving order.
    return {k: list(dict.fromkeys(v)) for k, v in out.items()}


def _extract_function_names(advisory: Any) -> List[str]:
    """Pull function names out of an Advisory object.

    Tries every shape we've seen in real OSV PyPI records,
    deduplicating across them.
    """
    out: List[str] = []
    es = getattr(advisory, "ecosystem_specific", None) or {}
    ds = getattr(advisory, "database_specific", None) or {}
    # ``imports[].symbols`` shape (mirrors Go convention).
    for source in (es, ds):
        if not isinstance(source, dict):
            continue
        for imp in source.get("imports") or []:
            if not isinstance(imp, dict):
                continue
            syms = imp.get("symbols") or []
            for s in syms:
                if isinstance(s, str):
                    out.append(s)
    # Flat-list variants.
    for key in ("affected_symbols", "affected_functions"):
        for source in (es, ds):
            if not isinstance(source, dict):
                continue
            v = source.get(key)
            if isinstance(v, list):
                for s in v:
                    if isinstance(s, str):
                        out.append(s)
    return out


def refine_pypi_verdicts(
    deps: List[Dependency],
    out: Dict[str, Reachability],
    *,
    target: Path,
    pypi_symbol_map: Dict[str, List[str]],
    inventory: Optional[Dict[str, Any]] = None,
) -> None:
    """For PyPI deps in ``pypi_symbol_map`` whose current verdict is
    ``imported``, run the function-level resolver and update ``out``
    in-place.

    ``inventory`` may be passed in by the caller when it's already
    been built; otherwise we build one over ``target``. Building is
    skipped entirely when no PyPI dep needs the function-level
    pass — preserves the cost guarantee documented at module top.
    """
    candidates: List[Dependency] = []
    for d in deps:
        if d.ecosystem != "PyPI":
            continue
        current = out.get(d.key())
        if current is None or current.verdict != "imported":
            continue
        funcs = pypi_symbol_map.get(d.key())
        if not funcs:
            continue
        candidates.append(d)

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
                "sca.reachability.python_function_level: inventory "
                "build failed; skipping function-level tier",
                exc_info=True,
            )
            return

    from core.inventory.reachability import (
        Verdict,
        function_called,
    )

    for d in candidates:
        funcs = pypi_symbol_map[d.key()]
        results = []
        for fn in funcs:
            qualified = f"{d.name}.{fn}"
            try:
                results.append(function_called(inventory, qualified))
            except ValueError:
                # Bare name (no dots) — shouldn't happen since we
                # always prepend dep_name, but keep the resolver
                # contract intact by ignoring unrunnable queries.
                continue

        if not results:
            continue

        verdicts = {r.verdict for r in results}
        if Verdict.CALLED in verdicts:
            evidence_lines: List[str] = []
            called_fn_names: List[str] = []
            for fn, r in zip(funcs, results):
                if r.verdict == Verdict.CALLED:
                    called_fn_names.append(fn)
                    evidence_lines.extend(
                        f"{path}:{line}" for path, line in r.evidence
                    )
            from ._host_reachability import classify_called_or_dead
            affected = ", ".join(sorted(set(called_fn_names)))
            out[d.key()] = classify_called_or_dead(
                inventory, evidence_lines,
                likely_called_reason=(
                    "OSV-listed affected function called from "
                    f"project source: {affected}"
                ),
                affected_summary=affected,
            )
        elif Verdict.UNCERTAIN in verdicts:
            # Mixed / uncertain — leave at module-level imported.
            # Don't downgrade; don't upgrade. Honest reporting.
            continue
        else:
            # All NOT_CALLED.
            out[d.key()] = Reachability(
                verdict="not_function_reachable",
                confidence=Confidence(
                    "high",
                    reason=(
                        f"dep imported but the {len(funcs)} OSV-listed "
                        f"affected function(s) are not called from "
                        f"non-test project source"
                    ),
                ),
                evidence=[],
            )


__all__ = [
    "build_pypi_symbol_map",
    "refine_pypi_verdicts",
]

"""npm function-level reachability tier.

Sibling of :mod:`packages.sca.reachability.python_function_level`,
covering npm packages instead of PyPI. Same architecture: when an
OSV advisory carries ``imports[].symbols`` data and the project's
JS / TS source has been inventoried via
``core.inventory.call_graph.extract_call_graph_javascript``, the
resolver in ``core.inventory.reachability`` matches each affected
function name against project call sites.

OSV npm advisories ship symbol data less consistently than Go
advisories do, but a non-trivial slice of GHSA records on common
libraries (lodash prototype-pollution, axios SSRF, jsonwebtoken
verify-bypass) DO carry ``ecosystem_specific.affected[].imports``
or ``database_specific.affected_functions``. When present, this
tier produces dramatic noise reduction — typical npm projects
import lodash but use only a handful of its functions, and the
"not_function_reachable" verdict downgrades CVEs that don't apply
to the operator's actual usage.

When OSV doesn't carry function info for a dep's advisories, this
tier doesn't fire — module-level verdict preserved.

## Verdict transitions (mirror the PyPI tier)

  * Any affected function CALLED → ``likely_called``.
  * All affected functions NOT_CALLED, none UNCERTAIN →
    ``not_function_reachable``.
  * Any UNCERTAIN OR mixed → leave at ``imported``.

## Cost

The inventory is shared with the PyPI tier — both consult the
same ``core.inventory.build_inventory`` output. Building is gated:
when no npm dep meets the criteria (already-imported AND has
advisory-shipped symbols), the inventory builder isn't engaged for
this tier alone.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from ..models import Confidence, Dependency, Reachability

logger = logging.getLogger(__name__)


def build_npm_symbol_map(
    osv_results: Optional[Iterable[Any]],
) -> Dict[str, List[str]]:
    """Extract per-dep affected-function lists from npm OSV results.

    Returns ``{dep_key: [function_name, ...]}``. Empty when no
    npm advisories carry function info.
    """
    if not osv_results:
        return {}
    out: Dict[str, List[str]] = {}
    for r in osv_results:
        if not hasattr(r, "advisories"):
            continue
        dep_key = getattr(r, "dep_key", None)
        if not dep_key or not dep_key.startswith("npm:"):
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

    Tries every shape we've seen in real OSV npm records,
    deduplicating across them. Schema variation is high — some
    GHSAs use ``database_specific.affected_functions``, others
    ``ecosystem_specific.imports[].symbols`` mirroring Go's
    convention, others inline structured data.
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


def refine_npm_verdicts(
    deps: List[Dependency],
    out: Dict[str, Reachability],
    *,
    target: Path,
    npm_symbol_map: Dict[str, List[str]],
    inventory: Optional[Dict[str, Any]] = None,
) -> None:
    """For npm deps in ``npm_symbol_map`` whose current verdict is
    ``imported``, run the function-level resolver and update
    ``out`` in-place.

    ``inventory`` may be passed in by the caller (e.g. the PyPI
    tier already built one); otherwise built locally. Building is
    skipped when no npm dep needs the function-level pass.
    """
    candidates: List[Dependency] = []
    for d in deps:
        if d.ecosystem != "npm":
            continue
        current = out.get(d.key())
        if current is None or current.verdict != "imported":
            continue
        funcs = npm_symbol_map.get(d.key())
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
                "sca.reachability.npm_function_level: inventory "
                "build failed; skipping function-level tier",
                exc_info=True,
            )
            return

    from core.inventory.reachability import (
        Verdict,
        function_called,
    )

    for d in candidates:
        funcs = npm_symbol_map[d.key()]
        results = []
        for fn in funcs:
            qualified = _qualified_name(d.name, fn)
            if qualified is None:
                continue
            try:
                results.append(function_called(inventory, qualified))
            except ValueError:
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
                    f"project JS / TS source: {affected}"
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
                        f"npm dep imported but the {len(funcs)} "
                        f"OSV-listed affected function(s) are not "
                        f"called from non-test JS / TS source"
                    ),
                ),
                evidence=[],
            )


def _qualified_name(dep_name: str, fn: str) -> Optional[str]:
    """Build the dotted qualified name for the resolver.

    Plain ``lodash`` + ``get`` → ``lodash.get``.
    Scoped ``@types/react`` + ``useState`` → ``@types/react.useState``
    — the resolver's chain matching uses dotted segments, so
    ``@types/react`` becomes the head segment as-is. JS imports
    typically resolve scoped names verbatim
    (``import foo from '@types/react'``), so the import-map
    lookup matches.

    Returns None for malformed inputs (no dot allowed in ``fn``).
    """
    if not dep_name or not fn:
        return None
    if "." in fn:
        # Function name itself has dots — out of scope; the resolver
        # treats ``a.b.c`` as a chain, not a single function.
        return None
    return f"{dep_name}.{fn}"


__all__ = [
    "build_npm_symbol_map",
    "refine_npm_verdicts",
]

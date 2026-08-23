"""npm function-level reachability tier.

Sibling of :mod:`packages.sca.reachability.python_function_level`,
covering npm packages instead of PyPI. Same architecture: when an
OSV advisory carries ``imports[].symbols`` data and the project's
JS / TS source has been inventoried via
``core.inventory.call_graph.extract_call_graph_javascript``, the
resolver in ``core.analysis.reachability`` matches each affected
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
from typing import Any, TYPE_CHECKING

from ..models import Confidence, Dependency, Reachability
from ._shared import extract_function_names as _extract_function_names

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

logger = logging.getLogger(__name__)


def build_npm_symbol_map(
    osv_results: Iterable[Any] | None,
) -> dict[str, list[str]]:
    """Extract per-dep affected-function lists from npm OSV results.

    Returns ``{dep_key: [function_name, ...]}``. Empty when no
    npm advisories carry function info.
    """
    if not osv_results:
        return {}
    out: dict[str, list[str]] = {}
    for r in osv_results:
        if not hasattr(r, "advisories"):
            continue
        dep_key = getattr(r, "dep_key", None)
        if not dep_key or not dep_key.startswith("npm:"):
            continue
        funcs: list[str] = []
        for adv in r.advisories:
            funcs.extend(_extract_function_names(adv))
        if funcs:
            out.setdefault(dep_key, []).extend(funcs)
    # Dedup per-dep while preserving order.
    return {k: list(dict.fromkeys(v)) for k, v in out.items()}


def refine_npm_verdicts(
    deps: list[Dependency],
    out: dict[str, Reachability],
    *,
    target: Path,
    npm_symbol_map: dict[str, list[str]],
    inventory: dict[str, Any] | None = None,
) -> None:
    """For npm deps in ``npm_symbol_map`` whose current verdict is
    ``imported``, run the function-level resolver and update
    ``out`` in-place.

    ``inventory`` may be passed in by the caller (e.g. the PyPI
    tier already built one); otherwise built locally. Building is
    skipped when no npm dep needs the function-level pass.
    """
    candidates: list[Dependency] = []
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

    from core.analysis.reachability import (
        Verdict,
        function_called,
    )

    for d in candidates:
        funcs = npm_symbol_map[d.key()]
        paired = []
        for fn in funcs:
            qualified = _qualified_name(d.name, fn)
            if qualified is None:
                continue
            try:
                paired.append((fn, function_called(inventory, qualified)))
            except ValueError:
                continue

        if not paired:
            continue

        verdicts = {r.verdict for _, r in paired}
        if Verdict.CALLED in verdicts:
            evidence_lines: list[str] = []
            called_fn_names: list[str] = []
            for fn, r in paired:
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
                        f"npm dep imported but the {len(paired)} "
                        f"OSV-listed affected function(s) are not "
                        f"called from non-test JS / TS source"
                    ),
                ),
                evidence=[],
            )


def _qualified_name(dep_name: str, fn: str) -> str | None:
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

"""Java (Maven) function-level reachability tier.

Sibling of the PyPI / npm / Go tiers, covering Maven coordinates
now that the Java call-graph extractor in
``core.inventory.call_graph`` emits the same ``FileCallGraph`` shape
the resolver consumes.

Maven is unique among the function-level tiers in that there is
*no* module-level Maven scanner — Maven deps come into ``scan()``
with verdict ``not_evaluated``. So this tier is gated on both
``imported`` (in case a future module-level scanner is added) AND
``not_evaluated`` (current state). When OSV ships per-symbol info
the tier promotes to ``likely_called`` or downgrades to
``not_function_reachable``; otherwise the verdict is preserved.

## Verdict transitions

  * Any affected method CALLED → ``likely_called``.
  * All affected methods NOT_CALLED, none UNCERTAIN →
    ``not_function_reachable``.
  * Any UNCERTAIN OR mixed → leave at the existing verdict.

## Qualified-name shape

Java OSV records (when symbol info is present at all) follow the
same Go-style convention:

  * ``ecosystem_specific.imports[].path`` is the Java package, e.g.
    ``com.fasterxml.jackson.databind``.
  * ``ecosystem_specific.imports[].symbols`` is a list of
    ``Class.method`` or ``Class$Inner.method`` strings.

We emit the qualified name ``<path>.<symbol>`` = ``com.fasterxml
.jackson.databind.ObjectMapper.readValue``. The Java extractor's
import map binds short names like ``ObjectMapper`` to their full
package + class path, so the chain ``["ObjectMapper", "readValue"]``
generated from a project-source call resolves to the OSV qualified
name.

## Limitation

Instance-method dispatch where the variable name doesn't match the
type (``ObjectMapper mapper = new ObjectMapper(); mapper
.readValue(...)``) won't bind through the static import map and so
won't resolve to the OSV symbol. Static and class-level calls
(``ObjectMapper.SOME_METHOD()``, ``Class.staticMethod()``) work
correctly. Same family of limitation as Go interface dispatch and
Python method-on-instance.

The flat fallback shapes (``affected_functions`` /
``affected_symbols`` without a path) are skipped for Java — unlike
Go where the dep name equals the import path, Maven dep names
(``groupId:artifactId``) are not Java packages, so the dep name
alone can't form a valid qualified name.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from ..models import Confidence, Dependency, Reachability

logger = logging.getLogger(__name__)


def build_maven_symbol_map(
    osv_results: Optional[Iterable[Any]],
) -> Dict[str, List[str]]:
    """Extract per-dep qualified-name targets from Maven OSV results.

    Returns ``{dep_key: [qualified_name, ...]}``. Each qualified
    name is ``<advisory_import_path>.<symbol>`` — Java OSV records
    pair each symbol with the affected Java package
    (``imports[].path``).

    Empty when no Maven advisories carry symbol info.
    """
    if not osv_results:
        return {}
    out: Dict[str, List[str]] = {}
    for r in osv_results:
        if not hasattr(r, "advisories"):
            continue
        dep_key = getattr(r, "dep_key", None)
        if not dep_key or not dep_key.startswith("Maven:"):
            continue
        qualified: List[str] = []
        for adv in r.advisories:
            qualified.extend(_extract_qualified(adv))
        if qualified:
            out.setdefault(dep_key, []).extend(qualified)
    return {k: list(dict.fromkeys(v)) for k, v in out.items()}


def _extract_qualified(advisory: Any) -> List[str]:
    """Pull ``<package>.<symbol>`` qualified names out of an Advisory.

    Reads ``ecosystem_specific.imports[].path`` and
    ``ecosystem_specific.imports[].symbols``, plus the same shape
    under ``database_specific``. Skips entries without a path —
    the Maven dep name is ``groupId:artifactId``, not a Java
    package, so we can't synthesise a qualified name from it.
    """
    out: List[str] = []
    es = getattr(advisory, "ecosystem_specific", None) or {}
    ds = getattr(advisory, "database_specific", None) or {}
    for source in (es, ds):
        if not isinstance(source, dict):
            continue
        for imp in source.get("imports") or []:
            if not isinstance(imp, dict):
                continue
            path = imp.get("path")
            if not isinstance(path, str) or not path:
                continue
            symbols = imp.get("symbols") or []
            for s in symbols:
                if isinstance(s, str) and s:
                    out.append(f"{path}.{s}")
    return out


def refine_maven_verdicts(
    deps: List[Dependency],
    out: Dict[str, Reachability],
    *,
    target: Path,
    maven_symbol_map: Dict[str, List[str]],
    inventory: Optional[Dict[str, Any]] = None,
) -> None:
    """For Maven deps in ``maven_symbol_map`` whose current verdict
    is ``imported`` or ``not_evaluated``, run the function-level
    resolver and update ``out`` in-place.

    Maven has no module-level scanner so the typical starting
    verdict is ``not_evaluated``. We accept either gate so the tier
    works today AND continues to work if a module-level Maven
    scanner is added later.
    """
    candidates: List[Dependency] = []
    for d in deps:
        if d.ecosystem != "Maven":
            continue
        current = out.get(d.key())
        if current is None:
            continue
        if current.verdict not in ("imported", "not_evaluated"):
            continue
        symbols = maven_symbol_map.get(d.key())
        if not symbols:
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
                "sca.reachability.java_function_level: inventory "
                "build failed; skipping function-level tier",
                exc_info=True,
            )
            return

    from core.inventory.reachability import (
        Verdict,
        function_called,
    )

    for d in candidates:
        qualified_names = maven_symbol_map[d.key()]
        results = []
        for qualified in qualified_names:
            if not qualified or "." not in qualified:
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
            called_qns: List[str] = []
            for qn, r in zip(qualified_names, results):
                if r.verdict == Verdict.CALLED:
                    called_qns.append(qn)
                    evidence_lines.extend(
                        f"{path}:{line}" for path, line in r.evidence
                    )
            from ._host_reachability import classify_called_or_dead
            affected = ", ".join(sorted(set(called_qns)))
            out[d.key()] = classify_called_or_dead(
                inventory, evidence_lines,
                likely_called_reason=(
                    "OSV-listed affected symbol called from "
                    f"project Java source: {affected}"
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
                        f"Maven dep declared but the "
                        f"{len(qualified_names)} OSV-listed "
                        f"affected symbol(s) are not called from "
                        f"non-test Java source"
                    ),
                ),
                evidence=[],
            )


__all__ = [
    "build_maven_symbol_map",
    "refine_maven_verdicts",
]

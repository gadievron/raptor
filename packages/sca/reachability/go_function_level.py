"""Go function-level reachability tier.

Sibling of the PyPI / npm tiers, covering Go modules now that the
Go call-graph extractor in ``core.inventory.call_graph`` emits the
same ``FileCallGraph`` shape the resolver consumes.

The Go module-level reachability already harvests
``ecosystem_specific.imports[].symbols`` from OSV advisories (in
``_build_go_symbol_map``) and uses them for module-level matching.
This tier consumes the same symbol set but matches against actual
call sites in the project's Go source — distinguishing "your code
imports the affected module AND calls the vulnerable function"
from "your code only imports the module".

Of all the ecosystems wired in SCA today, Go has the most reliable
OSV symbol data. Go's `vulncheck` ecosystem standard ships
``imports[].symbols`` with practically every advisory, so this
tier produces meaningful noise reduction on virtually every CVE
match against Go projects.

## Verdict transitions (mirror the PyPI + npm tiers)

  * Any affected function CALLED → ``likely_called``.
  * All affected functions NOT_CALLED, none UNCERTAIN →
    ``not_function_reachable``.
  * Any UNCERTAIN OR mixed → leave at ``imported``.

## Qualified-name shape

OSV's Go symbols come in two shapes per advisory:

  * Plain function: ``HandlerFunc`` — top-level package function.
  * Method: ``Server.ServeHTTP`` — method on a type, where ``Server``
    is the type name.

For both, the resolver's chain matching uses the dotted path
``<module_path>.<symbol>`` — e.g. ``net/http.HandlerFunc`` or
``net/http.Server.ServeHTTP``. The Go extractor's import map
preserves slashes in the value (``imports["http"] = "net/http"``)
so the chain ``["http", "HandlerFunc"]`` resolves to
``"net/http" + "." + "HandlerFunc" = "net/http.HandlerFunc"``,
matching the OSV symbol shape.

For method symbols (``Type.Method``), the chain is
``["http", "Server", "ServeHTTP"]`` — still resolves correctly
because the resolver concatenates middle parts.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from ..models import Confidence, Dependency, Reachability

logger = logging.getLogger(__name__)


def build_go_symbol_map(
    osv_results: Optional[Iterable[Any]],
) -> Dict[str, List[str]]:
    """Extract per-dep qualified-name targets from Go OSV results.

    Returns ``{dep_key: [qualified_name, ...]}``. Each qualified
    name is ``<advisory_import_path>.<symbol>`` — Go OSV records
    pair each symbol with the specific sub-package it lives in
    (``imports[].path``), which is often a sub-module of the dep
    (``golang.org/x/crypto/ssh.ParsePrivateKey`` lives under
    ``golang.org/x/crypto`` but the actual import path in
    project source is the sub-module).

    The resolver matches against this qualified name as-is —
    chain comparison handles slashes in the head and dots in the
    tail, so ``imports[].path = "golang.org/x/crypto/ssh"`` plus
    a project chain ``["ssh", "ParsePrivateKey"]`` (where
    ``imports["ssh"] = "golang.org/x/crypto/ssh"``) resolves to a
    match against ``"golang.org/x/crypto/ssh.ParsePrivateKey"``.

    Empty when no Go advisories carry symbol info.
    """
    if not osv_results:
        return {}
    out: Dict[str, List[str]] = {}
    for r in osv_results:
        if not hasattr(r, "advisories"):
            continue
        dep_key = getattr(r, "dep_key", None)
        if not dep_key or not dep_key.startswith("Go:"):
            continue
        # Default fallback path = the dep's name (used for the
        # rare ``affected_functions`` flat shape that doesn't
        # carry a separate path).
        dep_name = dep_key.split(":", 1)[1].split("@", 1)[0]
        qualified: List[str] = []
        for adv in r.advisories:
            qualified.extend(_extract_qualified(adv, dep_name))
        if qualified:
            out.setdefault(dep_key, []).extend(qualified)
    return {k: list(dict.fromkeys(v)) for k, v in out.items()}


def _extract_qualified(advisory: Any, dep_name: str) -> List[str]:
    """Pull ``<path>.<symbol>`` qualified names out of an Advisory.

    Go advisories canonically use ``ecosystem_specific.imports[]
    .symbols`` paired with ``imports[].path`` (the affected
    sub-package). For each ``(path, symbol)`` pair we emit
    ``"<path>.<symbol>"``.

    Flat fallback shapes (``affected_symbols`` /
    ``affected_functions``) lack a per-symbol path; for those we
    emit ``"<dep_name>.<symbol>"`` — operator gets module-level
    matching for that case.
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
            symbols = imp.get("symbols") or []
            for s in symbols:
                if not isinstance(s, str):
                    continue
                head = path if isinstance(path, str) and path else dep_name
                if not head:
                    continue
                out.append(f"{head}.{s}")
    # Flat-list fallback — no per-symbol path.
    for key in ("affected_symbols", "affected_functions"):
        for source in (es, ds):
            if not isinstance(source, dict):
                continue
            v = source.get(key)
            if isinstance(v, list):
                for s in v:
                    if isinstance(s, str) and dep_name:
                        out.append(f"{dep_name}.{s}")
    return out


def refine_go_verdicts(
    deps: List[Dependency],
    out: Dict[str, Reachability],
    *,
    target: Path,
    go_symbol_map: Dict[str, List[str]],
    inventory: Optional[Dict[str, Any]] = None,
) -> None:
    """For Go deps in ``go_symbol_map`` whose current verdict is
    ``imported``, run the function-level resolver and update
    ``out`` in-place.

    Note: Go's existing module-level path can produce
    ``likely_called`` when ``advisory_symbols`` matches via the
    regex sweep. This tier consumes the same symbols but with
    chain-resolved matching from the inventory; results are
    typically consistent. When the existing module-level path
    produced ``likely_called``, this tier doesn't fire (gated on
    ``imported`` only) so its verdict isn't overwritten.
    """
    candidates: List[Dependency] = []
    for d in deps:
        if d.ecosystem != "Go":
            continue
        current = out.get(d.key())
        if current is None or current.verdict != "imported":
            continue
        symbols = go_symbol_map.get(d.key())
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
                "sca.reachability.go_function_level: inventory "
                "build failed; skipping function-level tier",
                exc_info=True,
            )
            return

    from core.inventory.reachability import (
        Verdict,
        function_called,
    )

    for d in candidates:
        qualified_names = go_symbol_map[d.key()]
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
                    f"project Go source: {affected}"
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
                        f"Go module imported but the "
                        f"{len(qualified_names)} OSV-listed "
                        f"affected symbol(s) are not called from "
                        f"non-test Go source"
                    ),
                ),
                evidence=[],
            )


__all__ = [
    "build_go_symbol_map",
    "refine_go_verdicts",
]


"""NuGet (C# / .NET) function-level reachability tier.

Sibling of the PyPI / npm / Go / Java / Cargo / RubyGems tiers.
Consumes C# call-graph data emitted by
``core.inventory.call_graph.extract_call_graph_csharp`` and runs
the cross-language resolver against OSV symbol data.

## Verdict transitions

  * Any affected symbol CALLED -> ``likely_called``
  * EVERY advisory-listed symbol evaluated and NOT_CALLED, none
    UNCERTAIN -> ``not_function_reachable``
  * Any UNCERTAIN, mixed, or unevaluable entry -> preserve existing
    verdict

## Qualified-name shape

NuGet OSV records ship symbols as fully-qualified .NET method
paths (``System.Text.Json.JsonSerializer.Deserialize``). The C#
extractor binds ``using System.Text;`` -> ``imports["Text"] =
"System.Text"``; a fully-qualified call chain resolves via the
import map.

The DOMINANT C# shape, however, is a bare namespace ``using``
(``using Newtonsoft.Json;`` + ``JsonConvert.DeserializeObject(s)``)
— C# brings every type of the namespace into scope WITHOUT binding
the class name, so the chain head (``JsonConvert``) is unbound and
the import-map resolver reads the call as NOT_CALLED. That is
resolver blindness, not evidence of absence: when a non-test file
binds the symbol's namespace and carries a class-shaped call chain
matching the affected symbol, this tier treats the symbol as
UNCERTAIN and preserves the prior verdict rather than minting a
high-confidence ``not_function_reachable`` on called code.

Limitation: instance-method calls and complex expression chains
(``Activator.CreateInstance(t).GetType().GetMethod(...)``) are
flagged as ``INDIRECTION_REFLECT`` so the resolver returns
UNCERTAIN. Direct static class/method calls work cleanly.
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


def build_nuget_symbol_map(
    osv_results: Iterable[Any] | None,
) -> dict[str, list[str]]:
    if not osv_results:
        return {}
    out: dict[str, list[str]] = {}
    for r in osv_results:
        if not hasattr(r, "advisories"):
            continue
        dep_key = getattr(r, "dep_key", None)
        if not dep_key or not dep_key.startswith("NuGet:"):
            continue
        dep_name = dep_key.split(":", 1)[1].split("@", 1)[0]
        qualified: list[str] = []
        for adv in r.advisories:
            qualified.extend(_extract_qualified(
                adv, dep_name, dep_is_namespace_head=True,
            ))
        if qualified:
            out.setdefault(dep_key, []).extend(qualified)
    return {k: list(dict.fromkeys(v)) for k, v in out.items()}


# NuGet package ids commonly ARE the root namespace
# ("Newtonsoft.Json"), so the shared extractor runs with
# dep_is_namespace_head=True; the byte-similar local copy it replaces
# double-prefixed already-qualified symbols and never normalised
# separators.


def refine_nuget_verdicts(
    deps: list[Dependency],
    out: dict[str, Reachability],
    *,
    target: Path,
    nuget_symbol_map: dict[str, list[str]],
    inventory: dict[str, Any] | None = None,
) -> None:
    # The any-dot check skips deps whose advisory entries are ALL
    # unresolved markers — nothing queryable, so the tier could
    # neither upgrade nor honestly downgrade; don't pay for an
    # inventory build to abstain.
    candidates = [
        d for d in deps
        if d.ecosystem == "NuGet"
        and out.get(d.key()) is not None
        and out[d.key()].verdict == "imported"
        and any("." in q for q in nuget_symbol_map.get(d.key()) or [])
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
                "sca.reachability.nuget_function_level: inventory "
                "build failed; skipping function-level tier",
                exc_info=True,
            )
            return

    from core.analysis.reachability import Verdict, function_called

    for d in candidates:
        qualified_names = nuget_symbol_map[d.key()]
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
        covered = len(paired) == len(qualified_names)
        bare_using_masked = any(
            r.verdict == Verdict.NOT_CALLED
            and _bare_using_masks(inventory, qn)
            for qn, r in paired
        )
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
                    f"project C# source: {affected}"
                ),
                affected_summary=affected,
            )
        elif Verdict.UNCERTAIN in verdicts or bare_using_masked \
                or not covered:
            # UNCERTAIN → preserve, per the tier's honesty rule.
            # bare_using_masked is the same epistemic state: the
            # resolver returned NOT_CALLED only because a bare
            # namespace ``using`` leaves the class name unbound —
            # the matching call chain is right there in the file.
            # ``not covered`` too: some advisory entry never paired
            # (an UNRESOLVED_ENTRY marker or a resolver refusal), so
            # "all listed symbols unreached" would overstate the
            # evidence.
            continue
        else:
            out[d.key()] = Reachability(
                verdict="not_function_reachable",
                confidence=Confidence(
                    "high",
                    reason=(
                        f"package imported but the {len(paired)} "
                        f"OSV-listed affected symbol(s) are not called "
                        f"from non-test C# source"
                    ),
                ),
                evidence=[],
            )


def _bare_using_masks(
    inventory: dict[str, Any], qualified_name: str,
) -> bool:
    """True when a non-test file both binds ``qualified_name``'s
    namespace via a bare ``using`` AND carries a class-shaped call
    chain matching the affected symbol (head == class, tail ==
    method). In that shape the import-map resolver CANNOT resolve
    the call — ``using Newtonsoft.Json;`` brings ``JsonConvert``
    into scope without binding it — so its NOT_CALLED answer is
    blindness, not evidence. Both conditions are required: a bound
    namespace alone (symbol's class never mentioned) leaves
    NOT_CALLED well-supported and the downgrade correct."""
    from core.analysis.reachability import _is_test_file

    parts = qualified_name.split(".")
    if len(parts) < 3:
        # Need namespace + class + method to describe the shape.
        return False
    func = parts[-1]
    klass = parts[-2]
    namespace = ".".join(parts[:-2])
    for file_record in inventory.get("files") or []:
        if not isinstance(file_record, dict):
            continue
        if _is_test_file(file_record.get("path") or ""):
            continue
        cg = file_record.get("call_graph")
        if not cg:
            continue
        imports = cg.get("imports") or {}
        if namespace not in imports.values():
            continue
        for call in cg.get("calls") or []:
            chain = call.get("chain") or []
            if len(chain) >= 2 and chain[0] == klass \
                    and chain[-1] == func:
                return True
    return False


__all__ = ["build_nuget_symbol_map", "refine_nuget_verdicts"]

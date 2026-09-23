"""PyPI function-level reachability tier.

Sits on top of the module-level Python scan (``packages.sca
.reachability.python``) and the cross-language resolver
(``core.analysis.reachability``). For PyPI deps that already came
back ``imported`` from the module-level pass AND have at least one
OSV advisory carrying ``affected_functions`` data, this module asks
the function-level resolver: "is the affected function actually
called from this project's source?".

Three downgrade outcomes:

  * **Any affected function returns CALLED** → upgrade verdict to
    ``likely_called`` (matches the Go pattern). A mix of
    CALLED + NOT_CALLED still upgrades — the dep is exercising
    vulnerable code even if not every listed function is hit.
  * **EVERY advisory-listed function evaluated and NOT_CALLED, none
    UNCERTAIN** → downgrade to ``not_function_reachable``. Same
    risk-multiplier weight as ``not_reachable``: we have positive
    evidence the vulnerable code path isn't exercised.
  * **Any UNCERTAIN (with no CALLED), or any entry no query spelling
    could evaluate** → leave the verdict at ``imported``. Honest
    reporting beats false confidence.

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
ignored — resolver queries are qualified with the dep's importable
module name(s) instead, resolved through the module-level tier's
dist→module mapping (``pyyaml`` → ``yaml``, ``Pillow`` → ``PIL``),
falling back to the PEP 503 / PEP 8 name guess. Imports bind the
module name, so qualifying with the raw distribution name would
never match a call chain for dist≠module packages.

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
from typing import Any
from collections.abc import Iterable

from ..models import Confidence, Dependency, Reachability
from ._shared import UNRESOLVED_ENTRY
from ._shared import extract_function_names as _extract_function_names

logger = logging.getLogger(__name__)


def build_pypi_symbol_map(
    osv_results: Iterable[Any] | None,
) -> dict[str, list[str]]:
    """Extract per-dep affected-function lists from OSV results.

    Returns ``{dep_key: [function_name, ...]}``. Empty when no
    advisories carry function info.
    """
    if not osv_results:
        return {}
    out: dict[str, list[str]] = {}
    for r in osv_results:
        if not hasattr(r, "advisories"):
            continue
        dep_key = getattr(r, "dep_key", None)
        if not dep_key or not dep_key.startswith("PyPI:"):
            continue
        funcs: list[str] = []
        for adv in r.advisories:
            funcs.extend(_extract_function_names(adv))
        if funcs:
            out.setdefault(dep_key, []).extend(funcs)
    # Dedup per-dep while preserving order.
    return {k: list(dict.fromkeys(v)) for k, v in out.items()}


def refine_pypi_verdicts(
    deps: list[Dependency],
    out: dict[str, Reachability],
    *,
    target: Path,
    pypi_symbol_map: dict[str, list[str]],
    inventory: dict[str, Any] | None = None,
) -> None:
    """For PyPI deps in ``pypi_symbol_map`` whose current verdict is
    ``imported``, run the function-level resolver and update ``out``
    in-place.

    ``inventory`` may be passed in by the caller when it's already
    been built; otherwise we build one over ``target``. Building is
    skipped entirely when no PyPI dep needs the function-level
    pass — preserves the cost guarantee documented at module top.
    """
    candidates: list[Dependency] = []
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

    from core.analysis.reachability import (
        ReachabilityResult,
        Verdict,
        function_called,
    )
    from .python import _candidate_modules

    # Prefer-stronger ordering for combining one function's verdicts
    # across candidate module names: any CALLED wins outright, else
    # any UNCERTAIN, and NOT_CALLED only when every candidate module
    # came back not-called.
    strength = {Verdict.NOT_CALLED: 0, Verdict.UNCERTAIN: 1, Verdict.CALLED: 2}

    # Per-file call context — import map, dotted call chains, and
    # locally-defined class names. Used to derive per-entry twins for
    # advisory spellings that name a class or submodule by its TAIL
    # alone, or skip intermediate submodules: Python does not require
    # importing the defining submodule (``import yaml`` +
    # ``yaml.composer.Composer.compose(...)`` is idiomatic), so the
    # call CHAIN, not the import map, carries the provenance — a
    # false downgrade requires a genuine call, the call is visible as
    # a chain, and a chain whose trailing segments match the entry
    # yields a twin from its resolved prefix. Local class names give
    # positive exclusion (a local ``Widget.run()`` never explains an
    # advisory entry); a chain head neither imported nor local (a
    # star-import access — the builder records no provenance for
    # ``from m import *``) is AMBIGUOUS and abstains instead of
    # letting the composed garbage reading pair NOT_CALLED.
    file_contexts: list[tuple[dict[str, str], list[list[str]], set[str]]] = []
    for f in inventory.get("files") or []:
        cg = f.get("call_graph") or {}
        imports_map = {
            k: v for k, v in (cg.get("imports") or {}).items()
            if isinstance(k, str) and isinstance(v, str) and v
        }
        chains = [
            c["chain"] for c in (cg.get("calls") or [])
            if isinstance(c, dict) and isinstance(c.get("chain"), list)
            and all(isinstance(s, str) for s in c["chain"])
        ]
        local_classes = {
            cls["name"] for cls in (cg.get("classes") or [])
            if isinstance(cls, dict) and isinstance(cls.get("name"), str)
        }
        if chains:
            file_contexts.append((imports_map, chains, local_classes))

    for d in candidates:
        funcs = pypi_symbol_map[d.key()]
        # Imports bind the MODULE name, not the PyPI distribution
        # name — installing ``pyyaml`` gives ``import yaml``,
        # ``pillow`` gives ``import PIL``. Qualify each affected
        # function with the same dist→module candidates the
        # module-level tier resolves through, otherwise every
        # dist≠module package reads all-NOT_CALLED and gets wrongly
        # downgraded despite a real call site.
        modules = _candidate_modules(d.name)
        # Distribution-name spellings a human author writes as the
        # entry head when dist and module names differ ("pyyaml.load"
        # for dist pyyaml, module yaml) — the same variants the
        # candidate heuristic derives. For unmapped dists these are
        # already candidate modules and the verbatim arm wins first;
        # only curated dist≠module packages reach the rebind arm.
        _norm = d.name.lower()
        dist_spellings: set[str] = {
            _norm, _norm.replace("-", "_"), _norm.replace("-", "."),
        }
        paired: list[tuple[str, ReachabilityResult]] = []
        for fn in funcs:
            if not fn:
                continue
            if fn == UNRESOLVED_ENTRY:
                # Counted-unresolved marker (junk-shaped advisory
                # data): never composed into a query — composing it
                # would pair NOT_CALLED and defeat the marker — but
                # it stays unpaired, so the coverage gate below
                # blocks the downgrade.
                continue
            # Advisory flat lists ship three entry shapes, and each
            # needs a resolver-bindable query spelling (the
            # shape-parametrised tests in
            # test_python_function_level.py are the closure oracle
            # for this policy — shapes outside it are not claimed):
            #   * bare ("get") → "<mod>.get" per candidate module;
            #   * module-head-qualified ("yaml.full_load" — the
            #     dominant GHSA/PYSEC spelling) → VERBATIM. Blindly
            #     prefixing minted "yaml.yaml.full_load", a garbage
            #     query the resolver answers as a well-formed
            #     NOT_CALLED — every pair went not-called and the
            #     tier manufactured a false high-confidence
            #     not_function_reachable on a dep whose vulnerable
            #     function IS called. "Module-head" means the FULL
            #     candidate-module prefix, not the first dot
            #     segment: candidate modules are themselves dotted
            #     for curated-map dists (protobuf →
            #     google.protobuf, ruamel.yaml, azure.identity, …)
            #     and for every hyphenated unmapped dist via the
            #     norm_dot heuristic — a first-segment check
            #     misclassified all of those as partial and
            #     re-minted the same garbage compose;
            #   * partially-qualified ("utils.extract_zipped_paths")
            #     → "<mod>.utils...." compose, and NEVER verbatim —
            #     a project-local module named ``utils`` would
            #     otherwise fake a CALLED (prefer-stronger combining
            #     makes a false CALLED win outright). An entry EQUAL
            #     to a candidate module names the module itself, not
            #     a function — skipped entirely (it stays unpaired,
            #     so the coverage gate below abstains from the
            #     downgrade). For a dotted candidate module
            #     (ruamel.yaml) the verbatim query would be a
            #     well-formed resolver question (module ``ruamel``,
            #     function ``yaml``) pairing NOT_CALLED — minting a
            #     false high-confidence suppression — while the
            #     dot-less twin abstained via the resolver's
            #     ValueError refusal. One semantic shape, one honest
            #     outcome: abstain.
            if any(fn == m for m in modules) or fn.lower() in dist_spellings:
                # An entry equal to the DISTRIBUTION name is the same
                # semantic shape as the module-named entry: it names
                # the package, not a function.
                continue
            if any(fn.startswith(m + ".") for m in modules):
                queries = [fn]
            else:
                queries = [f"{mod}.{fn}" for mod in modules]
                # Distribution-name-head spelling ("pyyaml.load"):
                # the compose above is the garbage reading
                # ("yaml.pyyaml.load" — well-formed, pairs
                # NOT_CALLED, and a single-entry list minted a false
                # high-confidence suppression on a dep whose
                # vulnerable function IS called). Rebind the
                # remainder onto each candidate module; the compose
                # twin stays queried (prefer-stronger combining
                # means it can only add signal, never override a
                # CALLED), so whichever reading the advisory meant,
                # the honest query is present.
                fn_lower = fn.lower()
                for ds in dist_spellings:
                    if fn_lower.startswith(ds + ".") and len(fn) > len(ds) + 1:
                        rest = fn[len(ds) + 1:]
                        queries = [f"{mod}.{rest}" for mod in modules] + queries
                        break
            # Call-chain-derived twins (restricted to chains whose
            # provenance places them under THIS dist's candidate
            # modules — a crafted entry can never borrow an unrelated
            # module's chain): for each candidate module m, take the
            # entry relative to m (strip a leading "<m>." if
            # present); every call chain whose trailing segments
            # equal the remainder is classified by its head:
            #   * prefixed chain, prefix head in the import map and
            #     the resolved prefix under m → twin
            #     "<resolved_prefix>.<remainder>"
            #     (``yaml.composer.Composer.compose(...)`` under
            #     ``import yaml`` → resolved prefix ``yaml.composer``);
            #   * whole-chain match, head in the import map and its
            #     resolution under m → twin "<resolution>.<rest>"
            #     (``from yaml.composer import Composer`` →
            #     ``yaml.composer.Composer.compose``);
            #   * head resolving OUTSIDE m, or a locally-defined
            #     class → positively excluded, no twin;
            #   * head neither imported nor local (star-import
            #     access) → AMBIGUOUS: the call may be this very
            #     entry, so the entry abstains below rather than
            #     letting the composed garbage reading pair
            #     NOT_CALLED into a suppression. Entries no chain
            #     matches raise no ambiguity — uncalled functions
            #     still downgrade whether the module is imported,
            #     star-imported, or absent.
            ambiguous = False
            for m in modules:
                rem = fn[len(m) + 1:] if fn.startswith(m + ".") else fn
                segs = rem.split(".")
                if len(segs) < 2 or not all(segs):
                    continue
                for imports_map, chains, local_classes in file_contexts:
                    for chain in chains:
                        if len(chain) < len(segs) or chain[-len(segs):] != segs:
                            continue
                        head = chain[0]
                        resolved0 = imports_map.get(head)
                        if resolved0 is None:
                            if head not in local_classes:
                                ambiguous = True
                            continue
                        if len(chain) > len(segs):
                            prefix = ".".join(
                                [resolved0, *chain[1:-len(segs)]],
                            )
                            if prefix == m or prefix.startswith(m + "."):
                                twin = f"{prefix}.{rem}"
                            else:
                                continue
                        else:
                            if not (
                                resolved0 == m
                                or resolved0.startswith(m + ".")
                            ):
                                continue
                            twin = ".".join([resolved0, *segs[1:]])
                        if twin not in queries:
                            queries.append(twin)
            best: ReachabilityResult | None = None
            for query in queries:
                try:
                    r = function_called(inventory, query)
                except ValueError:
                    continue
                if best is None or strength[r.verdict] > strength[best.verdict]:
                    best = r
                if best.verdict == Verdict.CALLED:
                    break
            if best is None:
                continue
            if ambiguous and best.verdict != Verdict.CALLED:
                # A provenance-less chain matches this exact entry:
                # binding is unproven but suppression would be a
                # false verdict if the star import covers it. Leave
                # the entry unpaired — the coverage gate abstains.
                continue
            paired.append((fn, best))

        if not paired:
            continue

        verdicts = {r.verdict for _, r in paired}
        covered = len(paired) == len(funcs)
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
                    f"project source: {affected}"
                ),
                affected_summary=affected,
            )
        elif Verdict.UNCERTAIN in verdicts or not covered:
            # Mixed / uncertain — leave at module-level imported.
            # Don't downgrade; don't upgrade. Honest reporting.
            # ``not covered`` is the same epistemic state: at least
            # one advisory entry never paired (every query spelling
            # refused by the resolver), so "all listed functions
            # unreached" would suppress on the evaluated remainder
            # while silently discarding the entry the project may
            # actually exercise.
            continue
        else:
            # All NOT_CALLED.
            out[d.key()] = Reachability(
                verdict="not_function_reachable",
                confidence=Confidence(
                    "high",
                    reason=(
                        f"dep imported but the {len(paired)} OSV-listed "
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

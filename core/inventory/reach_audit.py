"""Reachability audit harness — corpus-agnostic measurement of the
reachability substrate's classification accuracy.

Given a target tree plus a label map (function → ``"dead"`` | ``"live"``),
classify every labelled function with the shipped reachability signals and
report:

  * coverage — labelled-dead functions correctly classified dead;
  * **false-suppress** — labelled-live functions wrongly classified dead.
    This is the false-negative-critical metric: a witness kind earns the
    right to *enforce* (hard-suppress) only once its false-suppress count
    is zero across a labelled corpus. Until then, surface-only.

The harness is deliberately corpus-agnostic: it takes a directory and a
label map, names no particular corpus, and is driven by tests (a committed
synthetic corpus) and, off-repo, by whatever labelled trees the operator
points it at.

``classify_reachability`` composes the public accessors in precedence
order; it is the read-only "audit" sibling of the /agentic enrichment
prepass (which mutates a checklist with the same precedence).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

# Verdicts that mean "not reachable in this deployment" (dead).
_DEAD_VERDICTS = frozenset({
    "module_aborts", "lexical_dead", "build_excluded",
    "no_path_from_entry", "not_called",
})
# Verdicts that mean "reachable / has a live path".
_LIVE_VERDICTS = frozenset({
    "reachable", "framework_callable", "registered_via_call", "called",
})
# "uncertain" is neither — the substrate declines to claim.


def classify_reachability(
    inventory: Dict[str, object],
    file_path: str,
    name: str,
    line: int,
    module: str,
) -> str:
    """Strongest applicable reachability verdict for one function, in the
    same precedence the enrichment prepass uses:

    module_aborts → lexical_dead → build_excluded → framework/registration
    → entry-reachability (reachable / no_path_from_entry / uncertain) →
    1-hop function_called (called / not_called / uncertain).

    Sound witnesses (module_aborts / lexical_dead) come first so they win
    where they apply (they can hard-suppress); build_excluded (heuristic,
    whole-file) then catches anything in a never-compiled file — including
    functions above a module-abort line and framework-decorated functions,
    since a file the build never compiles registers nothing.
    """
    from core.inventory.reachability import (
        InternalFunction,
        Verdict,
        build_excluded,
        entry_reachability,
        function_called,
        is_framework_callable,
        is_lexically_dead,
        is_registered_via_call,
        module_aborts_on_load,
    )

    abort = module_aborts_on_load(inventory, file_path)
    if abort and line and line > int(abort.get("line") or 0):
        return "module_aborts"
    if is_lexically_dead(inventory, file_path, name, line):
        return "lexical_dead"
    if build_excluded(inventory, file_path):
        return "build_excluded"

    target = InternalFunction(file_path=file_path, name=name, line=line)
    # Specific reachable reasons first — framework decorator dispatch and
    # function-as-argument registration — so they surface as their own
    # (informative) verdicts rather than being absorbed into the general
    # "reachable" by entry-reachability (which also counts them as entries).
    if is_framework_callable(inventory, target):
        return "framework_callable"
    if is_registered_via_call(inventory, target):
        return "registered_via_call"
    # General entry-point forward reachability.
    er = entry_reachability(inventory, target)
    if er == "reachable":
        return "reachable"
    if er == "no_path_from_entry":
        return "no_path_from_entry"
    # er == "uncertain": fall through to the 1-hop verdict.
    try:
        verdict = function_called(inventory, f"{module}.{name}").verdict
    except ValueError:
        return "uncertain"
    if verdict == Verdict.CALLED:
        return "called"
    if verdict == Verdict.NOT_CALLED:
        return "not_called"
    return "uncertain"


@dataclass
class AuditReport:
    total: int = 0
    caught_dead: int = 0          # labelled dead, classified dead
    missed_dead: int = 0          # labelled dead, classified live/uncertain
    false_suppress: int = 0       # labelled LIVE, classified dead (FN-critical)
    live_ok: int = 0              # labelled live, classified live/uncertain
    not_found: int = 0            # labelled fn not in inventory (extraction
                                  # gap, NOT a reachability misclassification)
    per_verdict: Dict[str, int] = field(default_factory=dict)
    false_suppress_detail: list = field(default_factory=list)
    missed_detail: list = field(default_factory=list)
    not_found_detail: list = field(default_factory=list)

    @property
    def coverage(self) -> float:
        dead = self.caught_dead + self.missed_dead
        return self.caught_dead / dead if dead else 1.0


def _path_to_module(rel_path: str) -> Optional[str]:
    from pathlib import PurePosixPath
    p = PurePosixPath(rel_path.replace("\\", "/"))
    if not p.suffix:
        return None
    parts = list(p.with_suffix("").parts)
    return ".".join(parts) if parts else None


def audit_corpus(
    target_dir: str,
    labels: Dict[Tuple[str, str], str],
    *,
    inventory: Optional[Dict[str, object]] = None,
) -> AuditReport:
    """Classify each labelled ``(rel_path, func_name) → "dead"|"live"`` and
    tally coverage + false-suppress. ``inventory`` may be supplied (tests
    inject a synthetic one to stay tree-sitter-independent); otherwise it's
    built from ``target_dir``.
    """
    if inventory is None:
        import tempfile
        from core.inventory.builder import build_inventory
        with tempfile.TemporaryDirectory() as td:
            inventory = build_inventory(target_dir, td)

    # Index items by (rel_path, name) → line, for label lookup.
    line_of: Dict[Tuple[str, str], int] = {}
    for f in inventory.get("files", []):
        if not isinstance(f, dict):
            continue
        rel = f.get("path") or ""
        for it in f.get("items", []):
            if isinstance(it, dict) and it.get("kind", "function") == "function":
                line_of[(rel, it.get("name") or "")] = int(
                    it.get("line_start") or 0)

    report = AuditReport()
    for (rel, name), label in labels.items():
        module = _path_to_module(rel)
        if not module:
            continue
        if (rel, name) not in line_of:
            # The labelled function isn't in the inventory at all — an
            # extraction gap, not a reachability verdict. Bucket it
            # separately so it can't masquerade as a false-suppress (which
            # would falsely fail the FN gate) or a coverage miss.
            report.not_found += 1
            report.not_found_detail.append((rel, name))
            continue
        line = line_of[(rel, name)]
        verdict = classify_reachability(inventory, rel, name, line, module)
        report.total += 1
        report.per_verdict[verdict] = report.per_verdict.get(verdict, 0) + 1
        is_dead = verdict in _DEAD_VERDICTS
        if label == "dead":
            if is_dead:
                report.caught_dead += 1
            else:
                report.missed_dead += 1
                report.missed_detail.append((rel, name, verdict))
        else:  # label == "live"
            if is_dead:
                report.false_suppress += 1
                report.false_suppress_detail.append((rel, name, verdict))
            else:
                report.live_ok += 1
    return report


__all__ = ["AuditReport", "audit_corpus", "classify_reachability"]

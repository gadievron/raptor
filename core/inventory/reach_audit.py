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


@dataclass
class _ClassifyCtx:
    """Per-target inputs shared by the precedence stages."""
    inventory: Dict[str, object]
    file_path: str
    name: str
    line: int
    module: str
    target: object          # reachability.InternalFunction
    class_name: Optional[str] = None   # enclosing class, for method qualnames


# --- precedence stages: each (ctx, R) -> verdict string | None -------------
# R is the core.inventory.reachability module (the accessors). A stage returns
# its verdict when it fires, else None to fall through to the next stage.

def _stage_module_aborts(ctx: "_ClassifyCtx", R) -> Optional[str]:
    abort = R.module_aborts_on_load(ctx.inventory, ctx.file_path)
    if abort and ctx.line and ctx.line > int(abort.get("line") or 0):
        return "module_aborts"
    return None


def _stage_lexical_dead(ctx: "_ClassifyCtx", R) -> Optional[str]:
    if R.is_lexically_dead(ctx.inventory, ctx.file_path, ctx.name, ctx.line):
        return "lexical_dead"
    return None


def _stage_build_excluded(ctx: "_ClassifyCtx", R) -> Optional[str]:
    if R.build_excluded(ctx.inventory, ctx.file_path):
        return "build_excluded"
    return None


def _stage_framework(ctx: "_ClassifyCtx", R) -> Optional[str]:
    if R.is_framework_callable(ctx.inventory, ctx.target):
        return "framework_callable"
    return None


def _stage_registered(ctx: "_ClassifyCtx", R) -> Optional[str]:
    if R.is_registered_via_call(ctx.inventory, ctx.target):
        return "registered_via_call"
    return None


def _stage_entry(ctx: "_ClassifyCtx", R) -> Optional[str]:
    er = R.entry_reachability(ctx.inventory, ctx.target)
    if er == "reachable":
        return "reachable"
    if er == "no_path_from_entry":
        return "no_path_from_entry"
    return None


def _stage_one_hop(ctx: "_ClassifyCtx", R) -> Optional[str]:
    # A method called only via ``this.m()`` / ``self.m()`` resolves through the
    # method-match index under its CLASS-qualified name (``mod.Class.m``); the
    # bare ``mod.m`` form misses it and reads not_called. Try the class-qualified
    # name first (when the item is a method), then the bare form (top-level
    # functions / where the class-qualified form isn't how the file is indexed).
    candidates = []
    if ctx.class_name:
        candidates.append(f"{ctx.module}.{ctx.class_name}.{ctx.name}")
    candidates.append(f"{ctx.module}.{ctx.name}")
    verdicts = []
    for qn in candidates:
        try:
            verdicts.append(R.function_called(ctx.inventory, qn).verdict)
        except ValueError:
            continue
    if R.Verdict.CALLED in verdicts:
        return "called"
    if R.Verdict.NOT_CALLED in verdicts:
        # CHA: before demoting, check whether this is a polymorphic-dispatch
        # override that's dispatched via an unresolved member call somewhere —
        # a virtual call could reach it at runtime even though no resolved edge
        # exists. If so fall through to UNCERTAIN (not_called would be unsafe);
        # precise typed dispatch resolution is CodeQL's (Tier 2) job.
        if R.is_virtual_dispatch_candidate(ctx.inventory, ctx.class_name, ctx.name):
            return None
        return "not_called"
    return None


# Ordered precedence. Sound witnesses (module_aborts / lexical_dead) first so
# they win where they apply (they can hard-suppress); build_excluded
# (heuristic, whole-file) next so it catches anything in a never-compiled file
# — incl. functions above a module-abort line and framework-decorated ones,
# since a file the build never compiles registers nothing; then the specific
# reachable reasons (framework / registration) before the general
# entry-reachability and the 1-hop fallback. Adding a witness = insert a stage
# here + a VERDICTS entry in reach_witness.
PRECEDENCE = (
    _stage_module_aborts,
    _stage_lexical_dead,
    _stage_build_excluded,
    _stage_framework,
    _stage_registered,
    _stage_entry,
    _stage_one_hop,
)


def _lookup_class_name(
    inventory: Dict[str, object], file_path: str, name: str, line: int,
) -> Optional[str]:
    """The enclosing class of the ``(file_path, name)`` item, if any — used to
    build a method's class-qualified name for the 1-hop check. Scans the target
    file's items only (matching the other (inventory, file_path) accessors)."""
    files = inventory.get("files") or []
    if not isinstance(files, list):
        return None
    for f in files:
        if not isinstance(f, dict) or f.get("path") != file_path:
            continue
        for it in f.get("items") or []:
            if it.get("name") != name:
                continue
            if line and int(it.get("line_start") or 0) != line:
                continue
            return (it.get("metadata") or {}).get("class_name")
    return None


def classify_reachability(
    inventory: Dict[str, object],
    file_path: str,
    name: str,
    line: int,
    module: str,
) -> str:
    """Strongest applicable reachability verdict for one function — the first
    stage in :data:`PRECEDENCE` that fires, else ``"uncertain"``. Single
    source of truth consumed by the CodeQL prefilter, the /agentic enrichment
    prepass, and the /validate demoter."""
    from core.inventory import reachability as R
    ctx = _ClassifyCtx(
        inventory=inventory, file_path=file_path, name=name, line=line,
        module=module,
        target=R.InternalFunction(file_path=file_path, name=name, line=line),
        class_name=_lookup_class_name(inventory, file_path, name, line),
    )
    for stage in PRECEDENCE:
        verdict = stage(ctx, R)
        if verdict:
            return verdict
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

"""Coverage-aware ``/project clean``: snapshot a run's coverage into the
durable store before its dir is deleted, and classify the removal.

Per the locked model, deleting a run must not silently lose what it uniquely
contributed:

  - its coverage (examined extent) is **snapshotted** into the durable store,
    so clean/examined coverage survives the deletion;
  - findings the victim run held are linked with ``retained=False`` *iff no
    surviving run still holds them* — those functions become
    ``found_then_lost`` (re-examine); findings still held elsewhere stay
    ``open``;
  - the removal is **classified** (duplicate / sole-source findings) so the
    operator — and auto-dedup ``--keep`` — knows whether it was free or lossy.

Substantiation is computed against the **surviving runs** (the common case).
Not counting coverage already durably in the store is deliberately
conservative: at worst it flags a re-review that wasn't strictly needed,
which is the safe direction (re-running is cheap; silently skipping a lost
finding is not). The caller saves the store after processing all victims.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set, Tuple

from .importer import import_findings, import_run_dir, load_run_findings
from .record import load_records
from .store import CoverageStore


def _finding_key(f: Dict[str, Any]) -> Tuple[Any, Any, Any]:
    """A cross-run identity for a finding: ``(file, location, issue)``.

    Location is the line (``("L", n)``) or, absent a line, the id (``("I",
    id)``). The ``issue`` discriminator (rule / CWE / vuln type) is what keeps
    two *distinct* findings that happen to share a line from collapsing to one
    key — without it, a survivor holding either would mask the loss of the
    other, so a real finding could be silently discarded with no
    ``found_then_lost`` re-review flag. Preferring rule/CWE over id makes the
    key stable across runs (the same issue re-found at the same line matches
    even if its per-run id differs)."""
    file = f.get("file") or f.get("file_path") or f.get("path")
    line = f.get("line") or f.get("line_start") or f.get("start_line")
    issue = (f.get("rule_id") or f.get("cwe_id") or f.get("vuln_type")
             or f.get("rule") or f.get("id") or f.get("finding_id"))
    loc = ("L", line) if line is not None else ("I", f.get("id") or f.get("finding_id"))
    return (file, loc, issue)


def _files_examined(run_dir: Path) -> Set[str]:
    out: Set[str] = set()
    for rec in load_records(run_dir):
        out.update(rec.get("files_examined", []) or [])
    return out


@dataclass
class CleanConsequence:
    """What deleting one run does to coverage."""

    run: str
    duplicate: bool                              # adds nothing the survivors lack
    findings_lost: List[Tuple[Any, Any]] = field(default_factory=list)
    coverage_files: List[str] = field(default_factory=list)

    @property
    def lossy(self) -> bool:
        return bool(self.findings_lost)


def classify_removal(
    victim_run_dir: Path, surviving_run_dirs: Iterable[Path],
) -> CleanConsequence:
    """Read-only: classify what deleting ``victim`` would lose, net of the
    surviving runs. Safe to call before the operator confirms (no store
    mutation) — use it to drive the warning."""
    victim = Path(victim_run_dir)
    survivors = [Path(d) for d in surviving_run_dirs]

    surv_files: Set[str] = set()
    surv_finding_keys: Set[Tuple[Any, Any]] = set()
    for d in survivors:
        surv_files |= _files_examined(d)
        for f in load_run_findings(d):
            if isinstance(f, dict):
                surv_finding_keys.add(_finding_key(f))

    victim_files = _files_examined(victim)
    findings_lost = [
        _finding_key(f) for f in load_run_findings(victim)
        if isinstance(f, dict) and _finding_key(f) not in surv_finding_keys
    ]
    duplicate = victim_files.issubset(surv_files) and not findings_lost
    return CleanConsequence(
        run=victim.name,
        duplicate=duplicate,
        findings_lost=findings_lost,
        coverage_files=sorted(victim_files),
    )


def dedup_runs(
    run_dirs: Iterable[Path],
) -> Tuple[List[Path], List[CleanConsequence]]:
    """Greedy lossless dedup: return the run dirs that can be deleted without
    losing examined extent or a unique finding, because each is fully subsumed
    by the runs that remain. Always keeps at least one run; keeps the newest
    representative (oldest duplicates dropped first).

    Lossless by construction: a run is only marked droppable when it is a
    duplicate w.r.t. the *current* survivor set, and that set only ever shrinks
    by removing already-subsumed runs — so every survivor at drop-time stays,
    fully covering what was dropped. (Tool-specific coverage of a dropped run
    is independently preserved by :func:`apply_removal`'s store snapshot before
    deletion, so "duplicate" here need only mean files+findings subsumed.)
    """
    # Oldest-first so the newest run is the representative we keep. Run dir
    # names are timestamped, so name order is chronological.
    survivors = sorted((Path(d) for d in run_dirs), key=lambda p: p.name)
    droppable: List[Path] = []
    reasons: List[CleanConsequence] = []
    i = 0
    while i < len(survivors):
        victim = survivors[i]
        others = survivors[:i] + survivors[i + 1:]
        if not others:
            break
        cons = classify_removal(victim, others)
        if cons.duplicate:
            droppable.append(victim)
            reasons.append(cons)
            survivors.pop(i)          # next run shifts into i; re-evaluate
        else:
            i += 1
    return droppable, reasons


def apply_removal(
    store: CoverageStore,
    victim_run_dir: Path,
    checklist: Dict[str, Any],
    consequence: CleanConsequence,
) -> None:
    """Snapshot the victim's coverage into the store and link its findings
    with ``retained`` per the classification. Mutates the store; call AFTER
    the deletion is confirmed but BEFORE the dir is removed (it reads the
    victim's records/findings). Caller saves."""
    victim = Path(victim_run_dir)
    import_run_dir(store, victim, checklist)          # coverage persists
    inv_paths = {fe.get("path") for fe in checklist.get("files", []) if fe.get("path")}
    lost = set(consequence.findings_lost)
    for f in load_run_findings(victim):
        if isinstance(f, dict):
            retained = _finding_key(f) not in lost
            import_findings(store, [f], retained=retained, inventory_paths=inv_paths)


def clean_run(
    store: CoverageStore,
    victim_run_dir: Path,
    surviving_run_dirs: Iterable[Path],
    checklist: Dict[str, Any],
) -> CleanConsequence:
    """Classify + apply in one step (snapshot, retained flips, classification).
    Mutates the store (caller saves)."""
    consequence = classify_removal(victim_run_dir, surviving_run_dirs)
    apply_removal(store, victim_run_dir, checklist, consequence)
    return consequence


def format_consequence(c: CleanConsequence) -> str:
    """One-line operator summary of a planned/applied removal."""
    if c.duplicate:
        return f"  {c.run}: duplicate — covered by surviving runs; free to remove"
    if c.lossy:
        return (
            f"  {c.run}: drops {len(c.findings_lost)} unique finding(s) — "
            f"those functions become re-review gaps (found-then-lost)"
        )
    return f"  {c.run}: unique coverage preserved into the store; no findings lost"

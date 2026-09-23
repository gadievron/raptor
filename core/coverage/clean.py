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
from typing import Any, TYPE_CHECKING

from core.logging import get_logger

from .importer import import_findings, import_run_dir, load_run_findings
from .record import load_records
from .schema import iter_file_entries

if TYPE_CHECKING:
    from .store import CoverageStore
    from collections.abc import Iterable

logger = get_logger(__name__)


def _hashable(v: Any) -> Any:
    """A set-safe stand-in for a finding-key component.

    Findings are run-dir JSON — every field shape is attacker-
    writable, and an unhashable component (list line, dict rule id)
    detonated the survivor-set updates that gate ``/project clean``.
    Scalars pass through; containers collapse to their repr, which
    keeps distinct hostile values distinct enough for identity while
    never crashing the classification."""
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    return repr(v)


def _finding_key(f: dict[str, Any]) -> tuple[Any, Any, Any]:
    """A cross-run identity for a finding: ``(file, location, issue)``.

    Location is the line (``("L", n)``) or, absent a line, the id (``("I",
    id)``). The ``issue`` discriminator (rule / CWE / vuln type) is what keeps
    two *distinct* findings that happen to share a line from collapsing to one
    key — without it, a survivor holding either would mask the loss of the
    other, so a real finding could be silently discarded with no
    ``found_then_lost`` re-review flag. Preferring rule/CWE over id makes the
    key stable across runs (the same issue re-found at the same line matches
    even if its per-run id differs). Components are coerced set-safe
    (:func:`_hashable`) — the rows come straight from run-dir JSON."""
    file = f.get("file") or f.get("file_path") or f.get("path")
    line = next(
        (v for k in ("line", "line_start", "start_line")
         if (v := f.get(k)) is not None),
        None,
    )
    issue = (f.get("rule_id") or f.get("cwe_id") or f.get("vuln_type")
             or f.get("rule") or f.get("id") or f.get("finding_id"))
    loc = (
        ("L", _hashable(line)) if line is not None
        else ("I", _hashable(f.get("id") or f.get("finding_id")))
    )
    return (_hashable(file), loc, _hashable(issue))


def _files_examined(run_dir: Path) -> set[str]:
    """String members of every record's ``files_examined`` list.

    Records are run-dir JSON: the sibling consumers (importer,
    store_summary, summary) all guard the record and member shapes,
    and this walk must too — a legacy list-shaped record crashed the
    ``.get``, a non-list ``files_examined`` (one hostile string
    silently unioned its CHARACTERS into the survivor file set,
    mis-classing victim runs) and non-string members crashed or
    corrupted the set the whole ``/project clean`` lane keys on."""
    out: set[str] = set()
    for rec in load_records(run_dir):
        if not isinstance(rec, dict):
            logger.warning(
                "clean: skipping non-object coverage record (%s) in %s",
                type(rec).__name__, run_dir)
            continue
        fe = rec.get("files_examined") or []
        if not isinstance(fe, list):
            logger.warning(
                "clean: record in %s has non-list files_examined (%s); "
                "ignoring", run_dir, type(fe).__name__)
            continue
        out.update(x for x in fe if isinstance(x, str))
    return out


@dataclass
class CleanConsequence:
    """What deleting one run does to coverage."""

    run: str
    duplicate: bool                              # adds nothing the survivors lack
    findings_lost: list[tuple[Any, Any, Any]] = field(default_factory=list)
    coverage_files: list[str] = field(default_factory=list)

    @property
    def lossy(self) -> bool:
        return bool(self.findings_lost)


def _summarise_run(run_dir: Path) -> tuple[set[str], list[tuple[Any, Any, Any]]]:
    """One disk read per run: ``(files_examined, finding keys)``."""
    files = _files_examined(run_dir)
    keys = [
        _finding_key(f) for f in load_run_findings(run_dir)
        if isinstance(f, dict)
    ]
    return files, keys


def _classify(
    victim_name: str,
    victim_files: set[str],
    victim_keys: list[tuple[Any, Any, Any]],
    surv_files: set[str],
    surv_finding_keys: set[tuple[Any, Any, Any]],
) -> CleanConsequence:
    """Classification over precomputed summaries (no disk access)."""
    findings_lost = [k for k in victim_keys if k not in surv_finding_keys]
    duplicate = victim_files.issubset(surv_files) and not findings_lost
    return CleanConsequence(
        run=victim_name,
        duplicate=duplicate,
        findings_lost=findings_lost,
        coverage_files=sorted(victim_files),
    )


def classify_removal(
    victim_run_dir: Path, surviving_run_dirs: Iterable[Path],
) -> CleanConsequence:
    """Read-only: classify what deleting ``victim`` would lose, net of the
    surviving runs. Safe to call before the operator confirms (no store
    mutation) — use it to drive the warning."""
    victim = Path(victim_run_dir)

    surv_files: set[str] = set()
    surv_finding_keys: set[tuple[Any, Any, Any]] = set()
    for d in surviving_run_dirs:
        files, keys = _summarise_run(Path(d))
        surv_files |= files
        surv_finding_keys.update(keys)

    victim_files, victim_keys = _summarise_run(victim)
    return _classify(
        victim.name, victim_files, victim_keys, surv_files, surv_finding_keys,
    )


def dedup_runs(
    run_dirs: Iterable[Path],
) -> tuple[list[Path], list[CleanConsequence]]:
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
    # Each run's records/findings are read from disk exactly once; the
    # per-victim classification then works over the in-memory
    # summaries (the classify_removal-per-victim shape re-parsed every
    # survivor's JSON for every victim).
    summaries = {d: _summarise_run(d) for d in survivors}
    droppable: list[Path] = []
    reasons: list[CleanConsequence] = []
    i = 0
    while i < len(survivors):
        victim = survivors[i]
        others = survivors[:i] + survivors[i + 1:]
        if not others:
            break
        surv_files: set[str] = set()
        surv_finding_keys: set[tuple[Any, Any, Any]] = set()
        for d in others:
            files, keys = summaries[d]
            surv_files |= files
            surv_finding_keys.update(keys)
        victim_files, victim_keys = summaries[victim]
        cons = _classify(
            victim.name, victim_files, victim_keys,
            surv_files, surv_finding_keys,
        )
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
    checklist: dict[str, Any],
    consequence: CleanConsequence,
) -> None:
    """Snapshot the victim's coverage into the store and link its findings
    with ``retained`` per the classification. Mutates the store; call AFTER
    the deletion is confirmed but BEFORE the dir is removed (it reads the
    victim's records/findings). Caller saves."""
    victim = Path(victim_run_dir)
    import_run_dir(store, victim, checklist)          # coverage persists
    # iter_file_entries tolerates hostile checklist container shapes —
    # a raw walk crashed BETWEEN the operator's deletion confirmation
    # and the snapshot, the worst possible interleaving.
    inv_paths = {
        fe.get("path") for fe in iter_file_entries(checklist)
        if isinstance(fe.get("path"), str)
    }
    # Two batched import calls, split by the retained flag — the
    # one-call-per-finding shape rebuilt the inventory name index per
    # row (quadratic on finding-heavy victims, on the /project clean
    # path that holds the cross-process store lock).
    lost = set(consequence.findings_lost)
    retained_rows: list[dict[str, Any]] = []
    lost_rows: list[dict[str, Any]] = []
    for f in load_run_findings(victim):
        if isinstance(f, dict):
            if _finding_key(f) not in lost:
                retained_rows.append(f)
            else:
                lost_rows.append(f)
    if retained_rows:
        import_findings(store, retained_rows, retained=True,
                        inventory_paths=inv_paths)
    if lost_rows:
        import_findings(store, lost_rows, retained=False,
                        inventory_paths=inv_paths)


def clean_run(
    store: CoverageStore,
    victim_run_dir: Path,
    surviving_run_dirs: Iterable[Path],
    checklist: dict[str, Any],
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
    return (
        f"  {c.run}: unique coverage ({len(c.coverage_files)} examined "
        f"file(s)) preserved into the store; no findings lost"
    )

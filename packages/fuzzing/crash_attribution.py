"""Attribute AFL++ crashes back to the SMT-witness seeds that bred them.

``--from-smt-witness`` (``smt_seed.py``) plants seeds whose manifest
records the finding / attack path each seed came from. When AFL++ later
finds a crash, its filename records the mutation lineage:

* initial queue entries:  ``id:000001,time:0,execs:0,orig:SEEDNAME``
* derived queue entries:  ``id:000002,src:000001,...,op:havoc,rep:2``
* crashes:                ``id:000000,sig:06,src:000002,...``
* splice mutations carry two parents: ``src:000123+000456``

(verified live on afl-fuzz++4.33c). Walking the recorded ``src`` chain
from a crash to its root queue entries yields the ``orig:`` seed names —
an exact, fuzzer-recorded lineage, not a heuristic. Attribution is
stamped ONLY when every root of the chain is the same SMT seed; a
splice whose parents descend from different seeds, a missing queue
entry, or any break in the chain leaves the crash unattributed (a wrong
finding-confirmation is worse than none).

The attribution rides the crash Witness's ``outcome_detail`` —
``from_witness`` in ``core.labeled_attempts.view`` already projects a
``finding_id`` found there, so attributed crashes surface in
``raptor-verified-outcomes`` as oracle-verified confirmations of the
producing finding with no schema change.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from packages.fuzzing.smt_seed import MANIFEST_NAME, SEED_DIR_NAME
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from packages.fuzzing.crash_collector import Crash

logger = logging.getLogger(__name__)

# Chain-walk bounds: AFL ids are dense small integers; a legitimate
# lineage never needs more. Hitting a bound reads as "unattributed",
# never as a wrong attribution.
_MAX_CHAIN_DEPTH = 64
_MAX_VISITED = 256

_ID_RE = re.compile(r"(?:^|,)id:(\d+)")
_SRC_RE = re.compile(r"(?:^|,)src:([\d+]+)")
_ORIG_RE = re.compile(r"(?:^|,)orig:([^,]+)")
_INSTANCE_RE = re.compile(r",instance:([^,]+)$")


@dataclass
class CrashAttribution:
    """Exact-lineage attribution of one crash to one SMT seed."""

    crash_id: str
    seed_name: str
    origin_id: str  # finding_id / attack-path id from the seed manifest
    source_file: str  # producer file the witness model came from


@dataclass
class AttributionSummary:
    """Per-run attribution result."""

    attributed: dict[str, CrashAttribution] = field(default_factory=dict)
    total_crashes: int = 0
    unattributed: int = 0

    def by_finding(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for att in self.attributed.values():
            out.setdefault(att.origin_id, []).append(att.crash_id)
        return {k: sorted(v) for k, v in sorted(out.items())}


def _parse_srcs(name: str) -> list[str]:
    m = _SRC_RE.search(name)
    if not m:
        return []
    return [p for p in m.group(1).split("+") if p]


def _parse_orig(name: str) -> str | None:
    m = _ORIG_RE.search(name)
    return m.group(1) if m else None


def _instance_for_crash(crash_file: Path) -> tuple[str, Path] | None:
    """Resolve (instance name, afl output dir) for a crash file.

    Two layouts exist: ``<afl_out>/<instance>/crashes/<crash>`` and the
    merged directory ``<afl_out>/merged_crashes/<crash>,instance:<name>``
    (see ``AFLRunner._merge_crash_files``).
    """
    m = _INSTANCE_RE.search(crash_file.name)
    if m:
        return m.group(1), crash_file.parent.parent
    parent = crash_file.parent
    if parent.name == "crashes":
        return parent.parent.name, parent.parent.parent
    return None


def _queue_index(queue_dir: Path) -> dict[str, str]:
    """Map queue id -> queue entry filename."""
    index: dict[str, str] = {}
    try:
        for entry in queue_dir.iterdir():
            m = _ID_RE.search(entry.name)
            if m:
                index[m.group(1)] = entry.name
    except OSError:
        pass
    return index


def _root_orig_seeds(crash_name: str, queue_index: dict[str, str]) -> set[str] | None:
    """Walk the recorded src chain to the orig seed name(s).

    Returns the set of distinct root seed names, or None when the chain
    breaks (missing queue entry, no src on the crash, bounds hit) —
    a broken chain can never support an attribution.
    """
    frontier = _parse_srcs(crash_name)
    if not frontier:
        return None
    roots: set[str] = set()
    visited: set[str] = set()
    depth = 0
    while frontier:
        depth += 1
        if depth > _MAX_CHAIN_DEPTH or len(visited) > _MAX_VISITED:
            return None
        next_frontier: list[str] = []
        for qid in frontier:
            if qid in visited:
                continue
            visited.add(qid)
            entry_name = queue_index.get(qid)
            if entry_name is None:
                return None
            orig = _parse_orig(entry_name)
            if orig is not None:
                roots.add(orig)
                continue
            parents = _parse_srcs(entry_name)
            if not parents:
                return None
            next_frontier.extend(parents)
        frontier = next_frontier
    return roots or None


def load_seed_provenance(manifest_path: Path) -> dict[str, dict]:
    """Seed filename -> provenance entry from ``smt-seeds-manifest.json``."""
    try:
        data = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        logger.warning("SMT seed manifest unreadable (%s): %s", manifest_path, exc)
        return {}
    out: dict[str, dict] = {}
    for entry in data.get("seeds") or []:
        if isinstance(entry, dict) and entry.get("seed"):
            out[str(entry["seed"])] = entry
    return out


def attribute_crashes(
    crashes: list[Crash],
    manifest_path: Path,
) -> AttributionSummary:
    """Exact-lineage attribution of crashes to SMT-witness seeds.

    A crash is attributed only when every root of its recorded mutation
    chain is the same seed AND that seed is in the SMT manifest.
    """
    summary = AttributionSummary(total_crashes=len(crashes))
    provenance = load_seed_provenance(manifest_path)
    if not provenance:
        summary.unattributed = len(crashes)
        return summary

    queue_cache: dict[Path, dict[str, str]] = {}
    for crash in crashes:
        crash_file = Path(crash.input_file)
        located = _instance_for_crash(crash_file)
        if located is None:
            summary.unattributed += 1
            continue
        instance, afl_out = located
        queue_dir = afl_out / instance / "queue"
        if queue_dir not in queue_cache:
            queue_cache[queue_dir] = _queue_index(queue_dir)
        roots = _root_orig_seeds(crash_file.name, queue_cache[queue_dir])
        if not roots or len(roots) != 1:
            summary.unattributed += 1
            continue
        seed_name = next(iter(roots))
        entry = provenance.get(seed_name)
        if entry is None:
            summary.unattributed += 1
            continue
        summary.attributed[crash.crash_id] = CrashAttribution(
            crash_id=crash.crash_id,
            seed_name=seed_name,
            origin_id=str(entry.get("origin_id") or "unknown"),
            source_file=str(entry.get("source_file") or ""),
        )
    return summary


def manifest_path_for_run(run_out_dir: Path) -> Path:
    """Where ``--from-smt-witness`` wrote the manifest for this run."""
    return Path(run_out_dir) / SEED_DIR_NAME / MANIFEST_NAME

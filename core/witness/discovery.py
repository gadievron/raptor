"""Locate WitnessStore-shaped directories visible to a run.

A single RAPTOR run typically has 1-2 stores under its own output
dir (``<out>/witnesses/`` for fuzz crashes, ``<out>/analysis/
witnesses/`` for crash-agent LLM exploits, ``<out>/autonomous/
witnesses/`` for ``/agentic``). When the operator has a
``/project`` active, prior runs against the same target add more:
a ``/fuzz`` run last week may have produced witnesses that today's
``/validate`` should consume to upgrade its mitigation verdicts.

This module is the discovery seam between "find every store
visible to me" and the per-consumer matching logic (in e.g.
``core/witness/matching.py``).

Two scopes:

  * **Run-local** — always: the current run's own stores.
  * **Project-wide** — when a project root is known: all sibling
    runs' stores under that root.

Stores are returned as paths to the store *root* (the directory
containing ``manifests/`` and ``blobs/``). Consumers wrap each in
``WitnessStore(root)`` and iterate.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


# Sub-paths within a run's output dir that conventionally hold
# witness stores. Order is informational only — discovery returns
# every existing store; consumers do their own ranking.
_RUN_LOCAL_SUBPATHS = (
    "witnesses",
    "analysis/witnesses",       # crash-agent under raptor_fuzzing
    "autonomous/witnesses",     # /agentic's AutonomousSecurityAgentV2
)


def _is_store_dir(path: Path) -> bool:
    """A directory is a WitnessStore root when it contains a
    ``manifests/`` subdir (the blobs/ subdir is created on first
    write but absent on a never-written store)."""
    return path.is_dir() and (path / "manifests").is_dir()


def discover_witness_stores(
    output_dir: Optional[Path],
    *,
    project_root: Optional[Path] = None,
) -> List[Path]:
    """Return all WitnessStore root directories visible to this run.

    Args:
        output_dir: The current run's output dir. ``None`` is
            tolerated (returns empty list when project_root is
            also None).
        project_root: When set, also scan every sibling run under
            this directory. Typically the resolved
            ``<active_project>.output_dir`` from
            ``_resolve_active_project()``. ``None`` for runs
            without a project.

    Returns:
        Deduplicated list of store roots. Run-local stores appear
        first (operators tend to expect the current run's data
        listed first); project-wide siblings follow. Each path
        is verified to contain a ``manifests/`` subdir.

    Never raises. Missing dirs, permission errors, and unreadable
    project roots all log at debug and produce a shorter list.
    """
    seen: set = set()
    out: List[Path] = []

    # Run-local first
    if output_dir is not None:
        for sub in _RUN_LOCAL_SUBPATHS:
            candidate = Path(output_dir) / sub
            if _is_store_dir(candidate):
                resolved = candidate.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    out.append(candidate)

    # Project-wide siblings
    if project_root is not None:
        try:
            entries = list(Path(project_root).iterdir())
        except OSError as e:
            logger.debug(
                "discover_witness_stores: cannot list project root "
                "%s: %s", project_root, e,
            )
            entries = []

        for run_dir in sorted(entries):
            if not run_dir.is_dir():
                continue
            for sub in _RUN_LOCAL_SUBPATHS:
                candidate = run_dir / sub
                if _is_store_dir(candidate):
                    resolved = candidate.resolve()
                    if resolved not in seen:
                        seen.add(resolved)
                        out.append(candidate)

    return out


def iter_visible_witnesses(stores: List[Path]):
    """Yield (store_path, Witness) pairs across the supplied
    stores in their listed order.

    Dedup by ``bytes_hash`` — if the same exploit bytes appear in
    multiple stores (cross-run dedup), only the first occurrence
    is yielded. Run-local stores come first per
    :func:`discover_witness_stores`, so a project's older
    duplicate yields after the current run's copy.

    Failures within a store (malformed manifests, missing
    Witness fields) are skipped per the store's own
    ``list_witnesses`` contract.
    """
    from core.witness.store import WitnessStore

    seen_hashes: set = set()
    for root in stores:
        try:
            store = WitnessStore(root)
        except Exception as e:  # noqa: BLE001 — best-effort
            logger.debug(
                "iter_visible_witnesses: skipping %s: %s: %s",
                root, type(e).__name__, e,
            )
            continue
        try:
            for w in store.list_witnesses():
                if w.bytes_hash in seen_hashes:
                    continue
                seen_hashes.add(w.bytes_hash)
                yield root, w
        except Exception as e:  # noqa: BLE001 — best-effort
            logger.debug(
                "iter_visible_witnesses: iteration aborted in %s: "
                "%s: %s", root, type(e).__name__, e,
            )

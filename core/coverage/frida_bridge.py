"""Bridge: import frida drcov coverage into the persistent CoverageStore.

Called by the coverage importer when frida evidence is discovered
for the current target. Uses the existing import_drcov pipeline --
this module just discovers and orchestrates.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Optional

from core.logging import get_logger

if TYPE_CHECKING:
    from core.coverage.store import CoverageStore

log = get_logger("coverage.frida_bridge")


def import_frida_coverage(
    store: "CoverageStore",
    checklist: Dict[str, Any],
    search_dirs: list[Path],
    target_binary: Optional[str] = None,
    target_path: Optional[str] = None,
) -> int:
    """Discover frida drcov files and import them into the coverage store.

    Returns number of marks made. Zero if no frida evidence found (graceful).
    Requires target_binary (debug binary path for addr2line resolution).
    """
    if not search_dirs:
        return 0

    try:
        from packages.frida.evidence import discover_evidence
    except ImportError:
        return 0

    evidence_list = discover_evidence(search_dirs, target_path=target_path)
    if not evidence_list:
        return 0

    from core.coverage.collect import import_drcov

    _MAX_DRCOV_FILES = 10

    drcov_evidence = [ev for ev in evidence_list if ev.has_drcov][:_MAX_DRCOV_FILES]

    total = 0
    for ev in drcov_evidence:
        binary = target_binary or ev.target_binary
        if not binary:
            log.debug("frida drcov at %s skipped: no binary for addr2line", ev.run_dir)
            continue
        drcov_path = ev.run_dir / "coverage.drcov"
        try:
            marks = import_drcov(store, drcov_path, binary, checklist, tool="frida")
        except Exception as exc:
            log.warning("frida drcov import failed for %s: %s: %s",
                        drcov_path, type(exc).__name__, exc)
            continue
        if marks > 0:
            log.info("imported %d coverage marks from frida drcov at %s", marks, ev.run_dir)
        total += marks
    return total

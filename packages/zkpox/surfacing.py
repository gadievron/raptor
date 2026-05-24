"""Free end-of-run surfacing of ZKPoX eligibility.

The design's trigger model makes eligibility *free* — operators
see "N of M witnesses are ZKPoX-eligible" in the run summary
without asking for anything heavier (no bundle assembly, no
execution). This module is the run-script-facing entry point that
does the discovery + classification + render in one call.

Lives in ``packages/zkpox/`` (not ``core/reporting/``) because it
imports ``packages.zkpox.eligibility`` — and ``core/`` must not
import ``packages/``. Run scripts (``raptor_fuzzing``,
``raptor_agentic``) sit above both layers and call this alongside
``core.reporting.render_witness_summary``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def render_run_eligibility(
    output_dir: Optional[Path],
    *,
    project_root: Optional[Path] = None,
    indent: str = "   ",
) -> Optional[str]:
    """Discover witnesses visible to a run and render the free
    ZKPoX-eligibility summary block.

    Reuses ``core.witness.discover_witness_stores`` /
    ``iter_visible_witnesses`` (#614) so it sees the same stores
    the witness summary does — run-local plus, when a ``/project``
    is active, sibling runs.

    Returns ``None`` when there are no witnesses (caller skips the
    header), matching the cadence of
    ``core.reporting.render_witness_summary``.

    Never raises — discovery / classification failures log at
    debug and produce ``None``. The end-of-run summary must not
    crash because of a witness-store hiccup.
    """
    try:
        from core.witness import (
            discover_witness_stores,
            iter_visible_witnesses,
        )
        from packages.zkpox.eligibility import render_eligibility_summary
    except ImportError as e:
        logger.debug("render_run_eligibility: import failed: %s", e)
        return None

    try:
        stores = discover_witness_stores(
            output_dir, project_root=project_root,
        )
        if not stores:
            return None
        witnesses = [w for _, w in iter_visible_witnesses(stores)]
        return render_eligibility_summary(witnesses, indent=indent)
    except Exception as e:  # noqa: BLE001 — best-effort surfacing
        logger.debug(
            "render_run_eligibility: %s: %s", type(e).__name__, e,
        )
        return None

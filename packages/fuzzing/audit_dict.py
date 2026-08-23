"""Discovery of audit-generated AFL dictionaries.

/audit emits ``fuzz.dict`` (AFL ``name="value"`` format, tokens mined
from unique constants, parse-shape string literals, dispatch keys —
see ``core.audit.fuzz_handoff``). This module lets /fuzz pick that
dictionary up automatically when the operator did not pass ``--dict``:
own run dir first, then the newest sibling run dir — the same
convention the fuzz→audit ``coverage-fuzz.json`` bridge uses in the
other direction.

Best-effort and bounded: a missing or oversized dictionary simply
means no ``-x`` flag, exactly as before.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

DICT_FILENAME = "fuzz.dict"

# Refuse absurd dictionaries — AFL slows down badly past a few
# thousand tokens and a huge file suggests a broken producer.
MAX_DICT_BYTES = 1024 * 1024


def _usable(path: Path) -> bool:
    try:
        return path.is_file() and 0 < path.stat().st_size <= MAX_DICT_BYTES
    except OSError:
        return False


def discover_audit_dict(out_dir: Path | None) -> Path | None:
    """Find an audit-generated dictionary for this run.

    Looks in the run's own output dir first (shared-dir pipelines),
    then in sibling run dirs under the same parent (project layouts),
    newest dictionary by mtime. Returns None when nothing usable is
    found. Never raises.
    """
    if out_dir is None:
        return None
    try:
        out_dir = Path(out_dir)

        own = out_dir / DICT_FILENAME
        if _usable(own):
            logger.info("using audit-generated dictionary: %s", own)
            return own

        parent = out_dir.parent
        if not parent.is_dir():
            return None
        candidates = []
        for sibling in parent.iterdir():
            if sibling == out_dir or not sibling.is_dir():
                continue
            cand = sibling / DICT_FILENAME
            if _usable(cand):
                candidates.append(cand)
        if not candidates:
            return None
        best = max(candidates, key=lambda p: p.stat().st_mtime)
        logger.info(
            "using audit-generated dictionary from sibling run: %s", best,
        )
        return best
    except Exception:
        logger.debug("audit dictionary discovery failed", exc_info=True)
        return None

"""Per-artifact reload cache for the audit prep phase.

A resumed /audit segment re-ran the whole mechanical prep phase even
though the inputs (target tree + pinned checklist) were unchanged.
Each expensive prep artifact persists a lossless cache file under
``<out_dir>/prep-cache/`` keyed by a deterministic fingerprint of that
artifact's ACTUAL inputs; a resumed segment reloads on fingerprint
match and rebuilds loudly on mismatch or corruption. Writes are atomic
and best-effort — a cache failure never costs the run.

Doctrine: the fingerprint must cover every input that can change the
artifact, and nothing derived from per-segment state (gaps remaining,
journal, budgets) may be cached — per-segment state changes between
resumed segments without changing any fingerprintable input.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

PREP_CACHE_DIRNAME = "prep-cache"


def content_fingerprint(items: Iterable[tuple[str, bytes]]) -> str:
    """Deterministic fingerprint over ``(name, content)`` pairs.

    Pairs are hashed in the order given: callers whose builds are
    order-sensitive (aggregate byte budgets) fingerprint in build
    order; callers with order-free inputs pre-sort.
    """
    h = hashlib.sha256()
    for name, data in items:
        h.update(name.encode("utf-8", "replace"))
        h.update(b"\0")
        h.update(hashlib.sha256(data).digest())
    return h.hexdigest()


def source_fingerprint(source_texts: dict[str, str]) -> str:
    """Deterministic fingerprint of an in-memory source-text map.

    An artifact that is a pure function of the source texts is exact
    to reload whenever this fingerprint is unchanged on a resumed
    segment.
    """
    return content_fingerprint(
        (path, source_texts[path].encode("utf-8", "replace"))
        for path in sorted(source_texts)
    )


def prep_cache_path(out_dir: Path | str, filename: str) -> Path:
    return Path(out_dir) / PREP_CACHE_DIRNAME / filename


def load_prep_cache(
    out_dir: Path | str,
    filename: str,
    fingerprint: str,
    *,
    label: str,
) -> Any | None:
    """The cached payload, or None on miss/mismatch/corruption.

    A stale fingerprint logs at INFO (the rebuild that follows is the
    expensive path — it should be attributable); an unreadable cache
    logs at debug and rebuilds.
    """
    path = prep_cache_path(out_dir, filename)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("fingerprint") != fingerprint:
            logger.info(
                "%s prep cache stale (input fingerprint changed) — "
                "rebuilding", label,
            )
            return None
        return data.get("payload")
    except Exception:
        logger.debug("%s prep cache unreadable — rebuilding", label,
                     exc_info=True)
        return None


def write_prep_cache(
    out_dir: Path | str,
    filename: str,
    fingerprint: str,
    payload: Any,
    *,
    label: str,
) -> None:
    """Best-effort atomic persist; a failure never costs the run."""
    try:
        cache_dir = Path(out_dir) / PREP_CACHE_DIRNAME
        cache_dir.mkdir(parents=True, exist_ok=True)
        blob = json.dumps({"fingerprint": fingerprint, "payload": payload})
        fd, tmp = tempfile.mkstemp(dir=str(cache_dir), suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(blob)
        os.replace(tmp, cache_dir / filename)
    except Exception:
        logger.debug("%s prep cache write failed", label, exc_info=True)

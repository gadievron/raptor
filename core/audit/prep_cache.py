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

Integrity: the fingerprint AUTHENTICATES nothing — it is computed
over attacker-knowable inputs (the target's own source texts) with a
public recipe, and the cache lives in the target-writable run dir, so
a run-dir writer could forge a payload (empty detector results,
steered codeql prep) and stamp it with a recomputed fingerprint.
Every cache file therefore carries a run-bound HMAC token over its
canonical ``{fingerprint, payload}`` row
(``core.coverage.journal_mac``, prep-cache domain — the
journal/audit-log key and discipline); the loader treats a missing or
unverifiable token as a MISS and rebuilds from the tree. Fail toward
recompute: on hosts with no usable MAC key the cache never hits, and
it never serves unauthenticated payloads.
"""

from __future__ import annotations

import hashlib
import json
import logging
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
        from core.coverage import journal_mac

        data = json.loads(path.read_text(encoding="utf-8"))  # raw-open: RAPTOR-written prep cache in the run dir
        if data.get("fingerprint") != fingerprint:
            logger.info(
                "%s prep cache stale (input fingerprint changed) — "
                "rebuilding", label,
            )
            return None
        # Authority gate (module docstring): the payload is served as
        # a mechanical analysis input, so only a row whose run-bound
        # token verifies may hit — a forged/unstamped/replayed row is
        # a MISS, never an error (fail toward recompute).
        if not journal_mac.verify_prep_cache_row(
            data, data.get(journal_mac.TOKEN_KEY),
            journal_mac.audit_log_run_binding(out_dir),
        ):
            logger.info(
                "%s prep cache integrity token missing or unverified "
                "— rebuilding", label,
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
        from core.coverage import journal_mac

        # Raw json.dumps is deliberate: an unserialisable payload must
        # make the write fail (TypeError → best-effort skip) rather
        # than be stringified and later served back from the cache as
        # a corrupted payload shape.
        row: dict[str, Any] = {
            "fingerprint": fingerprint, "payload": payload,
        }
        token = journal_mac.mint_prep_cache_row(
            row, journal_mac.audit_log_run_binding(out_dir))
        if token is not None:
            row[journal_mac.TOKEN_KEY] = token
        blob = json.dumps(row)
        # Shared atomic writer: the hand-rolled mkstemp/replace pair
        # leaked its .tmp file when the write failed mid-way and never
        # fsynced before the rename.
        from core.atomic_fs import write_text_atomically
        write_text_atomically(cache_dir / filename, blob)
    except Exception:
        logger.debug("%s prep cache write failed", label, exc_info=True)

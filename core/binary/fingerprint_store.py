"""Persistent fingerprint store — substrate for drift detection.

Maps ``ref`` (operator-visible identifier, typically an image
ref like ``docker.io/library/alpine:3.18`` or a file path) to
the most recently observed :class:`CapabilityFingerprint`.
Stored on disk so subsequent scans can compare against the
previous run's baseline.

File layout
-----------
The store is a directory. One file per ref, named by SHA-256 of
the ref string:

::

    <store_dir>/
        sha256_abc.../...json     # one ref's most recent fingerprint
        sha256_def.../...json     # another ref
        ...

The hashing avoids escaping pathologies in filenames (image refs
contain ``/`` and ``:``); the original ref is recorded inside
the file so :func:`iter_refs` can enumerate by ref, not by hash.

Writes are atomic: tmp file + rename. A partial write never
leaves the store inconsistent.

File schema (versioned)
-----------------------
::

    {
        "schema_version": 1,
        "ref": "<operator-visible identifier>",
        "fingerprint": { ... CapabilityFingerprint.to_dict() ... }
    }

The fingerprint version (``schema_version`` inside the
fingerprint dict) is checked separately by consumers; the store
schema versions the wrapper around it.

Error handling
--------------
All operations return ``None`` / ``[]`` on routine failure
(missing file, corrupt JSON, permission denied). The store
NEVER raises during scan-path use — a drift-detector that
crashes on a corrupt entry would block scans.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Iterator, Optional, Tuple

from core.binary.fingerprint import CapabilityFingerprint

logger = logging.getLogger(__name__)


# Bump when the WRAPPER format around the fingerprint changes
# (not the fingerprint itself — that has its own version).
STORE_SCHEMA_VERSION = 1


def _ref_filename(ref: str) -> str:
    """SHA-256 of the ref → safe filename. Hashing avoids
    filename-escaping bugs across the variety of refs we'll see
    (image refs with ``/`` and ``:`` and ``@``, file paths with
    spaces, etc.)."""
    digest = hashlib.sha256(ref.encode("utf-8")).hexdigest()
    return f"{digest}.json"


def save_fingerprint(
    store_dir: Path, ref: str, fingerprint: CapabilityFingerprint,
) -> Optional[Path]:
    """Atomically write ``fingerprint`` to ``store_dir`` keyed
    by ``ref``. Replaces any previous entry for the same ref.

    Returns the written path, or None on any I/O failure
    (logs at warning).
    """
    if not ref:
        logger.debug(
            "core.binary.fingerprint_store: empty ref; skipping write",
        )
        return None
    try:
        store_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.warning(
            "core.binary.fingerprint_store: mkdir failed for %s: %s",
            store_dir, e,
        )
        return None

    payload = {
        "schema_version": STORE_SCHEMA_VERSION,
        "ref": ref,
        "fingerprint": fingerprint.to_dict(),
    }
    final_path = store_dir / _ref_filename(ref)
    # Atomic write: tmp file in the same dir (so rename is on
    # the same filesystem and stays atomic), then os.replace.
    try:
        fd, tmp_name = tempfile.mkstemp(
            prefix=".tmp-", suffix=".json", dir=store_dir,
        )
    except OSError as e:
        logger.warning(
            "core.binary.fingerprint_store: tempfile failed for %s: %s",
            store_dir, e,
        )
        return None
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, sort_keys=True, indent=2)
        os.replace(tmp_name, final_path)
    except OSError as e:
        logger.warning(
            "core.binary.fingerprint_store: write failed for %s: %s",
            final_path, e,
        )
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        return None
    return final_path


def load_fingerprint(
    store_dir: Path, ref: str,
) -> Optional[CapabilityFingerprint]:
    """Load the most recently stored fingerprint for ``ref``.

    Returns ``None`` when:
      * No entry exists for that ref (first-ever scan of this
        image — the drift detector treats this as "no baseline,
        no drift signal yet").
      * Store entry is corrupt / unreadable.
      * Store schema version doesn't match — caller treats as
        no-baseline rather than risking misinterpretation.
    """
    if not ref:
        return None
    file_path = store_dir / _ref_filename(ref)
    if not file_path.is_file():
        return None
    try:
        with open(file_path, "r") as f:
            payload = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.debug(
            "core.binary.fingerprint_store: load failed for %s: %s",
            file_path, e,
        )
        return None
    if not isinstance(payload, dict):
        return None
    version = payload.get("schema_version")
    if version != STORE_SCHEMA_VERSION:
        logger.debug(
            "core.binary.fingerprint_store: schema version %s != %s "
            "for %s; treating as no baseline",
            version, STORE_SCHEMA_VERSION, file_path,
        )
        return None
    fp_dict = payload.get("fingerprint")
    if not isinstance(fp_dict, dict):
        return None
    try:
        return CapabilityFingerprint.from_dict(fp_dict)
    except (KeyError, TypeError, ValueError) as e:
        logger.debug(
            "core.binary.fingerprint_store: from_dict failed for "
            "%s: %s", file_path, e,
        )
        return None


def iter_refs(
    store_dir: Path,
) -> Iterator[Tuple[str, CapabilityFingerprint]]:
    """Yield ``(ref, fingerprint)`` for every entry in the store.

    Useful for store-wide audits / CI gates / drift-detection
    reports. Skips entries that don't load cleanly (corrupt,
    wrong schema version, etc.) — logs each skip at debug.
    """
    if not store_dir.is_dir():
        return
    for entry in sorted(store_dir.iterdir()):
        if not entry.is_file() or not entry.name.endswith(".json"):
            continue
        if entry.name.startswith(".tmp-"):
            # An in-flight atomic write left a tmp file behind
            # (process killed mid-write). Skip silently — the
            # final-named entry is what's load-bearing.
            continue
        try:
            with open(entry, "r") as f:
                payload = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        if payload.get("schema_version") != STORE_SCHEMA_VERSION:
            continue
        ref = payload.get("ref")
        fp_dict = payload.get("fingerprint")
        if not isinstance(ref, str) or not isinstance(fp_dict, dict):
            continue
        try:
            fp = CapabilityFingerprint.from_dict(fp_dict)
        except (KeyError, TypeError, ValueError):
            continue
        yield ref, fp


def delete_fingerprint(store_dir: Path, ref: str) -> bool:
    """Remove the entry for ``ref``. Returns True if a file was
    removed, False if no entry existed. Useful for operators
    invalidating a baseline manually."""
    if not ref:
        return False
    file_path = store_dir / _ref_filename(ref)
    if not file_path.is_file():
        return False
    try:
        file_path.unlink()
        return True
    except OSError as e:
        logger.warning(
            "core.binary.fingerprint_store: delete failed for %s: %s",
            file_path, e,
        )
        return False


__all__ = [
    "STORE_SCHEMA_VERSION",
    "delete_fingerprint",
    "iter_refs",
    "load_fingerprint",
    "save_fingerprint",
]

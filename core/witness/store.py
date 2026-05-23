"""Hash-addressed persistence for :class:`~core.witness.types.Witness`
records and their underlying bytes.

Storage layout under the configured root directory::

    {root}/
        manifests/
            <sha256>.json          # Witness.to_dict() per witness
        blobs/
            <sha256>.bin           # raw bytes (de-duplicated by hash)
        index.json                 # listing of all known hashes

Same bytes seen by multiple pipelines collapse to a single blob —
the hash key naturally de-duplicates. Two ``Witness`` records can
share a single ``blobs/<sha256>.bin`` if their bytes happen to
match; each has its own manifest with its own provenance.

The store is process-local: no concurrent-writer locking. Each
pipeline run gets its own ``{out_dir}/witnesses/`` root, so
concurrent runs on the same host don't collide. Within a single
run, callers are expected to be sequential — same as the existing
finding-record producers in the project.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Iterator, Optional

from core.witness.types import Witness, compute_bytes_hash


logger = logging.getLogger(__name__)


class WitnessStoreError(Exception):
    """Raised when a store operation fails in a way the caller
    needs to surface (bad hash, missing blob, etc.). Distinct
    exception type so callers can catch witness-store errors
    specifically without swallowing arbitrary OSErrors."""


class WitnessStore:
    """Read/write Witness records + their bytes, hash-addressed.

    Construct with a root directory; the store creates the manifest
    and blob sub-directories on demand. ``root`` is typically
    ``{run_out_dir}/witnesses/`` so each pipeline run's witnesses
    cluster together.

    Operations:

    * :meth:`put` — store bytes + an associated Witness; idempotent
      on (hash, source, observed_outcome, produced_by) — putting a
      duplicate is a no-op for the blob and overwrites the manifest
      with the most recent record (timestamps cumulate via the
      index).
    * :meth:`get_bytes` — load the raw bytes for a hash.
    * :meth:`get_witness` — load a Witness record by hash.
    * :meth:`list_witnesses` — iterate every Witness in the store.
    * :meth:`has` — quick existence check.

    Failures (missing file, malformed JSON) raise
    :class:`WitnessStoreError`. The store does *not* swallow errors
    silently — a caller that gets a Witness back can rely on its
    manifest having parsed cleanly.
    """

    def __init__(self, root: Path):
        self.root = Path(root)
        self._manifests_dir = self.root / "manifests"
        self._blobs_dir = self.root / "blobs"

    def _ensure_dirs(self) -> None:
        """Create the manifest + blob directories if absent.

        Called lazily on the first write rather than eagerly in
        ``__init__`` so constructing a store object for a path
        that doesn't yet exist (e.g. dry-runs / planning) doesn't
        side-effect the filesystem.
        """
        self._manifests_dir.mkdir(parents=True, exist_ok=True)
        self._blobs_dir.mkdir(parents=True, exist_ok=True)

    def put(self, witness: Witness, data: bytes) -> Path:
        """Persist ``witness`` and ``data``. Returns the blob path.

        Validates four invariants before touching disk:

        1. ``witness.bytes_hash == sha256(data)`` — catches the
           producer bug of hashing a transformed copy of the bytes.
        2. If ``witness.bytes_len`` is set (non-zero), it matches
           ``len(data)``. If left at default ``0``, the store
           stamps it from the actual length.
        3. ``witness.outcome_detail`` is JSON-serialisable.
           Pre-check catches non-serialisable values
           (:class:`pathlib.Path`, :class:`datetime`, ``bytes``,
           etc.) with a clear ``WitnessStoreError`` *before* the
           blob is written, so a serialisation failure can't leave
           an orphan blob.

        Blob writes are idempotent — if the same hash is put again,
        the existing blob is reused (no rewrite). Both blob and
        manifest writes are atomic via the temp-file + rename
        pattern; a process killed mid-write leaves the on-disk
        state at "before the put started", never a partial /
        corrupt artefact.
        """
        expected = compute_bytes_hash(data)
        if expected != witness.bytes_hash:
            raise WitnessStoreError(
                f"witness.bytes_hash {witness.bytes_hash[:16]!r}... "
                f"does not match sha256(data) {expected[:16]!r}...; "
                "fix the producer to use compute_bytes_hash on the "
                "actual bytes being stored"
            )

        # Enforce bytes_len agreement when caller set it. Pre-fix
        # the store accepted (and persisted) a caller-supplied
        # bytes_len that disagreed with len(data) — silent corruption
        # of the manifest, which downstream consumers trust.
        if witness.bytes_len and witness.bytes_len != len(data):
            raise WitnessStoreError(
                f"witness.bytes_len ({witness.bytes_len}) does not "
                f"match len(data) ({len(data)}); pass bytes_len=0 to "
                f"let the store stamp it, or fix the producer"
            )
        if witness.bytes_len == 0 and data:
            witness.bytes_len = len(data)

        # Pre-serialise the manifest so non-JSON-safe values in
        # ``outcome_detail`` fail loudly here, not after we've
        # already written the blob. Common offenders:
        # :class:`pathlib.Path`, :class:`datetime`, ``bytes``,
        # custom classes. The fix at the call site is to stringify.
        try:
            manifest_text = (
                json.dumps(witness.to_dict(), indent=2) + "\n"
            )
        except (TypeError, ValueError) as exc:
            raise WitnessStoreError(
                f"witness manifest is not JSON-serialisable "
                f"({type(exc).__name__}: {exc}); convert any "
                f"Path / datetime / bytes / custom-class values in "
                f"outcome_detail to strings before constructing the "
                f"Witness"
            ) from exc

        self._ensure_dirs()

        blob_path = self._blobs_dir / f"{witness.bytes_hash}.bin"
        manifest_path = self._manifests_dir / f"{witness.bytes_hash}.json"

        # Atomic blob write: write to .tmp + os.replace. POSIX
        # guarantees the rename is atomic. Pre-fix ``write_bytes``
        # was direct and a crash mid-write left a partial blob
        # that subsequent puts would skip (since blob_path.exists()
        # was True), producing on-disk corruption invisible to
        # later readers.
        # ``.tmp`` paths are made unique per (pid, thread) so two
        # concurrent ``put()`` calls writing the same hash don't
        # race on the same temp file — the original ``.bin.tmp`` /
        # ``.json.tmp`` suffix collided when N threads wrote identical
        # bytes, with N-1 callers raising ``FileNotFoundError`` on
        # the second ``os.replace`` (the first one had already
        # consumed the shared tempfile). End state was still correct
        # (dedup by hash) but most callers got an exception. The
        # pid+tid suffix keeps the existing crash-mid-write guarantee
        # (each tempfile is still atomically renamed onto the final
        # path) while making same-hash concurrent writes succeed.
        suffix = f".{os.getpid()}.{threading.get_ident()}.tmp"
        if not blob_path.exists():
            blob_tmp = blob_path.with_suffix(".bin" + suffix)
            blob_tmp.write_bytes(data)
            try:
                os.replace(blob_tmp, blob_path)
            except FileNotFoundError:
                # Lost the race: another writer replaced the .tmp out
                # from under us. The final blob_path now holds the
                # same bytes (verified by hash); nothing to do.
                pass

        # Atomic manifest write. Pre-fix ``write_text`` was direct
        # and a crash mid-write left a malformed JSON file forever
        # — list_witnesses skipped it with a warning but get_witness
        # raised, and there was no recovery path other than manual
        # cleanup.
        manifest_tmp = manifest_path.with_suffix(".json" + suffix)
        manifest_tmp.write_text(manifest_text, encoding="utf-8")
        try:
            os.replace(manifest_tmp, manifest_path)
        except FileNotFoundError:
            pass

        logger.debug(
            "WitnessStore.put: hash=%s len=%d source=%s outcome=%s",
            witness.bytes_hash[:16],
            witness.bytes_len,
            witness.source.value,
            witness.observed_outcome.value,
        )

        return blob_path

    def has(self, bytes_hash: str) -> bool:
        """True iff a manifest with ``bytes_hash`` exists in the store."""
        return (self._manifests_dir / f"{bytes_hash}.json").is_file()

    def get_bytes(self, bytes_hash: str) -> bytes:
        """Load the raw bytes for ``bytes_hash``.

        Raises :class:`WitnessStoreError` if the blob is missing.
        Does NOT verify the loaded bytes match the hash (would be
        slow and the store-write enforced it on put); a caller that
        suspects on-disk corruption can recompute themselves.
        """
        blob_path = self._blobs_dir / f"{bytes_hash}.bin"
        if not blob_path.is_file():
            raise WitnessStoreError(
                f"blob not found for hash {bytes_hash[:16]!r}... "
                f"(expected at {blob_path})"
            )
        return blob_path.read_bytes()

    def get_witness(self, bytes_hash: str) -> Witness:
        """Load the Witness record for ``bytes_hash``.

        Raises :class:`WitnessStoreError` if the manifest is missing
        or malformed.
        """
        manifest_path = self._manifests_dir / f"{bytes_hash}.json"
        if not manifest_path.is_file():
            raise WitnessStoreError(
                f"manifest not found for hash {bytes_hash[:16]!r}... "
                f"(expected at {manifest_path})"
            )
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise WitnessStoreError(
                f"manifest at {manifest_path} is malformed JSON: {exc}"
            ) from exc
        return Witness.from_dict(data)

    def list_witnesses(self) -> Iterator[Witness]:
        """Iterate every Witness in the store.

        Skips manifests that fail to parse (logs at WARNING). The
        store's contract is "load all valid witnesses"; one corrupt
        file shouldn't abort enumeration. Use :meth:`get_witness`
        for a specific hash if strict-load semantics are needed.
        """
        if not self._manifests_dir.is_dir():
            return
        for manifest in sorted(self._manifests_dir.glob("*.json")):
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
                yield Witness.from_dict(data)
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                logger.warning(
                    "WitnessStore: skipping malformed manifest %s: %s",
                    manifest, exc,
                )

    def blob_path(self, bytes_hash: str) -> Optional[Path]:
        """Return the path to the raw bytes blob, or ``None`` if
        the store doesn't have one for this hash.

        Useful when a consumer wants to pass the bytes to a tool
        that takes a filename (gcc, gdb, etc.) rather than reading
        them into memory.
        """
        path = self._blobs_dir / f"{bytes_hash}.bin"
        return path if path.is_file() else None

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
from pathlib import Path

from core.atomic_fs import write_bytes_atomically, write_text_atomically
from core.json import load_json
from core.witness.types import Witness, compute_bytes_hash
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator


logger = logging.getLogger(__name__)


class WitnessStoreError(Exception):
    """Raised when a store operation fails in a way the caller
    needs to surface (bad hash, missing blob, etc.). Distinct
    exception type so callers can catch witness-store errors
    specifically without swallowing arbitrary OSErrors."""


_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

# Byte budget for a single witness manifest — small JSON documents.
_MAX_MANIFEST_BYTES = 8 * 1024 * 1024


def _valid_hash_key(bytes_hash: str) -> bool:
    """Whether *bytes_hash* is a plain SHA-256 hex digest.

    The hash is interpolated into on-disk paths
    (``manifests/<hash>.json`` / ``blobs/<hash>.bin``) — anything but
    hex digits could traverse outside the store root (``../``), so
    the shape is validated BEFORE any filesystem use.
    """
    return (
        isinstance(bytes_hash, str)
        and len(bytes_hash) == 64
        and all(c in _HEX_DIGITS for c in bytes_hash)
    )


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

    def __init__(self, root: Path) -> None:
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
            msg = (
                f"witness.bytes_hash {witness.bytes_hash[:16]!r}... "
                f"does not match sha256(data) {expected[:16]!r}...; "
                "fix the producer to use compute_bytes_hash on the "
                "actual bytes being stored"
            )
            raise WitnessStoreError(msg)

        # Enforce bytes_len agreement when caller set it. Pre-fix
        # the store accepted (and persisted) a caller-supplied
        # bytes_len that disagreed with len(data) — silent corruption
        # of the manifest, which downstream consumers trust.
        if witness.bytes_len and witness.bytes_len != len(data):
            msg = (
                f"witness.bytes_len ({witness.bytes_len}) does not "
                f"match len(data) ({len(data)}); pass bytes_len=0 to "
                f"let the store stamp it, or fix the producer"
            )
            raise WitnessStoreError(msg)
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
            msg = (
                f"witness manifest is not JSON-serialisable "
                f"({type(exc).__name__}: {exc}); convert any "
                f"Path / datetime / bytes / custom-class values in "
                f"outcome_detail to strings before constructing the "
                f"Witness"
            )
            raise WitnessStoreError(msg) from exc

        self._ensure_dirs()

        blob_path = self._blobs_dir / f"{witness.bytes_hash}.bin"
        manifest_path = self._manifests_dir / f"{witness.bytes_hash}.json"

        # Atomic blob write: witness blob is the durable per-scan
        # artefact; a torn write would leave a partial blob that
        # dedup would trust as canonical for that hash. The shared
        # primitive's PID+TID+random tempfile suffix keeps
        # concurrent same-hash puts from racing on one tempfile
        # (previously N callers raised FileNotFoundError on the
        # second os.replace; end state was still correct via
        # dedup-by-hash, but the exceptions surfaced up).
        if not blob_path.exists():
            write_bytes_atomically(blob_path, data, tmp_prefix=".blob-")

        # Atomic manifest write. Same reasoning: a torn manifest
        # left get_witness raising forever with no recovery path
        # other than manual cleanup.
        write_text_atomically(
            manifest_path, manifest_text, tmp_prefix=".manifest-",
        )

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
        if not _valid_hash_key(bytes_hash):
            return False
        return (self._manifests_dir / f"{bytes_hash}.json").is_file()

    def get_bytes(self, bytes_hash: str) -> bytes:
        """Load the raw bytes for ``bytes_hash``, VERIFIED.

        Raises :class:`WitnessStoreError` if the hash key is not a
        plain SHA-256 hex digest (it becomes an on-disk path), if the
        blob is missing, or if the loaded bytes do not hash to
        ``bytes_hash`` — the store is hash-addressed, so content that
        fails its own address is a planted/corrupt blob, not evidence.
        """
        if not _valid_hash_key(bytes_hash):
            raise WitnessStoreError(
                f"invalid bytes_hash {str(bytes_hash)[:32]!r}: expected "
                f"a 64-char SHA-256 hex digest"
            )
        blob_path = self._blobs_dir / f"{bytes_hash}.bin"
        if not blob_path.is_file():
            msg = (
                f"blob not found for hash {bytes_hash[:16]!r}... "
                f"(expected at {blob_path})"
            )
            raise WitnessStoreError(msg)
        data = blob_path.read_bytes()
        actual = compute_bytes_hash(data)
        if actual.lower() != bytes_hash.lower():
            raise WitnessStoreError(
                f"blob at {blob_path} does not match its address: "
                f"expected {bytes_hash[:16]!r}..., content hashes to "
                f"{actual[:16]!r}... — corrupt or planted blob"
            )
        return data

    def get_witness(self, bytes_hash: str) -> Witness:
        """Load the Witness record for ``bytes_hash``.

        Raises :class:`WitnessStoreError` if the hash key is invalid,
        the manifest is missing or malformed, or the manifest's own
        ``bytes_hash`` disagrees with the address it was loaded from
        (a planted manifest claiming someone else's hash).
        """
        if not _valid_hash_key(bytes_hash):
            raise WitnessStoreError(
                f"invalid bytes_hash {str(bytes_hash)[:32]!r}: expected "
                f"a 64-char SHA-256 hex digest"
            )
        manifest_path = self._manifests_dir / f"{bytes_hash}.json"
        if not manifest_path.is_file():
            msg = (
                f"manifest not found for hash {bytes_hash[:16]!r}... "
                f"(expected at {manifest_path})"
            )
            raise WitnessStoreError(msg)
        try:
            data = load_json(
                manifest_path, strict=True,
                max_bytes=_MAX_MANIFEST_BYTES,
            )
            if data is None:
                # strict load_json still returns None (no raise) for a
                # missing file — the is_file check above can race a
                # concurrent delete; keep the WitnessStoreError
                # contract instead of crashing in from_dict.
                msg = (
                    f"manifest at {manifest_path} vanished during read"
                )
                raise WitnessStoreError(msg)
            witness = Witness.from_dict(data)
        except json.JSONDecodeError as exc:
            msg = f"manifest at {manifest_path} is malformed JSON: {exc}"
            raise WitnessStoreError(msg) from exc
        except (KeyError, ValueError) as exc:
            msg = f"manifest at {manifest_path} has invalid structure: {exc}"
            raise WitnessStoreError(msg) from exc
        if witness.bytes_hash.lower() != bytes_hash.lower():
            raise WitnessStoreError(
                f"manifest at {manifest_path} claims bytes_hash "
                f"{witness.bytes_hash[:16]!r}... — inconsistent with "
                f"its address; refusing the record"
            )
        return witness

    def list_witnesses(self) -> Iterator[Witness]:
        """Iterate every Witness in the store.

        Skips manifests that fail to parse AND manifests whose
        filename is not a valid hash address or disagrees with the
        record's own ``bytes_hash`` (logs at WARNING) — enumeration
        must not launder planted records that a direct
        :meth:`get_witness` would refuse. Use :meth:`get_witness` for
        a specific hash if strict-load semantics are needed.
        """
        if not self._manifests_dir.is_dir():
            return
        for manifest in sorted(self._manifests_dir.glob("*.json")):
            if not _valid_hash_key(manifest.stem):
                logger.warning(
                    "WitnessStore: skipping manifest with non-hash "
                    "name %s", manifest,
                )
                continue
            try:
                data = load_json(
                    manifest, strict=True,
                    max_bytes=_MAX_MANIFEST_BYTES,
                )
                if data is None:
                    # Missing-file race (glob → delete → load):
                    # strict load_json returns None instead of
                    # raising; skip like any other unreadable row.
                    logger.warning(
                        "WitnessStore: skipping vanished manifest %s",
                        manifest,
                    )
                    continue
                witness = Witness.from_dict(data)
            except (json.JSONDecodeError, KeyError, ValueError, TypeError, OSError) as exc:
                logger.warning(
                    "WitnessStore: skipping malformed manifest %s: %s",
                    manifest, exc,
                )
                continue
            if witness.bytes_hash.lower() != manifest.stem.lower():
                logger.warning(
                    "WitnessStore: skipping manifest %s claiming "
                    "bytes_hash %s (inconsistent with its address)",
                    manifest, witness.bytes_hash[:16],
                )
                continue
            yield witness

    def blob_path(self, bytes_hash: str) -> Path | None:
        """Return the path to the raw bytes blob, or ``None`` if
        the store doesn't have one for this hash.

        Useful when a consumer wants to pass the bytes to a tool
        that takes a filename (gcc, gdb, etc.) rather than reading
        them into memory. NOTE: this path is returned unverified;
        callers that act on the CONTENT should use :meth:`get_bytes`
        (which verifies the hash) or recompute it themselves.
        """
        if not _valid_hash_key(bytes_hash):
            return None
        path = self._blobs_dir / f"{bytes_hash}.bin"
        return path if path.is_file() else None

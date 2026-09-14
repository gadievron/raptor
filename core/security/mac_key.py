"""Shared load-or-create discipline for per-purpose HMAC key files.

Several integrity surfaces (SAGE row MACs, the LLM response cache, the
scorecard sidecar, review-journal rows, the IRIS spec store, witness
provenance) each mint HMAC-SHA256 tokens under a 32-byte key file in
the per-user XDG data dir. They previously each carried a private copy
of the same read/create loop, and the copies drifted: some tolerated
the benign key-creation race, others mis-flagged the winner's mid-write
key as suspect. This module owns the one hardened discipline; callers
keep their own key path, warning voice, and mint/verify semantics.

The contract
    * Reading an existing key uses fd-fstat discipline: refuse symlinks
      (``O_NOFOLLOW`` at open, fstat on the actually-opened inode),
      non-regular files, foreign owners, and any group/other permission
      bits. A refused key is never used and never replaced — silently
      re-keying would mask tampering.
    * Creation is atomic: 0700 parent dir, ``O_EXCL`` 0600 file, and
      the key bytes are written to completion (a short ``os.write``
      would leave a torn key that every later load refuses).
    * The loser of a creation race polls through the winner's write
      window: between the winner's ``O_EXCL`` create and its write the
      file legitimately reads short or empty, so the loser retries for
      a bounded budget and only reports a suspect key once the budget
      is exhausted. No warning fires on the benign race.
    * A wrong-length key observed on the initial read routes on file
      age: freshly-modified content may be a concurrent cold-start's
      winner mid-write, so it takes the create path (and its bounded
      poll); STALE content is a torn/truncated key from a past crash
      and refuses immediately with a wrong-length warning — spinning
      the race budget there would cost the full retry stall (plus a
      misleading race-window message) on every call against a key
      only an operator ``rm`` can heal.

Per-purpose keys are deliberate: both functions take the key *path*
and must never grow a default location or unify key files. Deleting
one subsystem's key is that subsystem's documented reset semantics and
must not reset any other's trust surface. Callers keep their keys
OUTSIDE every LLM-writable and sandbox-readable tree (the per-user XDG
data dir): several sandbox profiles grant children repo-root read, and
a scanned target that could read an in-repo key could mint valid
tokens for forged records.

``core/sandbox/telemetry_mac.py`` deliberately does NOT consume this
module: its policy quarantines same-uid metadata-tampered keys and
re-keys (recording a tamper marker) instead of refusing forever. Keep
the shared mechanics here aligned with its read/race handling when
editing either.
"""

from __future__ import annotations

import os
import secrets
import stat
import time
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

class Refused:
    """Sentinel type: a key file EXISTS but is unusable (symlink,
    foreign owner, group/other-readable). Distinct from "absent" — an
    unusable key must never be silently replaced and must never mint
    or verify."""


#: The singleton :class:`Refused` instance returned by
#: :func:`read_existing_key`. Compare with ``is``.
REFUSED: Final[Refused] = Refused()

# Race-loser retry budget: total wait = _RACE_RETRIES * _RACE_RETRY_S.
# Larger tolerates slower winners (loaded hosts, network filesystems)
# but stalls longer on a genuinely torn key that reaches the race
# branch; smaller returns faster there but mis-flags honest slow
# winners as suspect keys. 20 x 10 ms shipped first on the race-fixed
# sites and has held; both directions are pinned by tests
# (test_mac_key.py: loser tolerance and budget-exhaustion warning).
_RACE_RETRIES = 20
_RACE_RETRY_S = 0.01

# Freshness window for wrong-length content observed on the INITIAL
# read (no O_EXCL loss yet, so no positive evidence of a concurrent
# creator). Within the window the content may be a mid-write file from
# a concurrent cold-start, so the create path (and its bounded poll)
# is taken; beyond it the content is stable torn/truncated and refuses
# immediately. Larger keeps stalling on a genuinely torn key for
# longer after the tear; smaller risks refusing an honest concurrent
# creator on filesystems with coarse mtime granularity (classic NFS
# rounds to 1 s, so anything under ~2 s can mis-age a brand-new file).
# Both directions are pinned by tests (fresh converges, stale refuses
# without a poll).
_FRESH_WINDOW_S = 5.0


def _recently_modified(path: Path) -> bool:
    """Whether *path* was modified within :data:`_FRESH_WINDOW_S`.

    Fails toward "fresh": a vanished or unstatable file routes to the
    create path, which resolves every shape safely — O_EXCL either
    wins on the vanished file or loses into the bounded poll.

    Mtime skew is bounded in BOTH directions: a slightly-future mtime
    (NFS / clock skew inside the window) still reads fresh so a
    racing peer's mid-write isn't misdiagnosed, but a FAR-future
    mtime cannot be a peer writing "just now" on this clock — treat
    it stale so a torn key with corrupt timestamps refuses loudly
    (operator-visible warning) instead of re-entering the race poll
    on every call forever.
    """
    try:
        st = os.lstat(path)
    except OSError:
        return True
    return abs(time.time() - st.st_mtime) < _FRESH_WINDOW_S


def read_existing_key(
    path: Path,
    *,
    key_len: int,
    warn: Callable[[Path, str, str], None],
) -> bytes | Refused | None:
    """Read an EXISTING key with fd-fstat discipline.

    Returns the key bytes (possibly short/over-length — the caller
    length-checks), ``None`` when the file is absent, or :data:`REFUSED`
    when the file exists but is unusable. Refuses symlinks
    (``O_NOFOLLOW`` at open, fstat on the actually-opened inode),
    non-regular files, foreign owners, and any group/other permission
    bits — an exposed or substituted key would let anyone mint valid
    tokens. Creation (``O_EXCL`` + 0600) needs no such check; this
    guard covers only the read-existing branch.
    """
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as exc:
        # ELOOP: symlink at the key path. Other OSErrors are equally
        # unusable — never fall back to a follow-the-link read.
        warn(
            path, f"open refused ({exc})",
            "if the key is a symlink, remove it and investigate how it "
            "got there; a fresh key is created on the next stamp",
        )
        return REFUSED
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            warn(
                path, "not a regular file",
                "remove the object at that path and investigate",
            )
            return REFUSED
        if st.st_uid != os.geteuid():
            warn(
                path,
                f"owned by uid={st.st_uid}, expected uid={os.geteuid()}",
                "investigate the foreign-owned key; restore your own "
                "0600 key file",
            )
            return REFUSED
        if st.st_mode & 0o077:
            warn(
                path,
                f"mode {stat.S_IMODE(st.st_mode):04o} grants group/other "
                "access",
                f"chmod 600 {path}",
            )
            return REFUSED
        # A single os.read may return fewer bytes than requested
        # (network filesystems); a short read would land a healthy key
        # in the wrong-length refusal, so loop to EOF. The cap stays at
        # key_len * 4 — genuinely oversized files still fail-close in
        # the caller's length check.
        chunks: list[bytes] = []
        remaining = key_len * 4
        while remaining > 0:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    except OSError:
        return None
    finally:
        os.close(fd)


def load_or_create_key(
    path: Path,
    *,
    key_len: int,
    warn: Callable[[Path, str, str], None],
    read_existing: Callable[[Path], bytes | Refused | None] | None = None,
    recreate_hint: str = "a fresh key is created on the next stamp",
) -> bytes | None:
    """Read the key at *path*, lazily creating it (0700 dir, 0600 file,
    ``O_EXCL``) if absent.

    Returns ``None`` when a key file exists but is unusable (refused
    metadata, wrong length) — the suspect key is never used, never
    replaced, and the caller refuses to mint/verify. ``OSError`` from
    key creation (e.g. an unwritable data dir) propagates; callers'
    ``key_usable()`` wrappers historically catch it.

    *read_existing* overrides the read step (default:
    :func:`read_existing_key` with the same *key_len*/*warn*) — the
    seam consumers route through their module-level ``_read_existing_key``
    so tests can script read sequences. *recreate_hint* is the
    "how a fresh key appears" clause of the remedy text (e.g.
    "a fresh key is created on the next store").
    """

    def _read(p: Path) -> bytes | Refused | None:
        if read_existing is not None:
            return read_existing(p)
        return read_existing_key(p, key_len=key_len, warn=warn)

    data = _read(path)
    if isinstance(data, Refused):
        return None
    if isinstance(data, bytes):
        if len(data) == key_len:
            return data
        if not _recently_modified(path):
            # STALE wrong-length content (torn write from ENOSPC or a
            # kill between a past creator's O_EXCL create and its
            # write): refuse immediately. Routing it through the create
            # path would spin the full race-retry budget — and emit a
            # race-window diagnosis — on every call against a key only
            # an operator rm can heal.
            warn(
                path,
                f"wrong length ({len(data)} bytes, expected {key_len})",
                f"remove the suspect key and investigate; {recreate_hint}",
            )
            return None
        # FRESH wrong-length content can be a concurrent cold-start's
        # winner mid-write (its O_EXCL create landed; its key bytes
        # haven't). Fall through to the creation attempt: losing the
        # O_EXCL race routes into the bounded poll below, which reads
        # the winner's completed key with no suspect-key warning. A
        # genuinely torn FRESH key exhausts that poll and refuses with
        # the same wrong-length warning (and refuses without the poll
        # once it ages past the window).

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = secrets.token_bytes(key_len)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Lost the creation race — re-read the winner's key (an
        # attacker pre-placing a symlink also lands here: O_EXCL
        # refuses to create through one, and the re-read refuses it).
        # A short or empty read is a TRANSIENT race shape too: the
        # winner has O_EXCL-created the file but not yet written the
        # key bytes, so keep polling alongside the vanished-file case
        # and only report a suspect key once the retries are exhausted.
        raced: bytes | Refused | None = None
        for _ in range(_RACE_RETRIES):
            raced = _read(path)
            if isinstance(raced, Refused):
                return None
            if isinstance(raced, bytes) and len(raced) == key_len:
                return raced
            time.sleep(_RACE_RETRY_S)
        if isinstance(raced, bytes):
            warn(
                path,
                f"wrong length ({len(raced)} bytes, expected {key_len})",
                f"remove the suspect key and investigate; {recreate_hint}",
            )
        return None
    try:
        # Write to completion: os.write may legally write fewer bytes
        # than asked, and an unchecked short write would leave a torn
        # key that every later load refuses until an operator rm.
        view = memoryview(key)
        while view:
            written = os.write(fd, view)
            view = view[written:]
    finally:
        os.close(fd)
    return key

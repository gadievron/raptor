"""HMAC provenance for review-journal rows.

Review-journal entries are the durable record the gap fold trusts: a
row whose ``verdict`` is conclusive and whose ``source_hash`` matches
the current source SUPPRESSES future review of that function (and,
when eligible, is imported as a $0 reused verdict). The journal lives
in run/project directories that are target-writable during runs and
restorable verbatim by ``/project import`` — and rows were plain
unauthenticated JSON, so a forged ``clean`` row silenced review of a
function forever.

Writers stamp each row at append time with an HMAC-SHA256 token over
the row's canonical JSON (token key excluded); the fold verifies
before granting a row verdict-reuse authority, and rows whose token
is present but invalid are skipped entirely (tampered). Rows with NO
token (pre-MAC legacy, or forged-unstamped) keep fold-credit only
behind the exact full-length source-hash gate and are never eligible
for $0 verdict reuse — the tolerant-reader compromise that avoids a
re-review storm on upgrade while denying unauthenticated rows every
authority tier above "the source hash checks out". Same trust story
and key-handling discipline as ``core/witness/provenance.py`` /
``core/llm/scorecard/integrity.py``.

Key
    ``$XDG_DATA_HOME/raptor/journal-mac.key`` (default
    ``~/.local/share/raptor/journal-mac.key``). Deliberately its OWN
    key file — per-purpose keys keep reset/rotation semantics scoped.
    No rotation: deleting the key demotes every stamped row to the
    unstamped tier (fold-credit behind the hash gate, no reuse) and
    new appends re-key lazily.

No run binding: journal rows deliberately travel across runs — the
project index aggregates them and cross-run verdict reuse is the
feature. A replayed validly-stamped row is genuine history for the
exact source hash it names; staleness is bounded by the fold's hash
compare, not the MAC.

Forward compatibility: verification round-trips the row through this
reader's dataclass, so a row written by a NEWER schema (additive
fields this reader doesn't know) — or stamped by another install's
key — reads as token-present-but-unverifiable. That is NOT treated
as a distinct security tier: whoever can edit a row can simply strip
its token and land in the unstamped tier anyway, so consumers demote
unverifiable rows to the same unstamped tier (exact-hash-gated fold
credit, never verdict reuse) instead of dropping them below it.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
import time
from pathlib import Path

from core.json.utils import dumps_canonical
from core.logging import get_logger

logger = get_logger(__name__)

_KEY_LEN = 32

# Sentinel: a key file EXISTS but is unusable (symlink, foreign owner,
# group/other-readable). Distinct from "absent" — an unusable key must
# never be silently replaced and must never mint or verify.
_REFUSED = object()

_warned_paths: set = set()

# Row key holding the token. Popped before canonicalisation so the
# MAC covers everything else in the row.
TOKEN_KEY = "integrity"

#: Tri-state provenance of a loaded row.
ROW_VERIFIED = "verified"
ROW_TAMPERED = "tampered"
ROW_UNSTAMPED = "unstamped"


def _key_path() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "raptor" / "journal-mac.key"


def _warn_once_suspect_key(path: Path, reason: str, remedy: str) -> None:
    key = str(path)
    if key in _warned_paths:
        logger.debug(f"journal integrity: suspect key {path} ({reason})")
        return
    _warned_paths.add(key)
    logger.warning(
        f"journal integrity: refusing key {path} — {reason}. Journal "
        f"rows will not mint or verify (stamped rows demote to the "
        f"unstamped tier: hash-gated fold credit only, no verdict "
        f"reuse) until this is fixed: {remedy}"
    )


def _read_existing_key(path: Path):
    """Read an EXISTING key with rowmac's fd-fstat discipline: refuse
    symlinks (O_NOFOLLOW + fstat on the opened inode), foreign owners,
    and any group/other permission bits."""
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as exc:
        _warn_once_suspect_key(
            path, f"open refused ({exc})",
            "if the key is a symlink, remove it and investigate how it "
            "got there; a fresh key is created on the next stamp",
        )
        return _REFUSED
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            _warn_once_suspect_key(
                path, "not a regular file",
                "remove the object at that path and investigate",
            )
            return _REFUSED
        if st.st_uid != os.geteuid():
            _warn_once_suspect_key(
                path,
                f"owned by uid={st.st_uid}, expected uid={os.geteuid()}",
                "investigate the foreign-owned key; restore your own "
                "0600 key file",
            )
            return _REFUSED
        if st.st_mode & 0o077:
            _warn_once_suspect_key(
                path,
                f"mode {stat.S_IMODE(st.st_mode):04o} grants group/other "
                "access",
                f"chmod 600 {path}",
            )
            return _REFUSED
        return os.read(fd, _KEY_LEN * 4)
    except OSError:
        return None
    finally:
        os.close(fd)


def _load_or_create_key() -> bytes | None:
    """Read the key, lazily creating it (0700 dir, 0600 file, O_EXCL)
    if absent. Returns None when a key file exists but is unusable —
    the suspect key is never used, never replaced."""
    path = _key_path()
    data = _read_existing_key(path)
    if data is _REFUSED:
        return None
    if data is not None and len(data) == _KEY_LEN:
        return data
    if data is not None:
        _warn_once_suspect_key(
            path,
            f"wrong length ({len(data)} bytes, expected {_KEY_LEN})",
            "remove the suspect key and investigate; a fresh key is "
            "created on the next stamp",
        )
        return None

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = secrets.token_bytes(_KEY_LEN)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Lost the creation race — re-read the winner's key (an
        # attacker pre-placing a symlink also lands here: O_EXCL
        # refuses to create through one, and the re-read refuses it).
        for _ in range(20):
            raced = _read_existing_key(path)
            if raced is _REFUSED:
                return None
            if raced is not None and len(raced) == _KEY_LEN:
                return raced
            if raced is not None:
                _warn_once_suspect_key(
                    path,
                    f"wrong length ({len(raced)} bytes, expected {_KEY_LEN})",
                    "remove the suspect key and investigate; a fresh key "
                    "is created on the next stamp",
                )
                return None
            time.sleep(0.01)
        return None
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return key


def key_usable() -> bool:
    """Whether this install can mint/verify tokens at all."""
    try:
        return bool(_load_or_create_key())
    except OSError:
        return False


def row_sha256(row: dict) -> str:
    """sha256 over the row's canonical JSON (token key excluded).

    Canonical form: :func:`core.json.utils.dumps_canonical` (stdlib
    ``sort_keys=True, separators=(",", ":"), default=str`` — the
    repo-wide frozen canonical byte form; its tests pin byte-identity
    against this function) — key order and whitespace don't matter,
    values do. The token covers the WHOLE row (verdict, source_hash,
    spans, producer, model, strategies, body, ...): partial coverage
    would let an attacker rewrite the unauthenticated remainder of a
    validly-stamped row."""
    scrubbed = {k: v for k, v in row.items() if k != TOKEN_KEY}
    canonical = dumps_canonical(scrubbed)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _mac_message(sha256_hex: str) -> bytes:
    # Domain separation: a token minted for another artifact class
    # can never verify here even if a key were ever shared by mistake.
    return b"review-journal-row\x00" + sha256_hex.encode("ascii")


def mint_row(row: dict) -> str | None:
    """Hex HMAC-SHA256 token over the row's canonical payload, or
    None when no usable key is available. Writers treat None as
    "persist unstamped" — the fold then applies unstamped-tier
    semantics."""
    try:
        key = _load_or_create_key()
    except OSError:
        return None
    if not key:
        return None
    return hmac.new(
        key, _mac_message(row_sha256(row)), hashlib.sha256,
    ).hexdigest()


def verify_row(row: dict, token: str | None) -> bool:
    """Whether *token* is a valid MAC over *row*'s canonical payload
    under this install's key. Constant-time; never raises — any
    failure is the caller's demote path."""
    if not token:
        return False
    try:
        expected = mint_row(row)
        if expected is None:
            return False
        return hmac.compare_digest(expected, str(token).strip().lower())
    except Exception:  # noqa: BLE001 — verification failure is the demote path, never an error
        return False


def entry_provenance(entry) -> str:
    """Tri-state provenance of a loaded ``ReviewJournalEntry``.

    * ``verified`` — token present and valid for the row's content.
    * ``tampered`` — token present but invalid: content edited, a row
      minted by another install, or a row written by a newer schema
      whose extra fields this reader's dataclass round-trip loses.
      Consumers give these the same authority as ``unstamped`` (the
      token is strippable, so "tampered" is attribution, not a
      security boundary) but log them distinctly.
    * ``unstamped`` — no token (pre-MAC legacy or forged-unstamped):
      fold-credit only behind the exact source-hash gate, never
      verdict reuse.
    """
    token = getattr(entry, "integrity", None)
    if not token:
        return ROW_UNSTAMPED
    row = entry.to_dict()
    return ROW_VERIFIED if verify_row(row, token) else ROW_TAMPERED


__all__ = [
    "ROW_TAMPERED",
    "ROW_UNSTAMPED",
    "ROW_VERIFIED",
    "TOKEN_KEY",
    "entry_provenance",
    "key_usable",
    "mint_row",
    "row_sha256",
    "verify_row",
]

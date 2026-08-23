"""HMAC provenance for the project-level IRIS spec store.

``<project>/iris-specs/specs.json`` carries taint specs whose
``evidence_tier`` gates SUPPRESSION-direction behaviour: a spec at or
above ``XREF_BACKED`` is recognised as a tool-corroborated sanitiser
by guard-adequacy analysis and is installed as a Joern flow-kill row —
both directions that make findings disappear. Pre-fix the store was
plain unauthenticated JSON and the tier was deserialised on trust, so
anyone who could write the project directory (or feed an unsigned
import) could plant a forged ``XREF_BACKED`` sanitiser and silence a
real flow.

Writers stamp the WHOLE envelope with an HMAC-SHA256 token over the
sha256 of its canonical JSON; readers verify before honouring stored
evidence tiers, and an unverified store demotes: every deserialised
tier is FLOORED to heuristic (prompt-direction context survives;
suppression authority requires re-corroboration by this install's
tools or an operator annotation). Same trust story and key-handling
discipline as ``core/llm/scorecard/integrity.py`` /
``core/sandbox/telemetry_mac.py`` (which copy ``core/sage/rowmac.py``).

Key
    ``$XDG_DATA_HOME/raptor/iris-store-mac.key`` (default
    ``~/.local/share/raptor/iris-store-mac.key``). Deliberately its
    OWN key file — per-purpose keys keep reset/rotation semantics
    scoped. No rotation: deleting the key floors every stored tier on
    the next read (the refine loop re-corroborates), and the next
    save re-keys lazily.

Binding note: the envelope's ``target_path`` rides inside the MAC, so
a forged target rebind breaks the token; a validly-stamped store
copied between projects OF THE SAME TARGET on the same install is
genuine historical data and verifies — that is the cross-run reuse
the store exists for.

Replay note: a valid token proves "this install's writer produced
these exact bytes at some point", not freshness — restoring an OLD
validly-stamped store resurrects genuine-but-outdated specs. The
checklist-fingerprint staleness handling and the refine loop's
refutation rounds bound that, not the MAC; accepted residual (same
posture as the scorecard sidecar).
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

# Top-level envelope key holding the token. Popped before
# canonicalisation so the MAC covers everything else.
TOKEN_KEY = "integrity"


def _key_path() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "raptor" / "iris-store-mac.key"


def _warn_once_suspect_key(path: Path, reason: str, remedy: str) -> None:
    key = str(path)
    if key in _warned_paths:
        logger.debug(f"iris-store integrity: suspect key {path} ({reason})")
        return
    _warned_paths.add(key)
    logger.warning(
        f"iris-store integrity: refusing key {path} — {reason}. Stored "
        f"IRIS spec tiers will not mint or verify (tiers floor to "
        f"heuristic on read; suppression-direction specs re-corroborate) "
        f"until this is fixed: {remedy}"
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


def payload_sha256(data: dict) -> str:
    """sha256 over the envelope's canonical JSON (token key excluded).

    Canonical form: :func:`core.json.utils.dumps_canonical`
    (stdlib ``sort_keys=True, separators=(",", ":"), default=str``) — key order and whitespace on disk don't
    matter, values do. The token covers the WHOLE envelope (specs,
    tiers, target_path, history, assumptions): partial coverage would
    let an attacker rewrite the unauthenticated remainder of a
    validly-stamped store."""
    scrubbed = {k: v for k, v in data.items() if k != TOKEN_KEY}
    canonical = dumps_canonical(scrubbed)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _mac_message(sha256_hex: str) -> bytes:
    # Domain separation: a token minted for another artifact class
    # can never verify here even if a key were ever shared by mistake.
    return b"iris-specs-store\x00" + sha256_hex.encode("ascii")


def mint(data: dict) -> str | None:
    """Hex HMAC-SHA256 token over the store's canonical payload, or
    None when no usable key is available. Writers treat None as
    "persist unstamped" — readers then floor tiers on load."""
    try:
        key = _load_or_create_key()
    except OSError:
        return None
    if not key:
        return None
    return hmac.new(
        key, _mac_message(payload_sha256(data)), hashlib.sha256,
    ).hexdigest()


def verify(data: dict, token: str | None) -> bool:
    """Whether *token* is a valid MAC over *data*'s canonical payload
    under this install's key. Constant-time; never raises — any
    failure is the caller's floor path."""
    if not token:
        return False
    try:
        expected = mint(data)
        if expected is None:
            return False
        return hmac.compare_digest(expected, str(token).strip().lower())
    except Exception:  # noqa: BLE001 — verification failure is the floor path, never an error
        return False


def stamp(data: dict) -> dict:
    """Return *data* with a fresh integrity token attached (in place;
    returned for chaining). When no usable key exists the token key
    is removed instead — an unstamped store under an unusable key is
    the honest representation."""
    token = mint(data)
    if token is None:
        data.pop(TOKEN_KEY, None)
        return data
    data[TOKEN_KEY] = {"token": token}
    return data


def extract_token(data: dict) -> str | None:
    """Pull the token string out of the envelope, tolerating the key
    being absent or malformed (both read as "unstamped")."""
    box = data.get(TOKEN_KEY)
    if isinstance(box, dict):
        token = box.get("token")
        return token if isinstance(token, str) else None
    return None


def verify_envelope(data: dict) -> bool:
    """Reader-facing chokepoint: whether the loaded store envelope was
    stamped by this install's writer."""
    if not isinstance(data, dict):
        return False
    return verify(data, extract_token(data))


__all__ = [
    "TOKEN_KEY",
    "extract_token",
    "key_usable",
    "mint",
    "payload_sha256",
    "stamp",
    "verify",
    "verify_envelope",
]

"""HMAC provenance for the scorecard sidecar.

``out/llm_scorecard.json`` is the ledger that steers model routing:
``should_short_circuit`` decides from it whether the cheap-tier
verdict is trusted (skipping full analysis), and ``policy_override=
force_short_circuit`` pins that decision unconditionally. The file
lives in the repo-local ``out/`` tree — writable by any same-user
process, including hostile build/test code that escaped a sandbox.
Pre-fix it carried no MAC and no verification, so a forged file
(fabricated 100000-correct cells, or a bare ``force_short_circuit``
pin) silently made every subsequent /agentic and /codeql run trust
the cheap "clear FP" verdict and suppress real findings.

Writers stamp the WHOLE document with an HMAC-SHA256 token over the
sha256 of its canonical JSON; readers verify before acting. Same
trust story and key-handling discipline as
``core/sandbox/telemetry_mac.py`` (which copies
``core/sage/rowmac.py``): the key lives OUTSIDE every LLM-writable
and sandbox-readable tree, symlinked / foreign-owned /
group-readable key files are refused rather than replaced, and
verification failure is a demote path, never an error.

Key
    ``$XDG_DATA_HOME/raptor/scorecard-mac.key`` (default
    ``~/.local/share/raptor/scorecard-mac.key``). Deliberately its
    OWN key file — per-purpose keys keep reset/rotation semantics
    scoped (deleting the SAGE key is SAGE's documented reset and
    must not invalidate scorecard provenance; likewise telemetry's).
    Never reuse ``rowmac.key`` or ``telemetry-mac.key``. No
    rotation: deleting the key makes the stamped sidecar fail
    verification (the scorecard demotes to quarantine-and-restart;
    ``scorecard adopt`` re-blesses it), and the next write re-keys
    lazily.

Demotion semantics (enforced in ``scorecard.py``)
  * token verifies — trusted; full behaviour.
  * usable key + nonempty file + missing/bad token — tampered or
    pre-MAC legacy; indistinguishable, so the content is DISCARDED
    in memory (never merged, never re-stamped — re-stamping would
    launder a forgery on the first honest write) and quarantined to
    ``<sidecar>.unverified`` on the next locked write. The operator
    re-adopts genuine pre-MAC history deliberately via
    ``scorecard adopt``.
  * unusable key (symlinked / foreign-owned / unwritable data dir)
    — an operator-side condition, not target tampering: content
    stays readable for introspection but the trust surface clamps
    (no SHORT_CIRCUIT, ``force_short_circuit`` pins not honoured).

Replay note: a valid token proves "this install's writer produced
these exact bytes at some point", not freshness — an attacker who
saved an OLD validly-stamped sidecar can restore it (rolling back a
pin release or resurrecting retired trust). That is genuine
historical data, categorically weaker than forgery, and preventing
it would need external anti-rollback state; accepted residual.
"""

from __future__ import annotations

import hashlib
import hmac
import json
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

# Top-level sidecar key holding the token. Popped before
# canonicalisation so the MAC covers everything else.
TOKEN_KEY = "integrity"


def _key_path() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "raptor" / "scorecard-mac.key"


def _warn_once_suspect_key(path: Path, reason: str, remedy: str) -> None:
    key = str(path)
    if key in _warned_paths:
        logger.debug("scorecard integrity: suspect key %s (%s)", path, reason)
        return
    _warned_paths.add(key)
    logger.warning(
        "scorecard integrity: refusing key %s — %s. Scorecard provenance tokens will not mint or verify (trust surface clamps: no short-circuit, pins not honoured) until this is fixed: %s", path, reason, remedy
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
    """Whether this install can mint/verify tokens at all.

    The scorecard uses it to attribute an unverifiable sidecar
    correctly: an unverified file under a USABLE key means someone
    wrote content this install's writer didn't stamp — tamper-or-
    legacy, quarantine territory. An UNUSABLE key (symlinked,
    foreign-owned, wrong length, unwritable data dir) is an
    operator-side condition that makes verification impossible for
    every file, honest or not — misreading that as tampering would
    throw away genuine calibration history over a host
    misconfiguration."""
    try:
        return bool(_load_or_create_key())
    except OSError:
        return False


def payload_sha256(data: dict) -> str:
    """sha256 over the sidecar's canonical JSON (token key excluded).

    Canonical form: :func:`core.json.utils.dumps_canonical` (stdlib
    ``sort_keys=True, separators=(",", ":"), default=str`` — the
    repo-wide frozen canonical byte form) — key order and whitespace
    on disk don't matter, values do. The token covers the WHOLE
    document: partial coverage would let an attacker rewrite the
    unauthenticated remainder of a validly-stamped file.
    """
    scrubbed = {k: v for k, v in data.items() if k != TOKEN_KEY}
    canonical = dumps_canonical(scrubbed)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _mac_message(sha256_hex: str) -> bytes:
    # Domain separation: a token minted for another artifact class
    # (telemetry, witness) can never verify here even if a key were
    # ever shared by mistake.
    return b"scorecard-file\x00" + sha256_hex.encode("ascii")


def mint(data: dict) -> str | None:
    """Hex HMAC-SHA256 token over the sidecar's canonical payload, or
    None when no usable key is available (unusable key file,
    unwritable data dir). Writers treat None as "persist unstamped" —
    readers then clamp the trust surface (key-unusable demotion)."""
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
    failure is the caller's demote path."""
    if not token:
        return False
    try:
        expected = mint(data)
        if expected is None:
            return False
        return hmac.compare_digest(expected, str(token).strip().lower())
    except Exception:  # noqa: BLE001 — verification failure is the demote path, never an error
        return False


def stamp(data: dict) -> dict:
    """Return *data* with a fresh integrity token attached (in place;
    returned for chaining). When no usable key exists the token key
    is removed instead — an unstamped file under an unusable key is
    the honest representation."""
    token = mint(data)
    if token is None:
        data.pop(TOKEN_KEY, None)
        return data
    data[TOKEN_KEY] = {"token": token}
    return data


def stamp_file(path: Path) -> bool:
    """Stamp the JSON document at *path* in place with a fresh
    integrity token. Returns False when no usable key exists (file
    left as-is). Convenience for test fixtures and the adopt flow's
    callers — NOT called by any automatic read/write path (the
    machinery must never re-stamp content it didn't verify)."""
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        msg = (
            f"cannot stamp {path}: expected a JSON object, got "
            f"{type(data).__name__}"
        )
        raise ValueError(msg)
    token = mint(data)
    if token is None:
        return False
    data[TOKEN_KEY] = {"token": token}
    path.write_text(
        json.dumps(data, indent=2) + "\n", encoding="utf-8",
    )
    return True


def extract_token(data: dict) -> str | None:
    """Pull the token string out of the sidecar dict, tolerating the
    key being absent or malformed (both read as "unstamped")."""
    box = data.get(TOKEN_KEY)
    if isinstance(box, dict):
        token = box.get("token")
        return token if isinstance(token, str) else None
    return None


__all__ = [
    "TOKEN_KEY",
    "extract_token",
    "key_usable",
    "mint",
    "payload_sha256",
    "stamp",
    "stamp_file",
    "verify",
]

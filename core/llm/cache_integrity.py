"""HMAC provenance for LLM response-cache entries.

The response cache (``LLMConfig.cache_dir``, on by default) replays
stored completions — including review verdicts — into every consumer
of ``LLMClient.generate`` / ``generate_structured``. Entries are
plain JSON files with deterministic names derived from the prompt, so
anyone who can write the cache directory (a same-user process, a
restored or shared cache tree) could plant an entry for a predictable
prompt and have it replayed as a fresh model response: a forged
"clean" review outcome with no LLM call and no trace. Pre-fix the
reader accepted any parseable file (a missing ``timestamp`` even read
as *fresh* — deliberate legacy-honour that also honoured forgeries).

Writers stamp each entry with an HMAC-SHA256 token over the entry's
canonical JSON *and the cache filename it was written under*; readers
verify before replaying and treat any failure as a cache miss (the
demote path for a cache: the call is re-issued to the provider and
the honest result overwrites the entry). Same trust story and
key-handling discipline as ``core/llm/scorecard/integrity.py`` /
``core/sandbox/telemetry_mac.py`` (which copy ``core/sage/rowmac.py``):
the key lives OUTSIDE every LLM-writable and sandbox-readable tree,
symlinked / foreign-owned / group-readable key files are refused
rather than replaced, and verification failure is a demote path,
never an error.

Key
    ``$XDG_DATA_HOME/raptor/llm-cache-mac.key`` (default
    ``~/.local/share/raptor/llm-cache-mac.key``). Deliberately its
    OWN key file — per-purpose keys keep reset/rotation semantics
    scoped (deleting the scorecard key must not invalidate the
    response cache, and vice versa). No rotation: deleting the key
    makes every stamped entry read as a miss (the cache refills with
    freshly-stamped entries), and the next write re-keys lazily.

Name binding
    The token covers the cache filename stem (``<key>`` /
    ``structured-<key>``) alongside the payload hash. Without it, any
    validly-stamped entry could be copied over ANOTHER prompt's
    filename and replay a genuine-but-wrong response there.

Upgrade note
    Entries written before this module carry no token and read as
    misses — a one-time cache refill, deliberately preferred over
    honouring unauthenticated verdict-bearing content.

Replay note: a valid token proves "this install's writer produced
this entry for this cache slot", not freshness — an attacker who
saved an OLD validly-stamped entry can restore it. That is genuine
historical data for the same prompt, categorically weaker than
forgery; staleness is bounded separately by ``cache_ttl_seconds``
(the authenticated ``timestamp`` rides inside the MAC'd payload).
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

# Top-level entry key holding the token. Popped before
# canonicalisation so the MAC covers everything else.
TOKEN_KEY = "integrity"


def _key_path() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "raptor" / "llm-cache-mac.key"


def _warn_once_suspect_key(path: Path, reason: str, remedy: str) -> None:
    key = str(path)
    if key in _warned_paths:
        logger.debug(f"llm-cache integrity: suspect key {path} ({reason})")
        return
    _warned_paths.add(key)
    logger.warning(
        f"llm-cache integrity: refusing key {path} — {reason}. Cache "
        f"entries will not mint or verify (every read is a miss; "
        f"responses are re-fetched from the provider) until this is "
        f"fixed: {remedy}"
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
    """Whether this install can mint/verify tokens at all. With an
    unusable key every read is a miss and every write persists
    unstamped — caching is effectively disabled for replay until the
    operator fixes the key (the warn-once above says how)."""
    try:
        return bool(_load_or_create_key())
    except OSError:
        return False


def payload_sha256(data: dict) -> str:
    """sha256 over the entry's canonical JSON (token key excluded).

    Canonical form: :func:`core.json.utils.dumps_canonical`
    (stdlib ``sort_keys=True, separators=(",", ":"), default=str``) — key order and whitespace on disk don't
    matter, values do. The token covers the WHOLE entry (content,
    model, provider, tokens_used, timestamp): partial coverage would
    let an attacker rewrite the unauthenticated remainder of a
    validly-stamped entry.
    """
    scrubbed = {k: v for k, v in data.items() if k != TOKEN_KEY}
    canonical = dumps_canonical(scrubbed)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _mac_message(name: str, sha256_hex: str) -> bytes:
    # Domain separation ("llm-cache-entry") keeps a token minted for
    # another artifact class from ever verifying here; the name
    # component binds the token to the cache slot it was written
    # under (see module docstring, "Name binding").
    return (
        b"llm-cache-entry\x00"
        + name.encode("utf-8", errors="replace")
        + b"\x00"
        + sha256_hex.encode("ascii")
    )


def mint(name: str, data: dict) -> str | None:
    """Hex HMAC-SHA256 token over the entry's canonical payload bound
    to cache slot *name* (the filename stem), or None when no usable
    key is available. Writers treat None as "persist unstamped" —
    readers then miss and re-fetch."""
    try:
        key = _load_or_create_key()
    except OSError:
        return None
    if not key:
        return None
    return hmac.new(
        key, _mac_message(name, payload_sha256(data)), hashlib.sha256,
    ).hexdigest()


def verify(name: str, data: dict, token: str | None) -> bool:
    """Whether *token* is a valid MAC over *data* for cache slot
    *name* under this install's key. Constant-time; never raises —
    any failure is the caller's miss path."""
    if not token:
        return False
    try:
        expected = mint(name, data)
        if expected is None:
            return False
        return hmac.compare_digest(expected, str(token).strip().lower())
    except Exception:  # noqa: BLE001 — verification failure is the miss path, never an error
        return False


def stamp(name: str, data: dict) -> dict:
    """Return *data* with a fresh integrity token for slot *name*
    attached (in place; returned for chaining). When no usable key
    exists the token key is removed instead — an unstamped entry
    under an unusable key is the honest representation."""
    token = mint(name, data)
    if token is None:
        data.pop(TOKEN_KEY, None)
        return data
    data[TOKEN_KEY] = {"token": token}
    return data


def extract_token(data: dict) -> str | None:
    """Pull the token string out of the entry dict, tolerating the
    key being absent or malformed (both read as "unstamped")."""
    box = data.get(TOKEN_KEY)
    if isinstance(box, dict):
        token = box.get("token")
        return token if isinstance(token, str) else None
    return None


def verify_entry(name: str, data: dict) -> bool:
    """Reader-facing chokepoint: whether the loaded entry *data* was
    stamped by this install's writer for cache slot *name*."""
    if not isinstance(data, dict):
        return False
    return verify(name, data, extract_token(data))


__all__ = [
    "TOKEN_KEY",
    "extract_token",
    "key_usable",
    "mint",
    "payload_sha256",
    "stamp",
    "verify",
    "verify_entry",
]

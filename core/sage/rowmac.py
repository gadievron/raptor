"""HMAC authentication for SAGE rows consumed mechanically.

Every mechanical hook in ``core/sage/hooks.py`` turns recalled free text
into a hard machine decision (skip an LLM call, suppress a finding,
append argv flags, replay a build command). Memory content is written by
multiple flows — including reflection of LLM output and federated peers
— so a poisoned row would otherwise become machine behaviour. Rows
intended for mechanical consumption therefore carry an HMAC token only
this install can mint; rows without a valid token demote to
human-visible hints.

Key
    ``$XDG_DATA_HOME/raptor/rowmac.key`` (default
    ``~/.local/share/raptor/rowmac.key``). 32 random bytes, file mode
    0600, directory 0700. Created by ``libexec/raptor-sage-setup`` on
    install and ALSO lazily (``O_EXCL``, race-tolerant) on first use, so
    non-setup installs work regardless of ordering. The key deliberately
    lives OUTSIDE the repo tree: several sandbox profiles grant children
    repo-root read, and a sandboxed target that could read an in-repo
    key could mint valid tokens for poisoned rows — defeating the
    mechanism. The per-user XDG data dir is outside every
    sandbox-readable target tree. There is no rotation: deleting the
    key simply makes every existing token fail verification, demoting
    old rows to hints until new outcomes are stored — that IS the reset
    semantics.

Token transport
    SAGE rows are free text (typed metadata may not round-trip
    faithfully across server versions), so the token is embedded in the
    content as a trailing `` [mac:<64 hex>]``. Consumers call
    :func:`strip` before any regex parsing, re-derive the decision
    fields from the parsed values, and :func:`verify` them against the
    token.

What is MAC'd
    The MAC covers a canonical, injective, length-prefixed encoding of
    the DECISION FIELDS only — the exact values the consumer acts on —
    never the surrounding prose. Recall may re-wrap the row or drift its
    metadata; prose is not what the machine consumes.

Legacy rows
    Rows stored before this mechanism existed carry no token and
    therefore lose mechanical effect the day it lands; they re-earn it
    as new outcomes are stored. That transition is deliberate — memories
    decay anyway, and nothing breaks: the hooks behave exactly as if no
    memory existed.

Federated / foreign rows can never verify (different key) — correct by
default; SAGE's inbox contract already declares federated content
untrusted.
"""

import hashlib
import hmac
import os
import re
from collections.abc import Mapping
from pathlib import Path

from core.logging import get_logger
from core.security import mac_key

logger = get_logger(__name__)

_KEY_LEN = 32

# Sentinel: a key file EXISTS but is unusable (symlink, foreign owner,
# group/other-readable). Distinct from "absent" — an unusable key must
# never be silently replaced (re-keying would mask tampering and
# permanently demote legitimate rows) and must never mint or verify.
_REFUSED = mac_key.REFUSED

# One loud warning per suspect path per process; repeats go to debug.
_warned_paths: set = set()

# Trailing token appended by stamp(); strip() removes it (and any
# whitespace immediately before it) from the end of the content.
# (?<!\s) pins the match to the start of its whitespace run (a bare
# leading \s* re-consumes a whitespace run from every scan position
# — quadratic); the earliest match always starts at the run start,
# so the stripped span is unchanged.
_TOKEN_RE = re.compile(r"(?<!\s)\s*\[mac:([0-9a-f]{64})\]\s*$")


def _key_path() -> Path:
    """Location of the per-install row-MAC key.

    ``$XDG_DATA_HOME/raptor/rowmac.key`` (default
    ``~/.local/share/raptor/rowmac.key``). Deliberately NOT anchored to
    the repo tree: sandboxed children hold repo-root read in several
    profiles, and the key must stay outside every sandbox-readable
    tree or a scanned target could mint valid row MACs.
    """
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "raptor" / "rowmac.key"


def _warn_once_suspect_key(path: Path, reason: str, remedy: str) -> None:
    key = str(path)
    if key in _warned_paths:
        logger.debug("rowmac: suspect key %s (%s)", path, reason)
        return
    _warned_paths.add(key)
    logger.warning(
        "rowmac: refusing key %s — %s. Row MACs will not mint or "
        "verify (mechanical recall demoted to hint-only) until this "
        "is fixed: %s",
        path, reason, remedy,
    )


def _read_existing_key(path: Path) -> bytes | mac_key.Refused | None:
    """Read an EXISTING key with the shared fd-fstat discipline
    (:func:`core.security.mac_key.read_existing_key`).

    Returns the key bytes, ``None`` when the file is absent, or
    ``_REFUSED`` when the file exists but is unusable. An exposed or
    substituted key would let anyone mint valid row MACs — forged
    "verified" rows would then be mechanically replayed into sweeps —
    so reads refuse symlinks (``O_NOFOLLOW`` at open, fstat on the
    actually-opened inode), foreign owners, and any group/other
    permission bits. Creation (``O_EXCL`` + 0600) needs no such check;
    this guard covers only the read-existing branch.
    """
    return mac_key.read_existing_key(
        path, key_len=_KEY_LEN, warn=_warn_once_suspect_key)


def _load_or_create_key() -> bytes | None:
    """Read the key, lazily creating it (0700 dir, 0600 file) if absent
    — the shared hardened discipline in
    :func:`core.security.mac_key.load_or_create_key`.

    Creation uses ``O_EXCL`` so concurrent first-users race safely: the
    loser polls through the winner's create-to-write window (a briefly
    empty/short file) and reads whatever the winner wrote.

    Returns ``None`` when a key file exists but is unusable (symlink,
    foreign owner, permissive mode, wrong length): the suspect key is
    never used, never replaced, and the caller refuses to mint/verify.
    A STABLE zero/short key (torn write from ENOSPC or a kill between
    the ``O_EXCL`` create and the write) is refused immediately with a
    wrong-length warning — silently HMAC'ing with an empty or truncated
    key would make every token forgeable, re-enabling the poisoned-row
    mechanical effect the MAC exists to block, and spinning the race
    budget on it would stall every mint/verify behind a misleading
    race-window message when the only remedy is removing the file.
    """
    return mac_key.load_or_create_key(
        _key_path(), key_len=_KEY_LEN, warn=_warn_once_suspect_key,
        read_existing=_read_existing_key,
        recreate_hint="a fresh key is created on the next store")


def _canonical(fields: Mapping[str, object]) -> bytes:
    """Injective canonical encoding of the decision fields.

    Key-sorted so insertion order never matters, and every key and
    value is length-prefixed so no combination of embedded separators
    or moved characters can collide with a different field map.
    """
    items = sorted((str(k), str(v)) for k, v in fields.items())
    out = bytearray()
    out += len(items).to_bytes(4, "big")
    for key, value in items:
        for part in (key.encode("utf-8"), value.encode("utf-8")):
            out += len(part).to_bytes(4, "big")
            out += part
    return bytes(out)


def mint(fields: Mapping[str, object]) -> str:
    """Return the hex HMAC-SHA256 token over the decision *fields*.

    Recreates the key lazily if it is missing (so a deleted key means
    old tokens fail verification while new stores keep working).
    Raises ``RuntimeError`` when the key file exists but is unusable
    (symlink / foreign owner / permissive mode) — never mints with a
    suspect key. ``stamp``'s callers already treat a stamp failure as
    "store unstamped"; ``verify`` treats it as the demote path.
    """
    key = _load_or_create_key()
    if key is None:
        msg = "row-MAC key unusable (see rowmac warning) — refusing to mint"
        raise RuntimeError(msg)
    return hmac.new(key, _canonical(fields), hashlib.sha256).hexdigest()


def verify(fields: Mapping[str, object], token: str | None) -> bool:
    """Whether *token* is a valid MAC over *fields* under this install's key.

    Constant-time comparison. Never raises: any failure (missing token,
    unreadable key, malformed input) returns False — the caller's
    demote path.
    """
    if not token:
        return False
    try:
        expected = mint(fields)
        return hmac.compare_digest(expected, str(token).strip().lower())
    except Exception:  # noqa: BLE001 — verification failure is the demote path, never an error
        return False


def stamp(content: str, fields: Mapping[str, object]) -> str:
    """Append `` [mac:<hex>]`` for *fields* to *content*."""
    return f"{content} [mac:{mint(fields)}]"


def strip(content: str) -> tuple[str, str | None]:
    """Split *content* into (clean text, token or None).

    Idempotent: text without a trailing token comes back unchanged with
    ``None``. Only the trailing token is consumed, so a quoted token in
    the middle of prose stays part of the text (and can never verify as
    that row's own token unless the fields genuinely match).
    """
    text = content or ""
    match = _TOKEN_RE.search(text)
    if not match:
        return (text, None)
    return (text[: match.start()], match.group(1))

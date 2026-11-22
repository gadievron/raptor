"""HMAC provenance for CodeQL database-cache metadata sidecars.

``<language>-metadata.json`` is the trust-bearing half of the database
cache: ``load_metadata`` feeds the serve decision
(``get_cached_database``), the extraction-mode contract
(``_cached_mode_mismatch``), the lost-race sibling-adoption gate
(``_sibling_adoption_verdict``) and both eviction legs. The
sidecar is plain JSON with a deterministic name derived from the repo
hash, so anyone who can write the cache tree (a same-user process, a
restored or shared cache) could plant a sidecar that vouches a stale,
failed, or foreign database into every later run — "success: true,
build_system: custom" over a DB that never ran that build.

Writers stamp each sidecar with an HMAC-SHA256 token over the entry's
canonical JSON *and the cache slot it vouches for*
(``<repo_hash>/<language>``); readers verify before trusting and
treat any failure as a cache miss (the demote path for a cache: the
database is rebuilt and the honest metadata overwrites the entry).
Same trust story and key-handling discipline as
``core/llm/cache_integrity.py`` / ``core/llm/scorecard/integrity.py``
/ ``core/sandbox/telemetry_mac.py``: the key lives OUTSIDE every
sandbox-granted and LLM-writable tree, symlinked / foreign-owned /
group-readable key files are refused rather than replaced, and
verification failure is a demote path, never an error.

Key
    ``$XDG_DATA_HOME/raptor/codeql-cache-mac.key`` (default
    ``~/.local/share/raptor/codeql-cache-mac.key``). Deliberately its
    OWN key file — per-purpose keys keep reset/rotation semantics
    scoped (deleting the LLM response-cache key must not invalidate
    the CodeQL DB cache, and vice versa). No rotation: deleting the
    key makes every stamped sidecar read as a miss (databases rebuild
    once and re-stamp), and the next write re-keys lazily.

Name binding
    The token covers ``<repo_hash>/<language>`` alongside the payload
    hash, and READERS derive that name from their own lookup
    arguments — never from the file content. Without it, any
    validly-stamped sidecar could be copied over ANOTHER slot's
    filename and vouch a genuine-but-wrong database there.

Scope note — the database content digest
    The metadata MAC binds the sidecar's claims, not the database
    bytes beside it. Content integrity is carried by a SEPARATE
    immutable-subset digest
    (``database_manager.database_content_digest``) minted at promote
    and stamped into the MAC'd sidecar as ``content_digest``, then
    recomputed and compared at serve. A full-tree digest was rejected:
    ``database analyze`` holds a legitimate writable bind on the
    canonical DB (results, logs, evaluator cache land inside it — see
    ``QueryRunner._analysis_scope``), so it would false-miss after the
    first analyze and degrade the cache into a permanent rebuild loop.
    The subset therefore covers only what analyze never writes — the
    yml, ``src.zip``, and the ``db-*`` relations outside evaluator
    cache dirs. The same walk refuses hostile tree shapes (internal
    symlinks / special files) at promote, adopt, and serve.

Upgrade note
    Sidecars written before this module carry no token and read as
    misses — a one-time rebuild per cached DB, deliberately preferred
    over honouring unauthenticated serve-steering content.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path

from core.json.utils import dumps_canonical
from core.logging import get_logger
from core.security import mac_key

logger = get_logger(__name__)

_KEY_LEN = 32

_warned_paths: set = set()

# Top-level entry key holding the token. Popped before
# canonicalisation so the MAC covers everything else.
TOKEN_KEY = "integrity"


def _key_path() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "raptor" / "codeql-cache-mac.key"


def _warn_once_suspect_key(path: Path, reason: str, remedy: str) -> None:
    key = str(path)
    if key in _warned_paths:
        logger.debug(f"codeql-cache integrity: suspect key {path} ({reason})")
        return
    _warned_paths.add(key)
    logger.warning(
        f"codeql-cache integrity: refusing key {path} — {reason}. Database "
        f"metadata will not mint or verify (every cache read is a miss; "
        f"databases are rebuilt) until this is fixed: {remedy}"
    )


def _read_existing_key(path: Path) -> bytes | mac_key.Refused | None:
    """Read an EXISTING key with the shared fd-fstat discipline
    (:func:`core.security.mac_key.read_existing_key`): refuse symlinks
    (O_NOFOLLOW + fstat on the opened inode), foreign owners, and any
    group/other permission bits."""
    return mac_key.read_existing_key(
        path, key_len=_KEY_LEN, warn=_warn_once_suspect_key)


def _load_or_create_key() -> bytes | None:
    """Read the key, lazily creating it (0700 dir, 0600 file, O_EXCL)
    if absent — the shared hardened discipline in
    :func:`core.security.mac_key.load_or_create_key` (race-loser
    bounded wait, wrong-length fail-closed). Returns None when a key
    file exists but is unusable — the suspect key is never used,
    never replaced."""
    return mac_key.load_or_create_key(
        _key_path(), key_len=_KEY_LEN, warn=_warn_once_suspect_key,
        read_existing=_read_existing_key)


def key_usable() -> bool:
    """Whether this install can mint/verify tokens at all. With an
    unusable key every cached-DB read is a miss and every write
    persists unstamped — caching is effectively disabled until the
    operator fixes the key (the warn-once above says how)."""
    try:
        return bool(_load_or_create_key())
    except OSError:
        return False


def payload_sha256(data: dict) -> str:
    """sha256 over the sidecar's canonical JSON (token key excluded).

    Canonical form: :func:`core.json.utils.dumps_canonical`. The token
    covers the WHOLE entry (success, build_system, created_at,
    database_path, ...): partial coverage would let an attacker
    rewrite the unauthenticated remainder of a validly-stamped
    sidecar."""
    scrubbed = {k: v for k, v in data.items() if k != TOKEN_KEY}
    canonical = dumps_canonical(scrubbed)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _mac_message(name: str, sha256_hex: str) -> bytes:
    # Domain separation ("codeql-db-metadata") keeps a token minted
    # for another artifact class from ever verifying here; the name
    # component binds the token to the cache slot it vouches for (see
    # module docstring, "Name binding").
    return (
        b"codeql-db-metadata\x00"
        + name.encode("utf-8", errors="replace")
        + b"\x00"
        + sha256_hex.encode("ascii")
    )


def mint(name: str, data: dict) -> str | None:
    """Hex HMAC-SHA256 token over the sidecar's canonical payload
    bound to cache slot *name* (``<repo_hash>/<language>``), or None
    when no usable key is available. Writers treat None as "persist
    unstamped" — readers then miss and rebuild."""
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
    exists the token key is removed instead — an unstamped sidecar
    under an unusable key is the honest representation."""
    token = mint(name, data)
    if token is None:
        data.pop(TOKEN_KEY, None)
        return data
    data[TOKEN_KEY] = {"token": token}
    return data


def extract_token(data: dict) -> str | None:
    """Pull the token string out of the sidecar dict, tolerating the
    key being absent or malformed (both read as "unstamped")."""
    box = data.get(TOKEN_KEY)
    if isinstance(box, dict):
        token = box.get("token")
        return token if isinstance(token, str) else None
    return None


def verify_entry(name: str, data: dict) -> bool:
    """Reader-facing chokepoint: whether the loaded sidecar *data* was
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

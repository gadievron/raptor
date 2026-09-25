"""HMAC provenance for verdict-feeding graph-store rows.

The /understand graph store lives in run/project output directories —
target-writable during runs and restorable verbatim by ``/project
import`` — and its call-edge rows can feed NEGATIVE reachability (a
suppression/demotion input: "this function is unreachable from every
entry point"). Unauthenticated rows would let a hostile artifact steer
those verdicts, so verdict-feeding rows are stamped at ingest with an
HMAC-SHA256 token and verified at query time; rows whose token is
absent or invalid demote to hint tier (prompt seeding only, never a
verdict input). Same trust story and key-handling discipline as
``core/coverage/journal_mac.py`` (the precedent this module mirrors).

Key
    ``$XDG_DATA_HOME/raptor/graph-mac.key`` (default
    ``~/.local/share/raptor/graph-mac.key``). Deliberately its OWN
    key file — per-purpose keys keep reset/rotation semantics scoped
    (deleting the journal key must not demote graph rows or vice
    versa; ``core.security.mac_key`` documents the discipline). No
    rotation: deleting the key demotes every stamped row to the
    unverifiable tier (hint only) and new ingests re-key lazily.

Run binding
    Tokens are bound to the store's resolved parent directory
    (:func:`store_binding`) — derived by the VERIFIER from the path it
    reads, never stored in a row (an attacker holding the store-dir
    write grant could plant any stored identity; the consumer's own
    directory cannot be forged from inside it — the
    ``audit_log_run_binding`` precedent). The parent directory, not
    the file: ``rebuild_graph`` ingests into a pid-suffixed sibling
    temp DB and renames it into place, and the swap must not demote
    every row it just minted. A store copied into another project (or
    another install) fails verification and demotes to hint tier —
    the safe direction.

Deletion is not detectable at row grain
    A row MAC authenticates content, not set membership: an attacker
    can DELETE edges to bias a reachability walk toward
    "unreachable". The snapshot token therefore covers the minted
    edge COUNT (:func:`snapshot_payload`); consumers compare the
    verified-row count against it and treat any shortfall as an
    incomplete edge set — the same epistemic state as a truncated
    walk, degrading negative conclusions to inconclusive.

Batch shape
    The call-edge lanes run at 10^5-10^6 rows; a key-file read per
    row is not affordable. :class:`RowStamper` loads the key once and
    precomputes the HMAC state over the constant ``domain || binding``
    prefix, so each row costs one canonical dump, one SHA-256, and
    one HMAC finalisation.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
from typing import Any

from core.json.utils import dumps_canonical
from core.logging import get_logger
from core.security import mac_key

logger = get_logger(__name__)

_KEY_LEN = 32

_warned_paths: set = set()

# Domain separation: a token minted for another artifact class (or the
# other row class here) can never verify, even if a key were ever
# shared by mistake.
_EDGE_DOMAIN = b"graph-call-edge\x00"
_SNAPSHOT_DOMAIN = b"graph-callgraph-snapshot\x00"


def _key_path() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "raptor" / "graph-mac.key"


def _warn_once_suspect_key(path: Path, reason: str, remedy: str) -> None:
    key = str(path)
    if key in _warned_paths:
        logger.debug(f"graph integrity: suspect key {path} ({reason})")
        return
    _warned_paths.add(key)
    logger.warning(
        f"graph integrity: refusing key {path} — {reason}. Graph edge "
        f"rows will not mint or verify (stamped rows demote to hint "
        f"tier: never a suppression/demotion input) until this is "
        f"fixed: {remedy}"
    )


def _read_existing_key(path: Path) -> bytes | mac_key.Refused | None:
    return mac_key.read_existing_key(
        path, key_len=_KEY_LEN, warn=_warn_once_suspect_key)


def _load_or_create_key() -> bytes | None:
    """Read the key, lazily creating it (0700 dir, 0600 file, O_EXCL)
    if absent — the shared hardened discipline in
    :func:`core.security.mac_key.load_or_create_key`. Returns None
    when a key file exists but is unusable — the suspect key is never
    used, never replaced."""
    return mac_key.load_or_create_key(
        _key_path(), key_len=_KEY_LEN, warn=_warn_once_suspect_key,
        read_existing=_read_existing_key,
        recreate_hint="a fresh key is created on the next ingest")


def key_usable() -> bool:
    """Whether this install can mint/verify graph tokens at all."""
    try:
        return bool(_load_or_create_key())
    except OSError:
        return False


def store_binding(graph_path: Path | str) -> str:
    """The run identity bound into graph tokens: the store's resolved
    PARENT directory. Derived — never stored in a row (see module
    docstring). One derivation for writers and readers; the parent
    (not the file) so ``rebuild_graph``'s sibling-temp-then-rename
    swap keeps freshly minted tokens valid."""
    try:
        return str(Path(graph_path).resolve().parent)
    except OSError:
        return str(Path(graph_path).parent)


def edge_payload(
    snapshot_id: str,
    src_file: str,
    src_name: str,
    dst_file: str,
    dst_name: str,
    *,
    kind: str = "CALLS",
    provenance: str = "mechanical",
) -> dict[str, Any]:
    """Canonical token payload for one verdict-feeding edge row.

    The token covers the endpoint files and names the reachability
    walk actually consumes, so rewriting a joined node row's name or
    file breaks verification of every edge touching it (the ids alone
    would authenticate nothing a consumer reads). File and name ride
    as SEPARATE fields, never a joined ``file::name`` ref: the joined
    form is ambiguous when names themselves carry ``::`` (C++
    qualified names), and an ambiguous payload would let a rewritten
    node row re-split the same ref — changing what the walk sees —
    while its edges still verify. Binding ``snapshot_id`` blocks
    cross-snapshot replay within the same store.
    """
    return {
        "dst_file": dst_file,
        "dst_name": dst_name,
        "kind": kind,
        "provenance": provenance,
        "snapshot": snapshot_id,
        "src_file": src_file,
        "src_name": src_name,
    }


def snapshot_payload(
    snapshot_id: str,
    target_path: str,
    checklist_hash: str,
    producer: str,
    edge_count: int,
    created_at: str,
) -> dict[str, Any]:
    """Canonical token payload for one callgraph snapshot row.

    ``edge_count`` is the deletion witness: row MACs cannot detect a
    removed row, so the snapshot token pins how many DISTINCT
    mechanical edges were minted and consumers treat any
    distinct-verified shortfall as an incomplete set (negative
    conclusions degrade to inconclusive). ``created_at`` is covered so
    the latest-snapshot acceptance rule (consumers refuse superseded
    generations) cannot be steered by rewriting an old snapshot's
    stored timestamp — a rewritten timestamp breaks the token instead.
    """
    return {
        "checklist_hash": checklist_hash,
        "created_at": created_at,
        "edge_count": int(edge_count),
        "id": snapshot_id,
        "producer": producer,
        "target": target_path,
    }


def _payload_sha_hex(payload: dict[str, Any]) -> str:
    canonical = dumps_canonical(payload)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class RowStamper:
    """Batch mint/verify for one (store, domain) pair.

    Loads the key once at construction and precomputes the HMAC state
    over the constant ``domain || binding || NUL`` prefix; each row
    then costs one canonical dump + SHA-256 + HMAC finalisation
    (``copy()`` of the precomputed state). An unusable key yields an
    unusable stamper: ``mint`` returns None (writers persist
    unstamped — the row keeps its hint value, it just never feeds a
    verdict) and ``verify`` returns False (the caller's demote path).
    """

    __slots__ = ("_base",)

    def __init__(self, graph_path: Path | str, domain: bytes) -> None:
        key: bytes | None
        try:
            key = _load_or_create_key()
        except OSError:
            key = None
        if not key:
            self._base = None
            return
        prefix = (
            domain
            + store_binding(graph_path).encode("utf-8", "surrogatepass")
            + b"\x00"
        )
        self._base = hmac.new(key, prefix, hashlib.sha256)

    @property
    def usable(self) -> bool:
        return self._base is not None

    def mint(self, payload: dict[str, Any]) -> str | None:
        """Hex token over *payload*'s canonical form, or None when no
        usable key is available."""
        if self._base is None:
            return None
        h = self._base.copy()
        h.update(_payload_sha_hex(payload).encode("ascii"))
        return h.hexdigest()

    def verify(self, payload: dict[str, Any], token: Any) -> bool:
        """Whether *token* is a valid MAC over *payload* under this
        install's key and this stamper's store binding. Constant-time;
        never raises — any failure is the caller's demote path."""
        if not token:
            return False
        try:
            expected = self.mint(payload)
            if expected is None:
                return False
            return hmac.compare_digest(expected, str(token).strip().lower())
        except Exception:  # noqa: BLE001 — verification failure is the demote path, never an error
            return False


def edge_stamper(graph_path: Path | str) -> RowStamper:
    """Stamper for verdict-feeding edge rows in the store at
    *graph_path*."""
    return RowStamper(graph_path, _EDGE_DOMAIN)


def snapshot_stamper(graph_path: Path | str) -> RowStamper:
    """Stamper for callgraph snapshot rows in the store at
    *graph_path*."""
    return RowStamper(graph_path, _SNAPSHOT_DOMAIN)


__all__ = [
    "RowStamper",
    "edge_payload",
    "edge_stamper",
    "key_usable",
    "snapshot_payload",
    "snapshot_stamper",
    "store_binding",
]

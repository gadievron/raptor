"""HMAC provenance for checklist ``checked_by`` review claims.

``checklist.json`` lives in run/project directories that are
target-writable during runs and restorable verbatim by ``/project
import`` — and its per-item ``checked_by`` labels are analysed/reviewed
state: the coverage backfill folds them into the coverage store under
review-grade tool labels, and store marks at that grade clear functions
out of every store-derived review-gap view. Rows were plain
unauthenticated JSON, so a forged ``checked_by`` row minted review
credit that durably suppressed review of a function.

Writers stamp each review CLAIM — one ``(item, label)`` pair — at the
moment the label is appended (:func:`core.inventory.coverage.
update_coverage`, the only code that adds one); read-modify-write
writers (rebuild carry-forward, project promotion) copy tokens
verbatim, so a planted row stays unstamped no matter how many
legitimate saves follow — the per-row-not-per-record laundering
argument from ``core.coverage.journal_mac.mint_coverage_row``. The one
consumer that converts claims into authority
(``core.coverage.importer.import_checked_by``) verifies before
granting a claim the record's tool label; unverified review-grade
claims demote to the ``<label>:machine`` hint tier
(``core.coverage.registry.classify``) — readable, loud, never a hard
refusal. Same trust story and key-handling discipline as
``core/coverage/journal_mac.py``.

Per-claim, not per-file/per-shard, deliberately: every checklist write
is a full read-modify-write through the accessors, so a file-, shard-,
or manifest-level token minted at the write chokepoint would re-stamp
— launder — any planted row sitting in the file when a legitimate
writer next saved it. Claims are also independent of shard membership,
file order, and byte offsets, so the sharded ``checklist/`` layout can
repack entries freely without touching token validity.

The claim payload covers identity (file, class, name, kind, label),
the item's line range (the importer resolves the store interval from
the row's own line fields — an uncovered range would let an attacker
stretch one stamped row's interval over the whole file), and the file
entry's content ``sha256`` (currency: a token replayed against a
since-changed file demotes — stale review credit must not survive
source change). Claims are deliberately NOT run-bound: like journal
rows, checklist marks aggregate across runs by design (project
promotion merging an older run's validly stamped claim is the
feature); a replayed stamped claim is genuine install history for the
exact file content it names.

Key
    ``$XDG_DATA_HOME/raptor/checklist-mac.key`` (default
    ``~/.local/share/raptor/checklist-mac.key``). Deliberately its OWN
    key file — per-purpose keys keep reset/rotation semantics scoped
    (``core.security.mac_key`` doctrine: never unify key files). No
    rotation: deleting the key demotes every stamped claim to the
    unstamped hint tier and new mints re-key lazily; no other
    subsystem's trust surface is touched.
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

# HMAC-SHA256 key length. 32 bytes = the hash's output/security level
# and the shared value every mac_key consumer uses (journal, witness,
# scorecard): SHORTER weakens the key below the primitive's strength;
# LONGER buys no security (HMAC pre-hashes longer keys) while breaking
# the one-length read/refuse contract in core.security.mac_key. Both
# directions pinned by tests (test_checklist_mac.py: created key is
# exactly 32 bytes; wrong-length keys refuse).
_KEY_LEN = 32

_warned_paths: set[str] = set()

#: Item key holding the per-label token map:
#: ``{"<checked_by label>": "<64-hex hmac token>"}``. Sits BESIDE
#: ``checked_by`` on the item dict — readers that don't know it
#: ignore it; the extractor dataclasses never round-trip marked items.
TOKEN_MAP_KEY = "checked_by_mac"

#: Tri-state provenance of a loaded claim.
CLAIM_VERIFIED = "verified"
CLAIM_TAMPERED = "tampered"
CLAIM_UNSTAMPED = "unstamped"

# Domain separation: a token minted for any other artifact class can
# never verify here even if a key were ever shared by mistake.
_CHECKLIST_CLAIM_DOMAIN = b"checklist-checked-claim\x00"


def _key_path() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "raptor" / "checklist-mac.key"


def _warn_once_suspect_key(path: Path, reason: str, remedy: str) -> None:
    key = str(path)
    if key in _warned_paths:
        logger.debug(f"checklist integrity: suspect key {path} ({reason})")
        return
    _warned_paths.add(key)
    logger.warning(
        f"checklist integrity: refusing key {path} — {reason}. Review "
        f"claims will not mint or verify (stamped checked_by claims "
        f"demote to the unstamped hint tier: examination evidence "
        f"only, no review credit) until this is fixed: {remedy}"
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
    :func:`core.security.mac_key.load_or_create_key`. Returns None
    when a key file exists but is unusable — the suspect key is never
    used, never replaced."""
    return mac_key.load_or_create_key(
        _key_path(), key_len=_KEY_LEN, warn=_warn_once_suspect_key,
        read_existing=_read_existing_key)


def key_usable() -> bool:
    """Whether this install can mint/verify claim tokens at all."""
    try:
        return bool(_load_or_create_key())
    except OSError:
        return False


def _item_class(item: dict[str, Any]) -> str:
    """The item's class name, derived the way ``update_coverage``
    disambiguates same-named twins: ``metadata.class_name`` (the shape
    the extractors serialise) with a bare ``class`` key fallback."""
    meta = item.get("metadata")
    cls = (
        (meta.get("class_name") if isinstance(meta, dict) else None)
        or item.get("class")
        or ""
    )
    return cls if isinstance(cls, str) else ""


def checked_claim(
    file_entry: dict[str, Any], item: dict[str, Any], label: str,
) -> dict[str, Any]:
    """The canonical claim payload for one ``(item, label)`` pair.

    ONE derivation shared by mint and verify so the two can never
    fork. Fields are taken from the row dicts exactly as they persist
    in checklist.json (JSON round-trip stable scalars only)."""
    return {
        "file": file_entry.get("path", file_entry.get("file", "")),
        "sha256": file_entry.get("sha256") or "",
        "class": _item_class(item),
        "name": item.get("name", ""),
        "kind": item.get("kind", "function"),
        "line_start": item.get("line_start"),
        "line_end": item.get("line_end"),
        "label": label,
    }


def claim_sha256(claim: dict[str, Any]) -> str:
    """sha256 over the claim's canonical JSON
    (:func:`core.json.utils.dumps_canonical`, the repo-wide frozen
    canonical byte form — key order and whitespace don't matter,
    values do)."""
    return hashlib.sha256(
        dumps_canonical(claim).encode("utf-8")).hexdigest()


def _mac_message(sha256_hex: str) -> bytes:
    return _CHECKLIST_CLAIM_DOMAIN + sha256_hex.encode("ascii")


def mint_checked_claim(
    file_entry: dict[str, Any], item: dict[str, Any], label: str,
) -> str | None:
    """Hex HMAC-SHA256 token over the claim's canonical payload, or
    None when no usable key is available. Writers treat None as
    "persist unstamped" — consumers then apply unstamped-tier
    semantics (hint-tier import, no review credit)."""
    try:
        key = _load_or_create_key()
    except OSError:
        return None
    if not key:
        return None
    return hmac.new(
        key,
        _mac_message(claim_sha256(checked_claim(file_entry, item, label))),
        hashlib.sha256,
    ).hexdigest()


def verify_checked_claim(
    file_entry: dict[str, Any], item: dict[str, Any], label: str,
    token: str | None,
) -> bool:
    """Whether *token* is a valid MAC over the ``(item, label)`` claim
    under this install's key. Constant-time; never raises — any
    failure is the caller's demote path."""
    if not token:
        return False
    try:
        expected = mint_checked_claim(file_entry, item, label)
        if expected is None:
            return False
        return hmac.compare_digest(expected, str(token).strip().lower())
    except Exception:  # noqa: BLE001 — verification failure is the demote path, never an error
        return False


def claim_provenance(
    file_entry: dict[str, Any], item: dict[str, Any], label: str,
) -> str:
    """Tri-state provenance of one ``(item, label)`` claim.

    * ``verified`` — token present and valid for the claim's content.
    * ``tampered`` — token present but invalid: content edited, a
      token minted by another install, or a stale claim (file content
      / line range moved since the mark). Consumers give these the
      same authority as ``unstamped`` (the token is strippable, so
      "tampered" is attribution, not a security boundary) but log
      them distinctly.
    * ``unstamped`` — no token (pre-MAC legacy or forged-unstamped):
      hint-tier import only, never review credit.
    """
    token_map = item.get(TOKEN_MAP_KEY)
    token = token_map.get(label) if isinstance(token_map, dict) else None
    if not token or not isinstance(token, str):
        return CLAIM_UNSTAMPED
    return (CLAIM_VERIFIED
            if verify_checked_claim(file_entry, item, label, token)
            else CLAIM_TAMPERED)


__all__ = [
    "CLAIM_TAMPERED",
    "CLAIM_UNSTAMPED",
    "CLAIM_VERIFIED",
    "TOKEN_MAP_KEY",
    "checked_claim",
    "claim_provenance",
    "claim_sha256",
    "key_usable",
    "mint_checked_claim",
    "verify_checked_claim",
]

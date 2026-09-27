"""HMAC frame authentication for the checklist substrate.

The checklist (single-file ``checklist.json`` or the sharded
``checklist/`` layout) is the inventory every review pipeline walks:
it decides WHICH functions exist to be reviewed. It lives in run and
project directories that are target-writable during runs and
restorable verbatim by ``/project import`` — and its integrity story
was per-shard sha256 alone, which is source CURRENCY, not
authentication: anyone who can write the run directory can replace
the frame wholesale with self-consistent hashes and steer the review
queue. Nothing bound the frame to the slot that created it.

Writers stamp the frame at the single write chokepoint
(``core.inventory._write_checklist_locked``) with an HMAC-SHA256
token over the document's canonical JSON (token excluded), the
on-disk FORM, and the resolved SLOT directory the frame was written
into. For the sharded layout the token rides on ``index.json`` and
covers the manifest — shard name set, per-shard sha256/bytes/counts,
totals, metadata — so shard-content authenticity chains through the
already-verified per-shard sha256. Readers classify every frame into
the journal-MAC tier vocabulary (same trust story and key-handling
discipline as ``core.coverage.journal_mac``):

* ``verified`` — token valid, slot matches: authenticated tier.
* ``tampered`` — token present but invalid: the accessors fail
  closed loudly (read-only consumers degrade to ``{}``; the
  read-modify-write accessor refuses; and every read that feeds a
  re-stamping ``save_checklist`` outside the plain accessor
  round-trip — run-to-project checklist promotion, the Ghidra
  diff-priority boost, and the exploitability-validation pipeline's
  parent-checklist reuse — applies the same gate, so an in-place
  edit is never re-stamped/laundered by any write route).
  Deliberately harsher than the journal's
  unverifiable-demotes-to-unstamped compromise: journal rows are
  irreplaceable history, while a checklist is mechanically
  REBUILDABLE from the target — the refusal remedy is one rebuild.
* ``unstamped`` — no token (pre-MAC legacy, or forged-unstamped):
  legacy tier, accepted with behavior otherwise unchanged so old
  runs keep working; warned once per slot, louder for frames born
  inside the stamp era (:data:`FRAME_MAC_ERA_START` mtime fence,
  same acknowledged utime residual as the annotations stamp era).
  A stamped frame verified while NO key file exists (deleted or
  rotated key) also lands here, with a rotation warning — the
  verify side never creates a key (see :func:`_load_verify_key`).
* ``relocated`` — token valid under this install's key but the
  MAC-covered slot names a DIFFERENT directory (frame copied or
  moved from another run/project): demoted to the legacy tier with
  a distinct warning, never refused. A valid MAC proves the frame
  is this install's own unedited history; operator ``mv`` /
  ``/project adopt`` / restore flows dominate this shape, and
  refusal would grant nothing — stripping the token lands in the
  accepted legacy tier anyway. Same posture as the journal MAC's
  verified-but-attributed-elsewhere rows
  (``core.coverage.journal_mac``): demote the authority the binding
  earned, never drop the data.

Key
    ``$XDG_DATA_HOME/raptor/checklist-frame-mac.key`` (default
    ``~/.local/share/raptor/checklist-frame-mac.key``). Deliberately its
    OWN per-purpose key file, never the journal's: per-purpose keys
    keep reset/rotation semantics scoped — deleting this key demotes
    every stamped checklist frame to the unstamped tier and new
    writes re-key lazily, without touching the journal's trust
    surface (and vice versa). Kept OUTSIDE every LLM-writable and
    sandbox-readable tree, like every other MAC key.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
from typing import Any

from core.security import mac_key

_KEY_LEN = 32

#: Document key holding the frame token. Popped before
#: canonicalisation so the MAC covers everything else; the accessors
#: also pop it from returned dicts so both on-disk forms hand
#: consumers the identical in-memory shape.
FRAME_TOKEN_KEY = "integrity"

#: Frame provenance tiers (journal_mac vocabulary + ``relocated``).
FRAME_VERIFIED = "verified"
FRAME_TAMPERED = "tampered"
FRAME_UNSTAMPED = "unstamped"
FRAME_RELOCATED = "relocated"

#: On-disk form discriminators, bound into the MAC message so a
#: validly-stamped single-file document can never be replayed as a
#: sharded index (or vice versa) even at the same slot.
FORM_SINGLE = "single-file"
FORM_SHARDED = "sharded-index"

# Domain separation: a token minted for another artifact class can
# never verify here even if a key were ever shared by mistake.
_FRAME_DOMAIN = b"checklist-frame\x00"

# Stamp-era fence for UNSTAMPED frames (mtime-fenced, like the
# annotations stamp era and the fp-feedback origin field). Frames
# whose artifact mtime predates this are genuinely pre-feature and
# log quietly; frames born inside the stamp era warn louder (an
# install without a usable key, or a stripped token). EARLIER would
# shout at honest pre-feature runs; LATER would keep stripped-token
# plants quiet for longer. Both directions accept — the fence tunes
# warning loudness only, never authority. Acknowledged residual: an
# attacker with run-dir write access can utime() a plant behind the
# fence, buying only the quieter log line.
FRAME_MAC_ERA_START = 1790513608.0  # 2026-09-27T12:53:28Z

_warned_key_paths: set[str] = set()
_warned_absent_key: set[str] = set()

# Warn-once registries for demoted frames, keyed by artifact path so
# a busy run does not repeat the same demotion line on every read.
_warned_unstamped: set[str] = set()
_warned_relocated: set[str] = set()

from core.logging import get_logger  # noqa: E402

logger = get_logger(__name__)


def _key_path() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "raptor" / "checklist-frame-mac.key"


def _warn_once_suspect_key(path: Path, reason: str, remedy: str) -> None:
    key = str(path)
    if key in _warned_key_paths:
        logger.debug(f"checklist integrity: suspect key {path} ({reason})")
        return
    _warned_key_paths.add(key)
    logger.warning(
        f"checklist integrity: refusing key {path} — {reason}. Checklist "
        f"frames will not mint or verify (stamped frames demote to the "
        f"unstamped legacy tier) until this is fixed: {remedy}"
    )


def _warn_once_absent_key(path: Path) -> None:
    key = str(path)
    if key in _warned_absent_key:
        logger.debug(f"checklist integrity: no key at {path}")
        return
    _warned_absent_key.add(key)
    logger.warning(
        f"checklist integrity: no key at {path} but a stamped "
        f"checklist frame exists — the key was deleted or rotated. "
        f"Stamped frames demote to the unstamped legacy tier (never "
        f"refused); the next checklist write mints a fresh key and "
        f"re-stamps."
    )


def _read_existing_key(path: Path) -> bytes | mac_key.Refused | None:
    """Read an EXISTING key with the shared fd-fstat discipline
    (:func:`core.security.mac_key.read_existing_key`)."""
    return mac_key.read_existing_key(
        path, key_len=_KEY_LEN, warn=_warn_once_suspect_key)


def _load_verify_key() -> bytes | mac_key.Refused | None:
    """Read-only key access for the VERIFY side — never creates.

    Verify-side lazy creation would turn a deleted or rotated key
    into a FRESH key under which every previously stamped frame
    reads ``tampered`` — refusing every checklist across all
    projects for what the module contract documents as reset
    semantics (delete the key ⇒ stamped frames demote to the
    unstamped tier; new writes re-key lazily). Only the mint side
    creates (:func:`_load_or_create_key`).

    Returns ``None`` when no key file exists (caller demotes to the
    unstamped tier with the rotation warning) or :data:`mac_key.REFUSED`
    when a key file exists but is unusable (refused metadata or
    wrong length — caller demotes; the suspect-key warning already
    fired). Never raises.
    """
    try:
        data = _read_existing_key(_key_path())
    except OSError:
        return mac_key.REFUSED
    if data is None or isinstance(data, mac_key.Refused):
        return data
    if len(data) != _KEY_LEN:
        # Wrong-length content: warn only once STALE — fresh
        # wrong-length bytes can be a concurrent cold-start winner
        # mid-write (the mint side's load_or_create resolves that
        # race with its bounded poll; this read just demotes once).
        if not mac_key._recently_modified(_key_path()):
            _warn_once_suspect_key(
                _key_path(),
                f"wrong length ({len(data)} bytes, expected {_KEY_LEN})",
                "remove the suspect key and investigate; a fresh key "
                "is created on the next checklist write",
            )
        return mac_key.REFUSED
    return data


def _load_or_create_key() -> bytes | None:
    """Read the key, lazily creating it (0700 dir, 0600 file, O_EXCL)
    if absent — the shared hardened discipline in
    :func:`core.security.mac_key.load_or_create_key`. Returns None
    when a key file exists but is unusable — the suspect key is never
    used, never replaced."""
    return mac_key.load_or_create_key(
        _key_path(), key_len=_KEY_LEN, warn=_warn_once_suspect_key,
        read_existing=_read_existing_key,
        recreate_hint="a fresh key is created on the next checklist write")


def key_usable() -> bool:
    """Whether this install can mint/verify frame tokens at all."""
    try:
        return bool(_load_or_create_key())
    except OSError:
        return False


def frame_binding(slot_dir: Path | str) -> str:
    """The slot identity bound into frame tokens: the resolved
    directory holding the ``checklist.json`` slot. Derived on both
    sides AFTER the accessors' symlink resolution, so run-local
    frames bind to the run dir and project-slot frames bind to the
    project dir regardless of which spelling reached the accessor.
    Never read from a run-dir artifact — the consumer's own directory
    cannot be forged from inside it (same rationale as
    :func:`core.coverage.journal_mac.audit_log_run_binding`)."""
    try:
        return str(Path(slot_dir).resolve())
    except OSError:
        return str(slot_dir)


def frame_digest(doc: dict[str, Any]) -> str:
    """sha256 over the document's canonical JSON (token key excluded).

    Canonical form: :func:`core.json.utils.dumps_canonical` — the
    repo-wide frozen canonical byte form shared with the journal MAC.
    The token covers the WHOLE document: for the sharded index that
    is the shard name+sha256+bytes+count set, totals, and metadata;
    for the single-file form it is the entire inventory. Partial
    coverage would let an attacker rewrite the unauthenticated
    remainder of a validly-stamped frame."""
    from core.json.utils import dumps_canonical

    scrubbed = {k: v for k, v in doc.items() if k != FRAME_TOKEN_KEY}
    canonical = dumps_canonical(scrubbed)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _mac_message(form: str, slot: str, digest_hex: str) -> bytes:
    return (
        _FRAME_DOMAIN
        + form.encode("ascii") + b"\x00"
        + slot.encode("utf-8", "surrogatepass") + b"\x00"
        + digest_hex.encode("ascii")
    )


def _mint_hex(form: str, slot: str, digest_hex: str) -> str | None:
    try:
        key = _load_or_create_key()
    except OSError:
        return None
    if not key:
        return None
    return hmac.new(
        key, _mac_message(form, slot, digest_hex), hashlib.sha256,
    ).hexdigest()


def mint_frame(
    doc: dict[str, Any], slot: str, form: str,
) -> dict[str, str] | None:
    """Frame token for *doc* as written at *slot* in on-disk *form*:
    ``{"slot": <resolved slot dir>, "mac": <hex>}``, or ``None`` when
    no usable key is available. Writers treat ``None`` as "persist
    unstamped" — readers then apply legacy-tier semantics. The
    claimed slot is INSIDE the MAC message, so a copied frame cannot
    be re-homed by rewriting it; readers compare the covered claim
    against their own derived slot."""
    mac = _mint_hex(form, slot, frame_digest(doc))
    if mac is None:
        return None
    return {"slot": slot, "mac": mac}


def frame_provenance(
    doc: dict[str, Any], slot: str, form: str,
) -> str:
    """Four-state provenance of a loaded checklist frame document.

    *slot* is the READER'S own derived binding
    (:func:`frame_binding`), never the token's stored claim. Never
    raises — any verification failure lands in a tier. Key access is
    READ-ONLY here (:func:`_load_verify_key`): an ABSENT key file
    (deleted/rotated) demotes stamped frames to ``unstamped`` with a
    rotation warning, and an exists-but-unusable key file demotes
    them the same way (with the suspect-key warning) — never
    ``tampered``, never fail-open to ``verified``: an environmental
    key problem is not evidence of frame tamper, and refusing every
    read until an operator fixes the key would fail the wrong
    direction. ``tampered`` requires a USABLE key whose MAC rejects
    the token."""
    token = doc.get(FRAME_TOKEN_KEY)
    if not token:
        return FRAME_UNSTAMPED
    if not (isinstance(token, dict)
            and isinstance(token.get("slot"), str)
            and isinstance(token.get("mac"), str)):
        # Present-but-malformed: whoever wrote it claimed a stamp it
        # cannot back. Same refusal as a wrong MAC.
        return FRAME_TAMPERED
    key = _load_verify_key()
    if key is None:
        _warn_once_absent_key(_key_path())
        return FRAME_UNSTAMPED
    if isinstance(key, mac_key.Refused):
        return FRAME_UNSTAMPED
    claimed_slot = token["slot"]
    try:
        expected = hmac.new(
            key, _mac_message(form, claimed_slot, frame_digest(doc)),
            hashlib.sha256,
        ).hexdigest()
    except Exception:  # noqa: BLE001 — verification failure is a tier, never an error
        return FRAME_TAMPERED
    if not hmac.compare_digest(
            expected, str(token["mac"]).strip().lower()):
        return FRAME_TAMPERED
    if claimed_slot != slot:
        return FRAME_RELOCATED
    return FRAME_VERIFIED


def _artifact_pre_era(artifact_path: Path | str) -> bool:
    """Whether the frame artifact's mtime predates the stamp era.

    Fails toward "in the era" (the louder warning): an unstatable
    artifact was just read successfully, so a stat failure here is
    anomalous and should not buy the quiet log line."""
    try:
        return os.stat(artifact_path).st_mtime < FRAME_MAC_ERA_START
    except OSError:
        return False


def warn_demoted_frame(
    artifact_path: Path | str, provenance: str, what: str,
) -> None:
    """One warning per artifact path for a frame read at legacy tier.

    ``unstamped`` frames are era-fenced: pre-era artifacts log at
    info (genuinely pre-feature — old runs keep working silently
    enough), in-era artifacts warn (an install without a usable key,
    or a stripped token). ``relocated`` frames always warn at the
    artifact path, so a copied frame's demotion is visible in the
    run log; the message deliberately does NOT echo the token's
    covered slot — the remedy (rebuild the inventory here) is the
    same wherever the frame came from. Demote-not-refuse in both
    cases — behavior is otherwise unchanged."""
    key = str(artifact_path)
    if provenance == FRAME_RELOCATED:
        if key in _warned_relocated:
            return
        _warned_relocated.add(key)
        logger.warning(
            "%s: checklist frame at %s verifies but was minted for a "
            "different slot — the frame was copied or moved from "
            "another run/project directory. Reading it at legacy tier "
            "(authenticated-tier authority withheld); rebuild the "
            "inventory here to re-stamp.",
            what, artifact_path,
        )
        return
    if provenance == FRAME_UNSTAMPED:
        if key in _warned_unstamped:
            return
        _warned_unstamped.add(key)
        if _artifact_pre_era(artifact_path):
            logger.info(
                "%s: checklist frame at %s carries no integrity token "
                "(pre-stamp legacy) — reading at legacy tier.",
                what, artifact_path,
            )
        else:
            logger.warning(
                "%s: checklist frame at %s carries no integrity token "
                "despite being written inside the stamp era — either "
                "this install has no usable checklist-frame-mac key, or the "
                "token was stripped. Reading at legacy tier; rebuild "
                "the inventory to re-stamp.",
                what, artifact_path,
            )


__all__ = [
    "FORM_SHARDED",
    "FORM_SINGLE",
    "FRAME_MAC_ERA_START",
    "FRAME_RELOCATED",
    "FRAME_TAMPERED",
    "FRAME_TOKEN_KEY",
    "FRAME_UNSTAMPED",
    "FRAME_VERIFIED",
    "frame_binding",
    "frame_digest",
    "frame_provenance",
    "key_usable",
    "mint_frame",
    "warn_demoted_frame",
]

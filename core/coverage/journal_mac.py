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

The ``.audit-log.jsonl`` event log in the same directory carries one
row class with the same authority (resume review-suppression via
``get_reviewed_set``) and gets the same treatment through its own
domain prefix (:func:`mint_audit_log_row` /
:func:`verify_audit_log_row`): writers stamp every appended event,
and the resume reader lets a row suppress ONLY when its token
verifies — everything else in the log stays telemetry-tier and
tolerant. UNLIKE journal rows, audit-log tokens ARE run-bound: the
MAC covers the run dir's resolved-path identity
(:func:`audit_log_run_binding`), supplied implicitly by whichever
directory the verifier reads — a row copied verbatim from a sibling
run's log fails verification, because the audit-log lane has no
source-hash gate or fold to bound a replay the way the journal does
(a replayed clean row is NOT genuine history for another run's
resume set). Moving a run dir demotes its rows to unstamped —
re-review, the safe direction, same posture as cross-install.

No run binding for JOURNAL rows: they deliberately travel across
runs — the project index aggregates them and cross-run verdict reuse
is the feature. A replayed validly-stamped row is genuine history
for the exact source hash it names; staleness is bounded by the
fold's hash compare, not the MAC.

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
from pathlib import Path

from core.json.utils import dumps_canonical
from core.logging import get_logger
from core.security import mac_key

logger = get_logger(__name__)

_KEY_LEN = 32

# Sentinel: a key file EXISTS but is unusable (symlink, foreign owner,
# group/other-readable). Distinct from "absent" — an unusable key must
# never be silently replaced and must never mint or verify.
_REFUSED = mac_key.REFUSED

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
    used, never replaced. The creation-race loser polls through the
    winner's create-to-write window instead of mis-flagging the
    mid-write key as suspect (which left the loser's rows unstamped —
    demoted to the no-reuse tier — under a false suspect-key
    warning)."""
    return mac_key.load_or_create_key(
        _key_path(), key_len=_KEY_LEN, warn=_warn_once_suspect_key,
        read_existing=_read_existing_key)


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


# Domain separation: a token minted for another artifact class can
# never verify here even if a key were ever shared by mistake. The
# audit event log shares the journal's key (same trust domain —
# review-suppression authority in target-writable run dirs; deleting
# the key demotes both artifact classes together) but its own domain
# prefix, so journal tokens never authenticate audit-log rows or vice
# versa.
_JOURNAL_DOMAIN = b"review-journal-row\x00"
_AUDIT_LOG_DOMAIN = b"audit-log-row\x00"
_PREP_CACHE_DOMAIN = b"prep-cache-artifact\x00"


def _mac_message(sha256_hex: str, domain: bytes = _JOURNAL_DOMAIN) -> bytes:
    return domain + sha256_hex.encode("ascii")


def _mint(row: dict, domain: bytes) -> str | None:
    try:
        key = _load_or_create_key()
    except OSError:
        return None
    if not key:
        return None
    return hmac.new(
        key, _mac_message(row_sha256(row), domain), hashlib.sha256,
    ).hexdigest()


def _verify(row: dict, token: str | None, domain: bytes) -> bool:
    if not token:
        return False
    try:
        expected = _mint(row, domain)
        if expected is None:
            return False
        return hmac.compare_digest(expected, str(token).strip().lower())
    except Exception:  # noqa: BLE001 — verification failure is the demote path, never an error
        return False


def mint_row(row: dict) -> str | None:
    """Hex HMAC-SHA256 token over the row's canonical payload, or
    None when no usable key is available. Writers treat None as
    "persist unstamped" — the fold then applies unstamped-tier
    semantics."""
    return _mint(row, _JOURNAL_DOMAIN)


def verify_row(row: dict, token: str | None) -> bool:
    """Whether *token* is a valid MAC over *row*'s canonical payload
    under this install's key. Constant-time; never raises — any
    failure is the caller's demote path."""
    return _verify(row, token, _JOURNAL_DOMAIN)


def audit_log_run_binding(out_dir: Path | str) -> str:
    """The run identity bound into audit-log tokens: the run dir's
    resolved path. Derived — never stored in the row or read from a
    run-dir artifact (an attacker holding the run-dir write grant
    could plant any STORED identity alongside a copied log; the
    consumer's own directory cannot be forged from inside it). One
    derivation for writers and the reader."""
    try:
        return str(Path(out_dir).resolve())
    except OSError:
        return str(out_dir)


def _audit_domain(run_binding: str) -> bytes:
    return (_AUDIT_LOG_DOMAIN
            + run_binding.encode("utf-8", "surrogatepass") + b"\x00")


def mint_audit_log_row(row: dict, run_binding: str) -> str | None:
    """Token for a ``.audit-log.jsonl`` row (the journal's sibling
    suppression lane): the resume path grants ``action=record`` /
    ``orchestrator_review`` rows review-SUPPRESSION authority, and the
    log lives in the same target-writable run dir whose forged-clean-
    row problem motivated the journal MAC. Same canonical form and
    key, own domain, RUN-BOUND via *run_binding*
    (:func:`audit_log_run_binding` — a row replayed from a sibling
    run's log must not verify). ``None`` = persist unstamped (the row
    keeps its telemetry value; it just never suppresses)."""
    return _mint(row, _audit_domain(run_binding))


def verify_audit_log_row(
    row: dict, token: str | None, run_binding: str,
) -> bool:
    """Audit-log twin of :func:`verify_row`, against the VERIFIER'S
    own run binding. Consumers that grant a row suppression authority
    MUST fail toward NOT suppressing when this returns False
    (unstamped legacy, tampered, and cross-run-replayed rows all
    re-review — the same tolerant-reader compromise as the journal's
    unstamped tier, which grants no verdict authority either)."""
    return _verify(row, token, _audit_domain(run_binding))


def _prep_cache_domain(run_binding: str) -> bytes:
    return (_PREP_CACHE_DOMAIN
            + run_binding.encode("utf-8", "surrogatepass") + b"\x00")


def mint_prep_cache_row(row: dict, run_binding: str) -> str | None:
    """Token for a ``prep-cache/`` artifact row (fingerprint +
    payload): resumed segments serve these payloads back as
    MECHANICAL analysis inputs (detector results, codeql prep,
    consistency prepass), and the cache lives in the target-writable
    run dir while its fingerprint is computed over attacker-knowable
    inputs — so fingerprint equality alone authenticates nothing.
    Same canonical form and key as the journal, own domain, RUN-BOUND
    via :func:`audit_log_run_binding` (a payload replayed from a
    sibling run must not verify). ``None`` = persist unstamped (the
    loader then treats it as a miss and rebuilds — fail toward
    recompute)."""
    return _mint(row, _prep_cache_domain(run_binding))


def verify_prep_cache_row(
    row: dict, token: str | None, run_binding: str,
) -> bool:
    """Prep-cache twin of :func:`verify_audit_log_row`. Loaders MUST
    treat False as a cache miss (rebuild from the tree) — never serve
    an unverified payload."""
    return _verify(row, token, _prep_cache_domain(run_binding))


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
    "audit_log_run_binding",
    "entry_provenance",
    "key_usable",
    "mint_audit_log_row",
    "mint_prep_cache_row",
    "mint_row",
    "row_sha256",
    "verify_audit_log_row",
    "verify_prep_cache_row",
    "verify_row",
]

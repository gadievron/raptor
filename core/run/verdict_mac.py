"""HMAC provenance for the ``manual_override`` operator claim.

``manual_override: true`` on a finding record is an OPERATOR assertion
consumed with pipeline authority: it bypasses the reachability
suppression chokepoint, the guard-dominance and fail-open refutation
gates, the fixture-detection pre-flight, the SAGE prior-verdict skip,
and the /validate proximity clamp. The records live in findings
artifacts inside sandbox-writable run directories, so the flag was
plain unauthenticated JSON — anything that can write the run dir
(hostile build code during a scan, an imported archive) could mint an
"operator" force-through that resurrects findings an operator
suppressed and overrides mechanical refutations run after run.

Writers stamp each override CLAIM at the moment the flag is set
(:func:`core.run.verdicts.set_manual_override`, the only code that
sets one — the ``raptor-review verdict tp`` surface behind it).
Read-modify-write passes (the /validate ``Finding`` model round-trip)
copy the token verbatim via a declared field, so a planted flag stays
unstamped no matter how many legitimate saves follow — the
per-claim-not-per-record laundering argument from
``core.inventory.checklist_mac``. Consumers that convert the claim
into bypass authority verify first
(:func:`verified_manual_override`); an unverified flag demotes to
ABSENT — the suppression or refutation proceeds exactly as if the
flag were never written — with a loud log line naming the re-apply
command. Strict demotion is deliberate: the flag's only effect is to
disable mechanical gates, so refusing a forged one is fail-safe,
while a legacy pre-MAC flag costs the operator one
``raptor-review verdict <id> tp`` re-apply.

The claim payload binds the finding's identity (id, file, function,
vuln_type — the stable coordinates a verdict edit resolves on), the
asserted value, and the operator's rationale
(``manual_override_reason``), so a genuine token spliced onto a
different finding, or a forged rationale riding a genuine token,
fails. Deliberately NOT run-bound: the schema contract promises the
edit survives across re-runs and project merge views — a replayed
stamped claim on the same finding identity is genuine operator
history. Line numbers are deliberately excluded: they shift under
re-scans of edited source while the operator's decision stands.

LLM-tier consumption (the Stage D ruling instructions that preserve
pre-existing rulings when the flag is set) stays hint-tier by the
annotations doctrine and is additionally fenced by the
ruling-confirmation receipts in ``core.witness.provenance``.

Key
    ``$XDG_DATA_HOME/raptor/verdict-mac.key`` (default
    ``~/.local/share/raptor/verdict-mac.key``). Deliberately its OWN
    key file — per-purpose keys keep reset/rotation semantics scoped
    (``core.security.mac_key`` doctrine: never unify key files). No
    rotation: deleting the key demotes every stamped claim to absent
    and new mints re-key lazily; no other subsystem's trust surface
    is touched.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
from typing import Any, Mapping

from core.json.utils import dumps_canonical
from core.logging import get_logger
from core.security import mac_key
from core.security.log_sanitisation import sanitise_for_terminal

logger = get_logger(__name__)

# HMAC-SHA256 key length — the shared value every mac_key consumer
# uses (journal, witness, checklist, scorecard); see the length
# doctrine in core/inventory/checklist_mac.py.
_KEY_LEN = 32

_warned_paths: set[str] = set()
_warned_findings: set[str] = set()

#: Finding key holding the claim token (64-hex HMAC). Sits BESIDE
#: ``manual_override`` on the finding dict; the /validate ``Finding``
#: model declares it so normalisation round-trips it.
TOKEN_KEY = "manual_override_mac"

# Domain separation: a token minted for any other artifact class can
# never verify here even if a key were ever shared by mistake.
_OVERRIDE_CLAIM_DOMAIN = b"manual-override-claim\x00"


def _key_path() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "raptor" / "verdict-mac.key"


def _warn_once_suspect_key(path: Path, reason: str, remedy: str) -> None:
    key = str(path)
    if key in _warned_paths:
        logger.debug(f"verdict integrity: suspect key {path} ({reason})")
        return
    _warned_paths.add(key)
    logger.warning(
        f"verdict integrity: refusing key {path} — {reason}. "
        f"manual_override claims will not mint or verify (stamped "
        f"overrides demote to absent: mechanical suppression and "
        f"refutation gates apply as if the flag were never set) "
        f"until this is fixed: {remedy}"
    )


def _read_existing_key(path: Path) -> bytes | mac_key.Refused | None:
    """Read an EXISTING key with the shared fd-fstat discipline
    (:func:`core.security.mac_key.read_existing_key`)."""
    return mac_key.read_existing_key(
        path, key_len=_KEY_LEN, warn=_warn_once_suspect_key)


def _load_or_create_key() -> bytes | None:
    """Read the key, lazily creating it (0700 dir, 0600 file, O_EXCL)
    if absent. Returns None when a key file exists but is unusable —
    the suspect key is never used, never replaced."""
    return mac_key.load_or_create_key(
        _key_path(), key_len=_KEY_LEN, warn=_warn_once_suspect_key,
        read_existing=_read_existing_key)


def key_usable() -> bool:
    """Whether this install can mint/verify override tokens at all."""
    try:
        return bool(_load_or_create_key())
    except OSError:
        return False


def override_claim(finding: Mapping[str, Any]) -> dict[str, Any]:
    """The canonical claim payload for one finding's override flag.

    ONE derivation shared by mint and verify so the two can never
    fork. Coordinates use the pipeline's binding order
    (:func:`core.run.verdicts.finding_coords` /
    ``core.project.findings_utils.get_finding_id`` — the same
    resolution a verdict edit matched the record on). The line is
    deliberately NOT bound (see module docstring).
    """
    from core.project.findings_utils import get_finding_id
    from core.run.verdicts import finding_coords

    f = dict(finding)
    rel, fn, _line = finding_coords(f)
    return {
        "id": get_finding_id(f) or "",
        "file": rel,
        "function": fn,
        "vuln_type": str(f.get("vuln_type") or ""),
        "value": True,
        "reason": str(f.get("manual_override_reason") or ""),
    }


def _claim_sha256(claim: dict[str, Any]) -> str:
    return hashlib.sha256(
        dumps_canonical(claim).encode("utf-8")).hexdigest()


def _mac_message(sha256_hex: str) -> bytes:
    return _OVERRIDE_CLAIM_DOMAIN + sha256_hex.encode("ascii")


def mint_override_token(finding: Mapping[str, Any]) -> str | None:
    """Hex HMAC-SHA256 token over the finding's override claim, or
    None when no usable key is available. Writers treat None as
    "persist unstamped" — consumers then demote the flag to absent."""
    try:
        key = _load_or_create_key()
    except OSError:
        return None
    if not key:
        return None
    return hmac.new(
        key,
        _mac_message(_claim_sha256(override_claim(finding))),
        hashlib.sha256,
    ).hexdigest()


def stamp_manual_override(finding: dict[str, Any]) -> bool:
    """Stamp ``finding``'s override claim in place (sets
    :data:`TOKEN_KEY`). Returns False — and leaves any existing token
    untouched — when no usable key is available; the caller decides
    how loudly to surface the unstamped persist."""
    token = mint_override_token(finding)
    if token is None:
        return False
    finding[TOKEN_KEY] = token
    return True


def verify_manual_override(finding: Mapping[str, Any]) -> bool:
    """Whether the finding's :data:`TOKEN_KEY` token is a valid MAC
    over its current override claim under this install's key.
    Constant-time; never raises — any failure is the demote path."""
    token = finding.get(TOKEN_KEY)
    if not token or not isinstance(token, str):
        return False
    try:
        expected = mint_override_token(finding)
        if expected is None:
            return False
        return hmac.compare_digest(expected, token.strip().lower())
    except Exception:  # noqa: BLE001 — verification failure is the demote path, never an error
        return False


def verified_manual_override(finding: Mapping[str, Any]) -> bool:
    """The consumer chokepoint: True only for a truthy
    ``manual_override`` whose claim token verifies.

    A truthy flag that does NOT verify (planted, spliced, tampered
    rationale, legacy pre-MAC, or a hand-edit outside the verdict
    CLI) demotes to absent with one warning per finding id per
    process — the gates it would have bypassed apply normally.
    Falsy / absent flags return False silently (string-False
    coercion via ``core.analysis.reach_chokepoint.
    coerce_manual_override`` so ``"false"`` never reads truthy).
    """
    if not isinstance(finding, Mapping):
        return False
    from core.analysis.reach_chokepoint import coerce_manual_override

    if not coerce_manual_override(finding.get("manual_override")):
        return False
    if verify_manual_override(finding):
        return True
    from core.project.findings_utils import get_finding_id

    fid = sanitise_for_terminal(
        str(get_finding_id(dict(finding)) or "?"), max_len=120)
    if fid not in _warned_findings:
        _warned_findings.add(fid)
        logger.warning(
            f"verdict integrity: manual_override on finding {fid} is "
            f"not verified (no valid claim token — planted, edited "
            f"outside the verdict CLI, or pre-MAC legacy). The flag "
            f"is IGNORED: suppression and refutation gates apply. "
            f"Re-apply it with: raptor-review verdict {fid} tp"
        )
    return False


__all__ = [
    "TOKEN_KEY",
    "key_usable",
    "mint_override_token",
    "override_claim",
    "stamp_manual_override",
    "verified_manual_override",
    "verify_manual_override",
]

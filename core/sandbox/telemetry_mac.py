"""HMAC provenance for sandbox telemetry consumed by triage.

The triage classifier's inputs live inside the run output directory —
a tree the sandboxed TARGET holds Landlock write access to while it
runs. ``proxy-events.jsonl`` is appended by the parent between spawns,
so a hostile target can append forged lines, truncate it, or pre-plant
a whole file (including a ``sandbox-summary.json`` for runs where the
real summariser never writes one because there were no denials). The
denials stream itself is already covered by the evidence-fd machinery
(core/sandbox/evidence.py); this module covers the artifacts that are
not.

Writers stamp each artifact with an HMAC-SHA256 token over the exact
fields triage acts on; triage verifies and demotes records that fail.
Same trust story as core/sage/rowmac.py, whose key-handling discipline
this module copies: the key lives OUTSIDE every sandbox-readable tree
(a target that could read it could mint valid tokens for forged
telemetry), symlinked / foreign-owned / group-readable key files are
refused rather than replaced, and verification failure is a demote
path, never an error.

Key
    ``$XDG_DATA_HOME/raptor/telemetry-mac.key`` (default
    ``~/.local/share/raptor/telemetry-mac.key``). Deliberately a
    SEPARATE key from rowmac's: per-purpose keys keep reset/rotation
    semantics scoped — deleting the SAGE key is SAGE's documented
    reset and must not also invalidate sandbox telemetry provenance,
    and vice versa. No rotation: deleting the key makes existing
    tokens fail verification (legacy-demote), and new runs re-key
    lazily.

Every ``fields`` mapping MUST carry a ``kind`` entry naming the
artifact class (``proxy-event``, ``sandbox-summary``) — domain
separation so a token minted for one artifact class can never verify
as another.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
import time
from collections.abc import Mapping
from pathlib import Path

from core.logging import get_logger

logger = get_logger(__name__)

_KEY_LEN = 32

# Sentinel: a key file EXISTS but is unusable (symlink, foreign owner,
# group/other-readable). Distinct from "absent" — an unusable key must
# never be silently replaced and must never mint or verify.
_REFUSED = object()

_warned_paths: set = set()


def _key_path() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "raptor" / "telemetry-mac.key"


def _warn_once_suspect_key(path: Path, reason: str, remedy: str) -> None:
    key = str(path)
    if key in _warned_paths:
        logger.debug("telemetry_mac: suspect key %s (%s)", path, reason)
        return
    _warned_paths.add(key)
    logger.warning(
        "telemetry_mac: refusing key %s — %s. Telemetry provenance "
        "tokens will not mint or verify (triage demotes to legacy/"
        "unverified handling) until this is fixed: %s",
        path, reason, remedy,
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
    data = data or b""

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
            data = raced if raced is not None else b""
            time.sleep(0.01)
        return data
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return key


def _canonical(fields: Mapping[str, object]) -> bytes:
    """Injective canonical encoding — key-sorted, length-prefixed —
    identical construction to rowmac's."""
    items = sorted((str(k), str(v)) for k, v in fields.items())
    out = bytearray()
    out += len(items).to_bytes(4, "big")
    for key, value in items:
        for part in (key.encode("utf-8"), value.encode("utf-8")):
            out += len(part).to_bytes(4, "big")
            out += part
    return bytes(out)


def key_usable() -> bool:
    """Whether this install can mint/verify tokens at all.

    Triage uses it to attribute unverifiable telemetry correctly:
    unstamped artefacts under a USABLE key mean the writer chose not
    to stamp — target-rewrite territory, fail toward tampering. An
    UNUSABLE key (symlinked, foreign-owned, wrong length, unwritable
    data dir) is an operator-side condition that makes verification
    impossible for every artefact, honest or not — misreading that
    as a target attack turns a host misconfiguration into permanent
    suspicious verdicts."""
    try:
        return bool(_load_or_create_key())
    except OSError:
        return False


def mint(fields: Mapping[str, object]) -> str | None:
    """Hex HMAC-SHA256 token over the decision *fields*, or None when
    no usable key is available (unusable key file, unwritable data
    dir). Writers treat None as "persist unstamped" — the legacy
    shape triage already handles."""
    if "kind" not in fields:
        raise ValueError("telemetry_mac.mint: fields must carry 'kind'")
    try:
        key = _load_or_create_key()
    except OSError:
        return None
    if not key:
        return None
    return hmac.new(key, _canonical(fields), hashlib.sha256).hexdigest()


def verify(fields: Mapping[str, object], token: str | None) -> bool:
    """Whether *token* is a valid MAC over *fields* under this
    install's key. Constant-time; never raises — any failure is the
    caller's demote path."""
    if not token:
        return False
    try:
        expected = mint(fields)
        if expected is None:
            return False
        return hmac.compare_digest(expected, str(token).strip().lower())
    except Exception:  # noqa: BLE001 — verification failure is the demote path, never an error
        return False


def run_binding(run_dir: "Path | str") -> str:
    """Canonical per-run binding baked into every MAC field set.

    Without it, any token this install ever minted verifies in ANY
    run directory forever — a target that can read old run dirs can
    replay a validly-stamped artefact (a clean summary, an
    audit-degraded marker) into its own run and have it verify. The
    binding is the run directory's resolved basename: the VERIFIER
    recomputes it from the directory it is actually reading, so a
    replayed artefact carries the wrong run's binding and fails.
    Basename (not full path) so archived/moved runs keep verifying.
    Residual: run dirs are operator-created before the target runs,
    so the target cannot choose a colliding name; an attacker with
    write access ABOVE the run dir is outside the sandbox grant.
    """
    return Path(run_dir).resolve().name


def proxy_event_fields(event: Mapping[str, object], run: str) -> dict:
    """The exact proxy-event fields triage acts on, in MAC form.

    Kept in one place so the writer (context._persist_proxy_events)
    and the verifier (triage) can never drift: host + result feed
    host_recon_pattern, resolved_ip feeds resolved_ip_screened."""
    return {
        "kind": "proxy-event",
        "run": run,
        # Position in the run's event stream: per-line MACs alone
        # let a target delete incriminating STAMPED lines and leave
        # a fully-verifying file; the verifier checks the surviving
        # sequence for gaps and duplicates.
        "seq": str(event.get("seq", "")),
        "host": event.get("host") or "",
        "result": event.get("result") or "",
        "resolved_ip": event.get("resolved_ip") or "",
    }


def audit_degraded_fields(payload: Mapping[str, object], run: str) -> dict:
    """MAC fields for sandbox-audit-degraded.json. Triage's only use
    of the marker is the reason-bearing low-confidence caveat — but a
    target-planted marker would let a hostile run cast doubt on its
    own suspicious verdict, so the marker's provenance matters."""
    return {
        "kind": "audit-degraded",
        "run": run,
        "reason": payload.get("reason") or "",
        "instructions": payload.get("instructions") or "",
    }


def triage_report_fields(report_sha256: str, run: str) -> dict:
    """MAC fields for sandbox-triage.json itself. The lifecycle
    regenerates the report at run end, but downstream consumers (the
    deep-analysis pass, /review, project views) may read it later —
    and on a run with NO telemetry the lifecycle writes nothing, so a
    target-planted report would otherwise survive to be read.

    ``report_sha256`` covers the WHOLE canonical report (minus the
    token itself): consumers forward more than the verdict — the deep
    pass sends inputs and caveats to the model — so authenticating a
    subset would let a target rewrite the unauthenticated remainder
    of a validly-stamped report ("all these signals are known tool
    noise...") while verification still says verified."""
    return {
        "kind": "sandbox-triage",
        "run": run,
        "report_sha256": report_sha256,
    }


def summary_fields(total_denials: int, denials_sha256: str, run: str) -> dict:
    """MAC fields for sandbox-summary.json: the denial payload is
    covered by its content hash, so a planted or edited summary fails
    verification even when the headline counters are preserved."""
    return {
        "kind": "sandbox-summary",
        "run": run,
        "total_denials": total_denials,
        "denials_sha256": denials_sha256,
    }

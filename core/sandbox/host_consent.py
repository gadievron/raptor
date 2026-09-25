"""WSL host-scoped consent marker for the ns-only untrusted floor.

Stock WSL2 kernels ship without Landlock, so untrusted-execution runs
whose containment floor requires the Landlock layer refuse (fail
closed). The per-run ``--sandbox-floor ns-only`` flag and the project
``sandbox-floor`` setting already consent the ns-only tier run-by-run
or project-by-project; this module adds the HOST-scoped standing
surface for that one situation: an operator-granted marker recording
"on THIS machine, WHERE Landlock is unavailable on THIS WSL kernel
family, untrusted work may run at the ns-only tier instead of
refusing".

The marker is CONDITIONAL, never a blanket downgrade — at read time it
applies only while ALL of these hold, and is inert otherwise:

* the running kernel identifies as WSL (:func:`core.startup.wsl.is_wsl`)
  — on a non-WSL host the marker is silently inert;
* Landlock is unavailable on the running kernel — the moment a kernel
  with Landlock boots, the marker is silently inert and the floor
  rises automatically (nothing to revoke, nothing to migrate);
* the running kernel's identity FAMILY matches the family the consent
  was granted against (see :func:`kernel_family` for the conservative
  match definition);
* the marker file itself validates: schema, floor value (exactly
  ``ns-only`` — the single consentable value for this surface),
  machine binding (``/etc/machine-id`` recorded at grant time must
  match — a marker copied from another host is inert), a non-future
  grant timestamp, and a hardened read (regular file, owned by this
  user, not group/other-writable). Any validation failure is INERT
  plus one warning per process — fail-closed to the normal refusal,
  never a guessed grant.

Storage is machine-scoped under ``$XDG_DATA_HOME/raptor/`` (default
``~/.local/share/raptor/``) — the same per-user data directory as the
per-purpose MAC keys, deliberately OUTSIDE every sandbox-readable
tree: several sandbox profiles grant children repo-root read, and a
consent marker a sandboxed target could rewrite would let the target
lower its own containment. Writes are atomic (tempfile + rename in
the destination directory), file mode 0600, directory 0700.

Precedence: this is the LOWEST-precedence consent surface — per-run
``--sandbox-floor`` > project ``sandbox-floor`` > the legacy
``RAPTOR_ALLOW_DEGRADED_UNTRUSTED`` env var > this marker > the
fail-closed class default. The marker only ever replaces the default
REFUSAL with ns-only; it never modifies a floor any other surface
chose (so a project-set higher floor is never lowered by it, and the
env waiver's frozen landlock mapping is untouched where set). See
``context.resolve_untrusted_floor``.

Granting happens exclusively through the TTY-gated ceremony
(``libexec/raptor-wsl-consent grant`` / ``bin/raptor wsl-consent
grant``) — :func:`write_marker` performs the grant-time detection
checks but the interactive confirmation lives in the CLI, which
hard-refuses a non-TTY stdin so an agent or injected instruction can
never self-grant. Revocation (:func:`remove_marker`) is deliberately
NOT TTY-gated: removing consent only raises the floor (fail-safe
direction), so scripts and unattended sessions may always revoke.
"""

from __future__ import annotations

import dataclasses
import errno
import json
import logging
import os
import re
import stat
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

__all__ = [
    "HostConsent",
    "HostConsentError",
    "applied_consent",
    "grant_preflight",
    "host_consented_floor",
    "kernel_family",
    "marker_path",
    "marker_status",
    "remove_marker",
    "write_marker",
]

#: The one floor label this surface can consent. Deliberately not a
#: parameter anywhere in this module: the marker exists for exactly
#: the Landlock-less-WSL-kernel situation, whose deliverable tier is
#: ns-only; a generalized host-floor store would be a much broader
#: consent surface than the ceremony's wording grants.
CONSENTED_FLOOR_LABEL = "ns-only"

_SCHEMA_VERSION = 1
_MARKER_NAME = "wsl-host-consent.json"
_MAX_MARKER_BYTES = 64 * 1024
#: Grant timestamps this far in the future are tamper evidence, not
#: clock skew.
_FUTURE_SKEW = timedelta(minutes=5)

#: Kernel identity source for the family match. ``osrelease`` is the
#: bare ``uname -r`` string (stable single-token format); the
#: ``/proc/version`` fallback :mod:`core.startup.wsl` uses for the
#: boolean WSL question is deliberately NOT used here — its free-form
#: build banner would make the family derivation format-dependent.
_OSRELEASE_PATH = "/proc/sys/kernel/osrelease"
#: Host binding read at grant time and re-checked at read time; a
#: marker copied to another machine fails the comparison and stays
#: inert.
_MACHINE_ID_PATH = "/etc/machine-id"

_NUMERIC_TOKEN_RE = re.compile(r"[0-9.]+")

# One warning per distinct inertness reason per process — a corrupt
# or mismatched marker is host state, not per-call news.
_warned_reasons: set[str] = set()
_warned_lock = threading.Lock()


class HostConsentError(RuntimeError):
    """A grant-time precondition failed (not WSL, Landlock present,
    kernel identity or machine id unreadable). Message is the
    operator-facing explanation."""


@dataclasses.dataclass(frozen=True)
class HostConsent:
    """An APPLIED host consent (every inertness condition passed)."""

    floor: str
    granted_at: str
    kernel_identity: str


def marker_path() -> Path:
    """Location of the host-consent marker.

    ``$XDG_DATA_HOME/raptor/wsl-host-consent.json`` (default
    ``~/.local/share/raptor/wsl-host-consent.json``) — machine-scoped,
    outside every sandbox-readable tree (same placement rationale as
    the per-purpose MAC keys in ``core/sage/rowmac.py``).
    """
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "raptor" / _MARKER_NAME


def kernel_family(identity: str) -> str:
    """Conservative kernel-identity FAMILY for the consent match.

    The trade-off, stated: matching the exact release string is too
    brittle — routine WSL kernel updates change only the version
    numbers (``5.15.167.4-microsoft-standard-WSL2`` →
    ``6.6.36.6-microsoft-standard-WSL2``) and would silently expire
    the consent on every minor update; matching the bare ``microsoft``
    token is too broad — it would carry the consent across a change of
    kernel FLAVOUR (a different build lineage than the one inspected
    at grant time). The middle: drop the purely numeric ``-``-tokens
    and keep the rest, lowercased — the release string's non-version
    identity (``microsoft-standard-wsl2``). Version bumps within the
    flavour keep the consent; a flavour change makes it inert until
    re-granted. The exact string is still recorded in the marker for
    audit.
    """
    text = identity.strip()
    first = text.splitlines()[0].strip() if text else ""
    tokens = [
        t for t in first.lower().split("-")
        if t and not _NUMERIC_TOKEN_RE.fullmatch(t)
    ]
    return "-".join(tokens)


def _warn_once(reason: str, message: str, *args: object) -> None:
    with _warned_lock:
        if reason in _warned_reasons:
            logger.debug("wsl-host-consent: " + message, *args)
            return
        _warned_reasons.add(reason)
    logger.warning("wsl-host-consent: " + message, *args)


def _reset_warning_latches() -> None:
    """Test support: re-arm the one-warning-per-reason latches."""
    with _warned_lock:
        _warned_reasons.clear()


def _read_first_line(path: str) -> str:
    """First line of *path*, stripped; ``""`` on any failure."""
    try:
        text = Path(path).read_text(encoding="ascii", errors="replace")
    except OSError:
        return ""
    return text.splitlines()[0].strip() if text.strip() else ""


def _is_wsl() -> bool:
    # Call-time import so tests (and the W1 consumers' documented
    # mocking contract) patch core.startup.wsl.is_wsl, the module
    # attribute, and every reader sees it.
    from core.startup.wsl import is_wsl
    return is_wsl()


def _landlock_available() -> bool:
    from .landlock import check_landlock_available
    return check_landlock_available()


def _read_marker_record(path: Path) -> "tuple[dict | None, str | None]":
    """Hardened read of the marker file.

    Returns ``(record, None)`` or ``(None, reason)``. ``reason`` is a
    stable key: ``"absent"`` (silent-inert) or one of the tamper /
    corruption reasons (warn-once inert). The read refuses symlinks,
    non-regular files, foreign owners and group/other-writable modes —
    a consent record another principal can rewrite is no record.
    """
    try:
        # O_NONBLOCK is the core/source/contained.py FIFO discipline:
        # a plain open of a writer-less FIFO planted at the marker
        # path blocks forever — hanging every floor resolution and
        # the startup banner. With the flag the open returns
        # instantly and the S_ISREG check below classifies the FIFO
        # not-regular-file (inert + warn); regular-file reads ignore
        # O_NONBLOCK, so real markers are unaffected.
        fd = os.open(
            str(path),
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return None, "absent"
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            return None, "symlink"
        return None, "unreadable"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, "not-regular-file"
        if st.st_uid != os.geteuid():
            return None, "foreign-owner"
        if st.st_mode & 0o022:
            return None, "permissive-mode"
        if st.st_size > _MAX_MARKER_BYTES:
            return None, "too-large"
        raw = os.read(fd, _MAX_MARKER_BYTES + 1)
    except OSError:
        return None, "unreadable"
    finally:
        os.close(fd)
    try:
        record = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None, "invalid-json"
    if not isinstance(record, dict):
        return None, "wrong-schema"
    return record, None


def _validate_record(record: dict) -> "tuple[HostConsent | None, str | None]":
    """Schema + tamper validation of a parsed marker record.

    Kernel/host CONDITIONS are checked by the caller; this checks only
    what the record itself must satisfy. Extra keys are tolerated
    (forward compatibility); wrong types and wrong values are not.
    """
    if record.get("schema") != _SCHEMA_VERSION:
        return None, "wrong-schema"
    floor = record.get("floor")
    if floor != CONSENTED_FLOOR_LABEL:
        # Exactly one consentable value — anything else in this slot
        # is a hand-edited or forged record, not a wider grant.
        return None, "wrong-floor"
    granted_at = record.get("granted_at")
    kernel_identity = record.get("kernel_identity")
    machine_id = record.get("machine_id")
    if not (isinstance(granted_at, str)
            and isinstance(kernel_identity, str) and kernel_identity
            and isinstance(machine_id, str) and machine_id):
        return None, "missing-field"
    try:
        granted = datetime.fromisoformat(granted_at)
    except ValueError:
        return None, "bad-granted-at"
    if granted.tzinfo is None:
        return None, "bad-granted-at"
    if granted > datetime.now(timezone.utc) + _FUTURE_SKEW:
        return None, "future-granted-at"
    running_machine_id = _read_first_line(_MACHINE_ID_PATH)
    if not running_machine_id or machine_id != running_machine_id:
        # Copied from another host (or the host identity is
        # unverifiable) — the consent was granted for a different
        # machine's kernel situation. Fail closed.
        return None, "machine-id-mismatch"
    return HostConsent(
        floor=floor,
        granted_at=granted_at,
        kernel_identity=kernel_identity,
    ), None


def _evaluate() -> "tuple[HostConsent | None, str]":
    """Full conditional-inertness evaluation.

    Returns ``(consent, "active")`` when the marker applies, else
    ``(None, reason)``. Ordering keeps non-WSL hosts nearly free: the
    cached :func:`~core.startup.wsl.is_wsl` short-circuits before any
    file access, and the marker file is only read (and the Landlock
    probe only consulted) on WSL.
    """
    if sys.platform != "linux" or not _is_wsl():
        return None, "not-wsl"
    record, reason = _read_marker_record(marker_path())
    if record is None:
        if reason != "absent":
            _warn_once(
                reason or "unreadable",
                "consent marker %s is unusable (%s) — treating it as "
                "ABSENT (untrusted floor keeps the fail-closed "
                "default). Re-grant with `bin/raptor wsl-consent "
                "grant` after fixing or removing the file.",
                marker_path(), reason,
            )
        return None, reason or "unreadable"
    if _landlock_available():
        # The consent's premise is gone: with Landlock present the
        # floor needs no lowering, so the marker is silently inert
        # and the full contract applies. Nothing to warn about —
        # this is the automatic-rise direction.
        return None, "landlock-available"
    consent, reason = _validate_record(record)
    if consent is None:
        _warn_once(
            reason or "invalid",
            "consent marker %s failed validation (%s) — treating it "
            "as ABSENT (untrusted floor keeps the fail-closed "
            "default). Re-grant with `bin/raptor wsl-consent grant` "
            "after fixing or removing the file.",
            marker_path(), reason,
        )
        return None, reason or "invalid"
    running_identity = _read_first_line(_OSRELEASE_PATH)
    running_family = kernel_family(running_identity)
    granted_family = kernel_family(consent.kernel_identity)
    if not running_family or running_family != granted_family:
        _warn_once(
            "kernel-family-mismatch",
            "consent marker %s was granted against kernel family %r "
            "but this kernel is %r — the consent is inert on this "
            "kernel (untrusted floor keeps the fail-closed default). "
            "Re-grant with `bin/raptor wsl-consent grant` if the "
            "ns-only consent should cover the new kernel.",
            marker_path(), granted_family or "<none>",
            running_family or "<none>",
        )
        return None, "kernel-family-mismatch"
    return consent, "active"


def applied_consent() -> "HostConsent | None":
    """The applied host consent, or ``None`` when the marker is absent
    or inert (any inertness rule). Never raises."""
    try:
        consent, _reason = _evaluate()
    except Exception:  # noqa: BLE001 — a consent probe must never break floor resolution
        logger.debug("wsl-host-consent evaluation failed", exc_info=True)
        return None
    return consent


def host_consented_floor() -> "str | None":
    """Floor label the host consent supplies (``"ns-only"``), or
    ``None`` when it does not apply. Never raises."""
    consent = applied_consent()
    return consent.floor if consent is not None else None


def marker_status() -> dict:
    """Read-only status for the CLI: marker path, presence, whether
    the consent currently applies, the inertness reason when it does
    not, and the raw record when one is readable. Never raises."""
    path = marker_path()
    status: dict = {"path": str(path), "present": False,
                    "applies": False, "reason": "absent", "record": None}
    try:
        record, read_reason = _read_marker_record(path)
        status["present"] = read_reason != "absent"
        status["record"] = record
        consent, reason = _evaluate()
        status["applies"] = consent is not None
        status["reason"] = reason
    except Exception:  # noqa: BLE001 — status is diagnostic, never a failure source
        logger.debug("wsl-host-consent status failed", exc_info=True)
        status["reason"] = "error"
    return status


def grant_preflight() -> dict:
    """Grant-time detection evidence, or :class:`HostConsentError`.

    Refuses when the consent's premise does not hold RIGHT NOW: not a
    WSL kernel, Landlock actually available (the marker would be
    born inert — and granting a standing floor reduction with no
    present need is exactly the scope creep the conditional design
    refuses), or the kernel identity / machine id needed for the
    conditional match is unreadable (an unverifiable grant could
    never be honoured at read time).
    """
    if sys.platform != "linux" or not _is_wsl():
        raise HostConsentError(
            "this kernel does not identify as WSL — the WSL host "
            "consent applies only on WSL hosts, so there is nothing "
            "to grant here. Use --sandbox-floor / the project "
            "sandbox-floor setting for per-run or per-project "
            "consent on other hosts."
        )
    if _landlock_available():
        raise HostConsentError(
            "Landlock is available on this kernel, so the untrusted "
            "floor needs no lowering and the marker would be inert "
            "from birth. Nothing to grant — the full mount-ns "
            "contract already applies."
        )
    kernel_identity = _read_first_line(_OSRELEASE_PATH)
    family = kernel_family(kernel_identity)
    if not kernel_identity or not family:
        raise HostConsentError(
            f"could not read a kernel identity from {_OSRELEASE_PATH} "
            f"— the conditional consent records the kernel family it "
            f"is granted against, so an unreadable identity cannot "
            f"be granted."
        )
    machine_id = _read_first_line(_MACHINE_ID_PATH)
    if not machine_id:
        raise HostConsentError(
            f"could not read {_MACHINE_ID_PATH} — the consent is "
            f"bound to this machine's identity so a copied marker "
            f"stays inert elsewhere; without the id the binding "
            f"cannot be recorded."
        )
    return {
        "kernel_identity": kernel_identity,
        "kernel_family": family,
        "machine_id": machine_id,
        "landlock_available": False,
        "is_wsl": True,
    }


def write_marker() -> Path:
    """Record the host consent (grant-time half of the ceremony).

    Re-runs :func:`grant_preflight` (the CLI displayed evidence from
    its own preflight call; re-deriving here keeps the recorded facts
    the write-time truth), then writes atomically: 0700 directory,
    0600 file, tempfile + rename in the destination directory so a
    reader never observes a partial record. The interactive TTY gate
    lives in the CLI, not here — this function is the mechanical
    write, and tests exercise it directly.
    """
    evidence = grant_preflight()
    path = marker_path()
    record = {
        "schema": _SCHEMA_VERSION,
        "floor": CONSENTED_FLOOR_LABEL,
        "granted_at": datetime.now(timezone.utc).isoformat(
            timespec="seconds"),
        "kernel_identity": evidence["kernel_identity"],
        "kernel_family": evidence["kernel_family"],
        "machine_id": evidence["machine_id"],
        "evidence": {
            "kernel_identity_source": _OSRELEASE_PATH,
            "landlock_available": evidence["landlock_available"],
            "is_wsl": evidence["is_wsl"],
        },
    }
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = json.dumps(record, indent=2, sort_keys=True) + "\n"
    fd, tmp_name = tempfile.mkstemp(
        prefix=_MARKER_NAME + ".", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, payload.encode("utf-8"))
        os.fsync(fd)
        os.close(fd)
        os.replace(tmp_name, str(path))
    except OSError:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return path


def remove_marker() -> bool:
    """Revoke: remove the marker. True when a marker was removed,
    False when none existed. Deliberately not TTY-gated (revocation
    only raises the floor — fail-safe); the CLI documents the
    asymmetry with the TTY-gated grant."""
    try:
        os.unlink(str(marker_path()))
    except FileNotFoundError:
        return False
    return True

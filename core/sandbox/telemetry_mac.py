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
Key-handling discipline follows core/sage/rowmac.py's fd-fstat reads,
with one deliberate divergence: an on-disk key whose STATE no honest
writer produces (group/other permission bits, a planted symlink, a
non-regular file, over-length content) is treated as TAMPER — the
object is quarantined beside the key (evidence preserved), a tamper
marker is appended (see ``tamper_marker_path``), and a fresh key is
created. Refusing forever instead — the rowmac behaviour — turned a
same-uid ``chmod g+r`` (cheap from any lane whose DAC reaches the
key; Landlock has no metadata rights) into a persistent integrity
DoS: ``key_usable()`` stayed False and triage accepted telemetry at
legacy confidence for every future run. Post-quarantine, tokens
minted under the old key FAIL verification, so triage fails toward
tampering — the honest verdict. Foreign-owned or unreadable keys stay
refused (unattributable; never recovered over another principal's
object), and verification failure remains a demote path, never an
error.

POSTURE DEPENDENCY — what a verifying token actually proves. The key
lives outside the run output directory (the tree the target holds
WRITE access to), but it is NOT outside every sandbox-readable tree:
only a mount namespace (pivoted rootfs) or a read allowlist
(``restrict_reads``) hides it from the child. On read-unrestricted
postures — the Landlock-only default of the ``full`` / ``target_run``
profiles, and macOS runs without ``restrict_reads`` — a hostile
target can read the key and mint valid tokens for forged telemetry.
The spawn layer records each run's posture via
``core.sandbox.summary.record_run_posture``; triage demotes
token-verified telemetry to legacy confidence when the posture could
not have hidden the key. A verifying token therefore means "written
by a key-holder" — only under a key-hiding posture does that narrow
to "written by the parent".

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

import errno
import hashlib
import hmac
import json
import os
import secrets
import stat
import time
from pathlib import Path

from core.logging import get_logger
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

logger = get_logger(__name__)

_KEY_LEN = 32

# Sentinel: a key file EXISTS but is unusable in a way this module
# cannot attribute or safely recover from (foreign owner, unreadable).
# Distinct from "absent" — a refused key is never used and never
# replaced.
_REFUSED = object()


class _TamperedKey:
    """A key whose ON-DISK STATE can only be the product of tampering
    (or debris no honest writer produces): permission bits granted to
    group/other on an own-uid regular file (the creator opens with
    0600 atomically — umask can only narrow that), a symlink at the
    key path, a non-regular file, or over-length content (a partial
    32-byte creation write can be SHORT, never long).

    Deliberately NOT ``_REFUSED``: refusing forever turns a same-uid
    ``chmod g+r`` — cheap from any lane whose DAC reaches the key,
    since Landlock has no metadata rights — into a persistent
    integrity DoS where ``key_usable()`` stays False and triage
    accepts telemetry at legacy confidence for every FUTURE run until
    an operator notices. Tamper is instead handled by quarantining the
    object (evidence preserved), recording a tamper marker, and
    re-keying — old tokens then FAIL verification, so triage fails
    toward tampering rather than toward acceptance.

    Stable SHORT content stays on the refusal path: it is the one
    shape that overlaps an honest creation race (winner crashed or
    stalled between its O_EXCL create and its write), and quarantining
    a slow winner's file mid-write would split-brain the key.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason


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
    """Read an EXISTING key with rowmac's fd-fstat discipline.

    Returns the raw bytes, ``None`` (absent), ``_REFUSED``
    (foreign-owned / unreadable — unattributable, never recovered),
    or a ``_TamperedKey`` (symlink, non-regular file, group/other
    permission bits on an own-uid file — states no honest writer
    produces; the caller quarantines and re-keys)."""
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if getattr(exc, "errno", None) == errno.ELOOP:
            try:
                if stat.S_ISLNK(os.lstat(str(path)).st_mode):
                    return _TamperedKey("symlink planted at the key path")
            except OSError:
                pass
        _warn_once_suspect_key(
            path, f"open refused ({exc})",
            "investigate how the object at the key path got there; a "
            "fresh key is created on the next stamp once it is removed",
        )
        return _REFUSED
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return _TamperedKey("not a regular file")
        if st.st_uid != os.geteuid():
            _warn_once_suspect_key(
                path,
                f"owned by uid={st.st_uid}, expected uid={os.geteuid()}",
                "investigate the foreign-owned key; restore your own "
                "0600 key file",
            )
            return _REFUSED
        if st.st_mode & 0o077:
            return _TamperedKey(
                f"mode {stat.S_IMODE(st.st_mode):04o} grants "
                "group/other access (the creator writes 0600; nothing "
                "honest widens it)",
            )
        # A single os.read may return fewer bytes than requested
        # (network filesystems); a short read would land a healthy key
        # in the wrong-length refusal, so loop to EOF. The cap stays at
        # _KEY_LEN * 4 — genuinely oversized files still fail-close in
        # the caller's length check.
        chunks: list[bytes] = []
        remaining = _KEY_LEN * 4
        while remaining > 0:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    except OSError:
        return None
    finally:
        os.close(fd)


def tamper_marker_path() -> Path:
    """The append-only tamper-event record kept BESIDE the key (same
    operator-owned data dir, outside every run directory). One JSON
    line per quarantine, so triage/operators can attribute a re-key:
    tokens minted under a quarantined key fail verification, and this
    marker is the loud explanation of why."""
    return _key_path().with_name("telemetry-mac.key.tamper.jsonl")


def _record_tamper_event(reason: str, quarantined_to: str) -> None:
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "reason": reason,
        "quarantined_to": quarantined_to,
        "pid": os.getpid(),
    }
    line = json.dumps(record, sort_keys=True) + "\n"
    try:
        fd = os.open(
            tamper_marker_path(),
            os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
        )
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
    except OSError:
        # The quarantine + WARNING already carry the event; a marker
        # write failure must not block the re-key.
        logger.warning(
            "telemetry_mac: could not append the key tamper marker "
            "(%s)", tamper_marker_path())


def tamper_events() -> list[dict]:
    """Parsed tamper-marker records, oldest first (forensics /
    triage). Best-effort: unparseable lines are skipped."""
    events: list[dict] = []
    try:
        with open(tamper_marker_path(), encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict):
                    events.append(rec)
    except OSError:
        return []
    return events


def _quarantine_tampered_key(path: Path, reason: str) -> bool:
    """Move a tampered key object aside (evidence preserved), record
    the tamper marker, and warn LOUDLY. Returns True when the path is
    clear for re-keying."""
    dest = path.with_name(
        f"{path.name}.tampered-"
        f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-"
        f"{secrets.token_hex(4)}")
    try:
        os.rename(str(path), str(dest))
    except FileNotFoundError:
        # A concurrent detector already moved it — the path is clear.
        return True
    except OSError as exc:
        _warn_once_suspect_key(
            path, f"{reason}; quarantine failed ({exc})",
            "remove the object at the key path and investigate",
        )
        return False
    logger.warning(
        "telemetry_mac: KEY TAMPER — %s. The object was quarantined to "
        "%s and a fresh key will be created; telemetry stamped under "
        "the old key will FAIL verification (triage reads that as "
        "tampering, which is the honest verdict here). Investigate "
        "what reached %s.",
        reason, dest, path,
    )
    _record_tamper_event(reason, dest.name)
    return True


def _load_or_create_key() -> bytes | None:
    """Read the key, lazily creating it (0700 dir, 0600 file, O_EXCL)
    if absent. A TAMPERED key (see _TamperedKey) is quarantined and
    replaced — with the event recorded — so a same-uid metadata flip
    cannot park provenance in ``key_usable()=False`` forever. Returns
    None when the key exists but is refused (foreign owner,
    unreadable) or when recovery is not possible."""
    path = _key_path()
    # Two passes with AT MOST ONE quarantine per call: the second pass
    # serves the retry after a quarantine (whether the tamper was seen
    # on the direct read or through the creation-race re-read); a key
    # that is tampered AGAIN after this call's quarantine refuses —
    # the marker and warning already fired, no quarantine treadmill.
    _quarantined = False
    for _pass in range(2):
        data = _read_existing_key(path)
        if isinstance(data, _TamperedKey) or (
                isinstance(data, bytes) and len(data) > _KEY_LEN):
            # Over-length content can never be a concurrent creator's
            # partial _KEY_LEN write — same tamper class as the
            # metadata shapes.
            reason = (data.reason if isinstance(data, _TamperedKey)
                      else f"wrong length ({len(data)} bytes, expected "
                           f"{_KEY_LEN})")
            if _quarantined or not _quarantine_tampered_key(path, reason):
                return None
            _quarantined = True
            data = None  # quarantined — fall through to creation
        if data is _REFUSED:
            return None
        if data is not None and len(data) == _KEY_LEN:
            return data
        # data is None (no key yet) or SHORT (a concurrent creator may
        # be mid-write between its O_EXCL create and its write):
        # attempt creation — an absent file wins the O_EXCL, a
        # concurrent creator makes it fail FileExistsError, whose retry
        # loop below rides out the mid-write window instead of
        # mis-flagging a suspect key.
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        key = secrets.token_bytes(_KEY_LEN)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                         0o600)
        except FileExistsError:
            # Lost the creation race — re-read the winner's key.
            # SHORT reads (0 <= len < _KEY_LEN) are RETRIED, not
            # aborted: the winner opens with O_EXCL and writes the key
            # in a second step, so the loser can legitimately observe
            # an empty or partial file mid-write — treating that as a
            # suspect wrong-length key aborted on the first iteration
            # and left the run unstamped (honest runs then triaged
            # toward tampered). A file still short after the full
            # retry budget is genuinely wrong-length stable content
            # and refuses then (quarantining it could split-brain a
            # slow winner). Tampered / over-length observations break
            # to the outer pass, which quarantines and re-keys.
            raced = None
            for _ in range(20):
                raced = _read_existing_key(path)
                if raced is _REFUSED:
                    return None
                if isinstance(raced, _TamperedKey):
                    break
                if raced is not None and len(raced) == _KEY_LEN:
                    return raced
                if raced is not None and len(raced) > _KEY_LEN:
                    break
                time.sleep(0.01)
            if isinstance(raced, _TamperedKey) or (
                    isinstance(raced, bytes) and len(raced) > _KEY_LEN):
                continue  # outer pass quarantines + re-keys
            if raced is not None:
                _warn_once_suspect_key(
                    path,
                    f"wrong length ({len(raced)} bytes, expected "
                    f"{_KEY_LEN}) after the creation-race retry budget",
                    "remove the suspect key and investigate; a fresh "
                    "key is created on the next stamp",
                )
            return None
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
        return key
    return None


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
    UNUSABLE key (foreign-owned, unreadable, unwritable data dir,
    stable short content) is an operator-side condition that makes
    verification impossible for every artefact, honest or not —
    misreading that as a target attack turns a host misconfiguration
    into permanent suspicious verdicts. TAMPERED keys (permission
    flips, planted symlinks, over-length content) do NOT land here:
    they are quarantined and re-keyed inside ``_load_or_create_key``,
    so this returns True and the old key's tokens fail verification
    instead — fail toward tampering, not toward legacy acceptance."""
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
        msg = "telemetry_mac.mint: fields must carry 'kind'"
        raise ValueError(msg)
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


def run_binding(run_dir: Path | str) -> str:
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


def proxy_events_count_fields(
    count: object, flags: object, run: str,
) -> dict:
    """MAC fields for the proxy-events count sidecar
    (``proxy-events.count.json``).

    The per-line seq MACs make interior deletion detectable (gaps),
    but a SUFFIX truncation — or whole-file deletion — between
    persist batches left a contiguous-from-0 stream that fully
    verified. The writer therefore persists the authoritative
    written-line count (tracked in parent memory, never renumbered
    from the target-writable file) plus any writer-side tamper flags
    (``stream_truncated``, ``persist_open_failure``, ...) after every
    batch; the verifier cross-checks the surviving stream against it.
    ``flags`` join the MAC so a target that can rewrite the sidecar
    cannot strip them without breaking the token."""
    if isinstance(flags, str):
        flag_list = [flags] if flags else []
    else:
        flag_list = [str(f) for f in (flags or [])]
    return {
        "kind": "proxy-events-count",
        "run": run,
        "count": str(count),
        "flags": ",".join(sorted(flag_list)),
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


def triage_deep_fields(report_sha256: str, run: str) -> dict:
    """MAC fields for sandbox-triage-deep.json (the advisory LLM pass).

    Same construction as ``triage_report_fields``: the run binding
    stops cross-run replay of a validly-stamped deep report, and
    ``report_sha256`` covers the WHOLE canonical report minus the
    token — assessments text, model, overall_note and
    triage_report_integrity included — so none of it can be rewritten
    under a surviving token. The artifact is advisory-by-design
    (rules_verdict is restated, never recomputed), but an operator
    reads the assessment prose; its provenance must not be weaker
    than the report it annotates."""
    return {
        "kind": "sandbox-triage-deep",
        "run": run,
        "report_sha256": report_sha256,
    }


def summary_fields(total_denials: int, denials_sha256: str, run: str,
                   corrupt_lines: int = 0,
                   inode_mismatch: bool = False,
                   planted_object: str = "",
                   posture: "Mapping | None" = None,
                   floor_refusals: int = 0,
                   floor_refusals_sha256: str = "",
                   cli_sandbox_disabled: bool = False,
                   disable_consent: str = "") -> dict:
    """MAC fields for sandbox-summary.json: the denial payload is
    covered by its content hash, so a planted or edited summary fails
    verification even when the headline counters are preserved.

    ``corrupt_lines`` / ``inode_mismatch`` are the summariser's tamper
    flags (evidence rewritten in place / evidence file swapped). They
    join the MAC only when set so tokens minted before the flags
    existed keep verifying; binding them means a target that can edit
    the summary cannot strip the flags without breaking the token.

    ``posture`` is the summariser's key-exposure record (see
    ``core.sandbox.summary.record_run_posture``). Only the fact triage
    acts on — ``mac_key_hidden`` — is bound, and only when a posture
    was recorded, so pre-posture tokens keep verifying. Binding it
    means the field cannot be stripped or flipped on disk without
    breaking the token; note it is intentionally NOT a proof of
    posture (a target that could read the key can mint any posture),
    which is why in-lifecycle triage prefers the parent-memory copy."""
    fields = {
        "kind": "sandbox-summary",
        "run": run,
        "total_denials": total_denials,
        "denials_sha256": denials_sha256,
    }
    if corrupt_lines:
        fields["corrupt_lines"] = int(corrupt_lines)
    if inode_mismatch:
        fields["inode_mismatch"] = True
    if planted_object:
        fields["planted_object"] = str(planted_object)
    if posture is not None:
        fields["posture_mac_key_hidden"] = bool(
            posture.get("mac_key_hidden"))
    # Containment-floor refusal binding (join only when refusals were
    # recorded, so tokens minted before the field existed keep
    # verifying — same posture as the tamper flags above). Binding
    # the count + content hash means a target that can edit the
    # summary cannot strip or forge the "environment could not
    # execute this payload" record without breaking the token.
    if floor_refusals:
        fields["floor_refusals"] = int(floor_refusals)
        fields["floor_refusals_sha256"] = str(floor_refusals_sha256)
    # CLI-disable attribution binding (join only when the writer
    # recorded an accepted disable, so pre-existing tokens keep
    # verifying — same join posture as the fields above). Both halves
    # of the pair join together and the verifier recomputes each from
    # its own on-disk field, so stripping or rewriting EITHER the
    # cli_sandbox_disabled flag or the consent-source label breaks
    # the token — the "this run executed unsandboxed, admitted by
    # this consent source" record is all-or-nothing.
    if cli_sandbox_disabled or disable_consent:
        fields["cli_sandbox_disabled"] = bool(cli_sandbox_disabled)
        fields["disable_consent"] = str(disable_consent)
    return fields

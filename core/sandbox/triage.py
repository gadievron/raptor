"""Rules-based triage over a completed run's sandbox telemetry.

Reads <run_dir>/sandbox-summary.json, <run_dir>/proxy-events.jsonl, and
<run_dir>/sandbox-audit-degraded.json (if present) and classifies the run
into a 3-tier verdict — clean / notable / suspicious — based on whether any
signature pattern resembling an escape/recon/credential-theft attempt fired,
as distinct from ordinary "tool needed something the profile didn't allow"
denial noise.

Pure, rules-based, offline: no LLM call, no network, no cost — cheap
enough that core/run/metadata.py runs it unconditionally on every
terminal-state transition (complete/fail/cancel/interrupt), right after
the sandbox-summary finalise it reads from. libexec/raptor-sandbox-triage
re-runs it by hand (stranded runs, post-hoc re-classification after
editing telemetry). This is the cheap deterministic pre-filter a future
LLM-based deeper-reasoning pass would consume, not a replacement for one.

Known limitation: socket()/ioctl() denials collapse to a generic
syscall="socket"/"ioctl" under audit tracing (see
core/sandbox/tracer.py:_NAME_TO_TYPE) — the AF_UNIX/AF_NETLINK/AF_PACKET
family and TIOCSTI/TIOCCONS/TIOCSCTTY ioctl-cmd detail isn't captured by the
current tracer record shape, so escape_primitive_denied can't distinguish a
docker.sock-escape attempt from an ordinary blocked AF_UNIX call. Fixing
this means enriching tracer.py's record with decoded syscall arguments — a
separate, larger change.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.atomic_fs import write_text_atomically
from core.sandbox import telemetry_mac
from core.sandbox.escalation_signatures import (
    DEFAULT_HOST_RECON_THRESHOLD,
    ESCAPE_PRIMITIVE_SYSCALLS,
    hostile_arg_label,
    is_credential_path,
)
from core.sandbox.profiles import host_recon_threshold_for_profile
from core.security.log_sanitisation import sanitise_for_terminal
from core.sandbox.proxy import PROXY_EVENTS_FILENAME
from core.sandbox.summary import (
    AUDIT_DEGRADED_FILE,
    MAX_DENIALS_PER_RUN,
    SUMMARY_FILE,
)

TRIAGE_FILE = "sandbox-triage.json"

# Control-plane record types written into the same denials stream by
# core/sandbox/audit_budget.py — not enforcement denials, must be excluded
# from the enforcement-oriented signal checks below.
_BUDGET_MARKER_TYPES = frozenset({
    "pid_budget_exceeded", "category_budget_exceeded",
    "category_budget_exceeded_sampling", "audit_summary",
})

VERDICT_CLEAN = "clean"
VERDICT_NOTABLE = "notable"
VERDICT_SUSPICIOUS = "suspicious"

SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

# Fraction of MAX_DENIALS_PER_RUN that counts as "near the cap" for
# volume_anomaly's cap-proximity check.
_VOLUME_ANOMALY_CAP_FRACTION = 0.9

# Evidence bounds. Evidence values (hostnames, paths) are attacker-
# controlled: a hostile target can mint thousands of distinct denied
# hosts, each an arbitrarily long string, to bloat sandbox-triage.json
# or to stuff content into a report a human or LLM pass later reads.
# Signals keep the true `count`; only the illustrative evidence list
# is capped, with an explicit elision marker so a capped list never
# masquerades as complete.
_MAX_EVIDENCE_ITEMS = 32
_MAX_EVIDENCE_ITEM_LEN = 512


# Verification outcomes for a triage input artifact. "verified" =
# provenance token(s) present and valid; "legacy" = no token at all
# (pre-MAC run, or no usable key when it was written) — accepted only
# for explicit/manual re-triage of old artefacts, with a confidence
# caveat; "tampered" = token(s) present-but-invalid, a mixed
# stamped/unstamped stream, or an unstamped artifact seen during the
# current lifecycle path. Failing records are excluded from signal
# derivation and a HIGH signal fires, because the only writer that
# stamps is this install's parent process: content that fails is
# content something else wrote into the run dir, and the one thing
# with both the motive and the write access is the target.
_INTEGRITY_VERIFIED = "verified"
_INTEGRITY_LEGACY = "legacy"
_INTEGRITY_TAMPERED = "tampered"


def _report_sha256(report: dict) -> str:
    """Canonical hash of the WHOLE report minus its own token — the
    MAC must cover everything consumers forward (verdict, signals,
    inputs, caveats, ...), not a subset a target could rewrite."""
    body = {k: v for k, v in report.items() if k != "mac"}
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, ensure_ascii=True)
        .encode("utf-8")
    ).hexdigest()


def verify_triage_report(report: Optional[dict], run_dir: Path) -> str:
    """Provenance state of a loaded sandbox-triage.json for downstream
    consumers: 'verified' / 'legacy' (no token) / 'tampered'.

    ``run_dir`` is the directory the report was READ from — the run
    binding is recomputed from it, so a report replayed from another
    run fails verification even though its token was validly minted.
    """
    if not isinstance(report, dict):
        return _INTEGRITY_TAMPERED
    token = report.get("mac")
    if not token:
        return _INTEGRITY_LEGACY
    fields = telemetry_mac.triage_report_fields(
        _report_sha256(report),
        run=telemetry_mac.run_binding(run_dir),
    )
    return (_INTEGRITY_VERIFIED
            if telemetry_mac.verify(fields, token)
            else _INTEGRITY_TAMPERED)


def _denials_sha256(denials: List[dict]) -> str:
    return hashlib.sha256(
        json.dumps(denials, sort_keys=True, ensure_ascii=True)
        .encode("utf-8")
    ).hexdigest()


def _verify_proxy_events(
        events: List[dict], run: str, *, allow_legacy: bool = True,
        ) -> Tuple[List[dict], int, str]:
    """Partition proxy events by provenance. Returns
    ``(usable_events, rejected_count, integrity)``."""
    if not events:
        return [], 0, _INTEGRITY_VERIFIED
    if not any("mac" in e for e in events):
        if not allow_legacy:
            return [], len(events), _INTEGRITY_TAMPERED
        return events, 0, _INTEGRITY_LEGACY
    usable = [
        e for e in events
        if telemetry_mac.verify(
            telemetry_mac.proxy_event_fields(e, run), e.get("mac"))
    ]
    rejected = len(events) - len(usable)
    integrity = (_INTEGRITY_TAMPERED if rejected
                 else _INTEGRITY_VERIFIED)
    # Stream continuity: per-line MACs alone let a target DELETE
    # incriminating stamped lines and leave a fully-verifying file.
    # The writer numbers events 0..n-1 inside the MAC; a gap means a
    # stamped line was removed, a duplicate means the file was
    # truncated mid-run and later batches re-counted over it. The
    # verified events themselves stay usable — they are genuine —
    # but the stream is flagged tampered so the verdict carries the
    # tampering signal.
    if usable:
        seqs = []
        for e in usable:
            try:
                seqs.append(int(e.get("seq")))
            except (TypeError, ValueError):
                integrity = _INTEGRITY_TAMPERED
        if seqs and (len(set(seqs)) != len(seqs)
                     or set(seqs) != set(range(min(seqs),
                                               min(seqs) + len(seqs)))
                     or min(seqs) != 0):
            integrity = _INTEGRITY_TAMPERED
    return usable, rejected, integrity


def _verify_summary(
        summary: Optional[dict], run: str, *, allow_legacy: bool = True,
        ) -> Tuple[Optional[dict], str]:
    """Returns ``(usable_summary, integrity)`` — a summary that fails
    verification is dropped entirely (its denials are untrusted as a
    whole; there is no per-record salvage)."""
    if summary is None:
        return None, _INTEGRITY_VERIFIED
    token = summary.get("mac")
    if not token:
        if not allow_legacy:
            return None, _INTEGRITY_TAMPERED
        return summary, _INTEGRITY_LEGACY
    fields = telemetry_mac.summary_fields(
        summary.get("total_denials", 0),
        _denials_sha256(summary.get("denials", [])),
        run=run,
    )
    if telemetry_mac.verify(fields, token):
        return summary, _INTEGRITY_VERIFIED
    return None, _INTEGRITY_TAMPERED


def _verify_audit_degraded(
        marker: Optional[dict], run: str, *, allow_legacy: bool = True,
        ) -> Tuple[Optional[dict], str]:
    if marker is None:
        return None, _INTEGRITY_VERIFIED
    token = marker.get("mac")
    if not token:
        if not allow_legacy:
            return None, _INTEGRITY_TAMPERED
        return marker, _INTEGRITY_LEGACY
    if telemetry_mac.verify(
            telemetry_mac.audit_degraded_fields(marker, run), token):
        return marker, _INTEGRITY_VERIFIED
    return None, _INTEGRITY_TAMPERED


def _cap_evidence(items: List[str]) -> List[str]:
    capped = [
        item if len(item) <= _MAX_EVIDENCE_ITEM_LEN
        else item[:_MAX_EVIDENCE_ITEM_LEN]
        + f"...[+{len(item) - _MAX_EVIDENCE_ITEM_LEN} chars]"
        for item in items
    ]
    if len(capped) > _MAX_EVIDENCE_ITEMS:
        dropped = len(capped) - _MAX_EVIDENCE_ITEMS
        capped = capped[:_MAX_EVIDENCE_ITEMS] + [f"...[+{dropped} more]"]
    return capped


def triage_run(run_dir: Path, *,
                host_recon_threshold: Optional[int] = None,
                allow_legacy: bool = True,
                ) -> Optional[Dict[str, Any]]:
    """Classify a completed run's sandbox telemetry.

    Returns the triage dict (also written to <run_dir>/sandbox-triage.json),
    or None if neither sandbox-summary.json nor proxy-events.jsonl exists
    for this run_dir — mirrors summarize_and_write's "no denials → None, no
    file written" convention so file-presence keeps meaning "something
    happened" across every sibling run-dir artifact.

    ``allow_legacy`` keeps the manual ``raptor-sandbox-triage`` surface
    able to re-triage old pre-provenance runs. Lifecycle callers MUST pass
    ``False``: the run dir is target-writable while the workload runs, so
    unstamped current-run artifacts cannot be allowed to drive a verdict.

    ``host_recon_threshold``: explicit override (e.g. from a CLI flag or a
    test wanting deterministic behaviour) takes precedence exactly as
    passed. When omitted (the ``None`` default — this is how
    ``core.run.metadata._finalize_sandbox_triage`` calls this), the
    threshold is resolved from whichever sandbox profile(s) this run's
    denial records were attributed to, via
    ``core.sandbox.profiles.host_recon_threshold_for_profile``.

    A single run_dir can aggregate telemetry from MULTIPLE sandbox()
    invocations, potentially under different profiles (e.g. mostly
    ``full``, with one nested ``debug`` call for a crash-analysis step) —
    there is no single well-defined "the profile" for the run as a whole.
    Best-effort resolution: take the MIN (most sensitive/tightest)
    threshold across every profile named in a seccomp-type denial record's
    ``profile`` field, erring toward flagging real recon over suppressing
    it. Falls back to DEFAULT_HOST_RECON_THRESHOLD when no denial carries a
    ``profile`` (clean runs, network-only denials, or a non-seccomp-type
    run) — this is the same behaviour as before this parameter existed.
    """
    run_dir = Path(run_dir)
    raw_summary = _load_json(run_dir / SUMMARY_FILE)
    raw_proxy_events = _load_jsonl(run_dir / PROXY_EVENTS_FILENAME)
    raw_audit_degraded = _load_json(run_dir / AUDIT_DEGRADED_FILE)

    # Existence check runs on the RAW inputs: even a fully-forged
    # artifact means "something happened" and must produce a report
    # (carrying the tampering signal), never silence. Presence is
    # probed with lstat, not "did it parse": MAC forgery already
    # fails toward suspicious, so destruction (garbage bytes, an
    # oversized blob, a planted FIFO/symlink) must not fail toward
    # clean by reading as "no telemetry".
    summary_present = _artifact_present(run_dir / SUMMARY_FILE)
    events_present = _artifact_present(run_dir / PROXY_EVENTS_FILENAME)
    summary_destroyed = summary_present and raw_summary is None
    events_destroyed = events_present and not raw_proxy_events
    if raw_summary is None and not raw_proxy_events:
        if not allow_legacy and (summary_destroyed or events_destroyed):
            pass  # fall through: unusable artifacts drive a report
        else:
            if not allow_legacy:
                _remove_stale_triage_report(run_dir)
            return None

    # Provenance gates: the run dir is target-writable during the
    # run, so every input is verified before it may drive a verdict.
    # The run binding is recomputed from THIS directory — artefacts
    # replayed from another run carry that run's binding and fail.
    #
    # When this install has NO usable telemetry-mac key, verification
    # is impossible for every artefact, honest or not: that is an
    # operator-side condition (symlinked/foreign/wrong-length key,
    # unwritable data dir), and reading it as target tampering would
    # turn a host misconfiguration into permanent suspicious verdicts.
    # Inputs are then accepted at legacy confidence and a distinct
    # MEDIUM provenance_unavailable signal (verdict >= notable) plus a
    # caveat carry the condition instead.
    provenance_unavailable = (not allow_legacy
                              and not telemetry_mac.key_usable())
    _verify_legacy = allow_legacy or provenance_unavailable
    _run_binding = telemetry_mac.run_binding(run_dir)
    summary, summary_integrity = _verify_summary(
        raw_summary, _run_binding, allow_legacy=_verify_legacy)
    proxy_events, rejected_events, events_integrity = (
        _verify_proxy_events(
            raw_proxy_events, _run_binding, allow_legacy=_verify_legacy))
    audit_degraded, degraded_integrity = (
        _verify_audit_degraded(
            raw_audit_degraded, _run_binding, allow_legacy=_verify_legacy))

    denials = (summary or {}).get("denials", [])
    enforcement_denials = [d for d in denials
                            if d.get("type") not in _BUDGET_MARKER_TYPES]
    budget_markers = [d for d in denials
                       if d.get("type") in _BUDGET_MARKER_TYPES]

    if host_recon_threshold is None:
        observed_profiles = {d["profile"] for d in enforcement_denials
                              if d.get("profile")}
        host_recon_threshold = min(
            (host_recon_threshold_for_profile(p, DEFAULT_HOST_RECON_THRESHOLD)
             for p in observed_profiles),
            default=DEFAULT_HOST_RECON_THRESHOLD,
        )

    signals: List[Dict[str, Any]] = []
    signals += _check_escape_primitive(enforcement_denials)
    signals += _check_hostile_syscall_args(enforcement_denials)
    signals += _check_seccomp_unattributed(enforcement_denials)
    signals += _check_resolved_ip_screened(proxy_events)
    signals += _check_host_recon(proxy_events, host_recon_threshold)
    signals += _check_credential_path_touch(enforcement_denials)
    signals += _check_volume_anomaly(summary, budget_markers)

    # Destruction detection: an artifact that exists but yields no
    # usable content (garbage bytes, oversized blob, FIFO, symlink)
    # is tampering evidence under fail-closed semantics — MAC forgery
    # already demotes; destruction must not grade better than forgery.
    destroyed = []
    if not allow_legacy:
        if summary_destroyed:
            destroyed.append("sandbox_summary")
            summary_integrity = _INTEGRITY_TAMPERED
        if events_destroyed:
            destroyed.append("proxy_events")
            events_integrity = _INTEGRITY_TAMPERED

    integrity = {
        "sandbox_summary": summary_integrity,
        "proxy_events": events_integrity,
        "audit_degraded": degraded_integrity,
    }
    tampered = [name for name, state in integrity.items()
                if state == _INTEGRITY_TAMPERED]
    if tampered:
        evidence = [f"{name}: provenance verification failed"
                    for name in sorted(set(tampered) - set(destroyed))]
        evidence += [
            f"{name}: file present but yielded no readable content "
            f"(destroyed/replaced)" for name in sorted(destroyed)]
        if rejected_events:
            evidence.append(
                f"{rejected_events} proxy event(s) rejected "
                f"(missing/invalid provenance token)")
        signals.append({
            "type": "telemetry_tampering",
            "severity": SEVERITY_HIGH,
            "count": len(tampered),
            "evidence": evidence,
        })

    if provenance_unavailable:
        signals.append({
            "type": "provenance_unavailable",
            "severity": SEVERITY_MEDIUM,
            "count": 1,
            "evidence": [
                "no usable telemetry-mac key on this install — "
                "telemetry accepted at legacy confidence; see the "
                "warn-once log line from core.sandbox.telemetry_mac "
                "for the key path and remedy",
            ],
        })

    verdict = _derive_verdict(signals)

    report: Dict[str, Any] = {
        "run_dir": str(run_dir),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
        "signals": signals,
        "inputs": {
            "sandbox_summary_present": raw_summary is not None,
            "proxy_events_present": bool(raw_proxy_events),
            "total_denials": (summary or {}).get("total_denials", 0),
            "total_proxy_events": len(proxy_events),
            "integrity": integrity,
        },
        "audit_degraded": audit_degraded is not None,
        "caveats": [],
    }
    legacy = sorted(name for name, state in integrity.items()
                    if state == _INTEGRITY_LEGACY)
    if legacy:
        report["caveats"].append(
            "Unstamped telemetry accepted at face value: "
            + ", ".join(legacy)
            + " carry no provenance token (pre-provenance run or no "
            "usable telemetry-mac key). The run dir is writable by "
            "the sandboxed target, so treat this verdict with "
            "correspondingly lower confidence."
        )
    if audit_degraded is not None:
        report["caveats"].append(
            "Audit tracer did not engage this run "
            f"(reason: {audit_degraded.get('reason', 'unknown')}); "
            "syscall-level attribution (escape_primitive_denied) was "
            "unavailable, so this verdict has lower confidence than a "
            "run with --audit fully engaged."
        )

    _write(run_dir / TRIAGE_FILE, report)
    return report


# ---- signal checks (each returns a list of 0 or 1 signal dicts) --------

def _check_escape_primitive(denials: List[dict]) -> List[dict]:
    hits = [d for d in denials
            if d.get("syscall") in ESCAPE_PRIMITIVE_SYSCALLS]
    if not hits:
        return []
    return [{
        "type": "escape_primitive_denied",
        "severity": SEVERITY_HIGH,
        "count": len(hits),
        "evidence": _cap_evidence(sorted({h["syscall"] for h in hits})),
    }]


def _check_hostile_syscall_args(denials: List[dict]) -> List[dict]:
    # socket()/ioctl() are argument-filtered by seccomp; the generic
    # syscall name alone cannot distinguish a TIOCSTI tty-injection or
    # SOCK_RAW attempt from ordinary AF_UNIX noise. Decode from the
    # record's raw `args` (present on every audit-mode tracer record),
    # so the check works on both enriched and pre-enrichment records.
    # Audit-mode only, like escape_primitive_denied: plain enforcement
    # ERRNOs these in-kernel with no argument capture.
    labels = []
    for d in denials:
        if d.get("syscall") in ("socket", "ioctl"):
            label = hostile_arg_label(d["syscall"], d.get("args") or [])
            if label is not None:
                labels.append(label)
    if not labels:
        return []
    return [{
        "type": "hostile_syscall_argument",
        "severity": SEVERITY_HIGH,
        "count": len(labels),
        "evidence": _cap_evidence(sorted(set(labels))),
    }]


def _check_seccomp_unattributed(denials: List[dict]) -> List[dict]:
    hits = [d for d in denials
            if d.get("type") == "seccomp" and "syscall" not in d]
    if not hits:
        return []
    return [{
        "type": "seccomp_denied_unattributed",
        "severity": SEVERITY_LOW,
        "count": len(hits),
        "evidence": [
            "non-audit run: syscall identity unavailable, only "
            f"profile={hits[0].get('profile')!r} known",
        ],
    }]


def _check_resolved_ip_screened(proxy_events: List[dict]) -> List[dict]:
    # ANY occurrence — doc-confirmed purely-attack pattern (see
    # docs/sandbox.md's audit-mode section), not threshold-based. Read
    # from proxy-events.jsonl rather than sandbox-summary.json's mirrored
    # network-type denial: the audit-mode mirror
    # (_record_proxy_denial -> record_denial(..., "network", ...)) writes
    # a plain type="network" denial indistinguishable from an ordinary
    # network-allowlist denial in the summary — resolved_ip is only
    # reliably present in proxy-events.jsonl's resolved_ip field.
    hits = [e for e in proxy_events if e.get("result") == "denied_resolved_ip"]
    if not hits:
        return []
    return [{
        "type": "resolved_ip_screened",
        "severity": SEVERITY_HIGH,
        "count": len(hits),
        "evidence": _cap_evidence(sorted({e["resolved_ip"] for e in hits
                                          if e.get("resolved_ip")})),
    }]


def _check_host_recon(proxy_events: List[dict], threshold: int) -> List[dict]:
    hosts = {e.get("host") for e in proxy_events
             if e.get("result") in ("denied_host", "would_deny_host")
             and e.get("host")}
    if len(hosts) < threshold:
        return []
    return [{
        "type": "host_recon_pattern",
        "severity": SEVERITY_MEDIUM,
        "count": len(hosts),
        "evidence": _cap_evidence(sorted(hosts)),
    }]


def _check_credential_path_touch(denials: List[dict]) -> List[dict]:
    hits = []
    for d in denials:
        path = d.get("path")
        if not path:
            continue
        if is_credential_path(path):
            hits.append(path)
    if not hits:
        return []
    return [{
        "type": "credential_path_touch",
        "severity": SEVERITY_HIGH,
        "count": len(hits),
        "evidence": _cap_evidence(sorted(set(hits))),
    }]


def _check_volume_anomaly(summary: Optional[dict],
                           budget_markers: List[dict]) -> List[dict]:
    evidence = []
    total = (summary or {}).get("total_denials", 0)
    cap_threshold = int(MAX_DENIALS_PER_RUN * _VOLUME_ANOMALY_CAP_FRACTION)
    if total >= cap_threshold:
        evidence.append(
            f"total_denials={total} near/at cap ({MAX_DENIALS_PER_RUN})"
        )
    marker_types = sorted({m.get("type") for m in budget_markers
                            if m.get("type") != "audit_summary"})
    if marker_types:
        evidence.append(f"audit budget markers present: {marker_types}")
    if not evidence:
        return []
    return [{
        "type": "volume_anomaly",
        "severity": SEVERITY_MEDIUM,
        "count": total,
        "evidence": evidence,
    }]


def _derive_verdict(signals: List[dict]) -> str:
    if any(s["severity"] == SEVERITY_HIGH for s in signals):
        return VERDICT_SUSPICIOUS
    if signals:
        return VERDICT_NOTABLE
    return VERDICT_CLEAN


# ---- I/O helpers ---------------------------------------------------------

# Bound on any single triage input file. Legitimate inputs are far
# smaller (denials are capped at MAX_DENIALS_PER_RUN records; proxy
# events at one line per CONNECT) — anything bigger is a planted
# artifact, and reading it unboundedly hands the target a memory
# lever over the parent's lifecycle hook.
_MAX_INPUT_BYTES = 64 * 1024 * 1024


def _read_bounded(path: Path) -> Optional[bytes]:
    """Open-and-read a triage input with the same discipline the
    writers use (see context._persist_proxy_events): the run dir is
    target-writable, so a plain ``open()`` here would follow a
    target-planted symlink out of the sandbox boundary, and block the
    LIFECYCLE (complete_run/fail_run run this in-process) forever on
    a target-planted FIFO with no writer. O_NOFOLLOW + O_NONBLOCK at
    open, fstat regular-file check on the actually-opened inode,
    bounded read. Any refusal returns None — absent and unreadable
    collapse to "no input", matching the writers' fail-quiet stance.
    """
    try:
        fd = os.open(
            str(path),
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        )
    except OSError:
        # ENOENT (common case), ELOOP (planted symlink), and friends.
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None  # FIFO / device / directory — never read
        if st.st_size > _MAX_INPUT_BYTES:
            return None
        chunks = []
        remaining = _MAX_INPUT_BYTES
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 1 << 20))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    except OSError:
        return None
    finally:
        os.close(fd)


def _load_json(path: Path) -> Optional[dict]:
    data = _read_bounded(path)
    if data is None:
        return None
    try:
        loaded = json.loads(data.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
    return loaded if isinstance(loaded, dict) else None


def _artifact_present(path: Path) -> bool:
    """Whether SOMETHING exists at path — including a dangling
    symlink or a FIFO the bounded reader refuses to read. Destruction
    must not read as absence: a target that replaces its telemetry
    with a FIFO, an oversized blob, or garbage bytes must land in the
    tampered path, not the "no telemetry" path."""
    try:
        os.lstat(path)
        return True
    except OSError:
        return False


def _load_jsonl(path: Path) -> List[dict]:
    data = _read_bounded(path)
    if data is None:
        return []
    out: List[dict] = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            out.append(record)
    return out


def _write(path: Path, report: dict) -> None:
    # Self-stamp: on a no-telemetry run the lifecycle writes no report,
    # so a target-planted sandbox-triage.json would otherwise survive
    # to be read by downstream consumers (deep pass, /review, project
    # views). Those consumers verify via verify_triage_report().
    token = telemetry_mac.mint(telemetry_mac.triage_report_fields(
        _report_sha256(report),
        run=telemetry_mac.run_binding(path.parent),
    ))
    if token:
        report["mac"] = token
    write_text_atomically(
        path,
        json.dumps(report, indent=2, ensure_ascii=True) + "\n",
        tmp_prefix=".~triage-",
    )


def _remove_stale_triage_report(run_dir: Path) -> None:
    """Remove a target-planted report on a current run with no telemetry.

    A clean lifecycle run writes no triage report. Without this cleanup a
    target can pre-plant ``sandbox-triage.json`` and leave it behind for
    downstream readers after triage correctly decides there was nothing to
    classify.
    """
    try:
        (run_dir / TRIAGE_FILE).unlink(missing_ok=True)
    except OSError:
        # Best-effort only: downstream consumers still verify provenance and
        # refuse an unstamped report. Never let cleanup fail the lifecycle.
        pass


def _cli_main(argv: Optional[list] = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Rules-based triage of a completed run's sandbox "
                    "telemetry for escape/recon/credential-theft signatures.",
    )
    parser.add_argument("run_dir", help="run directory to triage")
    parser.add_argument(
        "--json", action="store_true",
        help="print the full triage report as JSON on stdout "
             "(the report is also written to sandbox-triage.json)",
    )
    parser.add_argument(
        "--deep", action="store_true",
        help="after the rules pass, run the LLM deeper-reasoning pass "
             "over any non-clean verdict (uses the configured default "
             "model; writes sandbox-triage-deep.json; advisory only — "
             "never changes the rules verdict or the exit code)",
    )
    parser.add_argument(
        "--legacy", action="store_true",
        help="accept unstamped (pre-provenance) telemetry at face "
             "value. Only for run directories created before "
             "provenance stamping existed — on current runs an "
             "attacker who rewrote the telemetry produces exactly "
             "this unstamped shape, so the default (off) treats it "
             "as tampering. Do NOT pass this in CI gates.",
    )
    try:
        args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2

    target = Path(args.run_dir)
    if not target.is_dir():
        print(f"error: {target} is not a directory", file=sys.stderr)
        return 1

    # Fail-closed by default: this exit code is documented as a CI
    # gate, and unstamped telemetry on a current run is exactly what
    # a target that rewrote its own telemetry looks like.
    result = triage_run(target, allow_legacy=args.legacy)
    if result is None:
        print(f"(no sandbox telemetry found for {target})")
        return 0

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=True))
    else:
        print(f"Verdict: {result['verdict'].title()}  "
              f"({len(result['signals'])} signal(s)) -> "
              f"{target / TRIAGE_FILE}")
        for signal in result["signals"]:
            print(f"  - {signal['type']} [{signal['severity']}] "
                  f"count={signal['count']}")
        for caveat in result.get("caveats", []):
            # Caveat text embeds the audit-degraded reason, read from
            # a file inside the run dir — which the sandboxed target
            # may have write access to. Sanitise before a terminal.
            print(f"  ⚠️  {sanitise_for_terminal(caveat)}")
    if args.deep:
        if result["verdict"] == VERDICT_CLEAN:
            print("(clean verdict — deep pass has nothing to assess)")
        else:
            from core.sandbox.triage_deep import deep_analyse
            deep = deep_analyse(target)
            if deep is None:
                print("(deep pass unavailable — no LLM configured, or "
                      "the triage report failed provenance "
                      "verification; see log)", file=sys.stderr)
            elif not args.json:
                print(f"Deep assessment ({deep['model'] or 'LLM'}) — "
                      f"advisory, rules verdict stands:")
                for a in deep["assessments"]:
                    print(f"  - {a['signal_type']}: {a['judgement']} "
                          f"(confidence {a['confidence']:.2f}) — "
                          f"{a['rationale']}")
                if deep.get("overall_note"):
                    print(f"  note: {deep['overall_note']}")
    # Verdict-reflecting exit codes for scripting/CI gates:
    #   0 clean (or no telemetry), 1 error, 2 usage,
    #   3 notable, 4 suspicious. --deep never changes the code — the
    #   deterministic rules verdict is the gate.
    return {VERDICT_CLEAN: 0, VERDICT_NOTABLE: 3,
            VERDICT_SUSPICIOUS: 4}[result["verdict"]]


if __name__ == "__main__":
    raise SystemExit(_cli_main())

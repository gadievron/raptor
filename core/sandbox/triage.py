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
from typing import Any

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
from core.sandbox.proxy import (
    PROXY_EVENTS_COUNT_FILENAME,
    PROXY_EVENTS_FILENAME,
)
from core.sandbox.summary import (
    AUDIT_DEGRADED_FILE,
    MAX_DENIALS_PER_RUN,
    SUMMARY_FILE,
    get_proxy_persist_state,
    get_run_posture,
    reassert_audit_degraded,
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


def verify_triage_report(report: dict | None, run_dir: Path) -> str:
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


def _denials_sha256(denials: list[dict]) -> str:
    return hashlib.sha256(
        json.dumps(denials, sort_keys=True, ensure_ascii=True)
        .encode("utf-8")
    ).hexdigest()


def _verify_proxy_events(
        events: list[dict], run: str, *, allow_legacy: bool = True,
        count_record: dict | None = None,
        over_bound: bool = False,
        ) -> tuple[list[dict], int, str, str | None]:
    """Partition proxy events by provenance. Returns
    ``(usable_events, rejected_count, integrity, count_note)``.

    ``count_record`` is the raw ``proxy-events.count.json`` sidecar
    (or None when absent). The per-line seq MACs catch interior
    deletion (gaps) but not SUFFIX/whole-file truncation between
    persist batches — the surviving contiguous-from-0 stream fully
    verifies. The MAC'd sidecar carries the writer's authoritative
    count plus its tamper flags; a mismatch or flag marks the stream
    tampered, and ``count_note`` names the reason for the report's
    evidence list."""
    count_note: str | None = None

    def _with_count(usable, rejected, integrity):
        nonlocal count_note
        checked = integrity
        if over_bound:
            # The file continued past the streaming caps: the tail is
            # UNVERIFIED, so completeness cannot be attested — fail
            # toward suspicious, but with the over-bound attribution
            # (a count mismatch here is explained by the bound; the
            # truncation/erasure note would name the wrong cause).
            count_note = (
                f"proxy-events file exceeds the triage streaming "
                f"bound ({_MAX_EVENTS_STREAM_BYTES} bytes / "
                f"{_MAX_EVENTS_PARSED} events) — {len(usable)} "
                f"verified event(s) in the parsed prefix; events "
                f"beyond the bound were not verified"
            )
            return usable, rejected, _INTEGRITY_TAMPERED, count_note
        stamped_stream = any("mac" in e for e in events)
        if count_record is None:
            if stamped_stream and not allow_legacy:
                count_note = (
                    "proxy-events count sidecar missing for a "
                    "stamped event stream (deleted?)"
                )
                checked = _INTEGRITY_TAMPERED
            return usable, rejected, checked, count_note
        token = (count_record.get("mac")
                 if isinstance(count_record, dict) else None)
        count = (count_record.get("count")
                 if isinstance(count_record, dict) else None)
        flags = (count_record.get("flags") or []
                 if isinstance(count_record, dict) else [])
        fields = telemetry_mac.proxy_events_count_fields(
            count, flags, run)
        if not telemetry_mac.verify(fields, token):
            count_note = (
                "proxy-events count sidecar failed provenance "
                "verification (forged or edited)"
            )
            return usable, rejected, _INTEGRITY_TAMPERED, count_note
        if flags:
            count_note = (
                "writer-flagged proxy-events tampering: "
                + ", ".join(sorted(str(f) for f in flags))
            )
            return usable, rejected, _INTEGRITY_TAMPERED, count_note
        if not isinstance(count, int) or count < 0:
            count_note = "proxy-events count sidecar malformed"
            return usable, rejected, _INTEGRITY_TAMPERED, count_note
        seqs = []
        for e in usable:
            try:
                seqs.append(int(e.get("seq")))
            except (TypeError, ValueError):
                pass
        max_seq = max(seqs) if seqs else -1
        if len(usable) != count or max_seq != count - 1 or rejected:
            # Direction matters for the operator: fewer survivors
            # than the count is the erasure shape; MORE survivors
            # than the count is the interrupted-persist shape (crash
            # between the events append and the sidecar update — an
            # inherent two-file window) or a stale/replayed sidecar.
            # Both fail toward suspicious; only the attribution
            # differs.
            if (len(usable) > count and max_seq >= count - 1
                    and not rejected):
                count_note = (
                    f"proxy-events stream is AHEAD of its count "
                    f"sidecar (sidecar says {count} event(s), "
                    f"{len(usable)} verified surviving) — "
                    f"interrupted persist (run crashed between the "
                    f"events append and the sidecar update) or a "
                    f"stale/replayed sidecar"
                )
            else:
                count_note = (
                    f"proxy-events stream does not match its written "
                    f"count (sidecar says {count} event(s), "
                    f"{len(usable)} verified surviving) — suffix "
                    f"truncation or whole-file deletion"
                )
            return usable, rejected, _INTEGRITY_TAMPERED, count_note
        return usable, rejected, checked, count_note

    if not events:
        return _with_count([], 0, _INTEGRITY_VERIFIED)
    if not any("mac" in e for e in events):
        if not allow_legacy:
            return _with_count(
                [], len(events), _INTEGRITY_TAMPERED)
        return _with_count(events, 0, _INTEGRITY_LEGACY)
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
    # stamped line was removed. The verified events themselves stay
    # usable — they are genuine — but the stream is flagged tampered
    # so the verdict carries the tampering signal. Suffix/whole-file
    # truncation leaves no gap; the count sidecar check above covers
    # that half.
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
    return _with_count(usable, rejected, integrity)


def _verify_summary(
        summary: dict | None, run: str, *, allow_legacy: bool = True,
        ) -> tuple[dict | None, str]:
    """Returns ``(usable_summary, integrity)`` — a summary that fails
    verification is dropped entirely (its denials are untrusted as a
    whole; there is no per-record salvage). A summary the WRITER
    flagged as tamper-suspect (corrupt evidence lines / evidence-file
    inode mismatch) is dropped the same way even when its MAC
    verifies: the token only proves the summariser wrote it, and what
    the summariser wrote is "this run's evidence was tampered with"."""
    if summary is None:
        return None, _INTEGRITY_VERIFIED
    corrupt_lines = summary.get("corrupt_lines", 0)
    inode_mismatch = bool(summary.get("inode_mismatch"))
    planted_object = str(summary.get("planted_object") or "")
    writer_flagged = (bool(corrupt_lines) or inode_mismatch
                      or bool(planted_object))
    token = summary.get("mac")
    if not token:
        if not allow_legacy:
            return None, _INTEGRITY_TAMPERED
        if writer_flagged:
            return None, _INTEGRITY_TAMPERED
        return summary, _INTEGRITY_LEGACY
    posture = summary.get("posture")
    fields = telemetry_mac.summary_fields(
        summary.get("total_denials", 0),
        _denials_sha256(summary.get("denials", [])),
        run=run,
        corrupt_lines=corrupt_lines,
        inode_mismatch=inode_mismatch,
        planted_object=planted_object,
        posture=posture if isinstance(posture, dict) else None,
    )
    if telemetry_mac.verify(fields, token):
        if writer_flagged:
            return None, _INTEGRITY_TAMPERED
        return summary, _INTEGRITY_VERIFIED
    return None, _INTEGRITY_TAMPERED


def _verify_audit_degraded(
        marker: dict | None, run: str, *, allow_legacy: bool = True,
        ) -> tuple[dict | None, str]:
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


def _cap_evidence(items: list[str]) -> list[str]:
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
                host_recon_threshold: int | None = None,
                allow_legacy: bool = True,
                ) -> dict[str, Any] | None:
    """Classify a completed run's sandbox telemetry.

    Returns the triage dict (also written to <run_dir>/sandbox-triage.json),
    or None if none of sandbox-summary.json, proxy-events.jsonl, or the
    sandbox-audit-degraded.json marker exists for this run_dir — mirrors
    summarize_and_write's "no denials → None, no file written" convention
    so file-presence keeps meaning "something happened" across every
    sibling run-dir artifact. A marker-only run (audit degraded, no other
    telemetry — exactly what an unaudited fallback produces) yields a
    report carrying the degradation caveat, never silence.

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
    # Re-assert the audit-degraded marker before reading anything: the
    # marker is written into the target-writable run root BEFORE the
    # unaudited fallback executes, so the target can delete it. The
    # parent's in-process record (core.sandbox.summary) is out of the
    # target's reach; a True return means the on-disk marker had to be
    # restored at some point this run — tamper evidence in itself.
    marker_restored = reassert_audit_degraded(run_dir)
    raw_summary = _load_json(run_dir / SUMMARY_FILE)
    # The events JSONL streams (per-line MACs make incremental
    # verification safe) so honest chatty runs above the whole-file
    # input bound still grade on their real content.
    raw_proxy_events, events_over_bound = _load_jsonl_stream(
        run_dir / PROXY_EVENTS_FILENAME)
    raw_audit_degraded = _load_json(run_dir / AUDIT_DEGRADED_FILE)
    raw_events_count = _load_json(run_dir / PROXY_EVENTS_COUNT_FILENAME)

    # Existence check runs on the RAW inputs: even a fully-forged
    # artifact means "something happened" and must produce a report
    # (carrying the tampering signal), never silence. Presence is
    # probed with lstat, not "did it parse": MAC forgery already
    # fails toward suspicious, so destruction (garbage bytes, an
    # oversized blob, a planted FIFO/symlink) must not fail toward
    # clean by reading as "no telemetry".
    summary_present = _artifact_present(run_dir / SUMMARY_FILE)
    events_present = _artifact_present(run_dir / PROXY_EVENTS_FILENAME)
    count_present = _artifact_present(run_dir / PROXY_EVENTS_COUNT_FILENAME)
    summary_destroyed = summary_present and raw_summary is None
    events_destroyed = events_present and not raw_proxy_events
    degraded_present = _artifact_present(run_dir / AUDIT_DEGRADED_FILE)
    degraded_destroyed = degraded_present and raw_audit_degraded is None
    # The audit-degraded marker joins the existence gate: an unaudited
    # fallback naturally produces exactly "no summary, no proxy events,
    # marker only", and returning None here would silently launder
    # "audit failed, no other telemetry" into no-report. A marker-only
    # run must yield a report carrying the degradation caveat.
    # A surviving count sidecar with the events file gone is the
    # whole-file-deletion shape: events were written, then erased.
    # It must drive a (tampered) report, never silence.
    # The parent-memory persist mirror joins the gate too: a target
    # that erased BOTH the events file and its count sidecar leaves
    # the on-disk artifacts consistent-empty (the sidecar mechanism's
    # documented residual) — in-lifecycle, the parent's own record
    # says events existed, and silence would launder the erasure.
    _pm_persist = get_proxy_persist_state(run_dir)
    if (raw_summary is None and not raw_proxy_events
            and raw_audit_degraded is None and not marker_restored):
        if not allow_legacy and (summary_destroyed or events_destroyed
                                 or degraded_destroyed or count_present
                                 or (_pm_persist or {}).get(
                                     "expected_count")):
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
    # With no usable key the sidecar cannot verify for anyone —
    # operator-side condition, not tampering; the count check is
    # skipped and the provenance_unavailable signal carries it.
    proxy_events, rejected_events, events_integrity, count_note = (
        _verify_proxy_events(
            raw_proxy_events, _run_binding, allow_legacy=_verify_legacy,
            count_record=(None if provenance_unavailable
                          else raw_events_count),
            over_bound=events_over_bound))
    # Parent-memory floor over the sidecar cross-check (one-way: it
    # may condemn a shortened/erased stream, never excuse anything a
    # verifier already flagged). Covers the residual the on-disk
    # mechanism documents: simultaneous erasure of the events file
    # AND its sidecar is on-disk-consistent, but the parent's own
    # in-process record still knows how many lines it wrote.
    if _pm_persist:
        _pm_expected = int(_pm_persist.get("expected_count") or 0)
        _pm_found = len(raw_proxy_events or [])
        if _pm_expected and _pm_found < _pm_expected:
            events_integrity = _INTEGRITY_TAMPERED
            if not count_note:
                count_note = (
                    f"proxy-events stream is short of the parent-"
                    f"memory written count ({_pm_found} on disk, "
                    f"{_pm_expected} persisted by this process) — "
                    f"erasure of the events file"
                    + ("" if count_present
                       else " and its count sidecar"))
        _pm_flags = [f for f in _pm_persist.get("flags") or []]
        if _pm_flags and events_integrity != _INTEGRITY_TAMPERED:
            events_integrity = _INTEGRITY_TAMPERED
            if not count_note:
                count_note = (
                    "writer-flagged proxy-events tampering "
                    "(parent-memory record): "
                    + ", ".join(sorted(_pm_flags)))

    audit_degraded, degraded_integrity = (
        _verify_audit_degraded(
            raw_audit_degraded, _run_binding, allow_legacy=_verify_legacy))

    # Key-exposure posture gate: a verifying token only narrows to
    # "written by the parent" when the run's sandbox posture could
    # hide the telemetry-MAC key from the child (mount namespace or
    # restrict_reads read allowlist — see telemetry_mac's module
    # docstring). On a read-unrestricted run the target could read the
    # key and mint valid tokens itself, so "verified" would overstate:
    # demote to the legacy tier, clearly flagged below. The posture
    # comes from parent memory (record_run_posture — out of the
    # target's reach); the copy persisted inside the summary is only
    # as trustworthy as the key itself, so it is trusted ONE-WAY: an
    # on-disk "exposed" claim may demote (no attacker gains from
    # forging it), an on-disk "hidden" claim proves nothing and never
    # upgrades. Unknown posture (fresh-process re-triage, runs
    # predating posture wiring) keeps today's behaviour.
    posture = get_run_posture(run_dir)
    posture_source = "parent-memory" if posture is not None else None
    if posture is None:
        _disk_posture = (summary or {}).get("posture")
        if (isinstance(_disk_posture, dict)
                and not _disk_posture.get("mac_key_hidden", True)):
            posture = dict(_disk_posture)
            posture_source = "summary"
    key_exposed = (posture is not None
                   and not posture.get("mac_key_hidden", True))
    key_demoted: list[str] = []
    if key_exposed:
        if (raw_summary is not None
                and summary_integrity == _INTEGRITY_VERIFIED):
            summary_integrity = _INTEGRITY_LEGACY
            key_demoted.append("sandbox_summary")
        if raw_proxy_events and events_integrity == _INTEGRITY_VERIFIED:
            events_integrity = _INTEGRITY_LEGACY
            key_demoted.append("proxy_events")
        if (raw_audit_degraded is not None
                and degraded_integrity == _INTEGRITY_VERIFIED):
            degraded_integrity = _INTEGRITY_LEGACY
            key_demoted.append("audit_degraded")

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

    signals: list[dict[str, Any]] = []
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
        if degraded_destroyed:
            destroyed.append("audit_degraded")
            degraded_integrity = _INTEGRITY_TAMPERED
    # A restored marker means the parent WROTE the degradation marker
    # and something in the target-writable run dir later removed or
    # altered it — deletion of tamper-relevant evidence, regardless of
    # legacy mode (the restore record lives in parent memory, so it can
    # only be genuine). The restored content itself still feeds the
    # degradation caveat below; the integrity demotion carries the
    # deletion signal.
    if marker_restored:
        degraded_integrity = _INTEGRITY_TAMPERED

    integrity = {
        "sandbox_summary": summary_integrity,
        "proxy_events": events_integrity,
        "audit_degraded": degraded_integrity,
    }
    tampered = [name for name, state in integrity.items()
                if state == _INTEGRITY_TAMPERED]
    if tampered:
        restored = ["audit_degraded"] if marker_restored else []
        evidence = [f"{name}: provenance verification failed"
                    for name in sorted(set(tampered) - set(destroyed)
                                       - set(restored))]
        evidence += [
            f"{name}: file present but yielded no readable content "
            f"(destroyed/replaced)" for name in sorted(destroyed)]
        if marker_restored:
            evidence.append(
                "audit_degraded: marker written by the parent was "
                "missing/altered in the run dir and was restored from "
                "parent memory (evidence deletion)")
        if rejected_events:
            evidence.append(
                f"{rejected_events} proxy event(s) rejected "
                f"(missing/invalid provenance token)")
        if count_note:
            evidence.append(count_note)
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

    report: dict[str, Any] = {
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
            "mac_key_posture": (
                {**posture, "source": posture_source}
                if posture is not None else "unknown"),
        },
        "audit_degraded": audit_degraded is not None,
        "caveats": [],
    }
    legacy = sorted(name for name, state in integrity.items()
                    if state == _INTEGRITY_LEGACY
                    and name not in key_demoted)
    if legacy:
        report["caveats"].append(
            "Unstamped telemetry accepted at face value: "
            + ", ".join(legacy)
            + " carry no provenance token (pre-provenance run or no "
            "usable telemetry-mac key). The run dir is writable by "
            "the sandboxed target, so treat this verdict with "
            "correspondingly lower confidence."
        )
    if key_demoted:
        report["caveats"].append(
            "Telemetry provenance demoted to unverified/legacy tier: "
            + ", ".join(sorted(key_demoted))
            + " carry valid tokens, but this run's sandbox posture "
            "could not hide the telemetry-mac key from the target "
            "(no mount namespace and no restrict_reads read "
            "allowlist), so the target could have read the key and "
            "minted valid tokens itself. Token verification proves "
            "nothing for this run — treat these inputs with the same "
            "confidence as unstamped telemetry."
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

def _check_escape_primitive(denials: list[dict]) -> list[dict]:
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


def _check_hostile_syscall_args(denials: list[dict]) -> list[dict]:
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


def _check_seccomp_unattributed(denials: list[dict]) -> list[dict]:
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


def _check_resolved_ip_screened(proxy_events: list[dict]) -> list[dict]:
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


def _check_host_recon(proxy_events: list[dict], threshold: int) -> list[dict]:
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


def _check_credential_path_touch(denials: list[dict]) -> list[dict]:
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


def _check_volume_anomaly(summary: dict | None,
                           budget_markers: list[dict]) -> list[dict]:
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


def _derive_verdict(signals: list[dict]) -> str:
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


def _read_bounded(path: Path) -> bytes | None:
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


def _load_json(path: Path) -> dict | None:
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


# Streaming bounds for the proxy-events JSONL specifically. The count
# sidecar defence makes honest very-chatty streams legitimate at sizes
# the whole-file _read_bounded refuses (its 64 MiB bound buffers the
# entire input) — per-line MACs make incremental verification safe, so
# the events file is streamed line-by-line instead: constant memory
# per line, a per-line cap (an oversize line is skipped exactly like a
# corrupt one), and generous cumulative caps that bound a hostile
# planted file without misgrading honest chatty runs. Past the
# cumulative caps the parsed prefix is still returned and the caller
# fails toward suspicious with a DISTINCT over-bound note — never the
# truncation/erasure note.
_MAX_EVENT_LINE_BYTES = 64 * 1024
_MAX_EVENTS_STREAM_BYTES = 512 * 1024 * 1024
_MAX_EVENTS_PARSED = 500_000


def _load_jsonl_stream(path: Path) -> tuple[list[dict], bool]:
    """Stream-parse a JSONL file under the streaming bounds.

    Returns ``(events, over_bound)``. Same open discipline as
    ``_read_bounded`` (O_NOFOLLOW + O_NONBLOCK at open, fstat
    regular-file check) but never buffers the whole file.
    ``over_bound`` is True when input continued past a cumulative cap
    — the returned events are the verified-parseable prefix."""
    try:
        fd = os.open(
            str(path),
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        )
    except OSError:
        return [], False
    out: list[dict] = []
    over_bound = False
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return [], False
        carry = b""
        skipping_oversize_line = False
        total = 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            total += len(chunk)
            carry += chunk
            while True:
                nl = carry.find(b"\n")
                if nl < 0:
                    break
                line, carry = carry[:nl], carry[nl + 1:]
                if skipping_oversize_line:
                    # Tail of a line that already blew the per-line
                    # cap — resynchronise at this newline.
                    skipping_oversize_line = False
                    continue
                _parse_jsonl_line(line, out)
                if len(out) >= _MAX_EVENTS_PARSED:
                    over_bound = True
                    return out, over_bound
            if len(carry) > _MAX_EVENT_LINE_BYTES:
                # Oversize line: drop what we have and skip to the
                # next newline (same treatment as a corrupt line).
                carry = b""
                skipping_oversize_line = True
            if total >= _MAX_EVENTS_STREAM_BYTES:
                over_bound = True
                return out, over_bound
        if carry and not skipping_oversize_line:
            _parse_jsonl_line(carry, out)
        return out, over_bound
    except OSError:
        return out, over_bound
    finally:
        os.close(fd)


def _parse_jsonl_line(line: bytes, out: list[dict]) -> None:
    line = line.strip()
    if not line or len(line) > _MAX_EVENT_LINE_BYTES:
        return
    try:
        record = json.loads(line.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return
    if isinstance(record, dict):
        out.append(record)



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


def _cli_main(argv: list | None = None) -> int:
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

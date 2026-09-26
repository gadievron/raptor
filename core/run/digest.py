"""Shared run-digest reader + renderers.

ONE reader over a run directory's existing artifacts, consumed by both
operator introspection surfaces so they can never drift apart:

* ``raptor-run-status`` — read-only LIVE view of a run (phase,
  heartbeat age, spend vs cap, breaker/retry counts);
* the end-of-run digest — the ranked "what matters" summary printed at
  /agentic completion and served by ``raptor-review digest``.

Artifacts read (all optional — every layer degrades to absent):

* ``.raptor-run.json`` via :func:`core.run.metadata.load_run_metadata`
  (status / timestamps / ``extra`` counters / error);
* ``llm-telemetry.jsonl`` via the bounded JSONL reader (call /
  failed-attempt / breaker-trip counters, live cost sum, last event);
* ``cost-breakdown.json`` + ``spend-floor.json`` + the journal floor
  via :func:`core.audit.resume.resolve_prior_spend`, and the run's cap
  from ``audit-run-config.json`` where one exists;
* findings artifacts via
  :func:`core.project.findings_utils.load_findings_from_dir` +
  tri-state verdict reads (:mod:`core.run.finding_status`);
* oracle-verified outcomes via
  :func:`core.labeled_attempts.view.collect_outcomes`;
* ``suppressions.jsonl`` counts;
* the coverage store view (:mod:`core.coverage.store_summary`);
* deferred-tail operator hints via
  :func:`core.audit.resume.pipeline_tail_hint`.

Heartbeat is the existing mtime convention (there is no heartbeat
file): the freshest mtime across the run dir and its immediate
children, bounded — appenders like the telemetry sink and the journal
touch the dir's children on every event.

Every value read here comes out of the sandbox-writable run dir —
attacker bytes. The reader keeps them raw (JSON consumers get exact
values); the RENDERERS in this module escape at render
(``core.security.log_sanitisation``) before any terminal output, so
CLIs printing these strings verbatim stay inside the audited-writer
contract.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.logging import get_logger
from core.security.log_sanitisation import sanitise_for_terminal

logger = get_logger()

# Bounded reads: telemetry / suppressions are append-only JSONL in a
# child-writable dir; the shared 64 MiB artifact convention applies.
_MAX_JSONL_BYTES = 64 * 1024 * 1024
# Immediate-children heartbeat scan bound — a run dir with thousands
# of entries still answers in one readdir pass.
_HEARTBEAT_SCAN_CAP = 4096
# Digest listing caps (rendering; the counts stay exact).
_MAX_LISTED = 10

_TERMINAL_NONE = "unknown"


@dataclass
class RunDigest:
    """Everything both introspection surfaces need, read once."""

    run_dir: Path
    # lifecycle (.raptor-run.json)
    command: str = _TERMINAL_NONE
    status: str = _TERMINAL_NONE
    timestamp: str = ""
    end_timestamp: str | None = None
    duration_seconds: float | None = None
    error: str | None = None
    heartbeat_age_s: float | None = None
    # spend
    spend_usd: float | None = None
    spend_note: str = ""
    max_cost_usd: float | None = None
    # telemetry counters
    llm_calls: int = 0
    llm_failed_attempts: int = 0
    llm_timeouts: int = 0
    breaker_trips: int = 0
    last_call_class: str | None = None
    last_call_ts: str | None = None
    # findings
    findings_total: int | None = None
    verified: list[dict[str, Any]] = field(default_factory=list)
    exploitable_unverified: list[dict[str, Any]] = field(
        default_factory=list)
    # suppressions
    suppressed_dropped: int = 0
    suppression_verdicts: dict[str, int] = field(default_factory=dict)
    # coverage
    coverage_percent: float | None = None
    # operator hints (already operator-authored text or built here
    # from constants + paths)
    next_steps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = dict(self.__dict__)
        d["run_dir"] = str(self.run_dir)
        return d


def last_activity_age_s(run_dir: Path) -> float | None:
    """Seconds since the freshest mtime across the run dir and its
    immediate children (bounded readdir) — the run-liveness mtime
    convention. ``None`` when the dir cannot be statted."""
    try:
        latest = run_dir.stat().st_mtime
    except OSError:
        return None
    try:
        with os.scandir(run_dir) as it:
            for i, entry in enumerate(it):
                if i >= _HEARTBEAT_SCAN_CAP:
                    break
                try:
                    mtime = entry.stat(follow_symlinks=False).st_mtime
                except OSError:
                    continue
                latest = max(latest, mtime)
    except OSError:
        pass
    return max(0.0, time.time() - latest)


def _read_lifecycle(digest: RunDigest) -> None:
    from core.run.metadata import load_run_metadata
    meta = load_run_metadata(digest.run_dir)
    if not isinstance(meta, dict):
        return
    digest.command = str(meta.get("command") or _TERMINAL_NONE)
    digest.status = str(meta.get("status") or _TERMINAL_NONE)
    digest.timestamp = str(meta.get("timestamp") or "")
    end = meta.get("end_timestamp")
    digest.end_timestamp = str(end) if end else None
    dur = meta.get("duration_seconds")
    if isinstance(dur, (int, float)) and not isinstance(dur, bool):
        digest.duration_seconds = float(dur)
    extra = meta.get("extra")
    if isinstance(extra, dict):
        err = extra.get("error")
        if isinstance(err, str) and err:
            digest.error = err
        fc = extra.get("findings_count")
        if isinstance(fc, int) and not isinstance(fc, bool):
            digest.findings_total = fc
    if digest.status == "running":
        digest.heartbeat_age_s = last_activity_age_s(digest.run_dir)


def _read_spend(digest: RunDigest) -> None:
    try:
        from core.audit.resume import (
            load_run_config,
            resolve_prior_spend,
        )
        booked, note = resolve_prior_spend(digest.run_dir)
        cfg = load_run_config(digest.run_dir) or {}
        cap = cfg.get("max_cost_usd")
        if isinstance(cap, (int, float)) and not isinstance(cap, bool) \
                and cap > 0:
            digest.max_cost_usd = float(cap)
    except Exception:  # noqa: BLE001 — layer readers degrade to absent
        logger.debug("digest: spend layer unreadable", exc_info=True)
        return
    if booked > 0:
        digest.spend_usd = booked
        digest.spend_note = note


def _telemetry_ts(value: Any) -> str | None:
    """Displayable timestamp from a telemetry record's ``ts``.

    The sink stamps ``ts`` as an epoch FLOAT (``time.time()``);
    resume markers and foreign rows may carry ISO strings. Numeric
    values render as ISO UTC; strings pass through; anything else is
    dropped.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        from datetime import datetime, timezone
        try:
            return datetime.fromtimestamp(
                float(value), tz=timezone.utc,
            ).isoformat(timespec="seconds")
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str) and value:
        return value
    return None


def _read_telemetry(digest: RunDigest) -> None:
    from core.llm.telemetry import TELEMETRY_FILENAME
    path = digest.run_dir / TELEMETRY_FILENAME
    if not path.is_file():
        return
    from core.json.jsonl import load_jsonl
    records = load_jsonl(path, max_total_bytes=_MAX_JSONL_BYTES)
    live_cost = 0.0
    for rec in records:
        if not isinstance(rec, dict):
            continue
        event = rec.get("event")
        cost = rec.get("cost_usd")
        if isinstance(cost, (int, float)) and not isinstance(cost, bool):
            live_cost += max(0.0, float(cost))
        if event == "call":
            digest.llm_calls += 1
        elif event == "attempt_failed":
            digest.llm_failed_attempts += 1
            if rec.get("disposition") == "timeout":
                digest.llm_timeouts += 1
        elif event == "breaker_tripped":
            digest.breaker_trips += 1
            continue  # run_breaker is not a phase hint
        else:
            continue
        # Phase hint: the newest call-shaped record's class + ts,
        # updated together so the pair never mixes two records.
        cc = rec.get("call_class")
        if isinstance(cc, str) and cc:
            digest.last_call_class = cc
            digest.last_call_ts = _telemetry_ts(rec.get("ts"))
    # The telemetry sum is the ONLY spend source when no ledger was
    # ever reconciled (plain /agentic runs). On a RUNNING run it may
    # also run ahead of the last reconciliation — surface whichever
    # books more. On a terminal run an existing ledger is
    # authoritative (reconciliation corrects naive per-record
    # double-counting), so it is never overridden.
    if live_cost > 0 and (
        digest.spend_usd is None
        or (digest.status == "running" and live_cost > digest.spend_usd)
    ):
        digest.spend_usd = live_cost
        digest.spend_note = "live telemetry sum"


def _finding_line(finding: dict[str, Any]) -> dict[str, Any]:
    from core.project.findings_utils import finding_file, get_finding_id
    line = finding.get("line")
    if not isinstance(line, int) or isinstance(line, bool):
        line = None
    return {
        "finding_id": get_finding_id(finding) or "",
        "file": finding_file(finding),
        "line": line,
        "vuln_type": str(finding.get("vuln_type")
                         or finding.get("rule_id")
                         or finding.get("check_id") or ""),
    }


def _is_exploitable(finding: dict[str, Any]) -> bool:
    # The repo's verdict vocabulary — imported, never copied (the
    # digest must classify exactly like the project report/correlate
    # views, or a status they show as confirmed reads here as an
    # all-clear).
    from core.project.correlate import (
        NEGATIVE_VERDICTS,
        POSITIVE_VERDICTS,
    )
    from core.run.finding_status import read_verdict

    # A post-validation ruling slot is authoritative when present.
    # Negative-set INVERSION, not positive-set membership: the
    # confirm-direction vocabulary grows (confirmed_unverified,
    # likely_exploitable, ...) and a new positive status missed here
    # would render as a false all-clear — the worst failure
    # direction for an end-of-run digest. Anything not explicitly
    # ruled out stays in the operator's face.
    for slot in (
        finding.get("final_status"),
        (finding.get("ruling") or {}).get("status")
        if isinstance(finding.get("ruling"), dict) else None,
    ):
        if isinstance(slot, str) and slot:
            return slot not in NEGATIVE_VERDICTS
    if read_verdict(finding, "is_exploitable") is True:
        return True
    analysis = finding.get("analysis")
    if isinstance(analysis, dict) and \
            read_verdict(analysis, "is_exploitable") is True:
        return True
    # The plain ``status`` key doubles as a LIFECYCLE enum on
    # orchestrated records (analysed / skipped / error), so only a
    # recognised POSITIVE verdict word counts here — inversion would
    # read every analysed record as exploitable.
    status = finding.get("status")
    return isinstance(status, str) and status in POSITIVE_VERDICTS


def _collect_findings(run_dir: Path) -> list[dict[str, Any]]:
    """Per-finding records across the run-type shapes, merged by id.

    Source order builds precedence: raw findings files first, then
    the orchestrated per-finding results (an /agentic run has NO
    top-level findings.json — its verdicts live in
    orchestrated_report.json), then the /validate outcome records
    (post-validation status overrides an earlier exploitable claim —
    a ruled-out finding must not resurface in the digest). Later
    sources REPLACE earlier records with the same id; id-less records
    ride along unmerged.
    """
    from core.project.findings_utils import (
        MAX_FINDINGS_JSON_BYTES,
        get_finding_id,
        load_findings_from_dir,
    )
    by_id: dict[str, dict[str, Any]] = {}
    idless: list[dict[str, Any]] = []

    def _fold(records: list[Any]) -> None:
        for f in records:
            if not isinstance(f, dict):
                continue
            fid = get_finding_id(f)
            if isinstance(fid, str) and fid:
                by_id[fid] = f
            else:
                idless.append(f)

    try:
        _fold(load_findings_from_dir(run_dir))
    except Exception:  # noqa: BLE001 — layer readers degrade to absent
        logger.debug("digest: findings files unreadable", exc_info=True)
    from core.json import load_json
    for rel in ("orchestrated_report.json", "validation/findings.json"):
        path = run_dir / rel
        if not path.is_file():
            continue
        data = load_json(path, max_bytes=MAX_FINDINGS_JSON_BYTES)
        if isinstance(data, list):
            _fold(data)
        elif isinstance(data, dict):
            for key in ("findings", "results"):
                rows = data.get(key)
                if isinstance(rows, list):
                    _fold(rows)
                    break
    return list(by_id.values()) + idless


def _read_findings(digest: RunDigest) -> None:
    findings = _collect_findings(digest.run_dir)
    if findings and digest.findings_total is None:
        digest.findings_total = len(findings)

    verified_ids: set[str] = set()
    verified_files: set[str] = set()
    try:
        from core.labeled_attempts.view import collect_outcomes
        for outcome in collect_outcomes(digest.run_dir):
            if getattr(outcome, "status", "") != "verified":
                continue
            fid = str(getattr(outcome, "finding_id", "") or "")
            vfile = str(getattr(outcome, "file", "") or "")
            if fid:
                verified_ids.add(fid)
            elif vfile:
                # Id-less outcome: fall back to file-level dedup so
                # the same defect never counts under BOTH headings.
                verified_files.add(vfile)
            digest.verified.append({
                "finding_id": fid,
                "oracle": str(getattr(outcome, "oracle", "") or ""),
                "cwe_id": str(getattr(outcome, "cwe_id", "") or ""),
                "file": vfile,
            })
    except Exception:  # noqa: BLE001 — layer readers degrade to absent
        logger.debug("digest: outcomes layer unreadable", exc_info=True)

    for f in findings:
        if not isinstance(f, dict) or not _is_exploitable(f):
            continue
        row = _finding_line(f)
        if row["finding_id"] and row["finding_id"] in verified_ids:
            continue
        if not row["finding_id"] and row["file"] in verified_files:
            continue
        digest.exploitable_unverified.append(row)


def _read_suppressions(digest: RunDigest) -> None:
    path = digest.run_dir / "suppressions.jsonl"
    if not path.is_file():
        return
    from core.json.jsonl import load_jsonl
    for rec in load_jsonl(path, max_total_bytes=_MAX_JSONL_BYTES):
        if not isinstance(rec, dict):
            continue
        verdict = str(rec.get("verdict") or "unknown")
        # dropped defaults True for legacy records (the writer's
        # documented back-compat).
        if bool(rec.get("dropped", True)):
            digest.suppressed_dropped += 1
            digest.suppression_verdicts[verdict] = (
                digest.suppression_verdicts.get(verdict, 0) + 1)


def _read_coverage(digest: RunDigest) -> None:
    try:
        from core.coverage.store_summary import (
            coverage_view,
            store_llm_coverage_percent,
        )
        from core.inventory import read_checklist
        run = digest.run_dir
        view = coverage_view(
            [run],
            read_checklist(run) or None,
            run / "coverage.json",
            annotations_base=run / "annotations",
        )
        if view and view.get("llm_reviewable"):
            digest.coverage_percent = store_llm_coverage_percent(view)
    except Exception:  # noqa: BLE001 — layer readers degrade to absent
        logger.debug("digest: coverage layer unreadable", exc_info=True)


def _read_next_steps(digest: RunDigest) -> None:
    try:
        from core.audit.resume import pipeline_tail_hint
        hint = pipeline_tail_hint(
            digest.run_dir, digest.findings_total or 0)
        if hint:
            digest.next_steps.append(hint)
    except Exception:  # noqa: BLE001 — layer readers degrade to absent
        logger.debug("digest: tail-hint layer unreadable", exc_info=True)
    if digest.exploitable_unverified:
        findings_path = digest.run_dir / "findings.json"
        if findings_path.is_file():
            digest.next_steps.append(
                f"Validate the {len(digest.exploitable_unverified)} "
                f"exploitable-unverified finding(s): /validate "
                f"<target> --findings {findings_path}"
            )
    if digest.suppressed_dropped:
        digest.next_steps.append(
            "Review suppressed findings: jq -c . "
            f"{digest.run_dir / 'suppressions.jsonl'} — overturn one "
            "with: raptor-review verdict <finding-id> tp"
        )


def read_run_digest(run_dir: Path) -> RunDigest:
    """Read every digest layer from ``run_dir``. Never raises — each
    layer degrades to its absent default independently."""
    digest = RunDigest(run_dir=Path(run_dir))
    for layer in (_read_lifecycle, _read_spend, _read_telemetry,
                  _read_findings, _read_suppressions, _read_coverage,
                  _read_next_steps):
        try:
            layer(digest)
        except Exception:  # noqa: BLE001 — one broken layer must not hide the rest
            logger.debug("digest: %s failed", layer.__name__,
                         exc_info=True)
    return digest


# ── Rendering ────────────────────────────────────────────────────────
#
# Escape-at-render: every run-artifact string (status, error text,
# call classes, finding paths / ids / types, hint text) is rendered
# through sanitise_for_terminal before joining terminal output.

def _line(value: Any, max_len: int = 160) -> str:
    """One sanitised terminal-safe line for a run-artifact value."""
    text = " ".join(str(value if value is not None else "").split())
    return sanitise_for_terminal(text, max_len=max_len)


def _title(status: str) -> str:
    """snake_case status → Title Case for human output."""
    return " ".join(w.capitalize() for w in str(status).split("_")) \
        or _TERMINAL_NONE.capitalize()


def _age(seconds: float | None) -> str:
    if seconds is None:
        return _TERMINAL_NONE
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m{s % 60:02d}s"
    return f"{s // 3600}h{(s % 3600) // 60:02d}m"


def render_run_status(digest: RunDigest) -> str:
    """The live-introspection view (``raptor-run-status``)."""
    lines: list[str] = []
    lines.append(f"Run:       {_line(digest.run_dir, max_len=200)}")
    lines.append(f"Command:   {_line(digest.command, max_len=60)}")
    status_line = f"Status:    {_line(_title(digest.status), max_len=60)}"
    if digest.status == "running":
        status_line += f"  (heartbeat {_age(digest.heartbeat_age_s)} ago)"
    elif digest.duration_seconds is not None:
        status_line += f"  ({_age(digest.duration_seconds)})"
    lines.append(status_line)
    if digest.error:
        lines.append(f"Error:     {_line(digest.error, max_len=300)}")

    if digest.spend_usd is not None:
        spend = f"Spend:     ${digest.spend_usd:.2f}"
        if digest.max_cost_usd:
            pct = 100.0 * digest.spend_usd / digest.max_cost_usd
            spend += f" of ${digest.max_cost_usd:.2f} cap ({pct:.0f}%)"
        if digest.spend_note:
            spend += f"  [{_line(digest.spend_note, max_len=80)}]"
        lines.append(spend)
    elif digest.max_cost_usd:
        lines.append(f"Spend:     none booked of "
                     f"${digest.max_cost_usd:.2f} cap")

    if digest.llm_calls or digest.llm_failed_attempts \
            or digest.breaker_trips:
        llm = (f"LLM:       {digest.llm_calls} call(s), "
               f"{digest.llm_failed_attempts} failed attempt(s)")
        if digest.llm_timeouts:
            llm += f" ({digest.llm_timeouts} timeout(s))"
        if digest.breaker_trips:
            llm += f", {digest.breaker_trips} breaker trip(s)"
        lines.append(llm)
        if digest.last_call_class:
            last = (f"Last call: {_line(digest.last_call_class, max_len=60)}")
            if digest.last_call_ts:
                last += f" at {_line(digest.last_call_ts, max_len=40)}"
            lines.append(last)

    if digest.findings_total is not None:
        counts = f"Findings:  {digest.findings_total}"
        if digest.verified:
            counts += f", {len(digest.verified)} verified"
        if digest.exploitable_unverified:
            counts += (f", {len(digest.exploitable_unverified)} "
                       "exploitable-unverified")
        lines.append(counts)
    if digest.suppressed_dropped:
        lines.append(f"Suppressed: {digest.suppressed_dropped} "
                     "finding(s) pre-LLM")
    if digest.coverage_percent is not None:
        lines.append(f"Coverage:  {digest.coverage_percent:.1f}% of "
                     "reviewable units")
    return "\n".join(lines)


def render_run_digest(digest: RunDigest) -> str:
    """The ranked end-of-run "what matters" summary."""
    lines: list[str] = []
    header = (f"What matters — {_line(digest.command, max_len=60)} run, "
              f"{_line(_title(digest.status), max_len=40)}")
    if digest.spend_usd is not None:
        header += f", ${digest.spend_usd:.2f}"
    lines.append(header)

    if digest.verified:
        lines.append("")
        lines.append(f"  Verified ({len(digest.verified)}):")
        for v in digest.verified[:_MAX_LISTED]:
            lines.append(
                f"    ✓ {_line(v.get('finding_id'), max_len=60)}  "
                f"{_line(v.get('file'), max_len=90)}  "
                f"[{_line(v.get('oracle'), max_len=30)}"
                + (f", {_line(v.get('cwe_id'), max_len=20)}"
                   if v.get("cwe_id") else "") + "]")
        if len(digest.verified) > _MAX_LISTED:
            lines.append(f"    … {len(digest.verified) - _MAX_LISTED} "
                         "more")

    if digest.exploitable_unverified:
        lines.append("")
        lines.append(f"  Exploitable, unverified "
                     f"({len(digest.exploitable_unverified)}):")
        for row in digest.exploitable_unverified[:_MAX_LISTED]:
            loc = _line(row.get("file"), max_len=90)
            if row.get("line"):
                loc += f":{row['line']}"
            lines.append(
                f"    ⚠️ {_line(row.get('finding_id'), max_len=60)}  {loc}"
                + (f"  {_line(row.get('vuln_type'), max_len=50)}"
                   if row.get("vuln_type") else ""))
        if len(digest.exploitable_unverified) > _MAX_LISTED:
            lines.append(
                f"    … {len(digest.exploitable_unverified) - _MAX_LISTED}"
                " more")

    if not digest.verified and not digest.exploitable_unverified:
        lines.append("")
        lines.append("  No verified or exploitable-unverified findings.")

    if digest.suppressed_dropped:
        lines.append("")
        parts = ", ".join(
            f"{count} {_line(verdict, max_len=50)}"
            for verdict, count in sorted(
                digest.suppression_verdicts.items(),
                key=lambda kv: -kv[1])[:6])
        lines.append(f"  Suppressed pre-LLM: {digest.suppressed_dropped}"
                     f" ({parts})")

    if digest.coverage_percent is not None:
        lines.append("")
        lines.append(f"  Coverage: {digest.coverage_percent:.1f}% of "
                     "reviewable units")

    if digest.next_steps:
        lines.append("")
        lines.append("  Next steps:")
        for step in digest.next_steps:
            # Multi-line hints (pipeline_tail_hint) keep their line
            # structure; each LINE is sanitised individually.
            for i, part in enumerate(str(step).splitlines() or [""]):
                prefix = "    - " if i == 0 else "      "
                lines.append(prefix + _line(part, max_len=500))
    return "\n".join(lines)


__all__ = [
    "RunDigest",
    "last_activity_age_s",
    "read_run_digest",
    "render_run_digest",
    "render_run_status",
]

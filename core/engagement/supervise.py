"""Engagement supervisor — the full resume/park loop over one ledger.

Composes the EXISTING engagement machinery into the one unattended
loop the chain launcher deliberately does not own: depth policy +
budget governor (``core.engagement.governor``), the per-artifact
chain (``core.engagement.chain_elf``), and the durable park/resume
contract. Nothing here analyses anything — the supervisor sequences,
reserves, reconciles, parks, and reports.

NAME NOTE: ``core.run.supervisor`` is the pre-existing capped-shell
wall-bound module (are we under a supervisor SHELL, and what bound
should a long run take?). This module is the engagement's own
supervisor and REUSES that bound math (`supervisor_wall_bound`) — it
never twins it.

Contract (operator-schedulable, cron-safe):

* ``supervise(out)`` launches a fresh engagement exactly once;
  ``supervise(out, resume=True)`` is IDEMPOTENT — a complete
  engagement reports nothing-to-do forever, a parked one reports its
  parks without mutating them, an advanceable one advances.
* Distinct exit codes: ``RC_OK`` advanced, ``RC_FAILED`` segment
  failure (a re-run resumes), ``RC_USAGE`` caller error,
  ``RC_NOTHING`` complete, ``RC_PARKED`` parked — an operator
  acknowledgment is required, ``RC_DRAINED`` paused at a safe
  boundary (drain request or wall bound) — auto-resumable.
* Budgets persist at launch: ``--envelope`` lands on the ledger
  policy block (``governor.set_envelope``), ``--max-cost`` in the
  supervisor state — a bare ``--resume`` keeps enforcing both.
  Passing either flag on a resume REPLACES the persisted figure and
  records the replacement (residual map; policy amendment for the
  envelope). A supervisor that only enforced the launch shell's
  argv would run every cron re-entry uncapped.
* Parks are STICKY and never silent (M5): every park mints a park-id
  in the durable registry, refreshes the ``PARKED`` marker the
  project status view surfaces, and writes an interim report. Only
  ``--resume --acknowledge <park-id>`` (or ``--accept-code-drift``
  for code-drift parks) clears one; the automatic resume machinery
  touches segment-death states only.
* Code pinning (M6): launch records the framework's source-control
  snapshot plus the models-config hash; a resume under moved code
  parks ("code moved under the engagement") unless
  ``accept_code_drift`` records the acceptance in the residual map.
* Drain citizenship: at every segment boundary the supervisor honors
  the session ledger's drain-request records
  (``core.project.sessions.ledger_drain_requests``) — pause, clear
  the request, report, ``RC_DRAINED``.
* One live supervisor per engagement directory: the audit run-lock
  discipline (flock + identity-stamp dead-holder reclamation via
  ``boot_id`` — reboots read provably dead) on this family's OWN
  lock file.

The supervisor is unattended machinery: it parks, it never asks. It
spawns nothing itself — every subprocess ride goes through the chain
module's audited dispatch seam.
"""

from __future__ import annotations

import hashlib
import logging
import math
import secrets
import time
from pathlib import Path
from typing import Any

from core.engagement import chain_elf, governor
from core.engagement.ledger import (
    append_policy_amendment,
    append_residual,
    is_artifact_id,
    load_ledger,
    render_status_lines,
    set_artifact_policy,
    set_artifact_status,
    update_engagement_policy,
)
from core.atomic_fs.fs_lock import artifact_lock
from core.json import load_json, save_json

logger = logging.getLogger(__name__)

RC_OK = 0        # advanced / resumed work
RC_FAILED = 1    # segment failure — a re-run resumes
RC_USAGE = 2     # caller error
RC_NOTHING = 3   # nothing to do — engagement complete
RC_PARKED = 4    # parked — operator acknowledgment required
RC_DRAINED = 5   # paused at a safe boundary — auto-resumable

STATE_FILENAME = "engagement-state.json"
PARKS_FILENAME = "engagement-parks.json"
PARKED_MARKER_NAME = "PARKED"
INTERIM_REPORT_FILENAME = "engagement-interim-report.md"
SUPERVISOR_LOCK_NAME = ".engage-supervise.lock"

#: Registry cap — parks are operator-facing events, not a log stream;
#: a loop that mints hundreds is broken. Too low and a long multi-park
#: engagement loses history (each park is one row, acknowledged rows
#: stay); too high just buffers a runaway minter before the refusal.
_MAX_PARKS = 512

#: Defensive read bound for the state/registry/marker files (all
#: machine-written and small; a multi-KiB file here is tampering).
_STATE_MAX_BYTES = 1024 * 1024

#: Pass cap per invocation. Each pass retries only artifacts that
#: failed while OTHER artifacts progressed — so the cap only binds on
#: pathological flip-flopping. Too low and a long schedule needs an
#: extra cron tick to settle (harmless — resume continues); too high
#: and a flip-flopping chain burns wall time inside one invocation
#: instead of yielding to the scheduler.
_MAX_PASSES = 8

#: LLM stage directories under one artifact's chain dir — the spend
#: evidence surfaces ``measured_artifact_spend`` sums over.
_LLM_STAGE_DIRS = ("study", "audit", "audit-rereview")

#: Code-pin fields compared on resume (M6).
_PIN_FIELDS = ("base_sha", "dirty", "diff_sha256", "models_sha256")


def _say(message: str) -> None:
    print(message, flush=True)


def _esc(value: str, max_len: int = 300) -> str:
    from core.security.log_sanitisation import sanitise_for_terminal
    return sanitise_for_terminal(value, max_len=max_len)


def _now() -> str:
    # Z-suffixed (not "+00:00"): these timestamps also land in the
    # ledger's token-validated policy slots, whose charset has no "+".
    from datetime import datetime, timezone
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Durable state (M6 code pin + segment counter) ────────────────────

def state_path(output_dir: Path | str) -> Path:
    return Path(output_dir) / STATE_FILENAME


def load_state(output_dir: Path | str) -> dict[str, Any] | None:
    doc = load_json(state_path(output_dir), max_bytes=_STATE_MAX_BYTES)
    return doc if isinstance(doc, dict) else None


def _save_state(output_dir: Path | str, state: dict[str, Any]) -> None:
    sp = state_path(output_dir)
    with artifact_lock(sp, subject="engagement state"):
        save_json(sp, state)


def _models_config_hash() -> str:
    """sha256 of the models config bytes, or a named sentinel — the
    config steers every LLM stage, so it is part of the code pin."""
    from core.llm.detection import _models_config_path
    path = _models_config_path()
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "unreadable"
    return hashlib.sha256(data).hexdigest()


def code_snapshot() -> dict[str, Any]:
    """The M6 pin: framework source-control snapshot (base sha, dirty
    flag, diff hash — from ``core.run.provenance``) plus the models
    config hash. ``base_sha=None`` means the framework checkout is
    not a verifiable git repo — drift detection degrades to the
    models hash alone (recorded as a residual at pin time)."""
    from core.run.provenance import source_control_snapshot
    snap = source_control_snapshot()
    return {
        "base_sha": snap.get("base_sha"),
        "dirty": snap.get("dirty"),
        "diff_sha256": snap.get("diff_sha256"),
        "models_sha256": _models_config_hash(),
    }


def pin_drift(pin: dict[str, Any],
              current: dict[str, Any]) -> list[str]:
    """The pin fields that changed since launch. An unverifiable pin
    (``base_sha=None`` at launch) compares only the models hash —
    None-vs-None on the git fields is agreement, not drift."""
    changed: list[str] = []
    for field in _PIN_FIELDS:
        if pin.get(field) != current.get(field):
            changed.append(field)
    return changed


# ── Park registry (M5: park is not silence) ──────────────────────────

def parks_path(output_dir: Path | str) -> Path:
    return Path(output_dir) / PARKS_FILENAME


def marker_path(output_dir: Path | str) -> Path:
    return Path(output_dir) / PARKED_MARKER_NAME


def list_parks(output_dir: Path | str) -> list[dict[str, Any]]:
    doc = load_json(parks_path(output_dir), max_bytes=_STATE_MAX_BYTES)
    if not isinstance(doc, dict):
        return []
    parks = doc.get("parks")
    return [p for p in parks if isinstance(p, dict)] \
        if isinstance(parks, list) else []


def unacknowledged_parks(
        output_dir: Path | str,
        scope: str | None = None) -> list[dict[str, Any]]:
    return [p for p in list_parks(output_dir)
            if not p.get("acknowledged_at")
            and (scope is None or p.get("scope") == scope)]


def _write_marker(output_dir: Path | str) -> None:
    """The durable PARKED marker: present iff at least one
    unacknowledged park exists; carries the park summaries the
    project status view surfaces."""
    parks = unacknowledged_parks(output_dir)
    mp = marker_path(output_dir)
    if not parks:
        try:
            mp.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            logger.warning("engagement: stale PARKED marker at %s "
                           "could not be removed", mp)
        return
    save_json(mp, {
        "schema_version": 1,
        "updated_at": _now(),
        "parks": [
            {k: p.get(k) for k in ("park_id", "scope", "kind",
                                   "artifact_id", "reason", "at")
             if p.get(k) is not None}
            for p in parks
        ],
    })


def _registry_append(output_dir: Path | str,
                     park: dict[str, Any]) -> bool:
    pp = parks_path(output_dir)
    with artifact_lock(pp, subject="engagement parks"):
        doc = load_json(pp, max_bytes=_STATE_MAX_BYTES)
        if not isinstance(doc, dict):
            doc = {"schema_version": 1, "parks": []}
        parks = doc.setdefault("parks", [])
        if not isinstance(parks, list) or len(parks) >= _MAX_PARKS:
            return False
        parks.append(park)
        save_json(pp, doc)
    return True


def mint_park(output_dir: Path | str, *, scope: str, kind: str,
              reason: str,
              artifact_id: str | None = None) -> dict[str, Any]:
    """Mint a registry park record (the governor's ledger-side park
    writes — status/residual/amendment — are the CALLER's job where
    they apply; this is the operator-facing identity M5 requires) and
    refresh the marker. Returns the record."""
    park: dict[str, Any] = {
        "park_id": f"park-{secrets.token_hex(4)}",
        "scope": scope,
        "kind": kind,
        "reason": str(reason)[:400],
        "at": _now(),
    }
    if artifact_id is not None:
        park["artifact_id"] = artifact_id
    if not _registry_append(output_dir, park):
        logger.warning("engagement: park registry refused a record "
                       "(cap or corrupt registry) — the ledger park "
                       "still holds")
    _write_marker(output_dir)
    return park


def _stamp_acknowledged(output_dir: Path | str, park_id: str) -> bool:
    pp = parks_path(output_dir)
    with artifact_lock(pp, subject="engagement parks"):
        doc = load_json(pp, max_bytes=_STATE_MAX_BYTES)
        if not isinstance(doc, dict):
            return False
        hit = False
        for p in doc.get("parks") or []:
            if (isinstance(p, dict) and p.get("park_id") == park_id
                    and not p.get("acknowledged_at")):
                p["acknowledged_at"] = _now()
                hit = True
        if hit:
            save_json(pp, doc)
        return hit


def _reset_reservation_deaths(output_dir: Path | str,
                              artifact_id: str) -> None:
    doc = load_ledger(output_dir)
    row = next((r for r in (doc or {}).get("rows") or []
                if isinstance(r, dict)
                and r.get("artifact_id") == artifact_id), None)
    res = row.get("reservation") if isinstance(row, dict) else None
    if not isinstance(res, dict):
        return
    fresh = dict(res)
    fresh["deaths"] = 0
    fresh["updated_at"] = _now()
    set_artifact_policy(output_dir, artifact_id, reservation=fresh)


def acknowledge_park(output_dir: Path | str,
                     park_id: str) -> tuple[bool, str]:
    """Operator acknowledgment of one park (the M5 sticky-park key).
    Engagement-scope: clears the governor's engagement park record.
    Artifact-scope: unparks the row (status back to ``queued``) and
    resets its death counter. Both write an amendment + residual and
    refresh the marker. ``(ok, operator_message)``."""
    park = next((p for p in list_parks(output_dir)
                 if p.get("park_id") == park_id
                 and not p.get("acknowledged_at")), None)
    if park is None:
        # Registry-derived ids are sandbox-writable bytes — escape
        # each one before it joins an operator-facing message.
        known = [_esc(str(p.get("park_id")), 24) for p in
                 unacknowledged_parks(output_dir)]
        return False, (
            f"no unacknowledged park named {_esc(str(park_id), 64)}"
            + (f" — unacknowledged: {', '.join(known)}" if known
               else " — no parks are waiting"))
    if not _stamp_acknowledged(output_dir, park_id):
        return False, "park registry write failed"
    stamped_id = str(park["park_id"])  # registry-minted, token-shaped
    if park.get("scope") == "engagement":
        # Correspondence note: the registry row is the operator-facing
        # identity; the governor's ``policy.parked`` record is the
        # ledger authority. Acknowledging ANY engagement-scope row
        # clears the ledger record, but the sticky gate in
        # ``supervise()`` keeps holding while other engagement-scope
        # rows remain unacknowledged — so acknowledging one planted
        # registry row cannot unpark past a real waiting park.
        update_engagement_policy(output_dir, {"parked": None})
        append_residual(output_dir, "engagement_unparked",
                        f"operator acknowledged {stamped_id}")
        append_policy_amendment(output_dir, {
            "kind": "engagement_unparked", "park_id": stamped_id,
        })
        message = f"engagement park {stamped_id} acknowledged"
    else:
        aid = str(park.get("artifact_id") or "")
        if is_artifact_id(aid):
            set_artifact_status(
                output_dir, aid, "queued",
                detail=f"unparked by operator acknowledgment "
                       f"{stamped_id}")
            _reset_reservation_deaths(output_dir, aid)
            append_residual(output_dir, "artifact_unparked",
                            f"operator acknowledged {stamped_id}",
                            artifact_id=aid)
            append_policy_amendment(output_dir, {
                "kind": "artifact_unparked", "artifact_id": aid,
                "park_id": stamped_id,
            })
        message = (f"artifact park {stamped_id} acknowledged"
                   f" ({_esc(aid, 100)})")
    _write_marker(output_dir)
    return True, message


def _adopt_governor_park(output_dir: Path | str,
                         doc: dict[str, Any]) -> None:
    """An engagement park set by the governor out-of-band (the
    feasibility enforcer, an operator tool) must still carry a
    park-id the operator can acknowledge — mint the registry row when
    none is waiting."""
    if not governor.is_engagement_parked(doc):
        return
    if unacknowledged_parks(output_dir, scope="engagement"):
        return
    block = doc.get("policy") or {}
    parked = block.get("parked") if isinstance(block, dict) else {}
    reason = str((parked or {}).get("reason") or "engagement parked")
    kind = ("feasibility_conflict"
            if reason.startswith("feasibility_conflict")
            else "governor_park")
    mint_park(output_dir, scope="engagement", kind=kind, reason=reason)


def parked_run_line(run_dir: Path | str) -> str | None:
    """One bounded, escaped status line for a run directory carrying
    the PARKED marker (the ``/project status`` surface), or ``None``.
    Marker content is machine-written but run dirs are shared space —
    every shown field is escaped."""
    doc = load_json(marker_path(run_dir), max_bytes=_STATE_MAX_BYTES)
    if not isinstance(doc, dict):
        return None
    parks = [p for p in doc.get("parks") or [] if isinstance(p, dict)]
    if not parks:
        return None
    ids = ", ".join(_esc(str(p.get("park_id") or "?"), 24)
                    for p in parks[:4])
    more = f" +{len(parks) - 4} more" if len(parks) > 4 else ""
    first_reason = _esc(str(parks[0].get("reason") or ""), 120)
    return (f"engagement PARKED — {len(parks)} unacknowledged park(s) "
            f"[{ids}{more}] ({first_reason}) — acknowledge with "
            f"libexec/raptor-engage-supervise <run-dir> --resume "
            f"--acknowledge <park-id>")


# ── Interim engagement report (M5) ───────────────────────────────────

def interim_report_path(output_dir: Path | str) -> Path:
    return Path(output_dir) / INTERIM_REPORT_FILENAME


def write_interim_report(output_dir: Path | str, *,
                         trigger: str) -> Path:
    """The M5 interim report: parking (or pausing) is never silence.
    Rebuilt whole on every supervisor exit — policy, feasibility,
    committed spend, per-row status, parks with acknowledge hints,
    residuals. Every target-derived field is escaped by the ledger /
    governor renderers or here."""
    out = Path(output_dir)
    doc = load_ledger(out) or {}
    state = load_state(out) or {}
    lines: list[str] = [
        "# Engagement interim report",
        "",
        f"INTERIM — written by the engagement supervisor at every "
        f"pause, park, and exit. Trigger: {_esc(trigger, 200)}. "
        f"Generated {_now()}.",
        "",
    ]
    pin = state.get("code_pin") or {}
    if isinstance(pin, dict):
        sha = str(pin.get("base_sha") or "unverifiable")
        lines.append(
            f"Code pin: {sha[:12]} dirty={pin.get('dirty')} "
            f"models={str(pin.get('models_sha256') or '?')[:12]} "
            f"(launched {_esc(str(state.get('launched_at') or '?'), 40)}, "
            f"segments run: {state.get('segments', 0)})")
    for acceptance in state.get("code_drift_acceptances") or []:
        if isinstance(acceptance, dict):
            fields = ",".join(str(f) for f in
                              acceptance.get("fields") or [])
            lines.append(f"  code drift accepted at "
                         f"{_esc(str(acceptance.get('at') or '?'), 40)}"
                         f": {_esc(fields, 120)}")
    lines.append("")
    committed = governor.committed_usd(doc)
    block = doc.get("policy") if isinstance(doc.get("policy"), dict) \
        else {}
    envelope = block.get("envelope_usd")
    env_s = (f"${envelope:.2f}"
             if isinstance(envelope, (int, float))
             and not isinstance(envelope, bool) else "uncapped")
    lines.append(f"Spend committed: ${committed:.2f} of {env_s}")
    feasibility = block.get("feasibility")
    if isinstance(feasibility, dict):
        lines.append(
            f"Feasibility: {_esc(str(feasibility.get('verdict')), 24)} "
            f"(want ~${governor._usd(feasibility.get('want_usd')):.2f} "
            f"at {_esc(str(feasibility.get('at') or '?'), 40)})")
    lines.append("")
    parks = list_parks(out)
    waiting = [p for p in parks if not p.get("acknowledged_at")]
    lines.append(f"## Parks ({len(waiting)} unacknowledged / "
                 f"{len(parks)} total)")
    for p in parks:
        state_tag = ("acknowledged" if p.get("acknowledged_at")
                     else "WAITING")
        aid = p.get("artifact_id")
        where = f" artifact={_esc(str(aid), 100)}" if aid else ""
        lines.append(
            f"- [{state_tag}] {_esc(str(p.get('park_id')), 24)} "
            f"{_esc(str(p.get('kind')), 40)}"
            f" ({_esc(str(p.get('scope')), 12)}{where}) — "
            f"{_esc(str(p.get('reason') or ''), 300)} "
            f"at {_esc(str(p.get('at') or '?'), 40)}")
    if waiting:
        lines.append("")
        lines.append(
            "Resume a park: libexec/raptor-engage-supervise "
            "<run-dir> --resume --acknowledge <park-id> "
            "(code-drift parks: add --accept-code-drift)")
    lines.append("")
    lines.append("## Depth policy")
    lines.extend(governor.render_policy_lines(doc))
    lines.append("")
    lines.append("## Ledger status")
    lines.extend(render_status_lines(doc, out))
    lines.append("")
    path = interim_report_path(out)
    from core.atomic_fs import write_text_atomically
    write_text_atomically(path, "\n".join(lines) + "\n")
    return path


# ── Operator budget figures (persisted at launch) ────────────────────

def _valid_usd_figure(value: Any) -> bool:
    """Mirror of :func:`governor.set_envelope`'s acceptance — finite,
    within the governor's money ceiling. An operator typo REFUSES
    (usage error), it is never clamped into a different budget."""
    return (not isinstance(value, bool)
            and isinstance(value, (int, float))
            and math.isfinite(float(value))
            and 0.0 <= float(value) <= governor._MAX_USD)


def _persisted_max_cost(state: dict[str, Any]) -> float | None:
    """The per-stage chain budget persisted at launch. The state file
    is sandbox-writable, so the figure clamps on read (the governor's
    money-clamp doctrine) — a forged overclaim caps out, garbage
    reads as absent."""
    figure = state.get("max_cost_usd")
    if (isinstance(figure, (int, float))
            and not isinstance(figure, bool)):
        return governor._usd(figure)
    return None


# ── Spend measurement (segment reconcile evidence) ───────────────────

def measured_artifact_spend(output_dir: Path | str,
                            artifact_id: str) -> float:
    """Cumulative measured LLM spend for one artifact's chain: the
    max-of-evidence per LLM stage directory (spend floor vs reconciled
    cost breakdown — the same evidence family the audit resume books
    from), summed across stages. Clamped, $0 when nothing recorded."""
    from core.audit.resume import (
        booked_spend_usd,
        load_prior_cost_breakdown,
    )
    from core.run.resume import spend_floor_usd
    if not is_artifact_id(artifact_id):
        return 0.0
    chain_dir = chain_elf.chain_dir_for(output_dir, artifact_id)
    total = 0.0
    for name in _LLM_STAGE_DIRS:
        stage_dir = chain_dir / name
        if not stage_dir.is_dir():
            continue
        floor = spend_floor_usd(stage_dir)
        booked = booked_spend_usd(load_prior_cost_breakdown(stage_dir))
        total += max(floor, booked)
    return round(governor._usd(total), 6)


# ── Boundary checks (drain citizenship + wall bound) ─────────────────

def _boundary_pause(output_dir: Path,
                    deadline: float | None) -> tuple[str, str] | None:
    """``(kind, detail)`` when the loop must pause at this segment
    boundary — a fleet drain request or the capped-shell wall bound —
    else ``None``."""
    from core.project import sessions
    requests = sessions.ledger_drain_requests(output_dir)
    if requests:
        pids = sorted({int(r["session_pid"]) for r in requests})
        return "drain_honored", (
            f"drain requested by session(s) "
            f"{', '.join(str(p) for p in pids)}")
    if deadline is not None and time.monotonic() >= deadline:
        return "wall_bound_pause", ("supervisor shell wall bound "
                                    "reached — pausing before the "
                                    "next segment")
    return None


def _pause(output_dir: Path, state: dict[str, Any],
           kind: str, detail: str) -> int:
    from core.project import sessions
    if kind == "drain_honored":
        sessions.ledger_clear_drain_requests(output_dir)
    append_residual(output_dir, kind, detail)
    state["last_pause"] = {"kind": kind, "detail": detail,
                           "at": _now()}
    _save_state(output_dir, state)
    write_interim_report(output_dir, trigger=f"{kind}: {detail}")
    _say(f"engagement paused ({kind}): {_esc(detail)} — "
         "resume with --resume")
    return RC_DRAINED


# ── The loop ─────────────────────────────────────────────────────────

def _row_settled(row: dict[str, Any], tier: str,
                 mechanical_only: bool) -> bool:
    """Cheap terminal check so a cron tick does not reserve/reconcile
    settled rows. ``verdicted`` at the slot's tier is always settled;
    ``analysed`` at tier is settled only under the SAME degraded
    conditions (``mechanical_only``) — a full-capability resume must
    re-attempt it so the chain can lift recorded degradations."""
    status = row.get("status") or {}
    if not isinstance(status, dict):
        return False
    state = status.get("state")
    if state == "verdicted" and status.get("depth") == tier:
        return True
    return (state == "analysed" and status.get("depth") == tier
            and mechanical_only)


def _engagement_parked_exit(output_dir: Path,
                            doc: dict[str, Any]) -> int:
    _adopt_governor_park(output_dir, doc)
    _write_marker(output_dir)
    write_interim_report(output_dir, trigger="engagement parked")
    for park in unacknowledged_parks(output_dir, scope="engagement"):
        _say(f"engagement parked [{_esc(str(park.get('park_id')), 24)}]"
             f": {_esc(str(park.get('reason') or ''), 300)}")
    _say("resume with: libexec/raptor-engage-supervise <run-dir> "
         "--resume --acknowledge <park-id>")
    return RC_PARKED


def supervise(output_dir: Path | str, *,
              resume: bool = False,
              acknowledge: str | None = None,
              accept_code_drift: bool = False,
              target_root: Path | None = None,
              model: str | None = None,
              max_cost: float | None = None,
              envelope_usd: float | None = None,
              mechanical_only: bool = False) -> int:
    """Run (or resume) the full engagement loop. See the module
    docstring for the contract; returns an ``RC_*`` code."""
    out = Path(output_dir)
    doc = load_ledger(out)
    if doc is None:
        _say(f"no engagement ledger at {_esc(str(out))} — build one "
             "first (libexec/raptor-engage-ledger)")
        return RC_USAGE
    for label, figure in (("--envelope", envelope_usd),
                          ("--max-cost", max_cost)):
        if figure is not None and not _valid_usd_figure(figure):
            # Refuse a garbage budget outright — silently clamping an
            # operator typo into a different figure is worse than
            # stopping.
            _say(f"invalid {label} figure — need a finite USD value "
                 f"between 0 and {governor._MAX_USD:g}")
            return RC_USAGE
    state = load_state(out)
    if state is None and resume:
        _say("nothing to resume — no engagement state here; launch "
             "without --resume first")
        return RC_USAGE
    if state is not None and not resume:
        _say("engagement already launched — re-enter with --resume "
             "(idempotent; a complete engagement reports "
             "nothing-to-do)")
        return RC_USAGE

    from core.audit.run_lock import AuditRunLocked, acquire_run_lock
    try:
        acquire_run_lock(out, "engage-supervise",
                         lock_name=SUPERVISOR_LOCK_NAME,
                         subject="engagement supervisor")
    except AuditRunLocked as exc:
        _say(_esc(str(exc), 2000))
        return RC_FAILED

    from core.run.parent_liveness import maybe_start_orphan_watchdog
    maybe_start_orphan_watchdog("engage-supervise")

    # ── M6 code pin ──
    current_pin = code_snapshot()
    if state is None:
        if current_pin.get("base_sha") is None:
            append_residual(
                out, "code_pin_unverifiable",
                "framework checkout is not a verifiable git repo — "
                "code-drift detection limited to the models config "
                "hash")
        state = {
            "schema_version": 1,
            "launched_at": _now(),
            "segments": 0,
            "code_pin": current_pin,
        }
        if max_cost is not None:
            # Persist the per-stage chain budget: bare --resume
            # re-reads it from here, so the figure the operator set
            # at launch keeps riding every later segment.
            state["max_cost_usd"] = round(float(max_cost), 6)
        _save_state(out, state)
        if envelope_usd is not None:
            # Persist the launch envelope on the ledger policy block —
            # governor._envelope() falls back to the persisted figure,
            # so a bare --resume enforces the same cap as the launch
            # shell instead of running uncapped.
            governor.set_envelope(out, envelope_usd)
    else:
        stale = state.pop("in_flight", None)
        if isinstance(stale, dict):
            # A previous supervisor died mid-segment — the chain
            # never returned an rc, so no death was booked. Book it
            # from the durable dispatch marker (the reservation is
            # still open, pessimism kept it charged) so repeated
            # supervisor-fatal segments still reach the
            # PARK_AFTER_DEATHS bound instead of churning forever.
            _save_state(out, state)
            dead_aid = str(stale.get("artifact_id") or "")
            if is_artifact_id(dead_aid):
                append_residual(
                    out, "supervisor_fatal_segment",
                    f"segment {int(stale.get('segment') or 0)} never "
                    "concluded — a previous supervisor died "
                    "mid-segment; booking the death",
                    artifact_id=dead_aid)
                death = governor.record_segment_death(
                    out, dead_aid, detail="supervisor-fatal segment")
                if death and death.get("parked"):
                    mint_park(
                        out, scope="artifact", kind="segment_deaths",
                        artifact_id=dead_aid,
                        reason=f"{death['deaths']} unreconciled "
                               "segment death(s) — last: "
                               "supervisor-fatal segment")
        # Explicit budget flags on resume are operator updates: they
        # replace the persisted figures and leave a residual + policy
        # amendment saying so. A bare --resume changes nothing — it
        # keeps enforcing what launch persisted.
        block = doc.get("policy") \
            if isinstance(doc.get("policy"), dict) else {}
        prior_env = block.get("envelope_usd")
        prior_env = (float(prior_env)
                     if isinstance(prior_env, (int, float))
                     and not isinstance(prior_env, bool) else None)
        if (envelope_usd is not None
                and prior_env != round(float(envelope_usd), 6)):
            governor.set_envelope(out, envelope_usd)
            prior_s = (f"${prior_env:.2f}" if prior_env is not None
                       else "uncapped")
            append_residual(
                out, "envelope_updated",
                f"resume --envelope replaced the persisted engagement "
                f"envelope: {prior_s} -> ${float(envelope_usd):.2f}")
            append_policy_amendment(out, {
                "kind": "envelope_updated",
                "envelope_usd": round(float(envelope_usd), 6),
            })
            doc = load_ledger(out) or doc
        if (max_cost is not None
                and _persisted_max_cost(state)
                != round(float(max_cost), 6)):
            prior_mc = _persisted_max_cost(state)
            state["max_cost_usd"] = round(float(max_cost), 6)
            _save_state(out, state)
            prior_s = (f"${prior_mc:.2f}" if prior_mc is not None
                       else "unset")
            append_residual(
                out, "max_cost_updated",
                f"resume --max-cost replaced the persisted per-stage "
                f"chain budget: {prior_s} -> ${float(max_cost):.2f}")
        pin = state.get("code_pin")
        changed = pin_drift(pin if isinstance(pin, dict) else {},
                            current_pin)
        if changed and accept_code_drift:
            state.setdefault("code_drift_acceptances", []).append(
                {"at": _now(), "fields": changed})
            state["code_pin"] = current_pin
            _save_state(out, state)
            append_residual(
                out, "code_drift_accepted",
                f"--accept-code-drift: {','.join(changed)} changed "
                "since launch")
            append_policy_amendment(out, {
                "kind": "code_drift_accepted",
                "fields": ",".join(changed),
            })
            # The flag is the informed consent for code-drift parks —
            # acknowledge any that are waiting.
            for park in unacknowledged_parks(out, scope="engagement"):
                if park.get("kind") == "code_drift":
                    acknowledge_park(out, str(park.get("park_id")))
        elif changed:
            if not unacknowledged_parks(out, scope="engagement"):
                reason = ("code moved under the engagement: "
                          f"{','.join(changed)} changed since launch")
                governor.park_engagement(out, reason)
                mint_park(out, scope="engagement", kind="code_drift",
                          reason=reason + " — resume with "
                          "--accept-code-drift to proceed under the "
                          "moved code")
            doc = load_ledger(out) or doc
            return _engagement_parked_exit(out, doc)

    # A bare re-entry runs under the persisted figures: the chain
    # budget from the state file (clamped on read), the envelope via
    # governor._envelope()'s persisted-policy fallback.
    if max_cost is None:
        max_cost = _persisted_max_cost(state)

    # ── operator acknowledgment (M5) ──
    if acknowledge:
        ok, message = acknowledge_park(out, acknowledge)
        _say(message)
        if not ok:
            return RC_USAGE

    # ── sticky park gate ──
    doc = load_ledger(out) or doc
    if (governor.is_engagement_parked(doc)
            or unacknowledged_parks(out, scope="engagement")):
        return _engagement_parked_exit(out, doc)

    # ── policy + feasibility (S16) ──
    governor.ensure_policy(out, doc)
    doc = load_ledger(out) or doc
    acked_feasibility = any(
        p.get("scope") == "engagement"
        and p.get("kind") == "feasibility_conflict"
        and p.get("acknowledged_at")
        for p in list_parks(out))
    verdict = governor.enforce_feasibility(
        out, doc, envelope_usd,
        # An acknowledged feasibility park is the operator owning the
        # conflict — record the verdict, never re-park (the
        # per-segment envelope check still refuses over-envelope
        # reservations).
        attended=acked_feasibility,
        model=model)
    for line in verdict.lines():
        _say(line)
    doc = load_ledger(out) or doc
    if governor.is_engagement_parked(doc):
        return _engagement_parked_exit(out, doc)

    # ── wall bound (reused capped-shell math) ──
    from core.run.supervisor import supervisor_wall_bound
    bound = supervisor_wall_bound()
    deadline = (time.monotonic() + bound.bound_s
                if bound is not None else None)

    total_progressed = 0
    last_failed = 0
    last_refused = 0
    for _pass in range(_MAX_PASSES):
        doc = load_ledger(out) or {}
        order = governor.schedule_order(doc)
        progressed = failed = refused = 0
        for aid in order:
            pause = _boundary_pause(out, deadline)
            if pause is not None:
                return _pause(out, state, pause[0], pause[1])
            doc = load_ledger(out) or {}
            if governor.is_engagement_parked(doc):
                return _engagement_parked_exit(out, doc)
            if not is_artifact_id(aid):
                continue
            row = next((r for r in doc.get("rows") or []
                        if isinstance(r, dict)
                        and r.get("artifact_id") == aid), None)
            if row is None:
                continue
            status = row.get("status") or {}
            if isinstance(status, dict) \
                    and status.get("state") == "parked":
                continue
            slot = row.get("policy")
            tier = str(slot.get("tier") or governor.TIER_T0) \
                if isinstance(slot, dict) else governor.TIER_T0
            if tier == governor.TIER_T0:
                continue  # inventory tier — no chain by policy
            if _row_settled(row, tier, mechanical_only):
                continue
            if str(row.get("class") or "") != chain_elf.CLASS_ELF:
                # Non-ELF chains are a later capability: the chain
                # records the honesty degradation mechanically — no
                # LLM spend, so no reservation rides this call.
                rc = chain_elf.run_chain(
                    out, aid, target_root=target_root, model=model,
                    max_cost=max_cost,
                    mechanical_only=mechanical_only)
                if rc == chain_elf.RC_OK:
                    progressed += 1
                continue
            state["segments"] = int(state.get("segments", 0)) + 1
            _save_state(out, state)
            reservation = governor.reserve_segment(
                out, aid, state["segments"], model=model,
                envelope_usd=envelope_usd)
            if reservation is None:
                refused += 1
                continue
            # Durable dispatch marker: if the SUPERVISOR dies inside
            # run_chain (SIGKILL, OOM) the chain's rc is never
            # observed and no death would be booked — the resume's
            # recovery arm books it from this marker, so
            # PARK_AFTER_DEATHS still bounds an unattended crash
            # loop.
            state["in_flight"] = {
                "artifact_id": aid,
                "segment": state["segments"],
                "at": _now(),
            }
            _save_state(out, state)
            rc = chain_elf.run_chain(
                out, aid, target_root=target_root, model=model,
                max_cost=max_cost, mechanical_only=mechanical_only)
            state.pop("in_flight", None)
            _save_state(out, state)
            actual = measured_artifact_spend(out, aid)
            if rc in (chain_elf.RC_OK, chain_elf.RC_NOTHING):
                governor.reconcile_segment(out, aid, actual)
                if rc == chain_elf.RC_OK:
                    progressed += 1
            else:
                failed += 1
                death = governor.record_segment_death(
                    out, aid, detail=f"chain rc={rc}")
                if death and death.get("parked"):
                    # The governor already parked the row (status +
                    # residual + amendment) — mint the operator-facing
                    # park-id it cannot mint itself.
                    mint_park(
                        out, scope="artifact", kind="segment_deaths",
                        artifact_id=aid,
                        reason=f"{death['deaths']} unreconciled "
                               f"segment death(s) — last: chain "
                               f"rc={rc}")
        total_progressed += progressed
        last_failed, last_refused = failed, refused
        if progressed == 0:
            break

    # ── conclude ──
    _write_marker(out)
    if (last_refused > 0 and total_progressed == 0
            and last_failed == 0):
        # The last pass refused at least one reservation and funded
        # nothing — park pre-spend (the S16 posture) instead of
        # letting a cron loop grind refusals forever. Settled sibling
        # rows concluding RC_NOTHING in the same tick must not read
        # as "complete" while a live row sits unfunded; failure and
        # progress keep their own honest exits below.
        doc = load_ledger(out) or {}
        if not governor.is_engagement_parked(doc):
            reason = ("envelope_exhausted: reservation(s) refused "
                      "over the envelope with no funded progress")
            governor.park_engagement(out, reason)
            mint_park(out, scope="engagement",
                      kind="envelope_exhausted", reason=reason)
        doc = load_ledger(out) or {}
        return _engagement_parked_exit(out, doc)
    write_interim_report(
        out,
        trigger=(f"supervisor exit: progressed={total_progressed} "
                 f"failed={last_failed} refused={last_refused}"))
    if last_failed > 0:
        _say(f"{last_failed} segment(s) failed — chain state is "
             "durable; --resume retries from the failed stage")
        return RC_FAILED
    if total_progressed > 0:
        _say(f"advanced {total_progressed} segment(s)")
        return RC_OK
    waiting = unacknowledged_parks(out)
    if waiting:
        _say(f"{len(waiting)} park(s) awaiting acknowledgment — "
             "see the interim report")
        return RC_PARKED
    _say("engagement complete — nothing to do")
    return RC_NOTHING

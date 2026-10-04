"""Engagement report + coverage synthesis — one honest rendering of
what an engagement PROVED, over the artifacts the other layers wrote.

Pure synthesis: this module reads the engagement ledger
(:mod:`core.engagement.ledger`), the per-artifact chain state and
verdict records (:mod:`core.engagement.chain_elf`), the review-journal
verdict rows (:mod:`core.coverage.journal`), the landed coverage
overlay views (:mod:`core.coverage.store_summary` — the analyzed-by-
no-lane residual and the store-backed rollup), and the verified-
outcome export (:mod:`core.labeled_attempts.view`). It runs NO
analysis, spawns NO children, and calls NO LLM — tool output is the
verdict, and this module only renders it. Substrate it consumes is
never rebuilt here; a consumable that is absent or unloadable becomes
a DECLARED degradation in the report (``consumed`` block), never a
silent gap and never a reimplementation.

Doctrine (pinned by ``.github/tests/test_engagement_report_doctrine.py``
and the unit battery):

- **Earned-coverage honesty (M8).** The verdict table carries the
  fixed schema ``policy_depth | reached_depth | degradation_reasons |
  format_capability_tier_at_run_time`` for EVERY ledger row. "No
  findings" on any sub-full capability renders NON-ATTESTING — a row
  whose class the format-capability table caps below ``full`` and
  that carries no findings reads "no findings within <tier>
  capability — catalogs pending". The report can only DOWNGRADE an
  attestation, never mint one: ``attesting`` requires the chain's own
  verdict record to claim it AND the record's fields to re-verify
  (zero findings, zero degradations, reached == policy depth, tier
  ``full``, journal floor clear). A record that claims attestation
  but fails the re-check renders non-attesting with a named
  report-side degradation.
- **Read-coverage is advisory (N17).** Earned coverage = journal
  VERDICT rows, nothing else. The overlay's llm-category extent
  (which counts whole-file ``read`` marks at scanned depth) appears
  only as a LABELED advisory stratum; it never enters an earned
  count, an attestation, or a residual computation.
- **Scored-low is not verified-low (M3d).** The residual map splits
  low-tier artifacts by the governor's ``low_exposure_verified``
  policy flag: verified-low-exposure rows had the full mechanical
  exposure pass demonstrably run; everything else is merely
  scored-low and listed as unverified residue.
- **Second-life provenance (principle 9).** This file is registered
  in the escaping-closure baseline
  (``core.security.report_writer_audit._REPORT_WRITER_FILES``).
  Every value that originates in target bytes (paths, DT_NEEDED
  names, survivor file/function names, residual messages quoting
  member names) renders through :func:`core.security.markdown_render.
  md_inline` in the markdown report and
  :func:`core.security.log_sanitisation.sanitise_for_terminal` in the
  terminal summary. The JSON document stores raw values with a
  ``derived_from_target`` manifest — escape-at-render applies to
  every consumer, exactly like the ledger and the chain artifacts.
- **Output style.** Statuses are snake_case in the JSON document and
  Title Case in the human-readable rendering; never ALL_CAPS, no
  red/green indicators.
- **Atomic writes.** The JSON report leaves through ``save_json``
  under :func:`core.atomic_fs.fs_lock.artifact_lock`; the markdown leaves
  through :func:`core.atomic_fs.write_text_atomically` under the same
  lock. Nothing is written into the target tree.

Outputs, both under the engagement output directory:

- ``engagement-report.json`` — the synthesis document
  (``engagement-report/1``), provenance-stamped.
- ``engagement-report.md`` — the operator rendering.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.artifacts.provenance import stamp_provenance
from core.atomic_fs import write_text_atomically
from core.coverage.journal import VALID_VERDICTS
from core.engagement.chain_elf import (
    SURVIVORS_FILENAME,
    VERDICT_SCHEMA,
    chain_dir_for,
    load_chain_state,
)
from core.engagement.ledger import (
    TIER_FULL,
    is_artifact_id,
    load_engagement_policy,
    load_ledger,
    load_policy_amendments,
    read_artifact_checklist,
)
from core.atomic_fs.fs_lock import artifact_lock
from core.json import load_json, save_json
from core.security.log_sanitisation import sanitise_for_terminal
from core.security.markdown_render import md_inline

REPORT_SCHEMA = "engagement-report/1"
REPORT_JSON_FILENAME = "engagement-report.json"
REPORT_MD_FILENAME = "engagement-report.md"

# ── Attestation vocabulary (snake_case in JSON; Title Case rendered) ─
ATTESTING = "attesting"
NON_ATTESTING = "non_attesting"
FINDINGS_PRESENT = "findings_present"
NOT_ENGAGED = "not_engaged"

# Bounds, both directions: the JSON document must stay readable at
# engagement scale (the ledger itself caps rows, but survivors /
# residuals / amendments are append-shaped), while the caps must not
# hide real content — every truncation states the total it elided.
_MAX_SURVIVORS_JSON = 400
_MAX_RESIDUALS_JSON = 200
_MAX_AMENDMENTS_JSON = 100
_MAX_NO_LANE_SAMPLE = 10
_MAX_TABLE_ROWS_MD = 200
_MAX_SURVIVORS_MD = 50
_MAX_RESIDUALS_MD = 25
_MAX_AMENDMENTS_MD = 10
_MAX_WORDING_MD = 60

_LOW_TIERS = ("T0", "T1")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _esc(value: Any, max_len: int = 200) -> str:
    """Terminal-safe rendering for any target-derived text."""
    return sanitise_for_terminal(str(value), max_len=max_len)


def _title(state: Any) -> str:
    """snake_case status → Title Case for human-readable surfaces.

    Depth labels (``T0``..``T3``) and tier tokens pass through
    ``title()`` unharmed; multi-word snake states gain spaces.
    NEVER a render seam on its own — foreign values go through
    :func:`_title_md` so the escape happens AFTER the case change
    (escaping first would let ``str.title()`` case-mangle the
    ``\\xHH`` escape markers themselves).
    """
    return str(state).replace("_", " ").title()


def _title_md(value: Any) -> str:
    """Title Case a foreign status/kind for a markdown slot: case
    change first, ``md_inline`` escape second."""
    return md_inline(_title(value))


def _journal_label_md(label: Any) -> str:
    """A journal verdict LABEL for a markdown slot. Labels come from
    journal rows and chain verdict records — foreign bytes until
    proven vocabulary. Known labels render Title Case; anything else
    renders escaped verbatim, never title-cased raw (a forged label
    must not get the vocabulary's trusted rendering)."""
    if isinstance(label, str) and label in VALID_VERDICTS:
        return _title(label)
    return md_inline(label)


def _int_counts(counts: Any) -> dict[str, int]:
    """A journal-verdict count mapping reduced to its honest integer
    entries. Bools are excluded explicitly (``isinstance(True, int)``
    holds, so a record carrying ``{"clean": true}`` would otherwise
    satisfy a count floor with no countable row) and every other
    non-int value is dropped."""
    if not isinstance(counts, dict):
        return {}
    return {str(k): v for k, v in counts.items()
            if isinstance(v, int) and not isinstance(v, bool)}


def _nonzero_counts(counts: dict[str, int]) -> dict[str, int]:
    """Counts with zero entries dropped — the comparison-normal form
    (``{"finding": 0}`` recorded against a live journal without the
    label is agreement, not divergence)."""
    return {k: v for k, v in counts.items() if v != 0}


# ── Chain verdict + journal consumption (read-only) ──────────────────

def _chain_verdict(output_dir: Path,
                   artifact_id: str) -> dict[str, Any] | None:
    """The artifact's chain verdict record, or None. Only records
    carrying the chain's own schema tag are consumed — a hand-planted
    blob of another shape is ignored, not interpreted."""
    if not is_artifact_id(artifact_id):
        return None
    try:
        state = load_chain_state(chain_dir_for(output_dir, artifact_id))
    except ValueError:
        return None
    verdict = state.get("verdict")
    if isinstance(verdict, dict) and verdict.get("schema") == VERDICT_SCHEMA:
        return verdict
    return None


def _chain_run_dirs(output_dir: Path, artifact_id: str) -> list[Path]:
    """The chain's journal-carrying run dirs that exist on disk."""
    try:
        chain_dir = chain_dir_for(output_dir, artifact_id)
    except ValueError:
        return []
    return [d for d in (chain_dir / "audit", chain_dir / "audit-rereview")
            if d.is_dir()]


def _journal_counts(
    run_dirs: list[Path],
) -> tuple[dict[str, int], bool]:
    """Earned-coverage counts: journal VERDICT rows per verdict label,
    via the completeness-checked loader. ``complete`` is False when
    any consulted journal loaded partially — a bounded partial view
    is stated, never passed off as full earned coverage."""
    from core.coverage.journal import load_entries_checked
    counts: dict[str, int] = {}
    complete = True
    for run_dir in run_dirs:
        try:
            loaded = load_entries_checked(run_dir)
        except (OSError, ValueError):
            complete = False
            continue
        if not loaded.complete:
            complete = False
        for entry in loaded.entries:
            counts[entry.verdict] = counts.get(entry.verdict, 0) + 1
    return counts, complete


# ── M8 verdict table ─────────────────────────────────────────────────

def _display_policy_depth(row: dict[str, Any]) -> str:
    """The row's ASSIGNED depth for display: the governor's policy
    tier, else the status depth label's tier prefix, else
    ``unassigned``. Deliberately NOT the chain's defensive
    ``resolve_policy_depth`` default — the report states what was
    assigned, not what a chain would assume."""
    policy = row.get("policy")
    if isinstance(policy, dict):
        tier = policy.get("tier")
        if isinstance(tier, str) and tier in ("T0", "T1", "T2", "T3"):
            return tier
    status = row.get("status")
    if isinstance(status, dict):
        depth = status.get("depth")
        if isinstance(depth, str) and depth[:2] in ("T0", "T1",
                                                    "T2", "T3"):
            return depth[:2]
    return "unassigned"


def _verdict_recheck(verdict: dict[str, Any]) -> bool:
    """Re-verify an attesting claim from the record's own fields —
    the report may only ever DOWNGRADE, so a record that claims
    attestation without the invariants renders non-attesting. The
    count floor sees only honest integer counts (:func:`_int_counts`
    — ``{"clean": true}`` and ``{"clean": "3"}`` satisfy nothing),
    and a negative finding count is garbage, not zero findings."""
    counts = _int_counts(verdict.get("journal_verdicts"))
    findings = counts.get("finding", 0)
    total_rows = sum(counts.values())
    return (
        findings == 0
        and not (verdict.get("degradation_reasons") or [])
        and verdict.get("reached_depth") == verdict.get("policy_depth")
        and verdict.get("format_capability_tier") == TIER_FULL
        and verdict.get("journal_floor") is None
        and total_rows > 0
    )


def _verdict_table_entry(output_dir: Path,
                         row: dict[str, Any]) -> dict[str, Any]:
    """One fixed-schema verdict-table row (M8):
    ``policy_depth | reached_depth | degradation_reasons |
    format_capability_tier_at_run_time`` plus the attestation state
    and its wording."""
    artifact_id = str(row.get("artifact_id") or "")
    current_tier = str(row.get("format_tier") or "unknown")
    status = row.get("status") if isinstance(row.get("status"), dict) \
        else {}
    policy = row.get("policy") if isinstance(row.get("policy"), dict) \
        else {}
    verdict = _chain_verdict(output_dir, artifact_id)

    entry: dict[str, Any] = {
        "artifact_id": artifact_id,
        "class": str(row.get("class") or "unknown"),
        "path": str(row.get("path") or ""),
        "status_state": str(status.get("state") or "inventoried"),  # type: ignore[union-attr]
        "low_exposure": {
            "basis": str(policy.get("basis") or ""),  # type: ignore[union-attr]
            # ``is True``, not ``bool()`` — a hand-edited ledger
            # carrying the STRING "false" must not coerce to a
            # verified-low claim (M3d mirrors build_report's check).
            "low_exposure_verified":
                policy.get("low_exposure_verified") is True,  # type: ignore[union-attr]
        },
    }

    if verdict is not None:
        counts = _int_counts(verdict.get("journal_verdicts"))
        findings = counts.get("finding", 0)
        degradations = [
            d for d in (verdict.get("degradation_reasons") or [])
            if isinstance(d, dict)
        ]
        record_tier = str(
            verdict.get("format_capability_tier") or "unknown")
        entry.update({
            "policy_depth": str(verdict.get("policy_depth") or ""),
            "reached_depth": str(verdict.get("reached_depth") or ""),
            "degradation_reasons": degradations,
            # At-run-time tier, exactly as the chain recorded it —
            # a later ledger rebuild cannot rewrite what the run had.
            "format_capability_tier_at_run_time": record_tier,
            "tier_provenance": "at_run_time",
            "journal_verdicts": counts,
            "journal_floor": verdict.get("journal_floor"),
        })
        # A knowable disagreement is rendered, not adjudicated: the
        # ledger's CURRENT tier appears beside the at-run-time one
        # when they differ. Attestation stays a downgrade-only
        # re-check of the record — the current tier changes no
        # verdict here.
        entry["format_capability_tier_current"] = current_tier
        entry["tier_diverged_from_current"] = (
            record_tier != current_tier)
        # Record prose never masquerades as a report conclusion: the
        # rendered wording is DERIVED from the computed attestation
        # on every path; the record's own prose stays available in
        # the JSON document under ``record_wording`` (raw — named in
        # the ``derived_from_target`` manifest).
        entry["record_wording"] = str(verdict.get("wording") or "")
        claimed = verdict.get("attesting") is True
        rechecked = _verdict_recheck(verdict)
        if findings > 0:
            entry["attestation"] = FINDINGS_PRESENT
            entry["wording"] = (
                f"findings present — {findings} finding row(s) "
                "recorded at verdict time")
        elif claimed and rechecked:
            entry["attestation"] = ATTESTING
            entry["wording"] = (
                f"attested at {entry['reached_depth']} — attesting "
                "claim re-verified from the record's own fields")
        else:
            entry["attestation"] = NON_ATTESTING
            if claimed and not rechecked:
                # Downgrade-only rule: name the report-side reason.
                entry["degradation_reasons"] = degradations + [{
                    "stage": "report",
                    "reason": "verdict_recheck_failed",
                }]
                entry["wording"] = (
                    "attestation claim failed the report re-check — "
                    "rendered non-attesting")
            else:
                entry["wording"] = (
                    "non-attesting — the chain did not claim "
                    "attestation")
        return entry

    # No chain verdict: nothing ran to completion for this row.
    entry.update({
        "policy_depth": _display_policy_depth(row),
        "reached_depth": "none",
        "degradation_reasons": [],
        "format_capability_tier_at_run_time": current_tier,
        "tier_provenance": "current_table",
        "journal_verdicts": {},
        "journal_floor": None,
        "attestation": NOT_ENGAGED,
    })
    entry["format_capability_tier_current"] = current_tier
    entry["tier_diverged_from_current"] = False
    entry["record_wording"] = ""
    if current_tier != TIER_FULL:
        # The M8 wording rule: zero findings at sub-full capability is
        # a capability statement, never a clean bill.
        entry["wording"] = (
            f"no findings within {current_tier} capability — "
            "catalogs pending")
    else:
        entry["wording"] = (
            "not engaged — no analysis chain has run "
            f"(policy depth {entry['policy_depth']})")
    return entry


# ── Coverage synthesis (earned = journal rows; overlay consumed) ─────

def _artifact_coverage(output_dir: Path, row: dict[str, Any],
                       target_root: str) -> dict[str, Any] | None:
    """Per-artifact coverage synthesis: earned journal rows, the
    checklist denominator, and the landed overlay views (consumed —
    absence is declared, never papered over). ``target_root`` is the
    ledger's engagement target — a pre-existing overlay store whose
    recorded target does not match it is dropped with a declared
    degradation, never silently consumed."""
    artifact_id = str(row.get("artifact_id") or "")
    if not is_artifact_id(artifact_id):
        return None
    run_dirs = _chain_run_dirs(output_dir, artifact_id)
    checklist = read_artifact_checklist(output_dir, artifact_id)
    verdict = _chain_verdict(output_dir, artifact_id)
    if not run_dirs and checklist is None and verdict is None:
        return None

    counts, complete = _journal_counts(run_dirs)
    entry: dict[str, Any] = {
        "artifact_id": artifact_id,
        "journal_verdict_rows": counts,
        "journal_load_complete": complete,
        "checklist_present": checklist is not None,
    }
    if verdict is not None:
        at_verdict = _int_counts(verdict.get("journal_verdicts"))
        entry["journal_verdict_rows_at_verdict_time"] = at_verdict
        # A verdict that recorded rows the live journal no longer
        # shows is a visible divergence, never a silent one. The
        # comparison is PER LABEL — summed totals would let a swapped
        # composition (a finding row vanished, a clean row appeared)
        # mask itself behind an equal total. Exactly one vanished row
        # already flags.
        entry["journal_rows_absent_since_verdict"] = any(
            n > counts.get(label, 0)
            for label, n in at_verdict.items())
        # The knowable-disagreement flag, both directions: any
        # per-label difference between the recorded composition and
        # the live journal (rows appeared OR vanished) is rendered.
        # Identical labels with identical counts remain unknowable by
        # construction — counts carry no row identity.
        entry["journal_composition_diverged_since_verdict"] = (
            _nonzero_counts(at_verdict) != _nonzero_counts(counts))

    if checklist is None or not run_dirs:
        entry["overlay"] = {
            "consumed": False,
            "reason": ("checklist_slot_absent" if checklist is None
                       else "no_run_dirs"),
        }
        return entry

    chain_dir = chain_dir_for(output_dir, artifact_id)
    store_path = chain_dir / "coverage-synth.json"
    if store_path.exists():
        # Consume-if-present provenance gate: the report never writes
        # this path (the builder below is read-only), so a
        # pre-existing store file arrived from OUTSIDE this synthesis
        # — planted, or copied in from another engagement. It may
        # seed the view only when the target it records is THIS
        # engagement's target; anything else (mismatch, no recorded
        # target, unparseable file) is a declared degradation, never
        # a silent enrichment of the coverage numbers.
        planted = load_json(store_path)
        recorded = (planted.get("target")
                    if isinstance(planted, dict) else None)
        if not target_root or recorded != target_root:
            entry["overlay"] = {
                "consumed": False,
                "reason": "overlay_store_target_mismatch",
                "recorded_target": (str(recorded)
                                    if recorded is not None else None),
            }
            return entry

    try:
        from core.coverage.store_summary import (
            coverage_view,
            no_lane_residual,
        )
        # Ephemeral store path — coverage_view's builder is read-only
        # (never saves), so nothing is written here.
        view = coverage_view(run_dirs, checklist, str(store_path))
    except (OSError, ValueError, ImportError, KeyError):
        entry["overlay"] = {"consumed": False,
                            "reason": "overlay_view_failed"}
        return entry
    if not view:
        entry["overlay"] = {"consumed": False,
                            "reason": "empty_inventory"}
        return entry

    residual = no_lane_residual(view)
    sample = [
        {"file": str(g.get("file") or ""),
         "function": str(g.get("function") or ""),
         "line": g.get("line")}
        for g in residual[:_MAX_NO_LANE_SAMPLE]
    ]
    by_category = view.get("functions_by_category") or {}
    entry["overlay"] = {
        "consumed": True,
        "checklist_items": view.get("total_functions", 0),
        "reviewed_analysed_depth": view.get("functions_reviewed", 0),
        "llm_reviewable": view.get("llm_reviewable", 0),
        "no_lane_residual": len(residual),
        "no_lane_sample": sample,
        # N17: llm-category EXTENT counts whole-file read marks at
        # scanned depth — advisory stratum only, never earned.
        "advisory_llm_extent_including_reads": by_category.get(
            "llm", 0),
        "advisory_note": (
            "llm extent counts whole-file read marks (advisory "
            "stratum; earned coverage = journal verdict rows only)"),
    }
    return entry


# ── Survivors + verified outcomes (consumed) ─────────────────────────

def _collect_survivors(
    output_dir: Path, artifact_ids: list[str],
) -> tuple[list[dict[str, Any]], int, list[dict[str, str]]]:
    """Finding-grade survivors across every chain's handoff artifact
    (bounded; the total is stated so a cap never hides volume).

    Returns ``(survivors, total, degraded)``. A handoff file that
    EXISTS but does not load (malformed, oversized past the JSON
    loader's bound) or loads without a survivor list is a DECLARED
    degradation — a chain wrote findings this report could not read,
    which must never render as "0 survivors" silently. An absent file
    stays silent: that chain handed nothing off."""
    survivors: list[dict[str, Any]] = []
    degraded: list[dict[str, str]] = []
    total = 0
    for artifact_id in artifact_ids:
        if not is_artifact_id(artifact_id):
            continue
        try:
            chain_dir = chain_dir_for(output_dir, artifact_id)
        except ValueError:
            continue
        handoff_path = chain_dir / SURVIVORS_FILENAME
        doc = load_json(handoff_path)
        if doc is None:
            # ``load_json`` returns None for BOTH missing and
            # unreadable (malformed / oversized) files — only an
            # existing-but-unloadable handoff is a degradation.
            if handoff_path.exists():
                degraded.append({"artifact_id": artifact_id,
                                 "reason": "survivors_unloadable"})
            continue
        if not isinstance(doc, dict):
            degraded.append({"artifact_id": artifact_id,
                             "reason": "survivors_malformed"})
            continue
        items = doc.get("survivors")
        if not isinstance(items, list):
            degraded.append({"artifact_id": artifact_id,
                             "reason": "survivors_malformed"})
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            total += 1
            if len(survivors) < _MAX_SURVIVORS_JSON:
                survivors.append({
                    "artifact_id": artifact_id,
                    "file": str(item.get("file") or ""),
                    "function": str(item.get("function") or ""),
                    "run": str(item.get("run") or ""),
                })
    return survivors, total, degraded


def _verified_outcomes_summary(output_dir: Path) -> dict[str, Any]:
    """Verified-outcome counts by oracle and status, consumed from the
    landed export (best-effort by that API's own contract); an
    unloadable backend is a declared degradation."""
    try:
        from core.labeled_attempts.view import collect_outcomes
        outcomes = collect_outcomes(output_dir)
    except Exception:  # noqa: BLE001 — degrade, never break the report
        return {"consumed": False, "reason": "backend_unavailable"}
    by_key: dict[str, int] = {}
    for outcome in outcomes:
        try:
            key = f"{outcome.oracle.value}:{outcome.status.value}"
        except AttributeError:
            continue
        by_key[key] = by_key.get(key, 0) + 1
    return {"consumed": True, "count": len(outcomes),
            "by_oracle_status": by_key}


# ── The report document ──────────────────────────────────────────────

def build_report(output_dir: Path | str) -> dict[str, Any]:
    """Synthesize the engagement report document from the artifacts on
    disk. Raises ``FileNotFoundError`` when no ledger exists — a
    report over nothing would be an attestation-shaped lie.
    """
    out = Path(output_dir)
    doc = load_ledger(out)
    if not isinstance(doc, dict):
        raise FileNotFoundError(
            f"no engagement ledger under {out}")

    rows = [r for r in (doc.get("rows") or []) if isinstance(r, dict)]
    target_root = str(doc.get("target_root") or "")
    table = [_verdict_table_entry(out, row) for row in rows]

    by_attestation: dict[str, int] = {}
    for entry in table:
        att = entry["attestation"]
        by_attestation[att] = by_attestation.get(att, 0) + 1

    # M3d strata over the governor's policy slots.
    scored_low: list[str] = []
    verified_low: list[str] = []
    for row in rows:
        policy = row.get("policy")
        if not isinstance(policy, dict):
            continue
        if policy.get("tier") in _LOW_TIERS:
            aid = str(row.get("artifact_id") or "")
            if policy.get("low_exposure_verified") is True:
                verified_low.append(aid)
            else:
                scored_low.append(aid)

    coverage = [c for c in (_artifact_coverage(out, row, target_root)
                            for row in rows) if c is not None]
    earned_total: dict[str, int] = {}
    at_verdict_total: dict[str, int] = {}
    for c in coverage:
        for verdict, n in (c.get("journal_verdict_rows") or {}).items():
            earned_total[verdict] = earned_total.get(verdict, 0) + n
        for verdict, n in (c.get("journal_verdict_rows_at_verdict_time")
                           or {}).items():
            if isinstance(n, int):
                at_verdict_total[verdict] = \
                    at_verdict_total.get(verdict, 0) + n

    artifact_ids = [str(r.get("artifact_id") or "") for r in rows]
    survivors, survivors_total, survivors_degraded = \
        _collect_survivors(out, artifact_ids)

    residuals = [r for r in (doc.get("residuals") or [])
                 if isinstance(r, dict)]
    amendments = load_policy_amendments(out)
    collisions = [c for c in (doc.get("collisions") or [])
                  if isinstance(c, dict)]
    parked = [str(r.get("artifact_id") or "") for r in rows
              if isinstance(r.get("status"), dict)
              and r["status"].get("state") == "parked"]

    policy_block = load_engagement_policy(out)
    counts = doc.get("counts") if isinstance(doc.get("counts"), dict) \
        else {}

    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "generated_at": _now(),
        "target_root": target_root,
        "counts": counts,
        "policy": {
            "engagement_parked": isinstance(
                policy_block.get("park"), dict),
            "block": policy_block,
            "amendment_count": len(amendments),
        },
        "attestation_totals": by_attestation,
        "verdict_table": table,
    }
    report["coverage"] = {
        "earned_note": (
            "earned coverage = review-journal verdict rows; "
            "read-coverage is an advisory stratum and never "
            "counts as earned"),
        "earned_journal_rows_total": earned_total,
        "at_verdict_time_rows_total": at_verdict_total,
        "per_artifact": coverage,
    }
    report["survivors"] = {
        "total": survivors_total,
        "listed": survivors,
        "degraded": survivors_degraded,
        "note": (
            "raw-binary /validate has no mechanical stage-0 "
            "decomp adapter — survivors await operator-run "
            "/validate; nothing here promotes a finding"),
    }
    report["verified_outcomes"] = _verified_outcomes_summary(out)
    report["residual_map"] = {
        "ledger_residuals_total": len(residuals),
        "ledger_residuals": residuals[:_MAX_RESIDUALS_JSON],
        "identity_collisions": len(collisions),
        "parked_artifacts": parked,
        "scored_low_unverified": scored_low,
        "verified_low_exposure": verified_low,
        "policy_amendments": amendments[-_MAX_AMENDMENTS_JSON:],
    }
    # Escape-at-render manifest for every downstream consumer
    # (assembled in two slices — table/survivor paths, then coverage
    # paths — mirroring the document sections).
    manifest = [
        "target_root",
        "verdict_table.path",
        "verdict_table.wording",
        "verdict_table.record_wording",
        "survivors.listed.file",
        "survivors.listed.function",
    ]
    manifest += [
        "residual_map.ledger_residuals.message",
        "coverage.per_artifact.overlay.no_lane_sample.file",
        "coverage.per_artifact.overlay.no_lane_sample.function",
        "coverage.per_artifact.overlay.recorded_target",
    ]
    report["derived_from_target"] = manifest
    stamp_provenance(report, "engage-report", untrusted=True)
    return report


# ── Markdown rendering (Title Case; every foreign value escaped) ─────

def _md_row(cells: list[str]) -> str:
    return "| " + " | ".join(cells) + " |"


def _degradation_cell(reasons: list[dict[str, Any]]) -> str:
    if not reasons:
        return "none"
    first = reasons[0]
    label = f"{first.get('stage', '')}: {first.get('reason', '')}"
    if len(reasons) > 1:
        label += f" (+{len(reasons) - 1} more)"
    return label


def render_markdown(report: dict[str, Any]) -> str:
    """The operator rendering. Statuses Title Case; every value that
    can carry target bytes goes through ``md_inline``."""
    lines: list[str] = []
    lines.append("# Engagement Report")
    lines.append("")
    lines.append(f"- Target: `{md_inline(report.get('target_root'))}`")
    lines.append(f"- Generated: {md_inline(report.get('generated_at'))}")
    counts = report.get("counts") or {}
    # The ledger's counts block is a FOREIGN dict — a hand-edited
    # ledger can carry strings where ints belong, so every value
    # renders escaped, exactly like the keys.
    lines.append(f"- Ledger rows: {md_inline(counts.get('rows', 0))}")
    by_class = counts.get("by_class") \
        if isinstance(counts.get("by_class"), dict) else {}
    if by_class:
        parts = ", ".join(
            f"{md_inline(cls)} {md_inline(by_class[cls])}"
            for cls in sorted(by_class, key=str))
        lines.append(f"- By class: {parts}")
    policy = report.get("policy") or {}
    parked_line = ("Parked" if policy.get("engagement_parked")
                   else "Not Parked")
    lines.append(
        f"- Engagement policy: {parked_line}, "
        f"{policy.get('amendment_count', 0)} amendment(s)")
    totals = report.get("attestation_totals") or {}
    if totals:
        parts = ", ".join(
            f"{_title(k)} {totals[k]}" for k in sorted(totals))
        lines.append(f"- Attestation: {parts}")
    lines.append("")

    # M8 fixed-schema verdict table.
    lines.append("## Verdict Table")
    lines.append("")
    lines.append(_md_row([
        "Artifact", "Class", "Policy Depth", "Reached Depth",
        "Degradation Reason",
        "Format Capability Tier (At Run Time)", "Attestation",
    ]))
    lines.append(_md_row(["---"] * 7))
    table = report.get("verdict_table") or []
    for entry in table[:_MAX_TABLE_ROWS_MD]:
        tier_cell = md_inline(
            entry.get("format_capability_tier_at_run_time"))
        if entry.get("tier_diverged_from_current"):
            # SF-4 provenance label: the record's claimed tier no
            # longer matches the ledger row's CURRENT format tier.
            # Both shown, verdict unchanged — recorded facts stay
            # recorded, the disagreement stays visible.
            tier_cell += (
                " (record; current "
                f"{md_inline(entry.get('format_capability_tier_current'))})")
        lines.append(_md_row([
            md_inline(entry.get("artifact_id")),
            md_inline(entry.get("class")),
            md_inline(entry.get("policy_depth")),
            md_inline(entry.get("reached_depth")),
            md_inline(_degradation_cell(
                entry.get("degradation_reasons") or [])),
            tier_cell,
            _title(entry.get("attestation")),
        ]))
    if len(table) > _MAX_TABLE_ROWS_MD:
        lines.append("")
        lines.append(
            f"… {len(table) - _MAX_TABLE_ROWS_MD} more row(s) in "
            f"`{REPORT_JSON_FILENAME}`.")
    lines.append("")

    wordings = [e for e in table
                if e.get("attestation") != ATTESTING]
    if wordings:
        lines.append("### Attestation Wording")
        lines.append("")
        for entry in wordings[:_MAX_WORDING_MD]:
            lines.append(
                f"- `{md_inline(entry.get('artifact_id'))}` — "
                f"{md_inline(entry.get('wording'), max_chars=400)}")
        if len(wordings) > _MAX_WORDING_MD:
            lines.append(
                f"- … {len(wordings) - _MAX_WORDING_MD} more in "
                f"`{REPORT_JSON_FILENAME}`.")
        lines.append("")

    # Coverage synthesis.
    lines.append("## Coverage Synthesis")
    lines.append("")
    coverage = report.get("coverage") or {}
    lines.append(md_inline(coverage.get("earned_note"), max_chars=400))
    lines.append("")
    earned = coverage.get("earned_journal_rows_total") or {}
    if earned:
        # Journal verdict labels are FOREIGN until proven vocabulary
        # (append_entry does not validate them) — unknown labels
        # render escaped, never title-cased raw.
        parts = ", ".join(
            f"{_journal_label_md(k)} {earned[k]}" for k in sorted(earned))
        lines.append(f"- Earned journal verdict rows: {parts}")
    else:
        lines.append("- Earned journal verdict rows: none recorded")
    at_verdict = coverage.get("at_verdict_time_rows_total") or {}
    if at_verdict != earned and at_verdict:
        parts = ", ".join(
            f"{_journal_label_md(k)} {at_verdict[k]}"
            for k in sorted(at_verdict))
        lines.append(
            f"- Rows recorded at verdict time: {parts} — the live "
            "journal differs; the divergence is per-artifact below")
    lines.append("")
    per_artifact = coverage.get("per_artifact") or []
    if per_artifact:
        lines.append(_md_row([
            "Artifact", "Journal Rows", "Checklist Items",
            "Reviewed (Analysed Depth)", "No-Lane Residual",
            "Advisory Llm Extent (Incl. Reads)",
        ]))
        lines.append(_md_row(["---"] * 6))
        for c in per_artifact[:_MAX_TABLE_ROWS_MD]:
            rows_n = sum((c.get("journal_verdict_rows") or {}).values())
            complete = "" if c.get("journal_load_complete") \
                else " (partial load)"
            if c.get("journal_rows_absent_since_verdict"):
                complete += " (rows absent since verdict)"
            elif c.get("journal_composition_diverged_since_verdict"):
                # Rows APPEARED since the verdict (or labels shifted
                # without any vanishing) — still a knowable
                # disagreement between the record and the live
                # journal, rendered, verdict unchanged.
                complete += " (composition diverged since verdict)"
            overlay = c.get("overlay") or {}
            if overlay.get("consumed"):
                cells = [
                    str(overlay.get("checklist_items", 0)),
                    str(overlay.get("reviewed_analysed_depth", 0)),
                    str(overlay.get("no_lane_residual", 0)),
                    str(overlay.get(
                        "advisory_llm_extent_including_reads", 0)),
                ]
            else:
                reason = _title_md(overlay.get("reason")
                                   or "unavailable")
                cells = ["—", "—", reason, "—"]
            lines.append(_md_row(
                [md_inline(c.get("artifact_id")),
                 f"{rows_n}{complete}"] + cells))
        lines.append("")
        lines.append(
            "Advisory columns are labeled strata only — they never "
            "count as earned coverage (N17).")
        lines.append("")

    # Survivors.
    survivors = report.get("survivors") or {}
    lines.append("## Findings And Survivors")
    lines.append("")
    total = survivors.get("total", 0)
    lines.append(f"- Finding-grade survivors: {total}")
    lines.append(f"- {md_inline(survivors.get('note'), max_chars=400)}")
    listed = survivors.get("listed") or []
    for item in listed[:_MAX_SURVIVORS_MD]:
        lines.append(
            f"  - `{md_inline(item.get('artifact_id'))}` "
            f"`{md_inline(item.get('file'))}`:"
            f"`{md_inline(item.get('function'))}` "
            f"({md_inline(item.get('run'))})")
    if total > min(len(listed), _MAX_SURVIVORS_MD):
        shown = min(len(listed), _MAX_SURVIVORS_MD)
        lines.append(f"  - … {total - shown} more in "
                     f"`{REPORT_JSON_FILENAME}`.")
    for deg in survivors.get("degraded") or []:
        lines.append(
            f"- Handoff degraded for "
            f"`{md_inline(deg.get('artifact_id'))}`: "
            f"{_title_md(deg.get('reason') or 'unloadable')} — the "
            "survivor count above excludes this chain's handoff")
    lines.append("")

    # Verified outcomes.
    outcomes = report.get("verified_outcomes") or {}
    lines.append("## Verified Outcomes")
    lines.append("")
    if outcomes.get("consumed"):
        lines.append(
            f"- Oracle-verified outcomes visible to this run: "
            f"{outcomes.get('count', 0)}")
        by_key = outcomes.get("by_oracle_status") or {}
        for key in sorted(by_key):
            lines.append(f"  - {_title_md(key)}: {by_key[key]}")
    else:
        lines.append(
            f"- Not consumed: "
            f"{_title_md(outcomes.get('reason') or 'unavailable')}")
    lines.append("")

    # Residual map.
    residual_map = report.get("residual_map") or {}
    lines.append("## Residual Map")
    lines.append("")
    lines.append(
        f"- Ledger residuals: "
        f"{residual_map.get('ledger_residuals_total', 0)}")
    for res in (residual_map.get("ledger_residuals")
                or [])[:_MAX_RESIDUALS_MD]:
        lines.append(
            f"  - {_title_md(res.get('kind'))}: "
            f"{md_inline(res.get('message'), max_chars=400)}")
    shown = min(len(residual_map.get("ledger_residuals") or []),
                _MAX_RESIDUALS_MD)
    if residual_map.get("ledger_residuals_total", 0) > shown:
        more = residual_map["ledger_residuals_total"] - shown
        lines.append(f"  - … {more} more in `{REPORT_JSON_FILENAME}`.")
    lines.append(
        f"- Identity collisions: "
        f"{residual_map.get('identity_collisions', 0)}")
    parked = residual_map.get("parked_artifacts") or []
    lines.append(f"- Parked artifacts: {len(parked)}")
    for aid in parked[:_MAX_RESIDUALS_MD]:
        lines.append(f"  - `{md_inline(aid)}`")
    scored = residual_map.get("scored_low_unverified") or []
    verified = residual_map.get("verified_low_exposure") or []
    lines.append(
        f"- Scored Low (unverified — never analysed at depth): "
        f"{len(scored)}")
    lines.append(
        f"- Verified Low Exposure (full mechanical exposure pass "
        f"ran): {len(verified)}")
    amendments = residual_map.get("policy_amendments") or []
    if amendments:
        lines.append(
            f"- Policy amendments (last "
            f"{min(len(amendments), _MAX_AMENDMENTS_MD)}):")
        for a in amendments[-_MAX_AMENDMENTS_MD:]:
            lines.append(
                f"  - {md_inline(a.get('at'))} "
                f"{_title_md(a.get('kind'))}")
    lines.append("")

    lines.append("## Next Steps")
    lines.append("")
    lines.append(
        "- Validate survivors: run /validate on the target with the "
        "recorded survivor list.")
    lines.append(
        "- Re-render visual maps: `libexec/raptor-render-diagrams "
        "<out-dir>`.")
    lines.append(
        "- Cross-run project view: `libexec/raptor-project-manager "
        "report` (and `correlate`).")
    lines.append(
        "- Coverage residual drill-down: `libexec/raptor-coverage-"
        "summary <dir> --residual`.")
    lines.append("")
    return "\n".join(lines)


# ── Terminal summary (bounded, escaped) ──────────────────────────────

def render_summary_lines(report: dict[str, Any]) -> list[str]:
    """A bounded operator summary for the launcher's terminal output."""
    counts = report.get("counts") or {}
    totals = report.get("attestation_totals") or {}
    survivors = report.get("survivors") or {}
    lines = [
        f"Engagement report — target "
        f"{_esc(report.get('target_root'))}",
        # counts is the ledger's FOREIGN block — the row count is
        # escaped like every other ledger value.
        f"  rows: {_esc(counts.get('rows', 0))}",
    ]
    if totals:
        parts = ", ".join(
            f"{_title(k)} {totals[k]}" for k in sorted(totals))
        lines.append(f"  attestation: {parts}")
    lines.append(f"  survivors: {survivors.get('total', 0)}")
    residual_map = report.get("residual_map") or {}
    lines.append(
        f"  residuals: {residual_map.get('ledger_residuals_total', 0)}"
        f" ledger, {len(residual_map.get('scored_low_unverified') or [])}"
        f" scored-low unverified")
    return lines


# ── Writers (atomic, locked, never into the target tree) ────────────

def write_report(
    output_dir: Path | str,
    report: dict[str, Any] | None = None,
) -> tuple[Path, Path]:
    """Atomically write both report artifacts (building the document
    first unless a prebuilt one is passed); returns
    ``(json_path, md_path)``."""
    out = Path(output_dir)
    if report is None:
        report = build_report(out)
    markdown = render_markdown(report)
    json_path = out / REPORT_JSON_FILENAME
    md_path = out / REPORT_MD_FILENAME
    with artifact_lock(json_path, subject="engagement report"):
        save_json(json_path, report)
        write_text_atomically(md_path, markdown)
    return json_path, md_path


__all__ = [
    "ATTESTING",
    "FINDINGS_PRESENT",
    "NON_ATTESTING",
    "NOT_ENGAGED",
    "REPORT_JSON_FILENAME",
    "REPORT_MD_FILENAME",
    "REPORT_SCHEMA",
    "build_report",
    "render_markdown",
    "render_summary_lines",
    "write_report",
]

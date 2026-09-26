"""Contradiction-triggered re-adjudication queue.

A recorded negative disposition (disproven / ruled-out / false-positive
/ dead-code ...) and a LATER independent claim at the same site are a
contradiction signal: either the disposition was wrong, or the new
claim is — and today both collision points resolve it silently. The
project merge fold prefers the more-progressed status, so the fresh
claim's representation is folded away; the /validate ``--findings``
import overwrites the working container wholesale. In both cases the
one moment where two independent adjudications disagree — exactly when
a recorded disproof is most worth re-examining — leaves no trace, and
the disagreement can only be rediscovered by hand-diffing artifacts.

The reverse direction is a contradiction too, at a higher bar: a LATER
source's disproof against an earlier CONFIRMED-TIER verdict (the
overturn class — see :data:`CONFIRMED_TIER_STATUSES`). A later disproof
over a mere hypothesis is ordinary validation progression and never
queues; a validated verdict being disproven by a different run is not
progression, it is one of the two adjudications being wrong. A third
class covers ONE completed run whose end-state holds both a
confirmed-tier verdict and a disproof at the same site (an intra-run
split — two final verdicts disagreeing inside one container). Each
queue record carries a ``shape`` field naming its class.

This module preserves the signal WITHOUT changing any verdict:

* the drop/fold behaviour at both chokepoints is untouched — a queue
  record is emitted IN ADDITION, never instead;
* nothing here overturns a recorded disposition. Re-adjudication is a
  validation-lane task; the queue is the input for a scoped /validate
  (or an operator review), not a verdict channel.

Matching granularity is site-level like the existing dedup keys
(``group_key``'s file+function; file+line as the fallback for
function-less rows). Mechanism (vuln_type / CWE) is compared but never
gates the match — a new claim whose mechanism falls outside the
disproof's recorded scope is queued WITH a mismatch note, because the
disproof may simply not cover it.

Queue records store capped raw fields (they are data, like
``suppressions.jsonl``); rendering sites apply the repo's
log-sanitisation conventions before any value reaches a terminal or
markdown surface.
"""

from __future__ import annotations

import json
import logging
import os
import stat as _stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING

from core.project.findings_utils import (
    _key_line,
    _key_str,
    finding_file,
    get_finding_id,
    load_findings_from_dir,
    oversized_findings_files,
    run_is_imported,
)

if TYPE_CHECKING:
    from collections.abc import Collection, Sequence

logger = logging.getLogger(__name__)

#: Queue artifact filename — one JSON object per line, tolerant schema
#: (consumers ignore unknown keys and non-dict lines) like its sibling
#: trail ``suppressions.jsonl``.
QUEUE_FILENAME = "readjudication-queue.jsonl"

#: Statuses that record a negative disposition. Mirrors the rank-4
#: family in ``core.project.merge._STATUS_RANK`` and
#: ``core.project.report._RULED_OUT_STATUSES`` — every member is a
#: "this is not a real/exploitable issue here" assertion that a later
#: independent positive claim contradicts. Deliberately includes the
#: environmental dispositions (dead_code / mitigated / unreachable):
#: a later signal that the site IS being hit is exactly as much a
#: reconsideration trigger for those as for a logical disproof.
DISPROOF_STATUSES = frozenset({
    "disproven",
    "ruled_out",
    "false_positive",
    "test_code",
    "dead_code",
    "mitigated",
    "unreachable",
})

#: Statuses that record a CONFIRMED-TIER (validated) positive verdict —
#: the rank-5+ family in ``core.project.merge._STATUS_RANK``. This is
#: the tier boundary for the overturn direction (a LATER source's
#: disproof contradicting an EARLIER source's claim at the same site):
#: only a validated claim queues. Adjudicated against the status
#: vocabulary, member by member:
#:
#: * IN — ``exploitable`` (rank 7), ``confirmed_constrained`` /
#:   ``confirmed_blocked`` (rank 6), ``confirmed`` /
#:   ``confirmed_unverified`` (rank 5): each asserts "this issue is
#:   real" as a concluded verdict; a later independent disproof
#:   OVERTURNS such a verdict rather than progressing it.
#: * OUT — ``poc_success`` (rank 3): an intermediate pipeline marker (a
#:   PoC artifact was built; validation had not concluded) that the
#:   vocabulary itself ranks BELOW the disproof family — a later
#:   disproof over it is the validation lane finishing its job.
#: * OUT — ``not_disproven`` (rank 2) and every unranked hypothesis
#:   grade (audit ``suspicious`` rows, dark rows, scanner defaults): a
#:   later run disproving a mere hypothesis is the system working as
#:   designed (/validate consuming /audit output), so queueing it
#:   would mint a record per ROUTINE validation pass and flood the
#:   queue; the merge fold already prefers the disproof, and no
#:   validated verdict is lost.
CONFIRMED_TIER_STATUSES = frozenset({
    "exploitable",
    "confirmed",
    "confirmed_unverified",
    "confirmed_blocked",
    "confirmed_constrained",
})

#: Queue-record shapes — the ``shape`` field, additive: readers treat
#: a missing shape as :data:`SHAPE_CLAIM_AFTER_DISPROOF`, the only
#: class pre-shape queues contained.
#:
#: * ``claim_after_disproof`` — a source LATER than a recorded disproof
#:   asserts the site again (any positive claim, hypothesis included).
#: * ``disproof_after_confirmed`` — a later source's disproof
#:   contradicts an earlier source's CONFIRMED-TIER verdict (the
#:   overturn class; tier boundary above).
#: * ``intra_run_split`` — ONE source's end-state carries both a
#:   confirmed-tier verdict and a disproof at the same site. Only
#:   detected for sources the caller marks FINAL (a completed run's
#:   container): two final verdicts disagreeing is a genuine
#:   inconsistency, while a claim+disproof pair passing through a
#:   LIVE container is transient in-pipeline refinement and stays
#:   excluded. Both sides must be final-status rows — a hypothesis
#:   beside a disproof in the same run is ordinary progression.
SHAPE_CLAIM_AFTER_DISPROOF = "claim_after_disproof"
SHAPE_OVERTURN = "disproof_after_confirmed"
SHAPE_INTRA_RUN_SPLIT = "intra_run_split"

#: Cap on free-text fields stored in a queue record. Findings rows are
#: LLM-authored or import-restored — unbounded prose must not turn the
#: queue into a multi-megabyte artifact.
_TEXT_CAP = 500

#: Cap on queue records per detection pass. Run dirs are agent-writable
#: and a hostile findings.json can stuff arbitrarily many rows; the cap
#: bounds the artifact and is announced with an explicit truncation
#: record (never a silent stop).
RECORD_CAP = 500

#: Cap on queue records per SITE. The queue's actionable unit is the
#: site (a scoped /validate targets sites), and mechanism identity is
#: attacker-influenced free text — without a per-site bound, one
#: matching site flooded with mechanism-varied claims fills the whole
#: global cap oldest-source-first and EVICTS every other site's real
#: contradiction. Beyond a handful of mechanism variants, extra
#: records at the same site add no adjudication signal; site
#: diversity is what the cap must preserve. Suppressions are counted
#: and announced (never silent).
SITE_RECORD_CAP = 5

#: Cap on a single mechanism identifier stored in a record. Mechanism
#: vocabulary is short (``CWE-N``, canonical vuln_type strings); the
#: raw field is attacker-influenced free text, and an uncapped entry
#: let one record smuggle megabytes past every _TEXT_CAP bound —
#: flooding the queue artifact beyond its readers' byte budgets. The
#: pair-dedup key uses the capped form (built from this same set).
_MECHANISM_CAP = 100


def _record_status(finding: dict[str, Any]) -> str:
    """The finding's most-final status string (``final_status`` wins,
    matching ``merge._status_rank``'s read order)."""
    for key in ("final_status", "status"):
        value = finding.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def is_disproof(finding: dict[str, Any]) -> bool:
    """True when *finding* records a negative disposition.

    ``ruling.status == "ruled_out"`` is checked as well: the stage-D
    merge normally syncs it into ``status``, but rows exported before
    that sync (or by producers that only write the ruling) still carry
    the disposition there.
    """
    if _record_status(finding) in DISPROOF_STATUSES:
        return True
    ruling = finding.get("ruling")
    return isinstance(ruling, dict) and ruling.get("status") == "ruled_out"


def is_confirmed_tier(finding: dict[str, Any]) -> bool:
    """True when *finding* records a confirmed-tier positive verdict
    (see :data:`CONFIRMED_TIER_STATUSES`). A row whose ruling says
    ``ruled_out`` is never confirmed-tier whatever its status field
    claims — :func:`is_disproof` wins the overlap conservatively (the
    row indexes as a disproof, not as an overturnable claim)."""
    return (_record_status(finding) in CONFIRMED_TIER_STATUSES
            and not is_disproof(finding))


def site_key(finding: dict[str, Any]) -> tuple[str, str, Any] | None:
    """Site identity for contradiction matching, or None when the row
    carries no usable location.

    Function-level first (``("fn", file, function)`` — the same
    file+function axis as ``findings_utils.group_key``), so two
    producers reporting different lines inside one function still
    match. Rows without a function fall back to ``("line", file,
    line)``. The two tiers deliberately do NOT cross-match: pairing a
    line-only row to a function-keyed disproof would need line-range
    data no finding shape carries.

    Known blind spots (named, not silently absorbed): a function
    RENAMED between the disproof and the new claim yields two sites
    and no match (nothing in the finding shape carries rename
    lineage); and producers with drifting function-name vocabularies
    (qualified vs bare names, module-scoped spellings) key different
    sites for the same code — pre-existing producer drift this
    matcher inherits rather than papers over.
    """
    file_path = finding_file(finding)
    if not file_path:
        return None
    function = _key_str(finding.get("function", ""))
    if function:
        return ("fn", file_path, function)
    line = _key_line(finding.get("line") or 0)
    if line:
        return ("line", file_path, line)
    return None


def _mechanisms(finding: dict[str, Any]) -> frozenset[str]:
    """The mechanism identifiers a row claims: normalised vuln_type
    plus CWE ids. The two vocabularies live in disjoint namespaces
    (lower-case types vs upper-case ``CWE-N``), so a set intersection
    only matches like with like.

    Entries are capped at :data:`_MECHANISM_CAP` — the raw fields are
    attacker-influenced free text and this set feeds BOTH the stored
    record and the pair-dedup key. Known coarseness: the schema's
    catch-all vuln_type ``other`` matches ``other``, so two unrelated
    novel-class claims read as mechanism-matched — acceptable because
    the comparison is a note, never a gate.
    """
    out: set[str] = set()
    vuln_type = finding.get("vuln_type")
    if isinstance(vuln_type, str) and vuln_type.strip():
        out.add(vuln_type.strip().lower()[:_MECHANISM_CAP])
    for key in ("cwe_id", "cwe"):
        cwe = finding.get(key)
        if isinstance(cwe, str) and cwe.strip():
            out.add(cwe.strip().upper()[:_MECHANISM_CAP])
    return frozenset(out)


def _cap_text(value: Any, cap: int = _TEXT_CAP) -> str:
    """Bound a record field. Storage-side capping only — records hold
    data; render sites escape (``core.security.log_sanitisation``)."""
    if not isinstance(value, str):
        value = "" if value is None else str(value)
    value = value.strip()
    if len(value) > cap:
        return value[: cap - 1] + "…"
    return value


def _claim_fields(finding: dict[str, Any], source: str) -> dict[str, Any]:
    """The new claim's identity + mechanism, capped."""
    return {
        "id": _cap_text(get_finding_id(finding) or "", 120),
        "source": _cap_text(source, 200),
        "status": _cap_text(_record_status(finding), 40),
        "rule_id": _cap_text(finding.get("rule_id") or "", 120),
        "tool": _cap_text(finding.get("tool") or "", 80),
        "mechanism": sorted(_mechanisms(finding)),
        # candidate_reasoning / dataflow_summary close the chain for
        # real /validate rows, which carry those fields rather than
        # title/description/message — without them every claim summary
        # from the validate corpus rendered empty.
        "summary": _cap_text(
            finding.get("title")
            or finding.get("description")
            or finding.get("message")
            or finding.get("candidate_reasoning")
            or finding.get("dataflow_summary")
            or "",
            300,
        ),
        "timestamp": _cap_text(finding.get("timestamp") or "", 40),
    }


def _disproof_fields(finding: dict[str, Any], source: str) -> dict[str, Any]:
    """The matched disproof's identity, scope, and — crucially — its own
    stated reconsideration condition (``disproved_because.
    would_reconsider_if``, the GATE-1 field), so the queue reader sees
    whether the new signal meets the condition the disproof itself
    named."""
    ruling = finding.get("ruling")
    ruling = ruling if isinstance(ruling, dict) else {}
    because = finding.get("disproved_because")
    because = because if isinstance(because, dict) else {}
    fields = {
        "id": _cap_text(get_finding_id(finding) or "", 120),
        "source": _cap_text(source, 200),
        "status": _cap_text(
            _record_status(finding) or ruling.get("status") or "", 40),
        "mechanism": sorted(_mechanisms(finding)),
        "reason": _cap_text(
            ruling.get("reason") or because.get("conclusion") or ""),
        "timestamp": _cap_text(finding.get("timestamp") or "", 40),
    }
    reconsider = because.get("would_reconsider_if")
    if isinstance(reconsider, str) and reconsider.strip():
        fields["would_reconsider_if"] = _cap_text(reconsider)
    return fields


def build_queue_record(
    claim: dict[str, Any],
    claim_source: str,
    disproof: dict[str, Any],
    disproof_source: str,
    *,
    prior_disproof_count: int = 1,
    prior_claim_count: int = 1,
    shape: str = SHAPE_CLAIM_AFTER_DISPROOF,
) -> dict[str, Any]:
    """One queue record: site identity, the claim side, the disproof
    side, and the mechanism comparison. ``action`` is always ``queued``
    — the queue NEVER overturns; adjudication happens in a scoped
    /validate.

    ``new_claim`` is the CLAIM-SIDE slot and ``disproof`` the
    disproof-side slot in EVERY shape (the field name is historical —
    pre-shape queues only held claim-after-disproof records, where the
    claim really was the newer item). ``shape`` carries the temporal
    direction; readers treat a missing shape as
    :data:`SHAPE_CLAIM_AFTER_DISPROOF`."""
    claim_mech = _mechanisms(claim)
    disproof_mech = _mechanisms(disproof)
    # Tri-state: True/False only when BOTH sides recorded a mechanism;
    # a side with no vocabulary at all is "unknown", not a mismatch.
    mechanism_match: bool | None = None
    if claim_mech and disproof_mech:
        mechanism_match = bool(claim_mech & disproof_mech)
    record: dict[str, Any] = {
        "kind": "readjudication",
        "action": "queued",
        "shape": _cap_text(shape, 40),
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "site": {
            "file": _cap_text(
                finding_file(claim) or finding_file(disproof), 300),
            "function": _cap_text(
                _key_str(claim.get("function", ""))
                or _key_str(disproof.get("function", "")),
                200,
            ),
            "line": _key_line(claim.get("line") or 0),
        },
        "new_claim": _claim_fields(claim, claim_source),
        "disproof": _disproof_fields(disproof, disproof_source),
        "mechanism_match": mechanism_match,
    }
    if mechanism_match is False:
        record["mechanism_note"] = (
            "new claim's mechanism is outside the disproof's recorded "
            "scope — the disproof may not cover it"
        )
    if prior_disproof_count > 1:
        record["prior_disproofs_at_site"] = prior_disproof_count
    if prior_claim_count > 1:
        record["prior_confirmed_at_site"] = prior_claim_count
    return record


def detect_contradictions(
    sources: Sequence[tuple[str, list[dict[str, Any]]]],
    *,
    final_sources: Collection[str] = frozenset(),
) -> list[dict[str, Any]]:
    """Detect cross-adjudication contradictions, in both directions.

    *sources* is ordered OLDEST-first (the same order the merge fold
    consumes). Three record shapes:

    * :data:`SHAPE_CLAIM_AFTER_DISPROOF` — a non-disproof claim in a
      source strictly LATER than a source that recorded a disproof at
      the same site (any claim tier: a fresh hypothesis against a
      recorded disproof is already a reconsideration signal).
    * :data:`SHAPE_OVERTURN` — a disproof in a source strictly LATER
      than a source that recorded a CONFIRMED-TIER verdict at the same
      site (see :data:`CONFIRMED_TIER_STATUSES` for the adjudicated
      tier boundary). The direction is deliberately asymmetric: a
      later disproof over a mere hypothesis is ordinary validation
      progression and stays unqueued; only a validated verdict being
      disproven is overturn-shaped.
    * :data:`SHAPE_INTRA_RUN_SPLIT` — a confirmed-tier verdict AND a
      disproof at the same site inside ONE source listed in
      *final_sources* (labels of sources that are a COMPLETED run's
      end-state container). Outside that opt-in, a claim+disproof
      pair inside one source never queues in either direction — that
      is in-pipeline refinement — and even inside it, a
      hypothesis-tier row beside a disproof is ordinary progression:
      BOTH sides must be final statuses.

    One record per (shape, site, claim source, disproof source, newer
    side's mechanism); when several disproofs (or confirmed claims)
    precede, the LATEST one is quoted and ``prior_disproofs_at_site``
    / ``prior_confirmed_at_site`` carries the count.

    Bounds — announced, never silent: :data:`SITE_RECORD_CAP` per
    site FIRST (mechanism identity is attacker-influenced free text;
    one flooded site must never occupy the global cap and evict other
    sites' real contradictions — site diversity is the queue's
    value), then :data:`RECORD_CAP` overall; both caps are shared
    across the shapes (a site flooded in one direction cannot annex
    headroom in another). Every suppression is counted on the
    terminal truncation record (``suppressed``), which each rendering
    surface (report section, /project findings notice, merge log,
    /review) re-states.
    """
    disproofs: dict[tuple, list[tuple[str, dict[str, Any]]]] = {}
    confirmed: dict[tuple, list[tuple[str, dict[str, Any]]]] = {}
    records: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    site_queued: dict[tuple, int] = {}
    suppressed = 0

    def _admit(pair: tuple, key: tuple) -> bool:
        """Shared pair-dedup + cap bookkeeping for every shape."""
        nonlocal suppressed
        if pair in seen:
            return False
        seen.add(pair)
        if (site_queued.get(key, 0) >= SITE_RECORD_CAP
                or len(records) >= RECORD_CAP):
            suppressed += 1
            return False
        site_queued[key] = site_queued.get(key, 0) + 1
        return True

    for label, findings in sources:
        rows = [f for f in findings if isinstance(f, dict)]
        # Detection first, then this source's rows are indexed — so a
        # same-source pair never fires in either direction.
        for finding in rows:
            if is_disproof(finding):
                continue
            key = site_key(finding)
            if key is None:
                continue
            prior = disproofs.get(key)
            if not prior:
                continue
            pair = (SHAPE_CLAIM_AFTER_DISPROOF, key, label,
                    prior[-1][0], _mechanisms(finding))
            if not _admit(pair, key):
                continue
            disproof_label, disproof_row = prior[-1]
            records.append(build_queue_record(
                finding, label, disproof_row, disproof_label,
                prior_disproof_count=len(prior),
            ))
        for finding in rows:
            if not is_disproof(finding):
                continue
            key = site_key(finding)
            if key is None:
                continue
            prior = confirmed.get(key)
            if not prior:
                continue
            pair = (SHAPE_OVERTURN, key, prior[-1][0], label,
                    _mechanisms(finding))
            if not _admit(pair, key):
                continue
            claim_label, claim_row = prior[-1]
            records.append(build_queue_record(
                claim_row, claim_label, finding, label,
                prior_claim_count=len(prior),
                shape=SHAPE_OVERTURN,
            ))
        if label in final_sources:
            local_conf: dict[tuple, list[dict[str, Any]]] = {}
            local_dis: dict[tuple, list[dict[str, Any]]] = {}
            for finding in rows:
                key = site_key(finding)
                if key is None:
                    continue
                if is_disproof(finding):
                    local_dis.setdefault(key, []).append(finding)
                elif is_confirmed_tier(finding):
                    local_conf.setdefault(key, []).append(finding)
            for key, conf_rows in local_conf.items():
                dis_rows = local_dis.get(key)
                if not dis_rows:
                    continue
                for conf in conf_rows:
                    pair = (SHAPE_INTRA_RUN_SPLIT, key, label, label,
                            _mechanisms(conf))
                    if not _admit(pair, key):
                        continue
                    records.append(build_queue_record(
                        conf, label, dis_rows[-1], label,
                        prior_disproof_count=len(dis_rows),
                        shape=SHAPE_INTRA_RUN_SPLIT,
                    ))
        for finding in rows:
            key = site_key(finding)
            if key is None:
                continue
            if is_disproof(finding):
                disproofs.setdefault(key, []).append((label, finding))
            elif is_confirmed_tier(finding):
                confirmed.setdefault(key, []).append((label, finding))
    if suppressed:
        records.append({
            "kind": "readjudication",
            "action": "truncated",
            "suppressed": suppressed,
            "note": (
                f"record caps reached (per-site {SITE_RECORD_CAP}, "
                f"total {RECORD_CAP}) — {suppressed} further "
                f"contradiction(s) not recorded"
            ),
        })
    return records


def _run_completed(run_dir: Path) -> bool:
    """Completed-run predicate gating intra-run split detection.
    Tolerant and fail-closed toward NOT queueing: missing or
    unreadable run metadata reads as not-completed, so a live or
    half-written container never has its transient claim+disproof
    pairs promoted to split records."""
    try:
        from core.run.metadata import STATUS_COMPLETED, load_run_metadata
        meta = load_run_metadata(run_dir)
        return (isinstance(meta, dict)
                and meta.get("status") == STATUS_COMPLETED)
    except Exception:  # noqa: BLE001 — predicate is an aid, never a crash
        return False


def detect_project_contradictions(
    run_dirs: Sequence[Path],
) -> list[dict[str, Any]]:
    """Project-level detection over per-run findings.

    *run_dirs* is ordered OLDEST-first, the order ``merge_findings``
    consumes. Runs restored by ``/project import`` are labelled
    ``(imported)`` on the record — their claims carry
    attacker-selectable statuses (unsigned archives), so a reader
    weighs those contradictions accordingly.

    COMPLETED runs (per their run metadata) are passed as final
    sources, enabling intra-run split detection over their end-state
    containers: a confirmed-tier verdict and a disproof both
    surviving to a run's completion is a genuine inconsistency. Live
    and swept-failed runs never split-detect — their containers are
    transient. (An imported run's status is archive-supplied like the
    rest of its rows; its split records carry the ``(imported)``
    label for the reader to weigh.)
    """
    sources: list[tuple[str, list[dict[str, Any]]]] = []
    final_labels: set[str] = set()
    for run_dir in run_dirs:
        run_dir = Path(run_dir)
        findings = load_findings_from_dir(run_dir)
        if not findings:
            continue
        label = run_dir.name
        if run_is_imported(run_dir):
            label += " (imported)"
        if _run_completed(run_dir):
            final_labels.add(label)
        sources.append((label, findings))
    return detect_contradictions(
        sources, final_sources=frozenset(final_labels))


#: Byte budget for the COMPLETION-TIME project sweep (see
#: :func:`refresh_project_queue`): the summed size of every sibling
#: run's findings artifacts, cheaply stat'd before anything is read.
#: Both directions of the limit matter: too LOW and the refresh
#: silently defers to a manual /project report on exactly the
#: many-run projects where cross-run contradictions accumulate; too
#: HIGH and every run completion re-reads a kernel-scale project's
#: whole findings corpus. 256 MiB (= 4 single-file size-gate maxima,
#: MAX_FINDINGS_JSON_BYTES) keeps ordinary projects — dozens of runs,
#: megabyte-scale findings — fully covered while bounding the
#: completion hook on outliers, which get a loud deferral notice
#: instead of a silent partial detection. No incremental mode exists
#: to prefer: every detection pass is a FRESH recomputation by
#: contract (see :func:`write_queue`), so the only honest cheap exit
#: is not running the sweep at all.
PROJECT_SWEEP_BYTE_BUDGET = 256 * 1024 * 1024


def refresh_project_queue(project_dir: Path) -> Path | None:
    """Recompute and (re)write the PROJECT-level queue artifact —
    ``<project>/_report/readjudication-queue.jsonl``, the same path
    ``/project report`` materialises — from the project's run dirs.

    The completion-time bridge: the import-time detector only sees
    the destination run's own container, so a sibling run's recorded
    disproofs and confirmed verdicts were invisible until an operator
    happened to run ``/project report``. Calling this at run
    completion closes that gap. Read-only over the run dirs (the
    shared ``core.run.locate`` enumerator; oldest-first, the merge
    fold's order) plus one atomic queue write.

    Cost-bounded: when the summed size of the runs' findings
    artifacts exceeds :data:`PROJECT_SWEEP_BYTE_BUDGET`, the sweep is
    SKIPPED with a loud deferral notice and any existing queue file is
    left in place — a stale-but-computed queue beats deleting signal
    this pass never recomputed, and ``/project report`` (uncapped)
    remains the full-detection surface.

    The per-file findings gate defers under the SAME contract: when
    any run's artifact exceeds ``MAX_FINDINGS_JSON_BYTES`` (so
    detection's loader would silently EXCLUDE that run — see
    :func:`core.project.findings_utils.oversized_findings_files` for
    the exact fallback-chain preview), the recompute is incomplete by
    construction and the refresh defers: return None, existing queue
    left byte-identical, loud notice with the skipped-file count.
    Rewriting or deleting the queue over the gate-excluded view could
    remove records that depended on the excluded run. The preview is
    stat-only like the budget; a file grown between the stat and the
    read is still refused by the loader's own re-check (that residual
    window needs a concurrent writer inside the project dir, which
    already equals the capability gained).

    ADJUDICATED: ``/project report`` deliberately remains the
    force-fresh surface — its own write path recomputes and writes
    the queue over the gated view, consistent with every other
    artifact it derives from that same view (its merged findings.json
    excludes the oversized run too), and the findings-file gate
    warning announces the exclusion there at warning level. If report
    also deferred, NO surface could refresh the queue while an
    oversized artifact existed.

    Returns the written path, or None when nothing was written (no
    runs, per-file-gate or budget deferral, empty detection, or
    refused write).
    """
    project_dir = Path(project_dir)
    from core.run.locate import run_dirs_newest_first
    run_dirs = list(reversed(run_dirs_newest_first(project_dir)))
    if not run_dirs:
        return None
    total_bytes = 0
    gate_skipped: list[Path] = []
    for run_dir in run_dirs:
        gate_skipped.extend(oversized_findings_files(run_dir))
        for name in ("findings.json", "openant_findings.json"):
            try:
                total_bytes += (run_dir / name).stat().st_size
            except OSError:
                continue
    if gate_skipped:
        logger.info(
            "readjudication: completion-time project sweep deferred for "
            "%s — %d findings artifact(s) exceed the per-file gate, so "
            "detection would silently exclude their run(s); an existing "
            "queue file is left as-is (never replaced by a partial "
            "recompute). Shrink or inspect the flagged file(s) — the "
            "findings-file gate warning names each — or run /project "
            "report, which recomputes over the gated view.",
            project_dir, len(gate_skipped),
        )
        return None
    if total_bytes > PROJECT_SWEEP_BYTE_BUDGET:
        logger.info(
            "readjudication: completion-time project sweep skipped for "
            "%s — findings artifacts total %d bytes (budget %d); an "
            "existing queue file is left as-is. Run /project report "
            "for the full detection.",
            project_dir, total_bytes, PROJECT_SWEEP_BYTE_BUDGET,
        )
        return None
    records = detect_project_contradictions(run_dirs)
    report_dir = project_dir / "_report"
    if not records and not report_dir.is_dir():
        # Nothing to write and nothing stale to clear — don't mint an
        # empty _report dir on every projectless-of-contradiction run.
        return None
    try:
        report_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        # A planted non-dir at _report: write_queue could not land
        # anyway; the refresh is best-effort by contract.
        logger.debug("readjudication: cannot create %s", report_dir,
                     exc_info=True)
        return None
    return write_queue(report_dir, records)


def queued_count(records: Sequence[dict[str, Any]]) -> int:
    """Queued contradiction signals (excludes marker records)."""
    return sum(
        1 for r in records
        if isinstance(r, dict) and r.get("action") == "queued"
    )


def suppressed_count(records: Sequence[dict[str, Any]]) -> int:
    """Contradictions the caps refused to record (from the truncation
    marker's ``suppressed`` field). Every surface that renders a
    queued count re-states this number — a capped queue must never
    read as a complete one. Tolerant: only positive int-typed fields
    count (the queue file is agent-writable)."""
    total = 0
    for record in records:
        if not isinstance(record, dict):
            continue
        if record.get("action") != "truncated":
            continue
        value = record.get("suppressed")
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            total += value
    return total


def record_shape(record: dict[str, Any]) -> str:
    """The record's shape; a missing / non-string shape reads as
    :data:`SHAPE_CLAIM_AFTER_DISPROOF` (the only class pre-shape
    queues contained)."""
    shape = record.get("shape")
    if isinstance(shape, str) and shape:
        return shape
    return SHAPE_CLAIM_AFTER_DISPROOF


def shape_counts(records: Sequence[dict[str, Any]]) -> dict[str, int]:
    """Queued records per shape (marker records excluded)."""
    counts: dict[str, int] = {}
    for record in records:
        if not isinstance(record, dict) or record.get("action") != "queued":
            continue
        shape = record_shape(record)
        counts[shape] = counts.get(shape, 0) + 1
    return counts


def contradicted_disproof_count(records: Sequence[dict[str, Any]]) -> int:
    """Distinct recorded disproofs that later claims contradict — the
    honest headline number ("N recorded disproofs contradicted").
    Claim-after-disproof records only: in the other shapes the
    ``disproof`` slot holds the NEWER item (the contradicting signal,
    not a contradicted disposition), so counting it would inflate."""
    seen: set[tuple] = set()
    for record in records:
        if not isinstance(record, dict) or record.get("action") != "queued":
            continue
        if record_shape(record) != SHAPE_CLAIM_AFTER_DISPROOF:
            continue
        disproof = record.get("disproof")
        disproof = disproof if isinstance(disproof, dict) else {}
        site = record.get("site")
        site = site if isinstance(site, dict) else {}
        seen.add((
            site.get("file"), site.get("function"), site.get("line"),
            disproof.get("source"), disproof.get("id"),
        ))
    return len(seen)


def write_queue(
    out_dir: Path, records: Sequence[dict[str, Any]],
) -> Path | None:
    """Write the queue artifact FRESH into *out_dir*; best-effort.

    Fresh, not append: every detection pass is a full recomputation
    over its current inputs, so appending would duplicate the same
    contradictions on each re-run of a merged view. An empty
    detection removes a stale queue file so a resolved contradiction
    doesn't linger.

    Hardening — the queue lives in agent-writable run/report dirs:

    * No-open lstat gate first: a pre-planted special (symlink, FIFO,
      device) at the queue path is refused LOUDLY without ever
      opening it — an open on a FIFO blocks forever (the plantable
      hang ``core.json.bounded`` documents), and this writer must
      never block or write through a link. lstat never follows and
      never blocks.
    * Atomic tempfile + rename via ``core.atomic_fs`` (the shared
      primitive, O_EXCL/O_NOFOLLOW-hardened tempfile) — concurrent
      merged-view regenerations replace the file whole instead of
      tearing each other's half-written lines. The gate is by-name;
      a special swapped in AFTER it is replaced by the rename, which
      opens nothing at the destination — the lstat is the loud
      refusal, the rename is the safety.

    Returns the written path, or None when nothing was written.
    """
    path = Path(out_dir) / QUEUE_FILENAME
    try:
        st = os.lstat(path)
    except OSError:
        st = None
    if st is not None and not _stat.S_ISREG(st.st_mode):
        logger.warning(
            "readjudication: refusing non-regular queue path %s "
            "(mode=0o%o) — planted special?", path, st.st_mode,
        )
        return None
    try:
        if not records:
            if st is not None:
                path.unlink(missing_ok=True)
            return None
        payload = "".join(
            json.dumps(record, sort_keys=True, allow_nan=False) + "\n"
            for record in records
        ).encode("utf-8")
        from core.atomic_fs import write_bytes_atomically
        write_bytes_atomically(path, payload, tmp_prefix=".~readj-")
    except (OSError, TypeError, ValueError):
        # Best-effort by contract: the queue is an additive signal —
        # a write failure must never break the merge / report / import
        # it rides on.
        logger.debug("readjudication queue write failed for %s", path,
                     exc_info=True)
        return None
    return path


__all__ = [
    "CONFIRMED_TIER_STATUSES",
    "DISPROOF_STATUSES",
    "PROJECT_SWEEP_BYTE_BUDGET",
    "QUEUE_FILENAME",
    "RECORD_CAP",
    "SHAPE_CLAIM_AFTER_DISPROOF",
    "SHAPE_INTRA_RUN_SPLIT",
    "SHAPE_OVERTURN",
    "SITE_RECORD_CAP",
    "build_queue_record",
    "contradicted_disproof_count",
    "detect_contradictions",
    "detect_project_contradictions",
    "is_confirmed_tier",
    "is_disproof",
    "queued_count",
    "record_shape",
    "refresh_project_queue",
    "shape_counts",
    "site_key",
    "suppressed_count",
    "write_queue",
]

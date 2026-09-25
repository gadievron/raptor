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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING

from core.project.findings_utils import (
    _key_line,
    _key_str,
    finding_file,
    get_finding_id,
    load_findings_from_dir,
    run_is_imported,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

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

#: Cap on free-text fields stored in a queue record. Findings rows are
#: LLM-authored or import-restored — unbounded prose must not turn the
#: queue into a multi-megabyte artifact.
_TEXT_CAP = 500

#: Cap on queue records per detection pass. Run dirs are agent-writable
#: and a hostile findings.json can stuff arbitrarily many rows; the cap
#: bounds the artifact and is announced with an explicit truncation
#: record (never a silent stop).
RECORD_CAP = 500


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
    only matches like with like."""
    out: set[str] = set()
    vuln_type = finding.get("vuln_type")
    if isinstance(vuln_type, str) and vuln_type.strip():
        out.add(vuln_type.strip().lower())
    for key in ("cwe_id", "cwe"):
        cwe = finding.get(key)
        if isinstance(cwe, str) and cwe.strip():
            out.add(cwe.strip().upper())
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
        "summary": _cap_text(
            finding.get("title")
            or finding.get("description")
            or finding.get("message")
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
) -> dict[str, Any]:
    """One queue record: site identity, the new claim, the matched
    disproof, and the mechanism comparison. ``action`` is always
    ``queued`` — the queue NEVER overturns; adjudication happens in a
    scoped /validate."""
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
    return record


def detect_contradictions(
    sources: Sequence[tuple[str, list[dict[str, Any]]]],
) -> list[dict[str, Any]]:
    """Detect recorded-disproof-vs-later-claim contradictions.

    *sources* is ordered OLDEST-first (the same order the merge fold
    consumes): a contradiction is a non-disproof claim in a source
    strictly LATER than a source that recorded a disproof at the same
    site. The reverse order (claim, then disproof) is ordinary
    validation progression, and a claim+disproof pair inside ONE
    source is intra-run pipeline progression — neither queues.

    One record per (site, claim source, disproof source, claim
    mechanism); when several disproofs precede the claim, the LATEST
    one is quoted and ``prior_disproofs_at_site`` carries the count.
    Bounded by :data:`RECORD_CAP` with an explicit truncation record.
    """
    disproofs: dict[tuple, list[tuple[str, dict[str, Any]]]] = {}
    records: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    truncated = 0
    for label, findings in sources:
        # Claims first, then this source's disproofs are indexed —
        # so a same-source pair never fires.
        for finding in findings:
            if not isinstance(finding, dict) or is_disproof(finding):
                continue
            key = site_key(finding)
            if key is None:
                continue
            prior = disproofs.get(key)
            if not prior:
                continue
            pair = (key, label, prior[-1][0], _mechanisms(finding))
            if pair in seen:
                continue
            seen.add(pair)
            if len(records) >= RECORD_CAP:
                truncated += 1
                continue
            disproof_label, disproof_row = prior[-1]
            records.append(build_queue_record(
                finding, label, disproof_row, disproof_label,
                prior_disproof_count=len(prior),
            ))
        for finding in findings:
            if not isinstance(finding, dict) or not is_disproof(finding):
                continue
            key = site_key(finding)
            if key is not None:
                disproofs.setdefault(key, []).append((label, finding))
    if truncated:
        records.append({
            "kind": "readjudication",
            "action": "truncated",
            "note": (
                f"record cap {RECORD_CAP} reached — "
                f"{truncated} further contradiction(s) not recorded"
            ),
        })
    return records


def detect_project_contradictions(
    run_dirs: Sequence[Path],
) -> list[dict[str, Any]]:
    """Project-level detection over per-run findings.

    *run_dirs* is ordered OLDEST-first, the order ``merge_findings``
    consumes. Runs restored by ``/project import`` are labelled
    ``(imported)`` on the record — their claims carry
    attacker-selectable statuses (unsigned archives), so a reader
    weighs those contradictions accordingly.
    """
    sources: list[tuple[str, list[dict[str, Any]]]] = []
    for run_dir in run_dirs:
        run_dir = Path(run_dir)
        findings = load_findings_from_dir(run_dir)
        if not findings:
            continue
        label = run_dir.name
        if run_is_imported(run_dir):
            label += " (imported)"
        sources.append((label, findings))
    return detect_contradictions(sources)


def queued_count(records: Sequence[dict[str, Any]]) -> int:
    """Queued contradiction signals (excludes marker records)."""
    return sum(
        1 for r in records
        if isinstance(r, dict) and r.get("action") == "queued"
    )


def contradicted_disproof_count(records: Sequence[dict[str, Any]]) -> int:
    """Distinct recorded disproofs the queue contradicts — the honest
    headline number ("N recorded disproofs contradicted")."""
    seen: set[tuple] = set()
    for record in records:
        if not isinstance(record, dict) or record.get("action") != "queued":
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


_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


def write_queue(
    out_dir: Path, records: Sequence[dict[str, Any]],
) -> Path | None:
    """Write the queue artifact FRESH into *out_dir*; best-effort.

    Fresh (truncate), not append: every detection pass is a full
    recomputation over its current inputs, so appending would
    duplicate the same contradictions on each re-run of a merged view.
    Symlink-refusing open (O_NOFOLLOW) — the queue lives in agent-
    writable run/report dirs, the same trust posture as
    ``core.json.append_jsonl``. An empty detection removes a stale
    queue file so a resolved contradiction doesn't linger (symlinked
    paths are left alone — never operate through one).

    Returns the written path, or None when nothing was written.
    """
    path = Path(out_dir) / QUEUE_FILENAME
    try:
        if not records:
            if path.is_symlink():
                logger.debug(
                    "readjudication: refusing symlinked queue path %s", path)
            elif path.is_file():
                path.unlink()
            return None
        payload = "".join(
            json.dumps(record, sort_keys=True, allow_nan=False) + "\n"
            for record in records
        ).encode("utf-8")
        flags = (os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                 | _O_NOFOLLOW | _O_CLOEXEC)
        fd = os.open(str(path), flags, 0o644)
        try:
            view = memoryview(payload)
            written = 0
            while written < len(view):
                n = os.write(fd, view[written:])
                if n <= 0:
                    raise OSError(
                        f"short write to {path}: os.write returned {n}")
                written += n
        finally:
            os.close(fd)
    except (OSError, TypeError, ValueError):
        # Best-effort by contract: the queue is an additive signal —
        # a write failure must never break the merge / report / import
        # it rides on.
        logger.debug("readjudication queue write failed for %s", path,
                     exc_info=True)
        return None
    return path


__all__ = [
    "DISPROOF_STATUSES",
    "QUEUE_FILENAME",
    "RECORD_CAP",
    "build_queue_record",
    "contradicted_disproof_count",
    "detect_contradictions",
    "detect_project_contradictions",
    "is_disproof",
    "queued_count",
    "site_key",
    "write_queue",
]
